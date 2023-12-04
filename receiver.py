#!/usr/bin/python3

import sys
import time
from socket import *
from struct import *
import csv

if len(sys.argv) < 2:
    print("Usage: {} ifname".format(sys.argv[0]))
    sys.exit(0)

# Nome da interface local
ifname = sys.argv[1]

# Cria um descritor de socket do tipo RAW 
ETH_P_ALL = 0x0003
s = socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))

# Associa socket a interface local
s.bind((ifname, 0))

# Initialize counters
arp_counter = 0
ipv4_counter = 0
tcp_counter = 0
udp_counter = 0
icmp_counter = 0
total_bytes = 0
arp_bytes = 0
ipv4_bytes = 0
tcp_bytes = 0
udp_bytes = 0
icmp_bytes = 0
ipv6_bytes = 0
ipv6_counter = 0

def format_mac(mac):
    return ':'.join('%02x' % b for b in mac)

def get_frame_type(ethertype):
    if ethertype > 1500:
        return "DIX"
    else:
        return "IEEE 802.3"

def get_current_time():
    return time.strftime("%Y-%m-%d %H:%M:%S")

print("Esperando quadros ...")
while True:
    # Receive data
    ret = s.recvfrom(65565)
    frame = ret[0]

    # Ethernet header
    eth_length = 14
    eth_header = frame[:eth_length]
    eth = unpack('!6s6sH', eth_header)
    mac_dst = frame[0:6]
    mac_src = frame[6:12]
    ethertype = ntohs(eth[2])


    arp_raw_data, _ = s.recvfrom(65535)  # Recebe dados brutos
    arp_eth_header = arp_raw_data[:14]  # Tamanho do cabeçalho Ethernet
    arp_eth = unpack("!6s6s2s", eth_header)

    # Write to CSV
    with open("layer2.csv", mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
        get_current_time(),
        get_frame_type(ethertype),  # Leave EtherType empty for IEEE 802.3 get_frame_type(ethertype),
        format_mac(mac_src),
        format_mac(mac_dst),
        hex(ethertype) if get_frame_type(ethertype) == "DIX" else "",
        len(frame)
    ])

    # Layer 2 - IP (0x0800) or IPv6 (0x86DD)
    if ethertype == 0x08:  # IPv4
        ipv4_counter += 1
        ipv4_bytes += len(frame)
        total_bytes += ipv4_bytes
        ip_header = frame[eth_length:eth_length + 20]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]
        src_ip = inet_ntoa(iph[8])
        dst_ip = inet_ntoa(iph[9])

        version = "IPv4" if version == 4 else "IPv6"


        # Write to CSV
        with open("layer3-ip.csv", mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
            get_current_time(),
            version,
            src_ip,
            dst_ip,
            ethertype,
            len(frame)
        ])

        # Layer 4 - TCP (6) or UDP (17)
        if protocol == 6:  # TCP
            tcp_counter += 1
            tcp_bytes += len(frame)
            tcp_header = frame[eth_length + iph_length:eth_length + iph_length + 20]
            tcph = unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            dst_port = tcph[1]
            sequence_number = tcph[2]
            ack_number = tcph[3]

            # Write to CSV
            with open("layer4.csv", mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                get_current_time(),
                "TCP",
                src_ip,
                src_port,
                dst_ip,
                len(frame)
            ])
            
        elif protocol == 1: # ICMP
            icmp_counter +=1
            icmp_bytes += len(frame)

            icmp_header = frame[eth_length + iph_length:eth_length + iph_length + 8]  # Obtém o cabeçalho ICMP (8 bytes)
            icmp_type, icmp_code, icmp_checksum = unpack('!BBH', icmp_header)
            
        elif protocol == 17:  # UDP
            udp_counter += 1
            udp_bytes += len(frame)
            udp_header = frame[eth_length + iph_length:eth_length + iph_length + 8]
            udph = unpack('!HHHH', udp_header)
            src_port = udph[0]
            dst_port = udph[1]

            # Write to CSV
            with open("layer4.csv", mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                get_current_time(),
                "UDP",
                src_ip,
                src_port,
                dst_ip,
                len(frame)
            ])

    elif ethertype == 0x86DD: # IPv6
        ipv6_bytes += len(frame)
        ipv6_counter += 1

    # Layer 3 - ARP (0x0806)
    elif ethertype == 0x608: #ethertype == b'\x08\x06':
        arp_counter += 1
        arp_bytes += len(frame)
        total_bytes += len(frame)
        arp_header = frame[eth_length:eth_length + 28]

        # Unpack ARP header
        arp_hdr = unpack('HHBBH6s4s6s4s', arp_header)
        arp_type = arp_hdr[4]

        src_mac = format_mac(frame[8:14])
        src_ip = inet_ntoa(arp_hdr[6])
        dst_mac = format_mac(frame[18:24])
        dst_ip = inet_ntoa(arp_hdr[8])

        arp_type = "request" if arp_hdr[2] + arp_hdr[3] == b'\x00\x01' else "reply"

        # Write to CSV for Layer 3 (ARP)
        with open('layer3-arp.csv', mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                get_current_time(),
                "ARP",
                arp_type,
                src_mac,
                src_ip,
                dst_mac,
                dst_ip,
                len(frame)
            ])

    print("-------------------------------------------------------------")
    
    print("\nARP Packets: {}, Bytes: {}".format(arp_counter, arp_bytes))
    print("IPv4 Packets: {}, Bytes: {}".format(ipv4_counter, ipv4_bytes))
    print("IPv6 Packets: {}, Bytes: {}".format(ipv6_counter, ipv6_bytes))
    print("TCP Packets: {}, Bytes: {}".format(tcp_counter, tcp_bytes))
    print("UDP Packets: {}, Bytes: {}".format(udp_counter, udp_bytes))
    print("ICMP Packets: {}, Bytes: {}".format(icmp_counter, icmp_bytes))
    print("Total Bytes: {}".format(total_bytes))
