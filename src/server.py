import scapy.all as scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP

def packet_handler(packet):
    if packet.haslayer(scapy.ICMP):
        icmp_packet = packet[scapy.ICMP]
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if icmp_packet.type == 8:
            icmp_type = "Echo Request"
        elif icmp_packet.type == 0:
            icmp_type = "Echo Reply"
        else:
            print(icmp_packet.type)
            icmp_type = "Unknown"

        print(f"ICMP Type: {icmp_type}")
        print(f"Source MAC Address: {src_mac}")
        print(f"Destination MAC Address: {dst_mac}")
        print(f"Source IP Address: {src_ip}")
        print(f"Destination IP Address: {dst_ip}")
        print("\n")

scapy.sniff(prn=packet_handler, filter="icmp", store=0)
