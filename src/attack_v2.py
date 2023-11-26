from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

source_mac = #Vous
dst_mac = #Joueur 3
src_ip = #Joueur 2
destination_ip = #Joueur 1

# Create the ICMP Echo Request packet with the destination IP
ping_packet = Ether(src=source_mac,dst=dst_mac) / IP(dst=destination_ip,src=src_ip) / ICMP()

# Send the packet to the destination IP
sendp(ping_packet)
