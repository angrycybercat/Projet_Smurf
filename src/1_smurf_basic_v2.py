from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP

# Set the source MAC address to the broadcast address
source_mac = "ff:ff:ff:ff:ff:ff"

# Replace the values with the desired destination IP
destination_ip = "192.168.56.107"

source_ip = "192.168.56.255"

# Create the ICMP Echo Request packet with the destination IP
ping_packet = Ether(src=source_mac) / IP(src=source_ip,dst=destination_ip) / ICMP()

# Send the packet to the destination IP
sendp(ping_packet,iface="eth0")
