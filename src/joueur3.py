from scapy.all import *
from scapy.layers.inet import IP, ICMP

src_ip ="192.168.43.217"
destination_ip ="192.168.43.54"

# Create the ICMP Echo Request packet with the destination IP
ping_packet = IP(dst=destination_ip,src=src_ip) / ICMP()

# Send the packet to the destination IP
send(ping_packet)
