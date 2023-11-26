from scapy.all import *

# target ip
ip_destination = "192.168.1.2"  

# broadcast
ip_source_broadcast = "192.168.1.255"  

# Port 7 "echo" port
port_destination = 7

message = "Hello, UDP Echo!"

udp_packet = IP(src=ip_source_broadcast, dst=ip_destination)/UDP(dport=port_destination)/Raw(load=message)

send(udp_packet)

print(f"Message envoyé: {message}")
