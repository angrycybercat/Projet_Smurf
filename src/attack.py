from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP


# Remplacez les valeurs par l'adresse IP et l'adresse MAC souhaitées
destination_ip = "192.168.1.1"
source_mac = "FF:FF:FF:FF:FF:FF"

# Créez le paquet ICMP Echo Request avec l'adresse IP de destination
ping_packet = Ether(src=source_mac)/IP(dst=destination_ip)/ICMP()

# Envoyez le paquet ICMP à l'adresse IP de destination
send(ping_packet)
