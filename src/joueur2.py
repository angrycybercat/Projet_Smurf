"""\
This script sends custom ICMP packets
Change MAC, IP adresses and network interface before running.

Author: Aya

Usage: sudo python joueur2.py
"""

from scapy.all import Ether, IP, sendp, ICMP

SRC_MAC = "9E:DB:7D:E2:EC:54"
SRC_IP = "192.168.43.217"

DST_MAC = "8C:C8:4B:4D:C4:D5"
DST_IP = "192.168.43.54"

IFACE = "Wi-Fi 2"

packet = Ether(src=SRC_MAC, dst=DST_MAC) / \
         IP(src=SRC_IP, dst=DST_IP)/ ICMP()

sendp(packet, iface=IFACE)
