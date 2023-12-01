from scapy.all import *

def udp_packet_callback(packet):
    if UDP in packet:
        print("Source IP:", packet[IP].src)
        print("Source Port:", packet[UDP].sport)
        print("\n")

# Start sniffing UDP packets
sniff(filter="udp", prn=udp_packet_callback, store=0)

