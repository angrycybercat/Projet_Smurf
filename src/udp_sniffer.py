from scapy.all import *

def packet_callback(packet):
    if packet.haslayer(UDP):
        # Affiche des informations sur le paquet UDP
        print("Paquet UDP capturé ! Source:", packet[IP].src, "Destination:", packet[IP].dst)
        print("Données du paquet :")
        print(packet[UDP].payload)

def main():
    print("Sniffer UDP démarré. En attente de paquets UDP...")
    # Capture en continu des paquets UDP
    sniff(filter="udp", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()

