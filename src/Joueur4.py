from scapy.all import *

# Adresse IP de la machine cible
ip_destination = "192.168.1.2"  # Remplacez par l'adresse IP de la machine cible

# Adresse IP de broadcast en source
ip_source_broadcast = "192.168.1.255"  # Remplacez par l'adresse de broadcast de votre réseau

# Port 7 est le port par défaut pour le service "echo"
port_destination = 7

# Message à envoyer
message = "Hello, UDP Echo!"

# Création du paquet UDP
udp_packet = IP(src=ip_source_broadcast, dst=ip_destination)/UDP(dport=port_destination)/Raw(load=message)

# Envoi du paquet
send(udp_packet)

# Affichage du message envoyé
print(f"Message envoyé: {message}")
