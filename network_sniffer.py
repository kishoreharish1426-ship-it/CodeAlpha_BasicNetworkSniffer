from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

LOG_FILE = "packet_log.txt"


def process_packet(packet):
    if IP not in packet:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"

    output = (
        f"\nTime: {timestamp}\n"
        f"Source IP      : {source_ip}\n"
        f"Destination IP : {destination_ip}\n"
        f"Protocol       : {protocol}\n"
        + "-" * 50
    )

    print(output)

    with open(LOG_FILE, "a") as file:
        file.write(output + "\n")


print("=" * 50)
print("      CodeAlpha - Basic Network Sniffer")
print("=" * 50)
print("Capturing packets...")
print("Press Ctrl + C to stop.\n")

sniff(prn=process_packet, store=False)