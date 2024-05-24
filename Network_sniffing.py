from scapy.all import sniff, IP, TCP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            print(f"IP Packet: {ip_src} -> {ip_dst} (TCP: {tcp_sport} -> {tcp_dport})")
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst}")

print("Starting network sniffer...")
sniff(filter="ip", prn=packet_callback, store=0)
