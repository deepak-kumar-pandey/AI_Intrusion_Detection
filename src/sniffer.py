from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    """Callback function executed every time Scapy captures a network packet."""
    if IP in packet:
        timestamp = datetime.now().strftime("%H:%M:%S")
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        pkt_len = len(packet)

        # Extract port information if available
        src_port = packet.sport if hasattr(packet, 'sport') else '-'
        dst_port = packet.dport if hasattr(packet, 'dport') else '-'

        print(f"[{timestamp}] {proto:<5} | {ip_src}:{src_port} -> {ip_dst}:{dst_port} | Length: {pkt_len} bytes")

def start_sniffing():
    print("=" * 60)
    print("  AI Intrusion Detection System - Live Packet Sniffer")
    print("=" * 60)
    print("Listening for incoming/outgoing traffic... (Press Ctrl+C to stop)\n")

    try:
        # store=False ensures captured packets are discarded from RAM immediately after processing
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n\nCapture terminated by user.")
    except PermissionError:
        print("\n[!] Permission Denied: Packet capture requires Administrator privileges on Windows.")

if __name__ == "__main__":
    start_sniffing()