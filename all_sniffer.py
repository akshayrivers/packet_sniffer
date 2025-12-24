import signal
import sys
import argparse
import time
from datetime import datetime

from scapy.all import sniff, PcapWriter
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether

# ---------- helpers ----------

def protocol_name(pkt):
    if pkt.haslayer(ARP): return "ARP"
    if pkt.haslayer(ICMP): return "ICMP"
    if pkt.haslayer(TCP): return "TCP"
    if pkt.haslayer(UDP): return "UDP"
    if pkt.haslayer(IP): return "IP"
    if pkt.haslayer(Ether): return "ETH"
    return pkt.__class__.__name__

def short_summary(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    proto = protocol_name(pkt)
    length = len(pkt)

    if pkt.haslayer(IP):
        ip = pkt[IP]
        sport = dport = ""
        if pkt.haslayer(TCP):
            sport = f":{pkt[TCP].sport}"
            dport = f":{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            sport = f":{pkt[UDP].sport}"
            dport = f":{pkt[UDP].dport}"
        return f"{ts} {ip.src}{sport} -> {ip.dst}{dport} {proto} len={length}"

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        return f"{ts} {arp.psrc} -> {arp.pdst} ARP op={arp.op} len={length}"

    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return f"{ts} {eth.src} -> {eth.dst} ETH type=0x{eth.type:04x} len={length}"

    return f"{ts} {pkt.summary()} len={length}"

# ---------- globals ----------
pcap_writer = None
running = True

# ---------- packet handler ----------

def process_packet(pkt):
    global pcap_writer
    print(short_summary(pkt))
    if pcap_writer:
        pcap_writer.write(pkt)

# ---------- signal handler ----------

def on_sigint(signum, frame):
    global running, pcap_writer
    print("\n[!] Ctrl-C received, stopping...")
    running = False
    if pcap_writer:
        pcap_writer.close()
        print("[+] PCAP file closed cleanly")
    sys.exit(0)

signal.signal(signal.SIGINT, on_sigint)

# ---------- main ----------

def main():
    global pcap_writer

    parser = argparse.ArgumentParser(description="Python Packet Sniffer with PCAP dump")
    parser.add_argument("-o", "--output", help="Output PCAP file")
    parser.add_argument("-t", "--time", type=int, help="Run time in seconds")
    args = parser.parse_args()

    if args.output:
        pcap_writer = PcapWriter(args.output, append=True, sync=True)
        print(f"[+] Writing packets to {args.output}")

    print("[*] Starting sniff on en0 (Ctrl-C to stop)")
    start_time = time.time()

    while running:
        try:
            sniff(
                iface="en0",
                prn=process_packet,
                store=False,
                count=50
            )
        except Exception as e:
            print(f"[!] Sniffer restarted due to: {e}")

        if args.time and (time.time() - start_time) >= args.time:
            print("[*] Time limit reached")
            break

    if pcap_writer:
        pcap_writer.close()
        print("[+] PCAP file closed cleanly")

if __name__ == "__main__":
    main()