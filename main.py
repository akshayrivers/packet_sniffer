import signal
import sys
from datetime import datetime
from scapy.layers.inet import IP,TCP,UDP,ICMP
from scapy.layers.l2 import ARP, Ether

from scapy.all import sniff

def protocol_name(pkt):
    if(pkt.haslayer(ARP)): return "ARP"
    if(pkt.haslayer(ICMP)): return "ICMP"
    if(pkt.haslayer(TCP)): return "TCP"
    if(pkt.haslayer(UDP)): return "UDP"
    if(pkt.haslayer(IP)): return "IP"
    if(pkt.haslayer(Ether)): return "ETH"
    return pkt.__class__.__name__

def short_summary(pkt):
    ts = datetime.now().strftime("%H:%M:%S")
    proto = protocol_name(pkt)
    length= len(pkt)
    length = len(pkt)
    if pkt.haslayer(IP):
        ip= pkt[IP]
        sport= dport=""
        if pkt.haslayer(TCP):
            sport= f":{pkt[TCP].sport}"
            dport= f":{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            sport= f":{pkt[UDP].sport}"
            dport= f":{pkt[TCP].dport}"
        return f"{ts} {ip.src}{sport} -> {ip.dst}{dport} {proto} len={length}"
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        return f"{ts} {arp.psrc} -> {arp.dst} ARP op={arp.op} len={length}"
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        return f"{ts} {eth.src} -> {eth.dst} ETH type=0x{eth.type:04x} len={length}"
    return f"{ts} {[pkt.summary()]} len={length}"
        
def process_packet(pkt):
    print(short_summary(pkt))
    

def on_sigint(signum,frame):
    print("\n[!] Stopping sniff (Ctrl-C)")
    raise SystemExit(0)

signal.signal(signal.SIGINT, on_sigint)
    
if __name__ == "__main__":
    print("[*] Starting sniff. Press Ctrl-C to stop")
    while True:
        try:
            sniff(prn=process_packet, store=False, iface="en0", count=50)
        except Exception as e:
            print(f"[!] Sniffer restarted due to: {e}")
            continue