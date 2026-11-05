from collections import Counter
from scapy.all import sniff, IP, TCP, UDP

# ports i care about. the mDNS/LLMNR ones showed up because my router
# screams them at multicast constantly
NAMES = {
    53: "DNS",
    443: "HTTPS",
    80: "HTTP",
    22: "SSH",
    5353: "mDNS",
    5355: "LLMNR",
}

talked_to = Counter()


def show_packet(pkt):
    if IP not in pkt:
        return

    src, dst = pkt[IP].src, pkt[IP].dst

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        # S = SYN, SA = SYN-ACK, A = ACK/data, FA = connection teardown
        flags = str(pkt[TCP].flags)
        name_s = NAMES.get(sport, str(sport))
        name_d = NAMES.get(dport, str(dport))
        print(f"{src:15} -> {dst:15}  TCP  {name_s:7} -> {name_d:7} [{flags}]")
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        print(f"{src:15} -> {dst:15}  UDP  {NAMES.get(sport, str(sport)):7} -> {NAMES.get(dport, str(dport))}")
    else:
        # probably ICMP. todo: handle it
        print(f"{src:15} -> {dst:15}  ???")

    for ip in (src, dst):
        # skip local + multicast, only keep actual remote hosts
        if not ip.startswith(("192.168.", "224.")):
            talked_to[ip] += 1


print("[*] sniffing. open a website. ctrl+c stops.\n")

try:
    sniff(prn=show_packet, store=0)  # store=0 or it hoards every packet in ram
except KeyboardInterrupt:
    pass

print("\n" + "=" * 45)
if talked_to:
    print(f"[*] talked to {len(talked_to)} remote host(s):")
    for ip, count in talked_to.most_common(10):
        print(f"    {ip:18} {count:4} pkts")
else:
    print("[*] nothing captured")
print("=" * 45)
