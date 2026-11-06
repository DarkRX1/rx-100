#!/usr/bin/env python3
"""rx-100 project 5: packet sniffer with protocol analysis.

captures packets on an interface, dissects them layer by layer,
classifies the conversation (dns / dhcp / arp / mdns / llmnr / tls ...)
and prints one tidy line per packet. keeps a live tally, can
export to pcap and hexdump payloads.

usage:
    sudo python sniffer.py -i wlp3s0                 # until ctrl+c
    sudo python sniffer.py -i wlp3s0 -c 20           # 20 packets
    sudo python sniffer.py -i wlp3s0 -t 60          # 60 seconds
    sudo python sniffer.py -i wlp3s0 -p dns          # only dns
    sudo python sniffer.py -i wlp3s0 -f "port 53"    # raw bpf filter
    sudo python sniffer.py -i wlp3s0 -x -c 5         # + hexdump
    sudo python sniffer.py -i wlp3s0 -o out.pcap     # save capture

ethics: point this at your own interface, your own traffic.
hexdump shows payload bytes - plaintext protocols leak
credentials. redact before sharing anything.
"""

import argparse
import signal
import sys
import time

try:
    from scapy.all import (
        sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP,
        DNS, BOOTP, DHCP, Ether, Raw,
    )
except ImportError:
    sys.exit("[-] scapy missing: pip install scapy")


# ---------------------------------------------------------------- classifier

def classify(pkt):
    """name the conversation. returns (label, detail or '').

    order matters, most specific first. note: mdns and llmnr carry
    a DNS layer inside, so the PORT checks must come before
    haslayer(DNS) or every multicast lookup gets mislabeled.
    """
    # DHCP sits inside BOOTP + DHCP options
    if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
        opt = pkt[DHCP].options[0]
        msg_type = {1: "discover", 2: "offer", 3: "request",
                    5: "ack"}.get(opt[1], opt[1])
        return "DHCP", msg_type

    # multicast service discovery FIRST - before haslayer(DNS),
    # because mdns/llmnr packets contain DNS layers too.
    if pkt.haslayer(UDP) and pkt.haslayer(IP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
        if sp == 5353 or dp == 5353:
            return "mDNS", "multicast service discovery"
        if sp == 5355 or dp == 5355:
            return "LLMNR", "link-local name lookup"

    if pkt.haslayer(DNS):
        try:
            name = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
        except Exception:
            name = ""
        if pkt[DNS].qr == 0 and name:
            return "DNS", "query  " + name
        elif name:
            return "DNS", "answer  " + name
        return "DNS", ""

    if pkt.haslayer(ARP):
        # op 1 = who-has (question), op 2 = is-at (self-announcement)
        if pkt[ARP].op == 1:
            return "ARP", "who-has"
        return "ARP", "announce (is-at)"

    if pkt.haslayer(ICMP):
        return "ICMP", "echo-request" if pkt[ICMP].type == 8 else "reply/other"

    if pkt.haslayer(TCP):
        s, d = pkt[TCP].sport, pkt[TCP].dport
        flags = str(pkt[TCP].flags)
        if d == 443 or s == 443:
            return "TLS", "SYN" if "S" in flags else "data/fin"
        if d == 80 or s == 80:
            return "HTTP", "SYN" if "S" in flags else "data/fin"

    return "", ""


# ---------------------------------------------------------------- formatter

def flow_string(pkt):
    """src:port -> dst:port line for l3 packets, else l2 info."""
    if pkt.haslayer(IP):
        ip = pkt[IP]
        l4 = ""
        if pkt.haslayer(TCP):
            l4 = f":{pkt[TCP].sport} -> {ip.dst}:{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            l4 = f":{pkt[UDP].sport} -> {ip.dst}:{pkt[UDP].dport}"
        else:
            l4 = f" -> {ip.dst}"
        return f"{ip.src}{l4}", len(pkt)
    if pkt.haslayer(IPv6):
        v6 = pkt[IPv6]
        return f"{v6.src} -> {v6.dst}", len(pkt)
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        if a.op == 1:
            return f"{a.psrc} asking about {a.pdst}", len(pkt)
        return f"{a.hwsrc} announces itself as {a.psrc}", len(pkt)
    if pkt.haslayer(Ether):
        e = pkt[Ether]
        return f"l2 only: {e.src} -> {e.dst} (type {hex(e.type)})", len(pkt)
    return "unparsed frame", len(pkt)


def timestamp(pkt):
    try:
        t = float(pkt.time)
    except Exception:
        t = time.time()
    return time.strftime("%H:%M:%S", time.localtime(t))


# ---------------------------------------------------------------- the loop

def main():
    ap = argparse.ArgumentParser(description="packet sniffer with protocol analysis")
    ap.add_argument("-i", "--interface", required=True, help="interface to listen on")
    ap.add_argument("-c", "--count", type=int, default=0, help="stop after N packets (0 = forever)")
    ap.add_argument("-t", "--seconds", type=int, default=0,
                    help="stop after N seconds (0 = forever)")
    ap.add_argument("-p", "--protocol", default=None,
                    choices=["dhcp", "dns", "arp", "icmp", "mdns", "llmnr",
                             "ssdp", "http", "tls"],
                    help="only show these conversations")
    ap.add_argument("-f", "--filter", default=None, help="raw BPF filter passed to libpcap")
    ap.add_argument("-x", "--hexdump", action="store_true", help="print payload hexdump")
    ap.add_argument("-o", "--out", default=None, help="write matching packets to this pcap on exit")
    args = ap.parse_args()

    # native time limit: alarm raises the same exception ctrl+c would,
    # so sniff() unwinds cleanly through the normal tally path.
    if args.seconds > 0:
        def _alarm(sig, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(args.seconds)

    # build the capture filter: user BPF + protocol shortcut glued together
    bpf_bits = []
    proto_bpf = {
        "dhcp": "udp port 67 or udp port 68",
        "dns": "port 53",
        "arp": "arp",
        "icmp": "icmp",
        "mdns": "port 5353",
        "llmnr": "udp port 5355",
        "ssdp": "udp port 1900",
        "http": "tcp port 80",
        "tls": "tcp port 443",
    }
    if args.protocol:
        bpf_bits.append(proto_bpf[args.protocol])
    if args.filter:
        bpf_bits.append(f"({args.filter})")
    bpf = " and ".join(bpf_bits) or None

    tally = {}
    captured = []

    def handle(pkt):
        captured.append(pkt)
        label, detail = classify(pkt)
        key = label or "other"
        tally[key] = tally.get(key, 0) + 1
        flow, plen = flow_string(pkt)
        tag = label.ljust(5) if label else "-"
        print(f"{timestamp(pkt)}  {tag}  {flow}  {detail}  ({plen}B)")
        if args.hexdump and pkt.haslayer(Raw):
            print(pkt[Raw].load.hex(sep=" ", bytes_per_sep=8))
            print()

    limits = []
    if args.count:
        limits.append(f"{args.count} packets")
    if args.seconds:
        limits.append(f"{args.seconds}s")
    print(f"[*] listening on {args.interface}" +
          (f"  filter: {bpf}" if bpf else "") +
          (f"  stop after {' or '.join(limits)}" if limits else "  [ctrl+c to stop]"))

    # scapy 2.8.0 chokes on count=None (int < None comparison kills the
    # socket after ONE packet). so: only pass count when user asked for one.
    # scapy's default (count unset) already means "no limit".
    kwargs = {"iface": args.interface, "filter": bpf,
              "prn": handle, "store": False}
    if args.count:
        kwargs["count"] = args.count

    try:
        sniff(**kwargs)
    except PermissionError:
        sys.exit("[-] need root for raw capture. sudo me.")
    except KeyboardInterrupt:
        print("\n[*] stopped.")

    if args.seconds > 0:
        signal.alarm(0)  # disarm if we stopped early via -c

    print("\n---- tally ----")
    for k, v in sorted(tally.items(), key=lambda x: -x[1]):
        print(f"  {v:5d}  {k}")

    if args.out:
        wrpcap(args.out, captured)
        print(f"\n[*] {len(captured)} packets written to {args.out}")


if __name__ == "__main__":
    main()
