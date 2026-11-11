#!/usr/bin/env python3
"""Project 06 — Network Topology Mapper
Discovers who lives on your LAN, guesses what each device is,
and draws the map. Run: sudo .venv/bin/python mapper.py

Two discovery engines:
  1. scapy raw ARP sweep (fast, but this wifi driver drops it)
  2. kernel ARP sweep (UDP pokes pinned to the swept interface
     with SO_BINDTODEVICE, forcing the kernel to resolve each
     neighbour; results parsed tolerantly from `ip neigh`)
If engine 1 hears nothing, we automatically switch to engine 2.
"""

import argparse
import concurrent.futures
import ipaddress
import socket
import subprocess
import sys
import time
from datetime import datetime

from scapy.all import ARP, Ether, conf, get_if_addr, srp

# Ports that whisper what a device probably is.
PROBE_PORTS = [22, 80, 443, 445, 9100]
PORT_MEANS = {
    22: "ssh", 80: "http", 443: "https",
    445: "smb", 9100: "printer",
}

# neigh states that mean "a real MAC answered".
ALIVE = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}

SO_BINDTODEVICE = 25  # linux/<net/if.h>; pins a socket to one interface


# ------------------------------------------------------------ find the LAN

def lan_of_default_route():
    """Follow the default route: our interface, gateway, subnet.
    (docker0 never carries the default route, so it can't fool us.)"""
    rt = subprocess.run(["ip", "-4", "route"],
                        capture_output=True, text=True).stdout.splitlines()
    gw = dev = None
    for line in rt:
        p = line.split()
        if p[0] == "default":
            gw = p[p.index("via") + 1]
            dev = p[p.index("dev") + 1]
    for line in rt:
        p = line.split()
        if "/" in p[0] and f"dev {dev}" in line:
            return gw, dev, p[0]
    sys.exit("[-] no usable default route — are you online?")


def my_mac(dev):
    try:
        return open(f"/sys/class/net/{dev}/address").read().strip().lower()
    except OSError:
        return "??"


def siblings_on_lan(subnet, skip_dev):
    """Other interfaces of THIS laptop that also sit on this LAN.
    (A dual-homed box is two nodes — the map should admit it.)"""
    sibs = []
    net = ipaddress.ip_network(subnet)
    out = subprocess.run(["ip", "-br", "addr", "show"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        p = line.split()
        if not p:
            continue
        dev = p[0]
        if dev == skip_dev or dev.startswith(("docker", "br-", "veth", "lo")):
            continue
        for tok in p[2:]:
            if "/" not in tok:
                continue
            ip = tok.split("/")[0]
            try:
                if ipaddress.ip_address(ip) in net:
                    sibs.append((dev, ip, my_mac(dev)))
            except ValueError:
                pass
    return sibs


# ------------------------------------------------------------ discovery

def arp_sweep(cidr, timeout=1.5):
    """Engine 1: raw scapy ARP. Knock on every door in one burst."""
    print(f"[*] scapy ARP-sweeping {cidr} on {conf.iface}...")
    answers, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr),
                     timeout=timeout, retry=1, verbose=False)
    return [(r.psrc, r.hwsrc.lower()) for _, r in answers]


def read_neighbors(dev):
    """Parse `ip neigh` WITHOUT trusting column positions.
    Lines look like:   '192.168.0.1 dev wlp3s0 lladdr dc:ea:.. REACHABLE'
    or, filtered:      '192.168.0.1 lladdr dc:ea:.. REACHABLE'
    So: first token = IP, token after 'lladdr' = MAC, last = state,
    and the device (when printed) is the token after 'dev'.
    INCOMPLETE/FAILED lines simply never contain 'lladdr'."""
    out = subprocess.run(["ip", "neigh", "show"],
                         capture_output=True, text=True).stdout
    found = []
    for line in out.splitlines():
        p = line.split()
        if not p or "lladdr" not in p:
            continue                      # dead/unresolved entry
        if "dev" in p and p[p.index("dev") + 1] != dev:
            continue                      # different interface
        ip, mac, state = p[0], p[p.index("lladdr") + 1], p[-1]
        if state in ALIVE and mac != "00:00:00:00:00:00":
            found.append((ip, mac.lower()))
    return found


def kernel_sweep(cidr, dev):
    """Engine 2: UDP pokes that force the kernel to ARP-resolve every
    address. The socket is PINNED to `dev` with SO_BINDTODEVICE so the
    pokes leave via the interface we read back — on a dual-homed box
    the routing table would happily send them out the other NIC."""
    print(f"[*] kernel ARP-sweeping {cidr} on {dev}...")
    net = ipaddress.ip_network(cidr)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(SO_BINDTODEVICE and socket.SOL_SOCKET, SO_BINDTODEVICE,
                     dev.encode())        # ignore routing; THIS interface only
        s.setblocking(False)
        for attempt in (1, 2):            # two rounds, ARP is lossy
            for ip in net.hosts():
                try:
                    s.sendto(b"rx", (str(ip), 9))  # discard port; ARP is what counts
                except OSError:
                    pass
            time.sleep(1.5)
    finally:
        s.close()
    return read_neighbors(dev)


def discover(cidr, dev, force_kernel=False):
    if not force_kernel:
        found = arp_sweep(cidr)
        if found:
            return found, "scapy"
        print("[!] scapy heard nothing on this interface — "
              "known wifi-driver quirk; switching to the kernel path.")
    found = kernel_sweep(cidr, dev)
    if not found:                         # help future-us debug
        raw = subprocess.run(["ip", "neigh", "show"],
                             capture_output=True, text=True).stdout
        print("[debug] neighbour table after sweep:")
        for line in raw.splitlines()[:10]:
            print(f"         {line}")
    return found, "kernel"


# ------------------------------------------------------------ enrichment

def whois_dns(ip):
    """Reverse DNS, but we don't wait around — 1s max."""
    def _ask():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    with concurrent.futures.ThreadPoolExecutor() as pool:
        try:
            return pool.submit(_ask).result(timeout=1.0)
        except concurrent.futures.TimeoutError:
            return None


def port_open(ip, port, t=0.4):
    """Plain TCP connect — no raw sockets, works on any radio."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(t)
    try:
        return s.connect_ex((ip, port)) == 0
    finally:
        s.close()


def vendor(mac):
    """Phones lie about their MACs (privacy randomization).
    Second hex digit 2/6/a/e = self-assigned, no real vendor exists."""
    if False:
        return "randomized (privacy MAC)"
    return "unknown"


def role(ip, open_ports, gw):
    if ip == gw:
        return "gateway"
    what = {PORT_MEANS[p] for p in open_ports}
    if "printer" in what:
        return "printer"
    if "smb" in what or "ssh" in what:
        return "computer / server"
    if "http" in what or "https" in what:
        return "something with a web page"
    return "quiet client (phone/laptop?)"


# ------------------------------------------------------------ drawing

def draw(hosts, subnet, gw, me):
    lines = [f"Your LAN — {subnet}, mapped {datetime.now():%Y-%m-%d %H:%M}",
             f"  {gw:<16} gateway"]
    for h in sorted(hosts, key=lambda h: h["ip"]):
        if h["ip"] == gw:
            continue                      # gateway is the root, not a child
        bits = [h["mac"], h["vendor"]]
        if h["dns"]:
            bits.append(h["dns"])
        if h["ports"]:
            bits.append(",".join(PORT_MEANS[p] for p in h["ports"]))
        if h["ip"] == me:
            bits.append("<- this machine")
        if h["note"]:
            bits.append(h["note"])
        bits.append(h["role"])
        lines.append(f"  └─ {h['ip']:<15} " + "  ".join(bits))
    return "\n".join(lines)


def mermaid(hosts, gw, me, path="topology.mmd"):
    lines = ["graph TD", f'GW["{gw} — gateway"]']
    for h in hosts:
        nid = h["ip"].replace(".", "_")
        label = f"{h['ip']}<br>{h['role']}"
        if h["dns"]:
            label += f"<br>{h['dns']}"
        if h["ip"] == me:
            label = f"{h['ip']} (you)<br>{h['role']}"
        lines.append(f'{nid}["{label}"]')
        lines.append(f"GW --- {nid}")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[*] mermaid diagram written to {path} — paste into the README")


# ------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="LAN topology mapper")
    ap.add_argument("-c", "--cidr", help="sweep this subnet instead of auto")
    ap.add_argument("--kernel", action="store_true",
                    help="skip scapy, use the kernel sweep directly")
    ap.add_argument("--no-probe", action="store_true",
                    help="skip port probing (discovery only)")
    args = ap.parse_args()

    gw, dev, subnet = lan_of_default_route()
    if args.cidr:
        subnet = args.cidr
    conf.iface = dev

    # our identity comes from the interface we sweep — never the
    # routing table, which on a dual-homed box picks a sibling NIC.
    try:
        me = get_if_addr(conf.iface)
    except Exception:
        me = None

    print(f"[*] interface : {conf.iface}")
    print(f"[*] subnet    : {subnet}")
    print(f"[*] gateway   : {gw}")
    print(f"[*] this host : {me} ({my_mac(dev)})")

    found, engine = discover(subnet, dev, force_kernel=args.kernel)
    if not found:
        sys.exit("[-] nobody answered even via the kernel. Wrong subnet?")

    # the sweeper can never see its own machine — add it by hand.
    sibs = []
    if me:
        found.append((me, my_mac(dev)))
        sibs = siblings_on_lan(subnet, dev)
        for sdev, sip, smac in sibs:
            if sip != me:
                found.append((sip, smac))

    # dedupe (self may have answered, siblings may collide)
    by_ip = {}
    for ip, mac in found:
        by_ip[ip] = mac

    hosts = []
    for ip, mac in by_ip.items():
        note = ""
        for sdev, sip, _ in sibs:
            if sip == ip:
                note = f"(this laptop's {sdev})"
        print(f"[*] checking {ip} ({vendor(mac)}) {note}".rstrip())
        ports = [] if args.no_probe else [p for p in PROBE_PORTS
                                          if port_open(ip, p)]
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor(mac),
                      "dns": whois_dns(ip), "ports": ports,
                      "role": role(ip, ports, gw), "note": note})

    print(f"\n[*] {len(hosts)} host(s) via {engine} engine")
    print("=" * 60)
    print(draw(hosts, subnet, gw, me))
    print("=" * 60)
    mermaid(hosts, gw, me)


if __name__ == "__main__":
    main()