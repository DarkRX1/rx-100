#!/usr/bin/env python3
# arp spoofing detector. watches ARP traffic for the same IP being claimed
# by two different MACs — which is basically the definition of arp poisoning
#
# run with sudo, same as the monitor:
#   sudo .venv/bin/python detector.py

from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, ARP

# ip -> {macs we've seen claiming it}. if one set ever gets bigger than
# one entry, someone on this lan is lying.
ip_macs = defaultdict(set)

# Gratuitous ARP happens on legitimate network changes too (dhcp renewals,
# router reboots, failover clusters). So instead of screaming on every
# second mac ever seen, keep quiet unless the claims happen close together.
CLAIM_WINDOW_SECONDS = 60

# ip -> {mac -> last time we saw this claim}
last_seen = defaultdict(dict)


def alert(ip, mac_a, mac_b):
    # two different macs both insist they own this ip. that's the attack
    print(f"\n[!!] ARP CONFLICT for {ip}")
    print(f"     {mac_a}")
    print(f"     {mac_b}")
    print(f"     at {datetime.now().strftime('%H:%M:%S')}\n")


def watch_arp(pkt):
    arp = pkt[ARP]

    # op 1 = "who has", op 2 = "i am". both announce psrc/hwsrc claims,
    # so count both
    ip = arp.psrc
    mac = arp.hwsrc

    if not ip or ip == "0.0.0.0":
        # probe announcements skip these
        return

    now = datetime.now().timestamp()
    macs = ip_macs[ip]

    if mac not in macs:
        if macs:
            # someone ELSE already claimed this ip. check if recently —
            # if the other claim was seconds ago we have a live conflict,
            # if it was hours ago it's probably just a legit change
            other_macs_recent = [
                m for m, t in last_seen[ip].items()
                if m != mac and now - t < CLAIM_WINDOW_SECONDS
            ]
            if other_macs_recent:
                alert(ip, other_macs_recent[0], mac)
        macs.add(mac)

    last_seen[ip][mac] = now

    # quiet log of everything we see, so you can tell the script is alive
    kind = "who-has" if arp.op == 1 else "is-at"
    print(f"{kind:8} {ip:16} {mac}")


print("[*] watching ARP traffic. ctrl+c stops.\n")

try:
    # bpf filter: the kernel drops non-ARP packets before python even
    # sees them, way cheaper than checking layers in the callback
    sniff(prn=watch_arp, store=0, filter="arp")
except KeyboardInterrupt:
    pass

print("\n" + "=" * 45)
claims = {ip: macs for ip, macs in ip_macs.items() if macs}
print(f"[*] saw {len(claims)} ip claim(s) during this run:")
for ip, macs in sorted(claims.items()):
    if len(macs) > 1:
        print(f"    {ip:16} {len(macs)} MACs  <-- conflicted")
    else:
        print(f"    {ip:16} {next(iter(macs))}")
print("=" * 45)
