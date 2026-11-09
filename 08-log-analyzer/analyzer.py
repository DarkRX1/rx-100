#!/usr/bin/env python3
"""Project 08 — Log Analyzer for Network Events
Generates a labeled corpus of network events (scan / burst / beacon),
captures what the kernel logs about them, then parses the log blind
and flags the anomalies statistically. Subcommands:

  sudo analyzer.py lab-up           # build the veth test range
  sudo analyzer.py arm              # install the logging rule (safe: policy accept)
  sudo analyzer.py gen scan         # inject a port-scan pattern
  sudo analyzer.py gen burst        # inject a SYN burst
  sudo analyzer.py gen beacon       # inject a fixed-cadence heartbeat
  sudo analyzer.py collect          # journalctl -> corpus/events.jsonl
  sudo analyzer.py disarm           # remove the logging rule
  sudo analyzer.py lab-down        # tear the range down
       analyzer.py analyze          # parse + flag anomalies (no root!)

WHY VETH: earlier attempts forged packets from fake IPs via scapy and
shot them out the physical NIC, expecting them to ricochet back through
the input hook. They can't — a switch never echoes a frame back to the
ingress port, so the frames leave and never return. Instead we build a
virtual wire (veth pair): rx_veth0 on the host, rx_veth1 inside the
'rx_attacker' namespace holding all three fake source IPs. Generation
then uses plain kernel TCP connects with a bound source address — real
SYNs crossing a real interface, guaranteed to reach the input hook.
Stdlib only; scapy removed entirely.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime

PREFIX = "rx_evt: "
CORPUS = "corpus/events.jsonl"

NS = "rx_attacker"       # namespace name
HOST_IF = "rx_veth0"     # host end of the virtual wire
NS_IF = "rx_veth1"       # attacker end
HOST_IP = "10.66.0.1"    # host address on the virtual wire

FAKE_SRC = {             # ground-truth labels, owned by the namespace
    "scan":   "10.66.0.150",
    "burst":  "10.66.0.151",
    "beacon": "10.66.0.152",
}


# ------------------------------------------------------------ helpers

def run(cmd, fatal=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if fatal and r.returncode != 0:
        sys.exit(f"[-] {' '.join(cmd)} failed:\n{r.stderr.strip()}")
    return r


# ------------------------------------------------------------ lab up/down

def lab_up():
    if NS in run(["ip", "netns", "list"]).stdout:
        sys.exit(f"[-] namespace '{NS}' already exists — run: lab-down first")
    run(["ip", "link", "add", HOST_IF, "type", "veth", "peer", "name", NS_IF])
    run(["ip", "netns", "add", NS])
    run(["ip", "link", "set", NS_IF, "netns", NS])
    run(["ip", "addr", "add", f"{HOST_IP}/24", "dev", HOST_IF])
    run(["ip", "link", "set", HOST_IF, "up"])
    # all three fake sources live on the attacker's end of the wire
    for ip in FAKE_SRC.values():
        run(["ip", "netns", "exec", NS, "ip", "addr", "add", f"{ip}/24",
             "dev", NS_IF])
    run(["ip", "netns", "exec", NS, "ip", "link", "set", NS_IF, "up"])
    run(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
    print(f"[+] range online: {HOST_IF} <-> {NS_IF}@{NS}")
    for ip in FAKE_SRC.values():
        print(f"      {ip} -> {HOST_IP}")


def lab_down():
    run(["ip", "netns", "del", NS], fatal=False)      # destroys the pair too
    run(["ip", "link", "del", HOST_IF], fatal=False)  # just in case
    print("[+] range torn down.")


# ------------------------------------------------------------ arm/disarm

def arm():
    # idempotent: rebuild the table from scratch every time
    run(["nft", "delete", "table", "ip", "rx_evt"], fatal=False)
    run(["nft", "add", "table", "ip", "rx_evt"])
    run(["nft", "add", "chain", "ip", "rx_evt", "input",
         "{ type filter hook input priority 10; policy accept; }"])
    # scoped to the lab wire: the corpus is 100% lab signal, zero floor
    run(["nft", "add", "rule", "ip", "rx_evt", "input",
         f"iifname \"{HOST_IF}\"",
         "tcp flags & (fin|syn|rst|ack) == syn",
         f"log prefix \"{PREFIX}\""])
    print(f"[+] armed: SYNs arriving on {HOST_IF} are LOGGED, not dropped.")
    print("    physical interfaces are untouched; connectivity unaffected.")


def disarm():
    run(["nft", "delete", "table", "ip", "rx_evt"])
    print("[+] logging rule removed — kernel back to its normal rules.")


# ------------------------------------------------------------ generate

def gen(pattern, count):
    # execution happens INSIDE the namespace via a hidden subcommand,
    # so no shell-quoting gymnastics and no scapy — plain kernel sockets
    run(["ip", "netns", "exec", NS, sys.executable,
         os.path.abspath(__file__), "_inject", pattern, str(count)])


def _inject(pattern, count):
    """Runs inside rx_attacker. Real connect()s with bound source IPs."""
    import socket
    src = FAKE_SRC[pattern]

    def fire(dport):
        s = socket.socket()
        s.bind((src, 0))
        s.settimeout(0.5)
        try:
            s.connect((HOST_IP, dport))       # SYN crosses the virtual wire
        except (ConnectionRefusedError, OSError):
            pass                              # RST back = expected; SYN logged
        finally:
            s.close()

    print(f"[*] {count} '{pattern}' connects: {src} -> {HOST_IP}")
    if pattern == "scan":                     # one source, many ports
        for i in range(count):
            fire(100 + i * 7)
            time.sleep(0.15)
    elif pattern == "burst":                  # flood, one port, ~instantly
        for _ in range(count):
            fire(9999)
    elif pattern == "beacon":                 # fixed 3s cadence, one port
        for _ in range(count):
            fire(5555)
            time.sleep(3.0)
    print(f"[+] {count} '{pattern}' SYNs sent from {src}")


# ------------------------------------------------------------ collect

def collect(since, out):
    raw = run(["journalctl", "-k", "--since", since,
               "-o", "json", "--no-pager"]).stdout
    events = []
    for line in raw.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = rec.get("MESSAGE", "")
        if PREFIX not in msg:
            continue
        ts = int(rec["__REALTIME_TIMESTAMP"]) / 1_000_000  # usec -> epoch
        fields = {}
        for tok in msg[len(PREFIX):].split():
            if "=" in tok:                    # keyword-parsed, not positional
                k, v = tok.split("=", 1)
                fields[k] = v
        events.append({"ts": ts, **fields})
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"[+] wrote {len(events)} events to {out} (window: {since} -> now)")
    if not events:
        print("[!] nothing captured — arm + lab-up + gen first?")


# ------------------------------------------------------------ analyze

def analyze(path):
    events = []
    with open(path) as f:
        for line in f:
            events.append(json.loads(line))
    if not events:
        sys.exit("[-] empty corpus")
    t0 = min(e["ts"] for e in events)
    t1 = max(e["ts"] for e in events)
    print(f"[*] {len(events)} events, {datetime.fromtimestamp(t0):%H:%M:%S} -> "
          f"{datetime.fromtimestamp(t1):%H:%M:%S} ({t1 - t0:.1f}s)")

    # ---- timeline: 10-second buckets ----
    buckets = Counter(int((e["ts"] - t0) / 10) for e in events)
    span = max(buckets) + 1
    top = max(buckets.values())
    print("\n  timeline (10s buckets)")
    for b in range(span):
        n = buckets.get(b, 0)
        print(f"    +{b * 10:>4}s {'#' * int(n / top * 30):<30} {n}")

    # ---- top sources ----
    by_src = Counter(e.get("SRC", "?") for e in events)
    print("\n  top sources")
    for src, n in by_src.most_common(5):
        ports = {e.get("DPT") for e in events if e.get("SRC") == src}
        print(f"    {src:<16} {n:>4} events   {len(ports)} unique ports")

    # ---- anomalies ----
    print("\n  anomaly flags")
    for src, n in by_src.items():
        flagged = False
        ts_list = sorted(e["ts"] for e in events if e.get("SRC") == src)
        ports = {e.get("DPT") for e in events if e.get("SRC") == src}

        if len(ports) >= 8:
            print(f"    [SCAN ]  {src} probed {len(ports)} ports "
                  f"in {n} events — horizontal scan signature")
            flagged = True

        if len(ts_list) >= 5:
            gaps = [b - a for a, b in zip(ts_list, ts_list[1:])]
            med = statistics.median(gaps)
            spread = statistics.pstdev(gaps) / med if med else 9
            if spread < 0.25 and med > 1.0:
                print(f"    [BEACON] {src} beacons every {med:.1f}s "
                      f"with {spread:.2f} jitter — fixed-cadence heartbeat")
                flagged = True

        per_sec = Counter(int(t) for t in ts_list)
        worst = per_sec.most_common(1)[0]
        if worst[1] >= 10:
            print(f"    [BURST ] {src} sent {worst[1]} packets within 1s "
                  f"(at +{worst[0] - int(t0)}s) — flood signature")
            flagged = True

        if not flagged:
            print(f"    [ ok  ]  {src} — no anomaly (background floor)")


# ------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="network event log analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lab-up")
    sub.add_parser("lab-down")
    sub.add_parser("arm")
    sub.add_parser("disarm")
    g = sub.add_parser("gen")
    g.add_argument("pattern", choices=list(FAKE_SRC))
    g.add_argument("-n", "--count", type=int, default=15)
    c = sub.add_parser("collect")
    c.add_argument("--since", default="30 minutes ago")
    c.add_argument("-o", "--out", default=CORPUS)
    a = sub.add_parser("analyze")
    a.add_argument("path", nargs="?", default=CORPUS)
    h = sub.add_parser("_inject")             # hidden: runs inside the ns
    h.add_argument("pattern")
    h.add_argument("count", type=int)
    args = ap.parse_args()

    if args.cmd == "lab-up":
        lab_up()
    elif args.cmd == "lab-down":
        lab_down()
    elif args.cmd == "arm":
        arm()
    elif args.cmd == "disarm":
        disarm()
    elif args.cmd == "gen":
        gen(args.pattern, args.count)
    elif args.cmd == "_inject":
        _inject(args.pattern, args.count)
    elif args.cmd == "collect":
        collect(args.since, args.out)
    elif args.cmd == "analyze":
        analyze(args.path)


if __name__ == "__main__":
    main()
