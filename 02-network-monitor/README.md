# Network Traffic Monitor

Second project in the 100 projects challenge. A packet sniffer using scapy that shows what my machine is actually talking to, live.

## What it does

Prints one line per packet crossing the network interface — source, destination, protocol, ports, and TCP flags — then keeps going until you hit Ctrl+C. On exit it prints a summary table of every remote host you exchanged packets with, sorted by packet count.

Running it for five minutes and reading the summary is the interesting part. I found out my machine was quietly talking to twelve different hosts just from normal browsing, most of which I never consciously visited.

## Requirements

- Python 3
- scapy (`pip install scapy`)
- root (raw packet capture is a kernel-level privilege, no way around it)

## Usage

```
sudo .venv/bin/python monitor.py
```

Then just use the internet normally. Ctrl+C to stop and see the summary.

Output looks like this:

```
192.168.0.219   -> 192.168.0.1      UDP  50600   -> DNS
192.168.0.219   -> 185.70.42.51     TCP  58618   -> HTTPS   [S]
185.70.42.51    -> 192.168.0.219    TCP  HTTPS   -> 58618   [SA]
192.168.0.219   -> 185.70.42.51     TCP  58618   -> HTTPS   [A]
192.168.0.219   -> 185.70.42.51     TCP  58618   -> HTTPS   [PA]
```

And the exit summary:

```
[*] talked to 12 remote host(s):
    199.232.173.91     1145 pkts
    142.251.150.119     310 pkts
    185.70.42.51         86 pkts
    ...
```

## Things I learned while building it

- scapy parses packets into layers (Ethernet -> IP -> TCP...). Checking `TCP in pkt` just asks "does this packet have a TCP layer", which is a weirdly pleasant way to handle packets in python.
- Raw sockets need root. Running without sudo gives you `PermissionError: [Errno 1] Operation not permitted` and nothing explains why.
- My router screams mDNS (UDP 5353) and LLMNR (UDP 5355) at multicast addresses constantly. Had to look both up. LLMNR turns out to be a classic MITM target that tools like Responder abuse.
- The TCP flags made the textbook handshake real: you can literally watch S, SA, A go past when you open a website.
- Half the "HTTPS" traffic was actually UDP on port 443. That's QUIC / HTTP3. Didn't expect to run into it on day two.
- Gotcha: running the script through VS Code's run button ignores sudo and the sniff dies with a permission error. Run it from the terminal.
- `store=0` in sniff() or scapy quietly keeps every packet in RAM for no reason.

## Known gaps

- ICMP packets print as `???` (no TCP/UDP layer). The handler is a TODO.
- The port-to-name table is small and hardcoded. Fine for now.
- Only IPv4. IPv6 traffic just gets skipped silently.

## Warning

Sniffing your own traffic: fine. Sniffing other people's traffic on a shared network without permission: illegal and also exactly the thing this tool makes easy to accidentally do. Promiscuous mode is powerful.

Written as project 2/100.
