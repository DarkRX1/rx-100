# Packet Sniffer

Project 5 / 100 — part of [rx-100](../..)

A live packet capture tool with layer-by-layer dissection and protocol classification. Point it at your interface and it prints every conversation crossing your wire, names what it sees, and keeps score.

## The idea

Every packet is a set of nested envelopes: Ethernet wraps IP wraps TCP/UDP wraps the actual payload. Capturing packets is easy — scapy does that in one line. The project is everything after: splitting the envelopes apart, and deciding what the packet *is*. Scapy dissects; the classifier names. That distinction is the whole tool.

The classifier checks, most specific first: DHCP, then multicast discovery (mDNS on 5353, LLMNR on 5355), then DNS, ARP, ICMP, then TCP services by port. Order is load-bearing — mDNS and LLMNR packets contain a DNS layer inside them, so if the generic DNS check ran first, every multicast lookup would be mislabeled. Same lesson as the firewall: rule priority is meaning.

## Usage

```
sudo python sniffer.py -i wlp3s0               # until ctrl+c
sudo python sniffer.py -i wlp3s0 -c 30         # 30 packets
sudo python sniffer.py -i wlp3s0 -t 60         # 60 seconds
sudo python sniffer.py -i wlp3s0 -p http -x    # only port 80, with hexdumps
sudo python sniffer.py -i wlp3s0 -p dns -o out.pcap
```

Root required for raw capture. Protocols filterable: dhcp, dns, arp, icmp, mdns, llmnr, ssdp, http, tls — or pass any raw BPF filter with `-f`.

## What a quiet network looks like

A 60-second baseline capture on an idle LAN:

```
     71  ARP
     24  mDNS
     23  LLMNR
     10  HTTP
      5  other
      2  TLS
```

Around 85% of all traffic was the router doing housekeeping. Working through the log, the pattern resolves: the router walks its DHCP lease table address by address — a `who-has` three times, one mDNS reverse lookup, one LLMNR name query — then moves to the next. Over a minute it cycled through more than twenty addresses, none of which ever answered. Every one is a device that once existed and doesn't anymore: phones gone from the house, laptops replaced, consoles sold. My network spends most of its bandwidth conducting a census of ghosts, roughly every 48 seconds.

Projects 2 and 3 observed pieces of this (the mDNS flood, the ARP chatter). Seeing the whole cycle laid out end to end is what the wide-angle lens is for.

## The detective story

Mid-baseline, the sniffer caught a plaintext HTTP session — an oddity, since everything else was multicast housekeeping or TLS. First clue: reverse DNS named the remote host `redirect.archlinux.org` (Athena is Arch-based, so plausible — but that's an IP, not a process). It recurred in later captures with identical fingerprint: same host, same 154-byte request, same 270-byte response. Something was polling on a schedule.

So I waited with the hexdump on, and read the answer off the wire in raw bytes:

```
GET /nm-check.txt HTTP/1.1
Host: ping.archlinux.org
Accept: */*
Connection: close
```

The file is the giveaway: `nm-check.txt`. It's **NetworkManager**, the desktop's connectivity checker, asking ping.archlinux.org whether the internet is reachable — and the answer that comes back, in cleartext any device on the LAN could read:

```
NetworkManager is online
```

The lesson: the mystery traffic was benign, but I couldn't know that without capturing its actual bytes. Metadata (IP, port, timing) narrows a suspect list; payload convicts. TLS showed up in the same captures as opaque `data/fin` lines — the same event, unreadable. The difference between the two is the entire argument for encryption, visible in my own terminal.

Bonus finding: across three full captures with active browsing, not one DNS query appeared on the wire. The browser resolves everything over DNS-in-HTTPS, hidden inside the same TLS stream. From the wire's perspective, DNS as a distinct protocol has quietly disappeared from this machine.

## Bugs found and fixed

**The mislabel hunt.** First 30-packet capture produced `-` unlabeled strays (turned out to be LLMNR, port 5355) and mDNS reverse lookups labeled as plain DNS — both fixed by teaching the classifier and reordering the checks.

**The scapy count=None regression.** Runs with `-c 30` worked flawlessly; every run without a count died after exactly one packet with `'<' not supported between int and NoneType`. First theory — that an external `timeout` wrapper was killing the process mid-capture — was disproven when a native timer failed identically. The delta between working and failing runs was one line: we passed `count=None`, and scapy 2.8.0's receive loop eventually compares its packet counter to it. Fix: don't pass `count` at all unless a limit was requested. Reminder that libraries have bugs too, and that "what changed between the working case and the failing case" beats a plausible story.

**ARPA archaeology.** Reverse-DNS-over-multicast queries like `249.0.168.192.in-addr.arpa` translate to "who is 192.168.0.249?" — the router trying to put names to its ghosts. Worth knowing how to read these in the wild.

## Ethics

Sniffers are dual-use by definition. Mine touches my own interface, my own traffic, my own LAN — that's the line. Everything quoted here is sanitized: MACs redacted (a MAC embeds the hardware vendor and effectively acts as a serial number), pcaps never published raw, and IPv6 link-local addresses redacted too (they can embed the MAC unless privacy extensions are on — a fact this project taught me).

If you borrow this tool: capture your own network, and treat a hexdump of plaintext traffic as the sensitive document it is.

## Known gaps

- IGMP and IPv6 MLD packets still fall through to unlabeled.
- No TCP stream reassembly — each packet is judged alone, so multi-packet HTTP exchanges can't be reconstructed.
- TLS is classified by port, not by protocol (no TLS ClientHello inspection).
- Classifies, but doesn't alert — no threshold or anomaly notification yet. The 60-second tally is the natural seed for that.

---

*rx-100 — project 5 of 100 · MIT license*
