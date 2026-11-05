<div align="center">

# ARP Spoofing Detector

Project 3 / 100 — part of [rx-100](../..)

A small watchdog that catches ARP poisoning on your LAN in real time.

![python](https://img.shields.io/badge/python-3.6+-blue.svg)
![scapy](https://img.shields.io/badge/dependency-scapy-orange.svg)
![root](https://img.shields.io/badge/requires-root-red.svg)
![status](https://img.shields.io/badge/status-working-brightgreen.svg)

</div>

---

## Background

ARP has no authentication. Any device on the LAN can shout *"I'm 192.168.0.1, send traffic to MY mac"* and every other device will simply believe it — the protocol comes from a friendlier era. An attacker doing this inserts themselves between you and the gateway: a man in the middle.

The attack has one unavoidable fingerprint though: **the same IP being claimed by two different MACs.** That's what this tool listens for.

## How it works

```
who-has  192.168.0.1     aa:bb:cc:dd:ee:ff   <- normal claim
is-at    192.168.0.1     de:ad:be:ef:ca:fe   <- wait, that's a SECOND mac
                                   |
                                   +-->  [!!] ARP CONFLICT
```

- Captures ARP packets via a kernel-level BPF filter (`filter="arp"`) — non-ARP traffic never even reaches Python
- Tracks every `psrc`/`hwsrc` claim it sees, from both `who-has` and `is-at` packets (both are evidence)
- Alarms only when two different MACs claim the same IP within a 60 second window
- On `ctrl+c`, prints a summary of all IPs observed and flags the conflicted ones

> **Why the time window?** Legit networks produce IP-to-new-MAC changes all the time — DHCP renewals, router reboots, device swaps. Alarming on "I once saw two MACs for this IP" would cry wolf constantly. The window trades a little stealth-resistance for a lot of sanity.
>
> Known limitation: a patient attacker spacing claims minutes apart could dodge it. Accepted for now.

## Usage

```bash
# own venv
python -m venv .venv
pip install scapy

# needs root — raw packet capture is a kernel-level privilege
sudo .venv/bin/python detector.py
```

Leave it running in a terminal and go about your day. `ctrl+c` stops it and prints the summary.

<details>
<summary>Output sample</summary>

```
[*] watching ARP traffic. ctrl+c stops.

who-has  192.168.0.1      aa:bb:cc:dd:ee:ff
is-at    192.168.0.1      aa:bb:cc:dd:ee:ff

[!!] ARP CONFLICT for 192.168.0.1
     aa:bb:cc:dd:ee:ff
     de:ad:be:ef:ca:fe
     at 10:19:00

=============================================
[*] saw 2 ip claim(s) during this run:
    192.168.0.1      2 MACs  <-- conflicted
    192.168.0.241    12:ca:da:xx:xx:xx
=============================================
```

</details>

## Testing it against myself

A detector that never fires is just a script. So with the detector running, I sent two fake gateway claims from another terminal:

```python
from scapy.all import send, ARP

send(ARP(op=2, psrc='192.168.0.1', hwsrc='de:ad:be:ef:ca:fe'))
send(ARP(op=2, psrc='192.168.0.1', hwsrc='de:ad:be:ef:ba:ad'))
```

Both were flagged within the same second. Attacked my own machine, caught myself doing it. (MACs in this README are placeholders — the real ones are nobody's business.)

## Weird thing it caught

On its first run it flagged a mystery device announcing itself at `192.168.0.241`. Took me a while to figure out.

It was my own laptop — I'd forgotten it was plugged in over ethernet while also on wifi. Two interfaces, two IPs, one machine. So the detector doubles as a passive LAN mapper, and it apparently knows my setup better than I do.

## Roadmap

- [ ] Silence-per-IP option (only print alerts)
- [ ] Log alerts to a file with timestamps
- [ ] Static ARP table check on startup (compare against `ip neigh`)
- [ ] Daemon mode / desktop notification on alert

## Warning

ARP spoofing knocks networks over. Don't send fake claims on any network that isn't yours or a lab — you'll grief everyone's internet, not just your target.

---

<div align="center">

*rx-100 — project 3 of 100 · MIT license*

</div>
