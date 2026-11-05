# Personal Firewall

Project 4 / 100 — part of [rx-100](../..)

A default-deny inbound firewall for my laptop, in nftables. Before this project my machine had zero inbound filtering — every unsolicited packet was accepted. Now anything that knocks without an invitation gets dropped, logged, and counted.

## The recon

`sudo nft list ruleset` showed exactly five tables, all Docker's, each stamped with a warning:

```
# Warning: table ip filter is managed by iptables-nft, do not touch!
```

Docker owns the NAT and forwarding rules for my containers and it regenerates them whenever it feels like it. So the first design decision wrote itself: I create my own table (`inet rx_firewall`) and never touch Docker's. Separate tables coexist in the kernel without interfering. In the real world you almost never own the whole ruleset — you always cohabit with someone else's rules. Might as well practice.

## The ruleset

Five rules do all the work:

| Rule | Why it exists |
|---|---|
| `iifname "lo" accept` | Loopback. Break it and localhost apps (incl. Docker) die mysteriously |
| `ct state established,related accept` | Answers to connections I started. This is why browsing keeps working |
| `udp sport 67 udp dport 68 accept` | DHCP renewals. They arrive as NEW, not "established" — block this and wifi dies in an hour |
| `meta l4proto ipv6-icmp accept` | IPv6 neighbor discovery. Block it and IPv6 breaks in confusing ways |
| `counter drop` (+ rate-limited log) | Everything else. Default policy for the chain is drop |

The DHCP and ICMPv6 rules are the ones tutorials skip. I know because I read the tutorials and then read my drop log. Outbound is still permissive — tightening it is future work (kill telemetry, force DNS through a resolver I choose).

## The dead man's switch

Applying experimental firewall rules to your daily machine is a good way to cut your own connectivity. So the script arms a rollback *before* applying anything:

```bash
systemd-run --on-active=120 sh -c 'nft delete table inet rx_firewall'
```

Two minutes after arming, my entire table evaporates — unless I deliberately stop the timer first. Lock myself out? I wait out the clock and I'm healed.

The switch has a 100% success rate: four armings, four clean detonations. Including one that fired while I was still reading logs. The lesson was free that time.

### The bug that almost ruined it

Version 1 had `set -e` at the top and a hardcoded unit name (`rx-rollback.timer`). After the bomb fires, systemd keeps the spent unit around — so every re-run collided on the name, systemd-run errored, and `set -e` aborted the script **before applying any rules**. The script printed an error, exited, and left the machine wide open. I only found out because my phone happily loaded a test server during what I believed was a protected window.

Two fixes:

- No `set -e`. Optional safety steps must not be able to kill critical ones.
- Unique unit names: `rx-rollback-$(date +%s)` — collisions now impossible.

And a third habit that survived the night: the script now **verifies its own effect**:

```bash
if sudo nft list table inet rx_firewall >/dev/null 2>&1; then
    echo "[+] firewall CONFIRMED active"
else
    echo "[!!] FAILED TO APPLY - NO PROTECTION"
fi
```

A state-changing script that doesn't check whether it changed anything is just a wish.

## The test

Victim: `python -m http.server` on port 8000. Attacker: my phone, on the same wifi.

```
firewall OFF   ->  phone loads the directory listing
firewall ON    ->  phone hangs forever
firewall OFF   ->  phone loads again
```

The journal caught the kills in the act:

```
rx_drop: SRC=192.168.0.242 DST=192.168.0.200 PROTO=TCP
         SPT=54464 DPT=8000 ... SYN
rx_drop: ... ID=44074   <- first knock
rx_drop: ... ID=44075   <- 1 second later
rx_drop: ... ID=44076   <- 2 seconds after that
(silence)                <- gave up
```

That sequence is TCP retransmission backoff, live: the phone knocked, got silence, waited longer, knocked again, doubled the wait, and quit. The exact behavior my port scanner's targets see — now I'm the one causing it.

First attempt at this test fooled me though: I checked `localhost:8000` from the laptop itself. Worked fine — because loopback is *supposed* to pass. Testing your firewall from inside the machine tests nothing. You need a foreign device doing the knocking.

## Bonus finding

With logging on, the drop log filled mostly with my own router: mDNS announcements (`UDP 5353` to `224.0.0.251`) roughly every two seconds, plus IGMP reports. The same multicast noise I watched in the traffic monitor (project 2) is now getting refused at the door. Trilogy: project 2 observed the noise, project 3 caught liars on the LAN, project 4 closed the door.

(MACs in the quoted logs are redacted. Learned that habit the hard way — earlier drafts of this project's README would have published my wifi card's serial-adjacent identifier for eternity.)

## Known gaps

- Not persistent across reboots. Deliberate for now — an experimental ruleset has no business auto-loading on a daily driver until it has survived some real use.
- Outbound is completely open.
- ICMPv4 (ping) inbound is blocked. Nobody needs to ping a laptop. Cost: I can't ping *my own* machine from the LAN to check it's up. Fine.
- Docker's tables and mine both hook `input` at the same priority; current behavior is fine but I don't fully understand the evaluation order between tables yet. Reading the nftables hooks documentation is on the list.

## Warning

Rules that drop everything inbound will also drop the thing you forgot you needed. That's the point of the dead man's switch. If you borrow this script, read it before running it — especially the part where it schedules its own deletion.

---

*rx-100 — project 4 of 100 · MIT license*
