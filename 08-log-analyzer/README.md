# 08 — Network Event Log Analyzer

**Category A finale.** A tool that generates a labeled corpus of network attack patterns, captures what the kernel logs about them, then parses the log **blind** and flags the anomalies statistically — the three planted signatures must be found with no hints, labels, or ground truth reaching the detector.

Pure stdlib. No scapy, no dependencies beyond `ip`, `nft`, and `journalctl`.

## The design

- **Test range:** a veth pair (`rx_veth0` on the host ↔ `rx_veth1` inside an `rx_attacker` network namespace). The namespace owns three fake source IPs; traffic crosses a real kernel interface and provably reaches the input hook.
- **Logging, not blocking:** an nftables rule scoped to the lab wire (`policy accept`) logs inbound SYNs. Physical interfaces untouched; connectivity unaffected.
- **Structured collection:** `journalctl -k -o json` → keyword-parsed fields (`SRC=`, `DPT=` split on `=`, never by column position) → JSONL corpus.
- **Blind analysis:** timeline buckets, top sources with port fan-out, and three detectors — horizontal scan (≥8 unique ports), burst (≥10 events in one second), beacon (median inter-arrival >1s with jitter <25%).

## Usage

```
sudo python3 analyzer.py lab-up        # build the virtual range
sudo python3 analyzer.py arm           # logging rule, scoped to the lab wire
sudo python3 analyzer.py gen scan  -n 12
sudo python3 analyzer.py gen burst -n 25
sudo python3 analyzer.py gen beacon -n 8    # ~24s — the pauses are the signal
sudo python3 analyzer.py collect --since "10 minutes ago"
sudo python3 analyzer.py disarm
sudo python3 analyzer.py lab-down
python3 analyzer.py analyze                 # no root required
```

## Results (replicated twice, identical verdicts)

45 events over 23.1s:

```
timeline (10s buckets)
  +   0s ############################## 40
  +  10s ##                             3
  +  20s #                              2

top sources
  10.66.0.151        25 events   1 unique ports
  10.66.0.150        12 events   12 unique ports
  10.66.0.152         8 events   1 unique ports

anomaly flags
  [SCAN ]  10.66.0.150 probed 12 ports in 12 events — horizontal scan signature
  [BURST ] 10.66.0.151 sent 25 packets within 1s (at +2s) — flood signature
  [BEACON] 10.66.0.152 beacons every 3.0s with 0.00 jitter — fixed-cadence heartbeat
```

All three planted signatures detected blind, zero false positives on the source addresses. The **0.00 jitter** on the beacon is a satisfying detail: the kernel's log timestamps are steadier than the phenomenon itself — the instrument resolved the signal perfectly.

## The debugging story (the instructive part)

The obvious first design — forge SYNs from fake LAN addresses via scapy, shoot them out the physical NIC, log them in nftables — **cannot work**, and understanding why is half this project:

1. **The ricochet failure.** A switch never echoes a frame back to its ingress port. Forged packets leave the NIC and never come back, so they never traverse the input hook, so no rule on the input chain ever sees them. The kernel-side counter of an armed rule sat untouched while injected packets demonstrably hit the wire.
2. **A red herring chased honestly.** Early runs showed a netfilter counter climbing while the journal stayed silent — which led to a genuinely useful detour: verifying the netfilter log backend (`/proc/net/netfilter/nf_log` — `nf_log_ipv4` was loaded), watching `dmesg -w` live, and confirming the *chain* was fine and the *traffic path* was the lie. Diagnosis by elimination, with two independent ledgers (counter vs journal) disagreeing until the real cause surfaced.
3. **The pivot.** The fix is architectural, not a patch: put the attacker in a network namespace on the far end of a virtual wire. Traffic generated there *must* cross the host's input hook. Guaranteed, reproducible, no privileged raw-socket injection, and plain kernel `connect()`s replace scapy entirely — the smallest, cleanest version of this tool is the one with zero third-party code.

## Lessons

- **Packet count is not proof of arrival.** Two ledgers (wire-side and hook-side) can disagree; measure both.
- **Parsing by keyword beats parsing by position** — reinforced from project 06's `ip neigh` bug, now applied to journal fields via `-o json`.
- **Synthetic ground truth makes detectors falsifiable.** Because we planted the patterns, a missed flag is a real bug and a false flag is a real finding — neither is deniable.
- **Scoped instrumentation.** The logging rule targets only the lab interface, so the corpus is 100% signal, zero background floor — unlike a real SOC feed, which this tool deliberately sets aside.

## Limitations

- Thresholds (8 ports, 10/s, 25% jitter) are tuned to this corpus. On real traffic they'd need calibration against a baseline — the census-style periodicity documented in projects 05/06 would likely trip the beacon detector, which in a real deployment is arguably a feature.
- Journal format is kernel-dialect dependent; the keyword parser mitigates but does not eliminate format drift across kernel versions.
- The range is ephemeral: everything (namespace, veth pair, nft table) disappears on teardown or reboot, leaving no residue.
- Single-host analysis only — no aggregation across machines, no persistence of historic baselines.
