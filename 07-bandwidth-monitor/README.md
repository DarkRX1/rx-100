# 07 — Bandwidth Monitor

**What it does:** live per-interface download/upload rates in the terminal, straight from the kernel's own byte counters — plus a session summary (totals, peak rate, duration). No dependencies, no root, no special files: the entire tool is "read `/proc/net/dev` twice, subtract, divide."

```
14:02:11  enp5s0     ↓    1.2MB/s ↑   48.8kB/s  ████████████████████
14:02:12  enp5s0     ↓  146.0B/s ↑     0.0B/s  ░░░░░░░░░░░░░░░░░░░░
14:02:13  enp5s0     ↓  120.0B/s ↑     0.0B/s  ░░░░░░░░░░░░░░░░░░░░

──── session summary ──────────────────────────────
enp5s0     total ↓      2.0MB  ↑    166.5kB  peak    1.2MB/s  (0:00:20 watched)
```

## How it works

`/proc/net/dev` exposes the kernel's cumulative rx/tx byte counters per interface — a format stable for decades. The monitor samples it once per interval, computes deltas, and renders:

- per-second rates with a bar scaled against the session's own peak,
- a session summary on exit (Ctrl-C or `-n`),
- `--plain` for log-friendly output, `-i` to pin one interface.

The deliberate design point: after six projects that needed raw sockets and root, this one is pure read-only arithmetic. Sometimes the kernel already collected the data; the engineer's job is honesty in the accounting, not privilege.

## Calibrating a measurement tool

Any monitor is a hypothesis until checked against something independent. This one was validated three ways, and the checks were the best part of the project:

**1. The differential test.** A "quiet" machine showed a persistent receive-only floor (~100–150 B/s) plus periodic megabyte-scale background bursts. Closing the browsers made the bursts vanish and the floor persist — separating application chatter from the interface's true background noise in one controlled experiment.

**2. Triple-ledger reconciliation.** A timed `curl` of a 10MB file was watched simultaneously by three independent instruments:

- curl's own report: 10,485,760 bytes in ~1.1s
- the monitor's sampled rate: one clean ~10MB/s sample, neighbors at the floor
- tcpdump: ~7,200 captured segments whose TCP sequence numbers sum to the transferred byte count within ~54 bytes

Three instruments — application, kernel counter, packet capture — agreeing to under 1% is what "trustworthy measurement" actually means.

**3. Route-awareness.** On a dual-homed machine (two interfaces, two default routes), the kernel silently sends traffic over whichever wire it prefers — so a monitor pinned to the wrong interface sees nothing during a download. First attempt did exactly that; the fix is asking `ip route` which interface the flow will actually use before watching. Lesson: on multi-path machines, *measure where the traffic actually goes*, not where you assume it does.

## What the monitor found on this LAN

- **"Idle" is a myth, and it's measurable.** The wired interface shows a persistent receive-only floor with near-zero transmit. From the companion sniffer project (#05) we know this LAN's router periodically broadcasts ARP requests for ~20 expired DHCP leases every ~48 seconds — broadcast frames nobody answers. A receive-only floor is the exact signature of being talked *at*, not talked *with*.
- **Background traffic has names.** A quiet window still carried megabyte-scale bursts attributed instantly by `ss -tup`: browser keepalives, QUIC sessions, and an editor's update checks. Idle machines don't exist; they just hide their conversations in small packets.

## Usage

```
python bandwidth.py                # live view, Ctrl-C to stop
python bandwidth.py -n 30          # 30 samples, then summary
python bandwidth.py -i wlp3s0      # watch one interface
python bandwidth.py --interval 0.5 --plain
```

Stdlib only — there is no `requirements.txt` because there is nothing to require.

## Limitations

- Counters are system-wide; a per-process breakdown needs `nethogs`/eBPF — a different, heavier tool.
- A driver reload or counter reset mid-session produces one bogus delta; treat a single wild sample as noise, not news.
- Bars scale per-interface against the session peak, so the first appearance always draws a full bar by definition.
- On multi-homed boxes, pin the interface that actually carries the flow (see "route-awareness" above).
