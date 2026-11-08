#!/usr/bin/env python3
"""Project 07 — Bandwidth Monitor
Watches /proc/net/dev and shows live rx/tx rates per interface.
Run: python bandwidth.py           (no root, no dependencies —
the kernel already counts every byte; we just read the ledger.)

  python bandwidth.py -n 10        # 10 samples then a session summary
  python bandwidth.py -i wlp3s0   # watch one interface only
  python bandwidth.py --plain      # no ANSI colours (for logs/README)
"""

import argparse
import sys
import time
from datetime import timedelta

INTERVAL = 1.0  # seconds between samples

# interesting units only; a /24 doesn't need petabytes
UNITS = [(1 << 30, "GB"), (1 << 20, "MB"), (1 << 10, "kB"), (1, "B")]


def human(n):
    for size, suffix in UNITS:
        if n >= size:
            return f"{n / size:.1f}{suffix}"
    return f"{n}B"


def read_counters():
    """Parse /proc/net/dev. The kernel format has been stable for
    decades — column 1 after ':' is rx bytes, column 9 is tx bytes."""
    stats = {}
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:  # skip two header lines
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            cols = rest.split()
            # tx_bytes is column 9 — if the interface is so fresh the
            # kernel gave us fewer columns, it carries no traffic anyway
            if len(cols) >= 10:
                stats[name.strip()] = (int(cols[0]), int(cols[8]))
    return stats


def bar(rate, peak, width=20):
    """A little ASCII meter — scaled against the busiest this session."""
    if peak <= 0:
        return ""
    filled = min(width, int(rate / peak * width))
    return "█" * filled + "░" * (width - filled)


def main():
    ap = argparse.ArgumentParser(description="live bandwidth monitor")
    ap.add_argument("-i", "--iface", help="watch only this interface")
    ap.add_argument("-n", "--samples", type=int, default=0,
                    help="stop after N samples (0 = run until Ctrl-C)")
    ap.add_argument("--interval", type=float, default=INTERVAL)
    ap.add_argument("--plain", action="store_true", help="no colours")
    args = ap.parse_args()

    UP = "" if args.plain else "\033[2K\r"  # redraw one line, or append

    prev = read_counters()
    if args.iface and args.iface not in prev:
        sys.exit(f"[-] no such interface: {args.iface}")

    # session bookkeeping
    start = time.time()
    peaks = {}      # iface -> highest combined rate seen
    totals = {}     # iface -> (rx, tx) accumulated this session
    lines_drawn = 0

    n = 0
    try:
        while args.samples == 0 or n < args.samples:
            time.sleep(args.interval)
            now = read_counters()
            stamp = time.strftime("%H:%M:%S")

            for iface, (rx, tx) in now.items():
                if args.iface and iface != args.iface:
                    continue
                prx, ptx = prev.get(iface, (rx, tx))
                drx, dtx = rx - prx, tx - ptx   # bytes since last sample
                rate_r = drx / args.interval
                rate_t = dtx / args.interval
                combo = rate_r + rate_t
                peaks[iface] = max(peaks.get(iface, 0), combo)
                arx, atx = totals.get(iface, (0, 0))
                totals[iface] = (arx + drx, atx + dtx)

                if combo > 0 or args.iface:
                    b = bar(combo, peaks[iface])
                    print(f"{UP}{stamp}  {iface:<10} "
                          f"↓ {human(rate_r)+'/s':>10} "
                          f"↑ {human(rate_t)+'/s':>10}  {b}")
                    lines_drawn += 1
            prev = now
            n += 1

    except KeyboardInterrupt:
        pass  # Ctrl-C is a normal, dignified way to end a monitoring session

    if not lines_drawn:
        print("[*] no traffic observed this session.")
        return

    print("\n──── session summary " + "─" * 30)
    elapsed = time.time() - start
    for iface, (arx, atx) in sorted(totals.items()):
        if arx + atx == 0:
            continue
        peak_rate = peaks[iface]
        print(f"{iface:<10} total ↓ {human(arx):>10}  ↑ {human(atx):>10}  "
              f"peak {human(peak_rate)+'/s':>10}  "
              f"({timedelta(seconds=int(elapsed))} watched)")
    print(f"watched {int(elapsed)}s at {args.interval}s intervals — "
          f"counts come straight from the kernel's own ledger.")


if __name__ == "__main__":
    main()
