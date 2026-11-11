#!/usr/bin/env python3
"""Project 10 — Hash Cracker (authorized lab use only)

All targets are self-generated with the `gen` subcommand. The tool exists
to measure how attackers recover passwords, not to attack anyone.

  python3 cracker.py gen password Summer2024! admin123
  python3 cracker.py crack <digest> --mode md5
  python3 cracker.py crack <digest> --brute 5 --charset lower
  python3 cracker.py bench --mode sha256

Stdlib only. Salted hashes are out of scope on purpose: the point is to
measure attacker speed, and a salt changes the economics of *reuse*, not
the per-hash cost. That distinction goes in the README.
"""

import argparse
import hashlib
import itertools
import json
import string
import time
from datetime import timedelta

MODES = {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}

# curated starter list: folklore passwords, common bases for mangling
BASE_WORDS = [
    "password", "letmein", "qwerty", "azerty", "admin", "login", "welcome",
    "monkey", "dragon", "master", "sunshine", "princess", "football",
    "iloveyou", "whatever", "computer", "internet", "secret", "hello",
    "freedom", "trustno1", "batman", "superman", "starwars", "pokemon",
    "summer", "winter", "spring", "autumn", "january", "december",
    "monday", "friday", "shadow", "hunter", "killer", "ninja", "legend",
    "google", "facebook", "amazon", "netflix", "spotify", "twitter",
    "apple", "samsung", "iphone", "android", "chrome", "firefox",
    "coffee", "pizza", "burger", "chocolate", "banana", "orange",
    "matrix", "cyber", "hacker", "anon", "root", "toor", "guest",
    "house", "garden", "flower", "money", "banking", "school", "college",
    "family", "mother", "father", "brother", "sister", "friend", "love",
    "music", "guitar", "soccer", "tennis", "champion", "winner",
    "abc", "aaa", "zzz", "asd", "qwe", "zxc", "123", "321", "111",
    "000", "121", "1234", "12345", "123456", "1234567", "12345678",
    "123456789", "1234567890", "87654321", "987654321", "147258369",
    "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm", "aaaaaa",
    "abc123", "abcd1234", "pass123", "passw0rd", "test123", "guest123",
    "admin123", "root123", "user", "username", "email", "mail",
    "dark", "darkrx", "white", "black", "blue", "red", "green",
    "dragonball", "minecraft", "fortnite", "steam", "discord", "twitch",
    "youtube", "tiktok", "insta", "snapchat", "gmail", "hotmail",
    "thomas", "jordan", "alexander", "daniel", "matthew", "andrew",
    "jessica", "ashley", "sarah", "emily", "hannah", "samantha",
    "michael", "david", "chris", "john", "james", "robert", "mary",
]

# a->@  o->0  e->3  i->1  s->$  t->7  (classic leet, no overlap tricks)
LEET = str.maketrans("aoeist", "@031$7")

SUFFIXES = ["", "1", "12", "123", "1234", "2024", "2026", "!",
            "!1", "@123", "!!", "#1", "123!", "2024!", "?", "."]


def digest(mode, word):
    return MODES[mode](word.encode()).hexdigest()


# ------------------------------------------------------------ wordlist + rules

def base_forms(word):
    yield word
    if word.lower() != word:
        yield word.lower()
    yield word.capitalize()
    yield word.upper()


def mangle(word):
    """Every candidate the rules produce for one base word."""
    for form in base_forms(word):
        for v in {form, form.translate(LEET)}:
            for suf in SUFFIXES:
                yield v + suf


def dictionary_candidates(extra_words):
    seen = set()
    for w in BASE_WORDS + list(extra_words):
        for cand in mangle(w):
            if cand not in seen:
                seen.add(cand)
                yield cand


# ------------------------------------------------------------ brute force

CHARSETS = {
    "lower": string.ascii_lowercase,
    "lowernum": string.ascii_lowercase + string.digits,
    "alnum": string.ascii_letters + string.digits,
}


def brute_candidates(charset, maxlen):
    for n in range(1, maxlen + 1):
        for tup in itertools.product(charset, repeat=n):
            yield "".join(tup)


# ------------------------------------------------------------ subcommands

def gen(plaintexts, mode, out):
    """Self-generated targets: we chose the plaintext, so we KNOW the answer."""
    with open(out, "w") as f:
        for pt in plaintexts:
            rec = {"mode": mode, "hash": digest(mode, pt),
                   "note": f"lab target, known plaintext"}
            f.write(json.dumps(rec) + "\n")
            print(f"[+] {mode}('{pt}') = {rec['hash'][:32]}...")
    print(f"[+] {len(plaintexts)} self-generated targets in {out}")
    print("    (lab rule: we only crack hashes we made ourselves)")


def crack(target, mode, wordlist, brute_max, charset):
    needle = target.lower()
    t0 = time.perf_counter()
    tried = 0

    words = []
    if wordlist:
        with open(wordlist) as f:
            words = [ln.strip() for ln in f if ln.strip()]
        print(f"[*] loaded {len(words)} base words from {wordlist}")

    for cand in dictionary_candidates(words):
        tried += 1
        if digest(mode, cand) == needle:
            dt = time.perf_counter() - t0
            print(f"[+] CRACKED by dictionary: '{cand}' "
                  f"({tried:,} candidates, {dt:.3f}s)")
            return cand
    print(f"[-] dictionary missed after {tried:,} candidates "
          f"({time.perf_counter() - t0:.2f}s)")

    if brute_max:
        cs = CHARSETS[charset]
        t1 = time.perf_counter()
        bt = 0
        for cand in brute_candidates(cs, brute_max):
            bt += 1
            if digest(mode, cand) == needle:
                dt = time.perf_counter() - t1
                print(f"[+] CRACKED by brute force: '{cand}' "
                      f"({bt:,} candidates, {dt:.3f}s)")
                return cand
        print(f"[-] brute force to {brute_max} chars over '{charset}' "
              f"({bt:,} candidates) missed")
    print("[-] target survives this lab's arsenal")


def bench(mode):
    """Measure honest rates, then extrapolate the numbers that matter."""
    samples = ["bench%d" % i for i in range(200_000)]

    t0 = time.perf_counter()
    for s in samples:
        digest(mode, s)
    rate = 200_000 / (time.perf_counter() - t0)
    print(f"[*] raw {mode} hashing rate on this machine: {rate:,.0f} H/s "
          f"(single thread, Python)")

    pools = [("lowercase (26)", 26), ("lower+digits (36)", 36),
             ("alnum (62)", 62), ("printable (95)", 95)]
    print(f"\n    exhaustive search time at the measured rate:")
    print("    " + f"{'length':<20}".ljust(20) + "".join(
        f"{name:>20}" for name, _ in pools))
    for n in range(4, 11):
        row = f"    {n:<20}"
        for _, p in pools:
            secs = p ** n / rate
            row += f"{str(timedelta(seconds=int(secs))):>20}"
        print(row)

    gpu = 40_000_000_000  # published ballpark for a modern rig on md5
    print(f"\n    same lengths at a published GPU-class rate "
          f"({gpu // 10**9} GH/s on md5):")
    for n in (6, 8, 10):
        row = f"    {n:<20}"
        for _, p in pools:
            secs = p ** n / gpu
            row += f"{str(timedelta(seconds=int(secs))):>20}"
        print(row)


# ------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description="hash cracker (lab use only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="hash known plaintexts into lab targets")
    g.add_argument("plaintexts", nargs="+")
    g.add_argument("--mode", choices=MODES, default="md5")
    g.add_argument("-o", "--out", default="targets.jsonl")

    c = sub.add_parser("crack", help="attack one digest")
    c.add_argument("target")
    c.add_argument("--mode", choices=MODES, default="md5")
    c.add_argument("--wordlist", default=None)
    c.add_argument("--brute", type=int, default=0, metavar="MAXLEN")
    c.add_argument("--charset", choices=CHARSETS, default="lower")

    b = sub.add_parser("bench", help="measure rates, extrapolate crack times")
    b.add_argument("--mode", choices=MODES, default="md5")

    args = ap.parse_args()
    if args.cmd == "gen":
        gen(args.plaintexts, args.mode, args.out)
    elif args.cmd == "crack":
        crack(args.target, args.mode, args.wordlist, args.brute, args.charset)
    elif args.cmd == "bench":
        bench(args.mode)


if __name__ == "__main__":
    main()
