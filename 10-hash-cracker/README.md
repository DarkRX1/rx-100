# Project 10 — Hash Cracker

A small password hash cracker built to understand how passwords actually fall. It attacks self generated targets only, made with the `gen` subcommand from plaintexts we picked ourselves. The point is measurement, not access.

## What it does

- `gen` hashes known plaintexts into lab targets (jsonl)
- `crack` attacks one digest with two methods:
  - dictionary plus mangling rules: about 150 base words, each expanded into capitalized, uppercase, leet substituted, and suffixed variants (1, 12, 123, 2024, ! and friends)
  - brute force over configurable charsets and max length
- `bench` measures the machine's real hash rate and prints exhaustive search times for realistic password lengths, at the measured rate and at a published GPU class rate

Stdlib only. No venv, no requirements.

## How to run

```
python3 cracker.py gen password Summer2024! P@ssw0rd admin123 dragon
python3 cracker.py crack f065d609e55983bc6087c073c91c9bc7 --mode md5
python3 cracker.py bench --mode md5
```

## What happened on this machine

Measured md5 rate: 2,437,362 H/s, single thread, plain Python.

The showcase result: `Summer2024!` cracked by dictionary rules in 2,046 candidates and 2 milliseconds. Project 09's strength analyzer scored the same string 60.1 bits and called it Moderate. Both tools are right, and the disagreement is the lesson. Entropy math assumes each character was chosen by dice. Real attackers start from a word list and apply rules: capitalize, append the year, add punctuation. Under that model the password is one word plus three transforms, and sixty assumed bits of randomness cost two thousand guesses.

The bench table makes the second half of the argument. At the measured rate:

- 6 chars, lowercase: 2 minutes
- 8 chars, lowercase: 24 hours
- 8 chars, all printable: 31,503 days
- 10 chars, alphanumeric: 398,550 days

At a published GPU class rate of 40 GH/s on md5, the same lengths shrink by five orders of magnitude: 8 printable characters falls in under 2 days. Length is the only lever that survives both tables.

## Scope and honest limits

Salted hashes are out of scope on purpose. A salt does not make one hash slower to guess, it stops one guessed password from matching every account that reused it. That is a statement about reuse economics and belongs in the README of a password project, not in this tool.

Other limits, stated plainly: single threaded Python is about a thousand times slower than serious crackers on the same CPU, the word list is a starter set rather than rockyou sized, and the GPU figures are published ballparks, not measurements from this lab.

## Lessons

1. Entropy scores measure how unpredictable a password looks. Rules measure how predictable people are. Attackers use rules.
2. Dictionary plus mangling is not a crude baseline. It is how the majority of real passwords are actually recovered.
3. Exponential math is unintuitive in both directions. Adding two characters multiplies work by a thousand. A GPU divides work by ten thousand. Length wins, because it is the one thing an attacker cannot buy.
