import argparse
import math


def score(password):
    """Return (points, reasons) for a password."""
    reasons = []

    # --- length penalty (was the whole v1 logic, now just one factor) ---
    if len(password) < 8:
        reasons.append("too short (< 8 chars)")

    # --- step 2: character classes -> entropy ---
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 32

    # guard: empty password has no classes, log2(0) explodes
    if pool == 0:
        return 0, ["empty or no usable characters"]

    bits = len(password) * math.log2(pool)
    reasons.append(f"{bits:.1f} bits of entropy")

    # --- bits -> points calibration (tune these as we add more checks) ---
    if bits < 28:
        points = 5
    elif bits < 36:
        points = 15
    elif bits < 60:
        points = 35
    elif bits < 80:
        points = 55
    elif bits < 100:
        points = 75
    else:
        points = 90

    if len(password) < 8:
        points -= 15  # length penalty applies after entropy scoring

    return points, reasons


def verdict(points):
    if points < 20:
        return "Very Weak"
    if points < 40:
        return "Weak"
    if points < 60:
        return "Moderate"
    if points < 80:
        return "Strong"
    return "Very Strong"


def parse_args():
    parser = argparse.ArgumentParser(description="Password strength analyzer")
    parser.add_argument("-f", "--file", default=None,
                        help="file of passwords, one per line")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.file:
        with open(args.file) as f:
            passwords = [line.strip() for line in f]
    else:
        passwords = [input("password: ")]
    for pw in passwords:
        points, reasons = score(pw)
        print(f"{pw:30} -> {points:>3} pts  {verdict(points):12} {'; '.join(reasons)}")


if __name__ == "__main__":
    main()