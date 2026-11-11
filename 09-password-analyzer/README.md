# 09 - Password Analyzer

A password strength analyzer that scores character composition and entropy. Standard library only, no dependencies, no venv needed.

## How it works

For each password it checks which character classes are present (lowercase, uppercase, digits, symbols), sizes the character pool accordingly, and computes Shannon entropy as bits = length * log2(pool). Bits map to points on a calibrated scale, anything shorter than 8 characters takes a penalty after scoring, and the final points produce a verdict from Very Weak to Very Strong.

## Usage

```
python analyzer.py                # type one password interactively
python analyzer.py -f testcases.txt
```

## Results from testcases.txt

```
password                       ->   5 pts  Very Weak    37.6 bits of entropy; too short (< 8 chars)
P@ssw0rd                       ->  35 pts  Moderate     47.4 bits of entropy
correct horse battery staple   ->  75 pts  Strong      91.9 bits of entropy
Tr0ub4dor&3                    ->  55 pts  Moderate    49.8 bits of entropy
xK9#mQ2!vLz                    ->  90 pts  Very Strong  78.8 bits of entropy
Summer2024!                    ->  75 pts  Strong      61.7 bits of entropy
```

The interesting rows are P@ssw0rd and Summer2024!. Pure entropy math calls them Moderate to Strong because substitution patterns and year suffixes add real pool size. A human attacker guesses them near the top of every wordlist. That gap is this project's main lesson.

## Limitations

Pure entropy scoring is blind to predictability. It cannot detect dictionary words, leetspeak substitutions, keyboard walks, dates, or leaked password lists. The correct fix is a dictionary check with edit distance matching against a common-password list, which would flip P@ssw0rd from Moderate to Very Weak instantly. That is the obvious next step if this tool ever gets a v2.

## Files

- analyzer.py: the analyzer
- testcases.txt: six synthetic test passwords, all folklore examples, none real
