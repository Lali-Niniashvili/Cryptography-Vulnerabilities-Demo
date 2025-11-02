# Cryptography Vulnerabilities Demo (Beginner-Friendly)

Learn **common crypto implementation flaws** by **seeing them in action**!

This repo demonstrates **real attack vectors** like:
- **Timing Attacks**
- **Padding Oracle**
- **Nonce Reuse**
- **Insecure Comparison**

...and shows **secure fixes** using modern Python libraries.

---

## Live Demo Output

```text
1. Timing Attack on Password Comparison
   Guess ''                        → 0.8 µs
   Guess 'c'                       → 1.2 µs
   Guess 'co'                      → 1.6 µs
   → Attacker sees increasing time → learns correct prefix!
   Secure compare: always ~3.1 µs → NO LEAK!
