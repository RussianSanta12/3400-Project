# 3400-Project

## What This Prototype Does

- Generates key pairs using two primes p and q, with n = p * q
- Computes a totient-like value using lcm(p - 1, q - 1)
- Selects a public exponent e with gcd(e, totient_like) = 1
- Computes private key d as the modular inverse of e
- Converts messages to polynomial form and back
- Encrypts with polynomial modular exponentiation
- Decrypts to recover the original plaintext
- Implements the nodal group operation used by the thesis-inspired core math

Note: This project is educational and not production cryptography.

## Run The Tests

From the repository ROOT(Not folder code is in), run:

		python -m unittest -v part3.test_nodal_curve_crypto