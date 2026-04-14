import unittest

from part3.nodal_curve_crypto import (
    DEFAULT_F,
    decrypt,
    encrypt,
    generate_keys,
    message_to_polynomial,
    nodal_group_operation,
    polynomial_to_message,
)


class TestNodalCurveCrypto(unittest.TestCase):
    def test_generate_keys_constraints(self):
        public_key, private_key, details = generate_keys(bit_length=64, include_primes=True)
        n, e = public_key
        p = details["p"]
        q = details["q"]
        totient_like = details["totient_like"]

        self.assertEqual(n, p * q)
        self.assertEqual((e * private_key) % totient_like, 1)

    def test_encrypt_decrypt_round_trip(self):
        public_key, private_key = generate_keys(bit_length=64)
        plaintext = "Hi"

        ciphertext = encrypt(plaintext, public_key)
        recovered = decrypt(ciphertext, private_key)

        self.assertEqual(recovered, plaintext)

    def test_empty_message_round_trip(self):
        public_key, private_key = generate_keys(bit_length=64)
        ciphertext = encrypt("", public_key)
        recovered = decrypt(ciphertext, private_key)
        self.assertEqual(recovered, "")

    def test_message_too_large_raises(self):
        # Tiny key makes n very small, so a longer message should fail size check.
        public_key, _ = generate_keys(bit_length=16)
        n, _ = public_key

        value = int.from_bytes(b"this message is too large", "big")
        self.assertGreaterEqual(value, n)

        with self.assertRaises(ValueError):
            message_to_polynomial("this message is too large", n)

    def test_group_operation_identity_case(self):
        modulus_n = 101
        h1 = [12]
        h2 = [(-12) % modulus_n]  # h1 + h2 == 0 mod n, and still 0 mod f(x)
        g2 = [3, 1]

        result = nodal_group_operation(h1, h2, g2, modulus_n, DEFAULT_F)
        self.assertEqual(result, [0])

    def test_group_operation_formula_case(self):
        modulus_n = 101
        h1 = [3, 4]
        h2 = [7]
        g2 = [2, 1]

        # Manual expectation for DEFAULT_F = x^2 + 1:
        # h1*h2 = 21 + 28x
        # h1*h2 + x = 21 + 29x
        # g2*(...) = (2 + x)(21 + 29x) = 42 + 79x + 29x^2
        # mod (x^2 + 1): x^2 = -1 -> 42 - 29 + 79x = 13 + 79x
        expected = [13, 79]

        result = nodal_group_operation(h1, h2, g2, modulus_n, DEFAULT_F)
        self.assertEqual(result, expected)

    def test_polynomial_message_reversibility(self):
        public_key, _ = generate_keys(bit_length=64)
        n, _ = public_key
        msg = "A"

        poly = message_to_polynomial(msg, n)
        restored = polynomial_to_message(poly)

        self.assertEqual(restored, msg)


if __name__ == "__main__":
    unittest.main()
