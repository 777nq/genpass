import unittest
from genpass import (
    generate_password,
    generate_passphrase,
    calculate_entropy,
    get_strength_rating,
    AMBIGUOUS_CHARACTERS
)

class TestGenPass(unittest.TestCase):
    def test_default_password_generation(self):
        res = generate_password(length=16)
        self.assertEqual(len(res["password"]), 16)
        self.assertGreater(res["entropy_bits"], 60)
        self.assertEqual(res["strength"], "Strong")

    def test_exclude_ambiguous(self):
        for _ in range(20):
            res = generate_password(length=32, exclude_ambiguous=True)
            for ch in AMBIGUOUS_CHARACTERS:
                self.assertNotIn(ch, res["password"])

    def test_character_classes_enforced(self):
        for _ in range(10):
            res = generate_password(
                length=12,
                include_upper=True,
                include_lower=True,
                include_digits=True,
                include_symbols=True
            )
            pwd = res["password"]
            self.assertTrue(any(c.isupper() for c in pwd))
            self.assertTrue(any(c.islower() for c in pwd))
            self.assertTrue(any(c.isdigit() for c in pwd))
            self.assertTrue(any(not c.isalnum() for c in pwd))

    def test_diceware_passphrase(self):
        res = generate_passphrase(word_count=5, separator="-")
        words = res["password"].split("-")
        self.assertEqual(len(words), 5)
        self.assertGreater(res["entropy_bits"], 40)

    def test_entropy_calculation(self):
        # 10 chars from 10 digits = 10 * log2(10) ≈ 33.22 bits
        entropy = calculate_entropy("1234567890", 10)
        self.assertAlmostEqual(entropy, 33.22, places=1)

    def test_minimum_length_validation(self):
        with self.assertRaises(ValueError):
            generate_password(length=2)

if __name__ == "__main__":
    unittest.main()
