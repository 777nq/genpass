# genpass

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: CSPRNG](https://img.shields.io/badge/entropy-CSPRNG%20secrets-brightgreen.svg)](#cryptographic-security)

A lightweight, cryptographically secure CLI credential and passphrase generation engine in Python. Engineered to eliminate weak pseudorandom generator vulnerabilities (CWE-338) while providing real-time Shannon entropy calculation and NIST SP 800-63B strength ratings.

---

## Key Features

- **Cryptographically Secure RNG**: Backed strictly by Python's `secrets` module (using OS-level entropy pools via `/dev/urandom` / Windows CryptoAPI).
- **Shannon Entropy Scoring**: Calculates true theoretical entropy in bits ($E = L \times \log_2(N)$) with contextual resistance ratings.
- **Diceware Passphrase Mode**: Generates memorable, high-entropy multi-word passphrases using an EFF-derived wordlist.
- **Ambiguity Filtering**: Option to strip easily confusable glyphs (`1`, `l`, `I`, `0`, `O`, `8`, `B`) for printed or high-legibility credentials.
- **DevOps & Pipeline Friendly**: Clean JSON export (`--json`) and quiet output (`--quiet`) for integration into provisioning scripts, secret managers, or CI/CD pipelines.
- **Zero Third-Party Dependencies**: Pure standard library implementation.

---

## Installation & Requirements

Requires **Python 3.8+**. No third-party packages needed.

```bash
git clone https://github.com/777nq/Password-Generator.git
cd Password-Generator
```

*(Optional)* Symlink or add to your PATH:
```bash
ln -s "$(pwd)/genpass.py" /usr/local/bin/genpass
```

---

## Usage

### 1. Standard Alphanumeric Generation

Generate a default 16-character high-entropy credential:
```bash
python genpass.py
```

```text
Generated Password : kX8#mP$2vL@9qW&5
Length             : 16 characters
Shannon Entropy    : 104.9 bits (Strong)
Analysis           : Meets enterprise security and OWASP baseline requirements.
```

### 2. Custom Constraints & Length

```bash
# 24-character credential without symbols
python genpass.py -l 24 --no-symbols

# Exclude ambiguous characters for high-readability tokens
python genpass.py -l 20 --exclude-ambiguous
```

### 3. Memorable Diceware Passphrases

Generate human-memorable passphrases utilizing cryptographically selected dictionary words:

```bash
# 5-word passphrase with hyphen separator (default)
python genpass.py --passphrase -w 5

# Custom delimiter
python genpass.py --passphrase -w 6 -s "_"
```

```text
Generated Password : Cobalt-Anchor-Falcon-Pinnacle-Summit
Length             : 36 characters
Shannon Entropy    : 44.83 bits (Moderate)
Analysis           : Suitable for memorized master credentials; resistant to dictionary lookup.
```

### 4. Batch Generation & JSON Output

```bash
# Generate 5 credentials formatted as structured JSON
python genpass.py -l 20 -c 5 --json
```

```json
[
  {
    "password": "jR9!wQ#2vT$8mK%1pL&4",
    "length": 20,
    "entropy_bits": 131.12,
    "charset_size": 94,
    "strength": "Very Strong",
    "feedback": "Military-grade entropy; practically immune to offline cracking.",
    "type": "alphanumeric"
  }
]
```

### 5. Shell Piping & Clipboard Integration

Use `--quiet` to output strictly the raw credential:

```bash
# Copy directly to clipboard (macOS / Linux / Windows)
python genpass.py -l 32 --quiet | pbcopy     # macOS
python genpass.py -l 32 --quiet | xclip -sel clip # Linux
python genpass.py -l 32 --quiet | clip       # Windows
```

---

## CLI Options

| Flag | Argument | Description | Default |
|------|----------|-------------|---------|
| `-l`, `--length` | `INT` | Character length of the generated password | `16` |
| `-c`, `--count` | `INT` | Quantity of passwords to output | `1` |
| `--no-upper` | - | Exclude uppercase characters (`A-Z`) | `False` |
| `--no-lower` | - | Exclude lowercase characters (`a-z`) | `False` |
| `--no-digits` | - | Exclude numerical digits (`0-9`) | `False` |
| `--no-symbols` | - | Exclude special characters (`!@#$...`) | `False` |
| `--exclude-ambiguous` | - | Omit visually similar glyphs (`il1Lo0O8B`) | `False` |
| `--passphrase` | - | Toggle Diceware multi-word passphrase mode | `False` |
| `-w`, `--words` | `INT` | Number of words for passphrase | `5` |
| `-s`, `--separator` | `STR` | Delimiter string between words | `-` |
| `--no-capitalize` | - | Disable word capitalization in passphrases | `False` |
| `--json` | - | Serialize results as structured JSON | `False` |
| `-q`, `--quiet` | - | Print raw password string only (ideal for pipes) | `False` |

---

## Cryptographic Security Note

Standard PRNG libraries (such as Python's `random` module) use the **Mersenne Twister** algorithm (MT19937). While suitable for simulations, MT19937 is entirely deterministic: an adversary who observes 624 outputs can reconstruct the internal state and predict all subsequent values ([CWE-338](https://cwe.mitre.org/data/definitions/338.html)).

`genpass` strictly leverages `secrets.choice` and `secrets.SystemRandom`, which query kernel-provided entropy sources (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, and `arc4random` on BSD/macOS), guaranteeing non-deterministic, cryptographically strong randomness.

---

## Running Tests

Unit tests cover character enforcement, entropy calculations, edge-case validation, and passphrase generation:

```bash
python -m unittest test_genpass.py -v
```

---

## License

This project is licensed under the [MIT License](LICENSE).
