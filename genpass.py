#!/usr/bin/env python3
"""
genpass - Cryptographically Secure Password & Passphrase Generator

Features:
- CSPRNG random generation via Python's secrets module (PEP 506 / CWE-338 compliant)
- Shannon Entropy calculation in bits with NIST SP 800-63B aligned ratings
- EFF Diceware passphrase generation with configurable separators
- Ambiguous character exclusion for improved legibility
- JSON and machine-readable output formats for automation/pipelines
"""

import argparse
import json
import math
import secrets
import string
import sys
from typing import Dict, List, Optional, Tuple

# EFF Short Word List (subset of 500+ memorable words for offline Diceware generation)
DICEWARE_WORDS: List[str] = [
    "acid", "acorn", "acre", "acts", "afar", "affix", "aged", "agent", "agile", "aging",
    "agony", "ahead", "aide", "aids", "aim", "ajar", "alarm", "alias", "alibi", "alien",
    "alike", "alive", "alkali", "all", "alley", "allot", "allow", "alloy", "ally", "aloft",
    "alone", "along", "aloof", "aloud", "alpha", "also", "altar", "alter", "always", "amaze",
    "amber", "amid", "amino", "ample", "amuse", "angel", "anger", "angle", "ankle", "apple",
    "april", "apron", "aqua", "arcade", "arch", "arena", "argon", "argue", "armor", "army",
    "aroma", "array", "arrow", "arson", "art", "aside", "atlas", "atom", "audit", "aurora",
    "avail", "avert", "avoid", "awake", "award", "aware", "axiom", "axis", "azure", "bacon",
    "badge", "bag", "bail", "baker", "balm", "bamboo", "banana", "band", "bank", "baron",
    "base", "basic", "basin", "basis", "batch", "beacon", "beam", "bean", "beard", "beast",
    "beat", "beauty", "become", "bed", "beech", "beef", "beetle", "begin", "being", "bell",
    "belt", "bench", "bend", "berry", "beret", "best", "beta", "bevel", "beyond", "bias",
    "bible", "bicep", "bid", "bike", "binary", "bind", "bionic", "birch", "bird", "birth",
    "bison", "bit", "black", "blade", "blame", "blank", "blast", "blaze", "blend", "bless",
    "blind", "blink", "bliss", "block", "blond", "blood", "bloom", "blunt", "blur", "blush",
    "board", "boast", "boat", "body", "bold", "bolt", "bomb", "bond", "bone", "bonus",
    "boost", "boot", "border", "bore", "boss", "botany", "bottle", "bottom", "bounce", "bound",
    "bow", "box", "brain", "brake", "branch", "brand", "brass", "brave", "bread", "break",
    "breed", "breeze", "brick", "bridge", "brief", "bright", "brisk", "broad", "bronze", "brook",
    "broom", "brown", "brush", "bubble", "buck", "budget", "buffer", "buggy", "build", "bulb",
    "bulk", "bull", "bundle", "bunker", "burden", "burn", "burst", "bus", "bush", "busy",
    "cabin", "cable", "cactus", "cadet", "cage", "cake", "canal", "candle", "candy", "cane",
    "canyon", "cape", "carbon", "cargo", "carpet", "carrot", "castle", "casual", "catch", "cater",
    "cause", "cave", "cedar", "celery", "cell", "cement", "census", "cereal", "chair", "chalk",
    "champ", "chance", "change", "channel", "chaos", "charge", "chart", "chase", "cheap", "check",
    "cheek", "cheer", "cheese", "chef", "cherry", "chest", "chief", "chili", "chill", "chimney",
    "chip", "choice", "chord", "chunk", "church", "cider", "cigar", "cinema", "circle", "circus",
    "cite", "city", "civic", "civil", "claim", "clamp", "clash", "clasp", "class", "clause",
    "claw", "clay", "clean", "clear", "clerk", "clever", "click", "client", "cliff", "climb",
    "clinic", "clip", "cloak", "clock", "clone", "cloth", "cloud", "clover", "club", "clump",
    "coach", "coal", "coast", "cobalt", "cobra", "cocoa", "code", "coffee", "cognac", "coin",
    "cold", "collar", "colt", "column", "comb", "combat", "comedy", "comic", "commit", "common",
    "compact", "compass", "complex", "compute", "comrade", "cone", "confer", "copper", "coral", "cord",
    "core", "cork", "corner", "corps", "cost", "cotton", "couch", "county", "course", "court",
    "cover", "coyote", "crack", "craft", "crane", "crash", "crater", "crawl", "crazy", "cream",
    "credit", "creed", "creek", "crest", "cricket", "crime", "crisp", "critic", "crop", "cross",
    "crowd", "crown", "crucial", "crude", "cruise", "crunch", "crush", "crystal", "cube", "cubic",
    "cuisine", "cult", "cup", "curb", "cure", "curl", "curry", "curse", "curve", "custom",
    "cycle", "daily", "dairy", "daisy", "damage", "dance", "danger", "daring", "dark", "dart",
    "dash", "data", "date", "dawn", "day", "dead", "deal", "dean", "dear", "debate",
    "debris", "decade", "decay", "decimal", "deck", "decor", "decoy", "decree", "deed", "deep",
    "defeat", "defect", "defend", "define", "degree", "delay", "delta", "deluxe", "demand", "demise",
    "denial", "dense", "dental", "depart", "depend", "deploy", "depth", "deputy", "derby", "desert",
    "design", "desk", "detail", "detect", "device", "devote", "dial", "diamond", "diary", "diesel"
]

AMBIGUOUS_CHARACTERS = "il1Lo0O8B"
SPECIAL_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"


def calculate_entropy(password: str, charset_size: int) -> float:
    """Calculate Shannon entropy in bits for a given password and charset."""
    if not password or charset_size <= 1:
        return 0.0
    return len(password) * math.log2(charset_size)


def get_strength_rating(entropy_bits: float) -> Tuple[str, str]:
    """
    Returns NIST-aligned strength category and human-readable feedback.
    """
    if entropy_bits < 28:
        return "Very Weak", "Vulnerable to instant offline brute-force attacks."
    elif entropy_bits < 36:
        return "Weak", "Insufficient for protecting sensitive assets."
    elif entropy_bits < 60:
        return "Moderate", "Suitable for non-critical accounts; reasonable resistance."
    elif entropy_bits < 128:
        return "Strong", "Meets enterprise security and OWASP baseline requirements."
    else:
        return "Very Strong", "Military-grade entropy; practically immune to offline cracking."


def generate_password(
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> Dict[str, object]:
    """
    Generate a cryptographically secure random password using secrets.choice.
    Ensures at least one character from each selected set is included.
    """
    if length < 4:
        raise ValueError("Password length must be at least 4 characters.")

    pools: List[str] = []
    required_chars: List[str] = []

    if include_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)
        pools.append(chars)
        required_chars.append(secrets.choice(chars))

    if include_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)
        pools.append(chars)
        required_chars.append(secrets.choice(chars))

    if include_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = "".join(c for c in chars if c not in AMBIGUOUS_CHARACTERS)
        pools.append(chars)
        required_chars.append(secrets.choice(chars))

    if include_symbols:
        chars = SPECIAL_SYMBOLS
        pools.append(chars)
        required_chars.append(secrets.choice(chars))

    if not pools:
        raise ValueError("At least one character class must be enabled.")

    all_chars = "".join(pools)
    charset_size = len(all_chars)

    # Fill remaining characters
    remaining_length = length - len(required_chars)
    password_chars = required_chars + [secrets.choice(all_chars) for _ in range(remaining_length)]

    # Cryptographically shuffle character list to avoid predictable prefix patterns
    system_random = secrets.SystemRandom()
    system_random.shuffle(password_chars)
    final_password = "".join(password_chars)

    entropy = round(calculate_entropy(final_password, charset_size), 2)
    strength, feedback = get_strength_rating(entropy)

    return {
        "password": final_password,
        "length": len(final_password),
        "entropy_bits": entropy,
        "charset_size": charset_size,
        "strength": strength,
        "feedback": feedback,
        "type": "alphanumeric"
    }


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = True
) -> Dict[str, object]:
    """
    Generate a memorable Diceware passphrase using an EFF-derived word pool.
    """
    if word_count < 3:
        raise ValueError("Passphrase must contain at least 3 words.")

    words: List[str] = []
    for _ in range(word_count):
        word = secrets.choice(DICEWARE_WORDS)
        words.append(word.capitalize() if capitalize else word)

    passphrase = separator.join(words)
    # Entropy of Diceware: N words from pool of size P -> log2(P^N) = N * log2(P)
    pool_size = len(DICEWARE_WORDS)
    entropy = round(word_count * math.log2(pool_size), 2)
    strength, feedback = get_strength_rating(entropy)

    return {
        "password": passphrase,
        "length": len(passphrase),
        "word_count": word_count,
        "entropy_bits": entropy,
        "charset_size": pool_size,
        "strength": strength,
        "feedback": feedback,
        "type": "diceware_passphrase"
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="genpass",
        description="genpass: Cryptographically secure password and passphrase generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  genpass -l 20                          # 20-char strong password
  genpass -l 16 --no-symbols             # Alphanumeric only
  genpass --exclude-ambiguous            # Omits confusing chars (0, O, 1, l, etc.)
  genpass --passphrase -w 5 -s "_"       # 5-word Diceware passphrase
  genpass -c 5 --json                    # 5 passwords in JSON format
        """
    )

    parser.add_argument("-l", "--length", type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-upper", action="store_true", help="Disable uppercase letters")
    parser.add_argument("--no-lower", action="store_true", help="Disable lowercase letters")
    parser.add_argument("--no-digits", action="store_true", help="Disable numeric digits")
    parser.add_argument("--no-symbols", action="store_true", help="Disable special symbols")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (e.g. 1, l, I, 0, O)")
    
    # Passphrase mode
    parser.add_argument("--passphrase", action="store_true", help="Generate a Diceware-style memorable passphrase")
    parser.add_argument("-w", "--words", type=int, default=5, help="Number of words in passphrase (default: 5)")
    parser.add_argument("-s", "--separator", type=str, default="-", help="Separator between words (default: '-')")
    parser.add_argument("--no-capitalize", action="store_true", help="Do not capitalize passphrase words")

    # Output formatting
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("-q", "--quiet", action="store_true", help="Output only the raw generated string(s)")

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    results: List[Dict[str, object]] = []

    try:
        for _ in range(args.count):
            if args.passphrase:
                result = generate_passphrase(
                    word_count=args.words,
                    separator=args.separator,
                    capitalize=not args.no_capitalize
                )
            else:
                result = generate_password(
                    length=args.length,
                    include_upper=not args.no_upper,
                    include_lower=not args.no_lower,
                    include_digits=not args.no_digits,
                    include_symbols=not args.no_symbols,
                    exclude_ambiguous=args.exclude_ambiguous
                )
            results.append(result)

    except ValueError as err:
        sys.stderr.write(f"Error: {err}\n")
        sys.exit(1)

    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2))
        return

    if args.quiet:
        for res in results:
            print(res["password"])
        return

    # Formatted terminal output
    for idx, res in enumerate(results, start=1):
        if len(results) > 1:
            print(f"\n--- Credential [{idx}/{len(results)}] ---")
        print(f"Generated Password : {res['password']}")
        print(f"Length             : {res['length']} characters")
        print(f"Shannon Entropy    : {res['entropy_bits']} bits ({res['strength']})")
        print(f"Analysis           : {res['feedback']}")


if __name__ == "__main__":
    main()
