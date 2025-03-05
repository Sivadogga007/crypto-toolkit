"""Corpus utilities and standard frequency distributions for classical cryptanalysis."""

import string
import random
from typing import Dict, List

# Standard English letter frequencies (percentages summing to 1.0)
# Source: Lewand, Robert (2000), Cryptological Mathematics
ENGLISH_LETTER_FREQ: Dict[str, float] = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

# Theoretical Index of Coincidence values
ENGLISH_IC: float = 0.0667
UNIFORM_IC: float = 1.0 / 26.0  # ~0.03846

# Representative English text samples for evaluation and benchmarks
SAMPLE_ENGLISH_PARAGRAPHS = [
    "Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties. Modern cryptography is heavily based on mathematical theory and computer science practice.",
    "The fundamental objective of cryptography is to enable two parties to communicate over an insecure channel in such a way that an adversary cannot understand what is being said. Confidentiality, integrity, and authenticity form the bedrock of information security.",
    "Historically classical ciphers relied on substitution and transposition techniques. The Caesar cipher shifted alphabet letters by a constant displacement while the Vigenere cipher introduced polyalphabetic substitution to flatten frequency distributions.",
    "Public key cryptography revolutionized secure communications by introducing asymmetric key pairs where encryption and decryption use mathematically related yet distinct keys. The security of systems like RSA relies on the computational hardness of integer factorization.",
    "Diffie and Hellman proposed a revolutionary method for two parties to establish a shared secret over an insecure channel without prior shared secrets. The protocol derives its security from the difficulty of computing discrete logarithms in finite groups.",
    "A side channel attack is any attack based on information gained from the implementation of a computer system rather than weaknesses in the implemented algorithm itself. Timing information, power consumption, and electromagnetic leaks represent prominent vectors.",
    "Random numbers are indispensable in cryptography for key generation, initialization vectors, salts, and nonces. Pseudorandom number generators must pass rigorous statistical tests to ensure unpredictability against computationally bounded adversaries.",
    "Modern digital signature schemes provide non-repudiation and integrity verification. Elliptic curve cryptography offers equivalent security to traditional RSA with substantially smaller key lengths and faster arithmetic operations."
]


def clean_text(text: str) -> str:
    """Normalizes text by stripping whitespace, punctuation, and converting to uppercase A-Z."""
    return ''.join(ch.upper() for ch in text if ch.upper() in string.ascii_uppercase)


def generate_sample_plaintext(min_length: int = 200, seed: int = 42) -> str:
    """Generates continuous natural English text of at least min_length uppercase letters."""
    rng = random.Random(seed)
    paragraphs = list(SAMPLE_ENGLISH_PARAGRAPHS)
    rng.shuffle(paragraphs)
    
    text = ""
    while len(clean_text(text)) < min_length:
        text += " " + rng.choice(SAMPLE_ENGLISH_PARAGRAPHS)
    
    return clean_text(text)[:min_length]
