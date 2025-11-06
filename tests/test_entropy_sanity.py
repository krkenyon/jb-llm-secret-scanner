# tests/test_entropy.py
from math import isfinite
from scan import shannon_entropy 

def test_shannon_entropy_values():
    samples = {
        "empty": "",
        "low_repeat": "AAAAAAAAAAAAAAAAAAAA",
        "wordish": "password123password123",
        "uuid": "550e8400-e29b-41d4-a716-446655440000",
        "hex_sha256": "4d9678dcf2b5d9b6202c5e84a9f2e2282f4cb6f20e0d08c19d8f0c3ed5b6b9c1",
        "base64y": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "randomish": "a8Fr92qP0zKwH3t5xR1YqVbN7tXu9c",
    }

    # optional: print for debugging if you like
    for name, s in samples.items():
        H = shannon_entropy(s)
        print(f"{name:12s} len={len(s):2d} H≈{H:.2f} bits/char")

    # assertions (pytest will report which fails)
    assert shannon_entropy(samples["low_repeat"]) < 0.5
    assert shannon_entropy(samples["wordish"]) < 3.5
    assert isfinite(shannon_entropy(samples["base64y"]))
    assert shannon_entropy(samples["randomish"]) >= 3.5
