"""Shannon entropy of raw bytes.

Entropy close to 8.0 indicates packed/encrypted/compressed content. Used for
whole-file and per-section analysis.
"""
from __future__ import annotations

import math
from collections import Counter


def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)
