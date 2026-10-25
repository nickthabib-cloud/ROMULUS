"""Deterministic statistics for hourly baseline-rate series."""
from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

RATE_MIN_COUNT = 5.0
RATE_MEAN_MULTIPLIER = 3.0
RATE_SIGMA_MULTIPLIER = 4.0


@dataclass(frozen=True)
class RateThreshold:
    """The reproducible parameters and result of one hourly-rate threshold."""

    mean: float
    sigma: float
    n: int
    value: float
    min_count: float
    k: float
    z: float


def threshold(series: Iterable[int | float], *, min_count: float = RATE_MIN_COUNT,
              k: float = RATE_MEAN_MULTIPLIER,
              z: float = RATE_SIGMA_MULTIPLIER) -> RateThreshold:
    """Return ``max(min_count, mean*k, mean + z*sample_sigma)`` deterministically."""
    values = sorted(float(value) for value in series)
    if len(values) < 2:
        raise ValueError("a rate threshold requires at least two history hours")
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("rate series values must be finite and non-negative")
    parameters = (float(min_count), float(k), float(z))
    if any(not math.isfinite(value) or value < 0 for value in parameters):
        raise ValueError("rate threshold parameters must be finite and non-negative")

    mean = math.fsum(values) / len(values)
    sigma = math.sqrt(math.fsum(sorted((value - mean) ** 2 for value in values)) / (len(values) - 1))
    value = max(parameters[0], mean * parameters[1], mean + parameters[2] * sigma)
    return RateThreshold(
        mean=round(mean, 6), sigma=round(sigma, 6), n=len(values), value=round(value, 6),
        min_count=parameters[0], k=parameters[1], z=parameters[2],
    )
