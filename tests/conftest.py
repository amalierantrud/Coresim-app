"""Felles testdata: en kort normalperiode og en baseline lært fra den."""
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from otdiag import aggregate_minutes, build_baseline, parse_tcpdump_line  # noqa: E402
from otdiag.sim import generate  # noqa: E402

T0 = datetime(2026, 10, 26, 9, 0)


def to_stats(lines):
    return list(aggregate_minutes(p for p in map(parse_tcpdump_line, lines) if p))


@pytest.fixture(scope="session")
def baseline():
    return build_baseline(to_stats(generate(T0, 20, seed=1)))


@pytest.fixture(scope="session")
def t_attack():
    return T0 + timedelta(minutes=30)
