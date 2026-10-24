"""Felles oppsett for Python-kommandoene i Splunk.

Gjør bin/lib (splunklib) og bin/otdiag importerbare, og har små hjelpere for å
gå mellom Splunk-rader (dict med strenger) og otdiag sine datatyper.
"""
import os
import sys
from datetime import datetime

BIN = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(BIN)
LOOKUPS = os.path.join(APP, "lookups")
for p in (os.path.join(BIN, "lib"), BIN):
    if p not in sys.path:
        sys.path.insert(0, p)


def to_dt(value):
    """Splunk sender _time som epoch-sekunder (streng)."""
    try:
        return datetime.fromtimestamp(float(value))
    except (TypeError, ValueError):
        return datetime.fromisoformat(str(value)[:19])


def to_epoch(dt):
    return round(dt.timestamp(), 3)


class Buffered:
    """Splunk sender data i biter (chunks). Kommandoer som trenger ALT samtidig
    (baseline, diagnose) samler opp og regner først når siste bit er kommet."""

    def collect(self, records):
        if not hasattr(self, "_buf"):
            self._buf = []
        self._buf.extend(records)
        # _finished settes av splunklib på siste bit; finnes den ikke, regner vi på det vi har
        return getattr(self, "_finished", True)
