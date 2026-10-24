"""otdiag - statistisk deteksjon og diagnose av angrep i OT-nettverk (INF219 / NORCE).

Pakken er skrevet i ren Python (kun standardbiblioteket), slik at den kan kjøres
både inne i Splunk (som kommandoen `| otdiagnose`) og i Jupyter/pytest.

Flyten er:
    tcpdump-linjer -> features (pakker per minutt) -> detect (avvik) -> diagnose (hendelser)
"""

from .features import Packet, MinuteStats, parse_tcpdump_line, aggregate_minutes, minute_stats_from_row
from .detect import Baseline, Anomaly, build_baseline, detect
from .diagnose import HostEvent, Incident, diagnose

__all__ = [
    "Packet", "MinuteStats", "parse_tcpdump_line", "aggregate_minutes", "minute_stats_from_row",
    "Baseline", "Anomaly", "build_baseline", "detect",
    "HostEvent", "Incident", "diagnose",
]

__version__ = "0.1.0"
