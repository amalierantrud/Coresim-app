"""Simulert coresim-trafikk i samme format som `index=anomaly_detection` på coresim.

Normaldriften er laget etter novemberopptaket (2025-11-27): hver simulator-node
sender UDP-multicast til sin egen gruppe 224.10.10.x med faste pakkestørrelser,
fire noder sender UDP til sim5 (192.168.10.199), og ruteren sender HSRP.
Ratene er omtrentlige og kan justeres i NODES etter målinger fra de ekte dataene.

Brukes av tools/gen_testdata.py (fil) og tools/replay.py (live til Splunk).
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator, List, Optional, Sequence, Tuple

# (kilde, mål, [(kildeport, målport, lengde, pakker per sekund), ...])
NODES: List[Tuple[str, str, List[Tuple[int, int, int, float]]]] = [
    ("192.168.10.116", "224.10.10.116", [(11611, 21611, 480, 10.0), (11621, 21621, 996, 10.0)]),
    ("192.168.10.200", "224.10.10.200", [(10011, 20011, 480, 10.0), (10012, 20012, 480, 10.0)]),
    ("192.168.10.101", "224.10.10.101", [(10111, 20111, 480, 5.0), (10121, 20121, 996, 5.0),
                                          (10131, 20131, 996, 3.0), (10141, 20141, 240, 2.0)]),
    ("192.168.10.110", "224.10.10.110", [(11011, 21011, 240, 6.0), (11021, 21021, 996, 3.5),
                                          (11022, 21022, 996, 4.0)]),
    ("192.168.10.104", "224.10.10.104", [(10411, 20411, 240, 11.0), (10421, 20421, 996, 0.7)]),
    ("192.168.10.102", "224.10.10.102", [(10211, 20211, 240, 9.0), (10221, 20221, 996, 2.6)]),
    ("192.168.10.120", "224.10.10.120", [(10011, 20011, 4, 9.0), (12012, 22012, 50, 9.5)]),
    ("192.168.10.19", "224.10.10.19", [(10019, 20019, 50, 0.75)]),
    ("192.168.10.171", "192.168.10.199", [(20104, 20104, 120, 2.0)]),
    ("192.168.10.172", "192.168.10.199", [(20204, 20204, 120, 2.0)]),
    ("192.168.10.174", "192.168.10.199", [(20404, 20404, 120, 2.0)]),
    ("192.168.10.180", "192.168.10.199", [(21004, 21004, 120, 2.0)]),
]
HSRP_RATE = 1.1  # ruter 192.168.10.1 -> 224.0.0.2

ATTACKER = "192.168.10.66"     # ukjent maskin koblet til nettet
INJECTOR = "192.168.10.77"     # falsk sensor
COMPROMISED = "192.168.10.19"  # kjent node som blir overtatt
ENGINEER = "192.168.10.80"     # engineering-stasjon (vedlikehold)
SIM5 = "192.168.10.199"


@dataclass
class Attack:
    kind: str          # flood, scan, inject, silent, ddos, maintenance
    start: datetime
    minutes: float
    target: str = ""
    note: str = ""

    @property
    def end(self) -> datetime:
        return self.start + timedelta(minutes=self.minutes)

    def active(self, t: datetime) -> bool:
        return self.start <= t < self.end


DEFAULT_TARGETS = {
    "flood": "224.10.10.101", "scan": "192.168.10.0/24", "inject": "224.10.10.101",
    "silent": "192.168.10.104", "ddos": SIM5, "maintenance": "192.168.10.102",
}


def _count(rate: float, rng: random.Random) -> int:
    """Antall pakker i ett sekund: jevn rate med litt variasjon (simulatorer sender jevnt)."""
    base = int(rate)
    n = base + (1 if rng.random() < rate - base else 0)
    if n and rng.random() < 0.05:
        n += rng.choice((-1, 1))
    return max(n, 0)


def _fmt(t: datetime, src: str, sport: Optional[int], dst: str, dport: Optional[int], rest: str) -> str:
    s = f"{src}.{sport}" if sport is not None else src
    d = f"{dst}.{dport}" if dport is not None else dst
    return f"{t:%Y-%m-%d %H:%M:%S.%f} IP {s} > {d}: {rest}"


def _udp(t, src, sport, dst, dport, length):
    return _fmt(t, src, sport, dst, dport, f"UDP, length {length}")


def _syn(t, src, sport, dst, dport, rng):
    return _fmt(t, src, sport, dst, dport, f"Flags [S], seq {rng.randrange(1, 2**31)}, win 1024, length 0")


def second_lines(sec: datetime, attacks: Sequence[Attack], rng: random.Random) -> List[str]:
    """Alle tcpdump-linjer for ett sekund, sortert på tid."""
    out: List[Tuple[datetime, str]] = []

    def at() -> datetime:
        return sec + timedelta(microseconds=rng.randrange(1_000_000))

    silent = {a.target for a in attacks if a.kind == "silent" and a.active(sec)}
    for src, dst, streams in NODES:
        if src in silent:
            continue
        for sport, dport, length, rate in streams:
            for _ in range(_count(rate, rng)):
                t = at()
                out.append((t, _udp(t, src, sport, dst, dport, length)))
    for _ in range(_count(HSRP_RATE, rng)):
        t = at()
        out.append((t, _fmt(t, "192.168.10.1", None, "224.0.0.2",
                            None, "HSRPv1-hello 20: state=active group=1 addr=192.168.10.1")))

    for a in attacks:
        if not a.active(sec):
            continue
        if a.kind == "flood":       # kompromittert node sender massivt mot en gruppe
            for _ in range(_count(400, rng)):
                t = at()
                out.append((t, _udp(t, COMPROMISED, 10019, a.target, 20111, 996)))
        elif a.kind == "inject":    # falsk sensor sender "målinger" til en gruppe
            for _ in range(_count(8, rng)):
                t = at()
                out.append((t, _udp(t, INJECTOR, 10111, a.target, 20111, 128)))
        elif a.kind == "scan":      # SYN-skanning av simulator-nettet
            for _ in range(_count(15, rng)):
                t = at()
                host = f"192.168.10.{rng.choice((101, 102, 104, 110, 116, 120, 199, 200))}"
                out.append((t, _syn(t, ATTACKER, rng.randrange(40000, 60000), host, rng.randrange(1, 10000), rng)))
        elif a.kind == "ddos":      # UDP-flood mot sim5 fra spoofede adresser
            for _ in range(_count(150, rng)):
                t = at()
                src = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
                out.append((t, _udp(t, src, rng.randrange(1024, 65535), a.target, 21004, 512)))
        elif a.kind == "maintenance":  # engineering-stasjon laster program til en node
            for _ in range(_count(30, rng)):
                t = at()
                out.append((t, _fmt(t, ENGINEER, 51515, a.target, 102,
                                    f"Flags [P.], seq 1:961, ack 1, win 8192, length 960")))
    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


def generate(start: datetime, minutes: int, attacks: Sequence[Attack] = (), seed: int = 219) -> Iterator[str]:
    """Genererer alle linjer for `minutes` minutter fra `start`."""
    rng = random.Random(seed)
    for s in range(minutes * 60):
        yield from second_lines(start + timedelta(seconds=s), attacks, rng)


def host_events_for(attacks: Sequence[Attack]) -> List[dict]:
    """Host events som hører til scenariene (det diagnosen kobler inn)."""
    rows = []
    for a in attacks:
        if a.kind == "flood":
            rows.append({"time": a.start - timedelta(minutes=2), "host_ip": COMPROMISED, "kind": "innlogging",
                         "user": "root", "suspicious": True,
                         "detail": "SSH-innlogging som root fra ukjent adresse 192.168.10.66"})
            rows.append({"time": a.start - timedelta(seconds=30), "host_ip": COMPROMISED, "kind": "prosess",
                         "user": "root", "suspicious": True,
                         "detail": "ukjent prosess /tmp/udpblast startet"})
        elif a.kind == "maintenance":
            rows.append({"time": a.start - timedelta(minutes=1), "host_ip": ENGINEER, "kind": "vedlikehold",
                         "user": "ingenior1", "suspicious": False,
                         "detail": "TIA Portal startet, endringsordre CHG-1042"})
    return rows
