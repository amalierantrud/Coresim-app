"""Fra rå tcpdump-linjer til statistikk per minutt.

Coresim sender én linje per pakke, f.eks.:
    2025-11-27 10:25:13.546932 IP 192.168.10.116.11621 > 224.10.10.116.21621: UDP, length 996
    2025-11-27 10:25:12.806562 IP 192.168.10.1 > 224.0.0.2: HSRPv1-hello 20: state=active ...
    2026-01-01 12:00:00.000001 IP 10.0.0.66.40000 > 192.168.10.101.502: Flags [S], seq 1, length 0

I Splunk gjøres samme jobb av props.conf + oppsummeringssøket. Denne modulen
brukes i tester, notatbøker og testdatagenerering.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, Iterator, Optional, Set, Tuple

_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?) IP "
    r"(?P<src>\d+\.\d+\.\d+\.\d+)(?:\.(?P<sport>\d+))? > "
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)(?:\.(?P<dport>\d+))?: (?P<rest>.*)$"
)
_LENGTH = re.compile(r"length (\d+)")
_FLAGS = re.compile(r"Flags \[([^\]]+)\]")


@dataclass(frozen=True)
class Packet:
    time: datetime
    src_ip: str
    dst_ip: str
    proto: str                      # "UDP", "TCP", "HSRP" eller "annet"
    length: int = 0
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # f.eks. "S" for SYN


def parse_tcpdump_line(line: str) -> Optional[Packet]:
    """Tolker én `tcpdump -tttt`-linje. Returnerer None hvis linjen ikke er en IP-pakke."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest")
    flags_m = _FLAGS.search(rest)
    if rest.startswith("UDP"):
        proto = "UDP"
    elif flags_m:
        proto = "TCP"
    elif rest.startswith("HSRP"):
        proto = "HSRP"
    else:
        proto = "annet"
    len_m = _LENGTH.search(rest)
    ts = m.group("ts")
    fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in ts else "%Y-%m-%d %H:%M:%S"
    return Packet(
        time=datetime.strptime(ts, fmt),
        src_ip=m.group("src"),
        dst_ip=m.group("dst"),
        proto=proto,
        length=int(len_m.group(1)) if len_m else 0,
        src_port=int(m.group("sport")) if m.group("sport") else None,
        dst_port=int(m.group("dport")) if m.group("dport") else None,
        tcp_flags=flags_m.group(1) if flags_m else None,
    )


FlowKey = Tuple[str, str, str]  # (src_ip, dst_ip, proto)


@dataclass
class MinuteStats:
    """Oppsummering av ett kommunikasjonspar i ett minutt - samme felt som ot_summary i Splunk."""
    minute: datetime
    src_ip: str
    dst_ip: str
    proto: str
    packets: int = 0
    bytes: int = 0
    dest_ports: int = 0     # antall ulike målporter (som dc(dest_port) i Splunk)
    syn: int = 0

    @property
    def key(self) -> FlowKey:
        return (self.src_ip, self.dst_ip, self.proto)

    @property
    def avg_len(self) -> float:
        return self.bytes / self.packets if self.packets else 0.0

    def as_row(self) -> dict:
        return {
            "_time": self.minute.isoformat(), "src_ip": self.src_ip, "dest_ip": self.dst_ip,
            "proto": self.proto, "packets": self.packets, "bytes": self.bytes,
            "avg_len": round(self.avg_len, 1), "dest_ports": self.dest_ports, "syn": self.syn,
        }


def aggregate_minutes(packets: Iterable[Packet]) -> Iterator[MinuteStats]:
    """Grupperer pakker per (minutt, kilde, mål, protokoll). Sortert på tid."""
    buckets: Dict[Tuple[datetime, str, str, str], MinuteStats] = {}
    ports: Dict[Tuple[datetime, str, str, str], Set[int]] = {}
    for p in packets:
        minute = p.time.replace(second=0, microsecond=0)
        k = (minute, p.src_ip, p.dst_ip, p.proto)
        s = buckets.get(k)
        if s is None:
            s = buckets[k] = MinuteStats(minute, p.src_ip, p.dst_ip, p.proto)
        s.packets += 1
        s.bytes += p.length
        if p.dst_port is not None:
            ports.setdefault(k, set()).add(p.dst_port)
        if p.tcp_flags and "S" in p.tcp_flags and "." not in p.tcp_flags:
            s.syn += 1
    for k in sorted(buckets, key=lambda k: k[0]):
        buckets[k].dest_ports = len(ports.get(k, ()))
        yield buckets[k]


def minute_stats_from_row(row: dict) -> MinuteStats:
    """Lager MinuteStats fra en rad i ot_summary (Splunk) eller en CSV-eksport av den."""
    t = row["_time"]
    if isinstance(t, datetime):
        minute = t
    else:
        try:
            minute = datetime.fromtimestamp(float(t))
        except ValueError:
            minute = datetime.fromisoformat(str(t)).replace(tzinfo=None)
    num = lambda f: int(float(row.get(f) or 0))
    return MinuteStats(minute.replace(second=0, microsecond=0), row["src_ip"], row.get("dest_ip") or row["dst_ip"],
                       row.get("proto", "UDP"), num("packets"), num("bytes"), num("dest_ports"), num("syn"))
