"""Statistisk deteksjon: sammenlign hvert minutt med en robust baseline.

Baseline lages fra en periode med normal drift. For hvert kommunikasjonspar
(kilde, mål, protokoll) lagres median, 5- og 95-persentil av pakker per minutt.
Et robust standardavvik beregnes som (p95 - p5) / 3.29, fordi en normalfordeling
har 3.29 standardavvik mellom 5- og 95-persentilen. Median og persentiler
påvirkes lite av et angrep som tilfeldigvis ligger i treningsperioden.

Regler (alle gir en `Anomaly`):
    volum_hoy / volum_lav  |z| >= k mot baseline for paret
    taus                   kjent par sender ingenting dette minuttet
    ny_flyt                paret finnes ikke i baseline
    storrelse              snitt pakkestørrelse avviker tydelig fra normalen
    skanning               én kilde treffer mange ulike porter
    mange_kilder           langt flere kilder enn normalt mot samme mål
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence

from .features import FlowKey, MinuteStats

ROBUST_SD_FACTOR = 3.29


@dataclass
class FlowBaseline:
    med: float
    p5: float
    p95: float
    med_len: float
    minutes: int

    @property
    def robust_sd(self) -> float:
        """Robust standardavvik med gulv, så helt jevn trafikk ikke gir enorme z-verdier."""
        return max((self.p95 - self.p5) / ROBUST_SD_FACTOR, 0.1 * self.med, 5.0)


TOTAL = "*"  # src_ip-verdi for rader som gjelder all trafikk mot et mål


@dataclass
class Baseline:
    flows: Dict[FlowKey, FlowBaseline]        # per (kilde, mål, protokoll)
    dst_totals: Dict[str, FlowBaseline]       # sum av all trafikk mot hvert mål
    sources_per_dst: Dict[str, float]         # median antall kilder per mål per minutt

    # --- lagre/lese som rader (f.eks. Splunk-lookup ot_baseline.csv) ---
    def to_rows(self) -> List[dict]:
        def row(src, dst, proto, b):
            return {"src_ip": src, "dest_ip": dst, "proto": proto, "minutes": b.minutes,
                    "med": b.med, "p5": b.p5, "p95": b.p95, "med_len": round(b.med_len, 1),
                    "robust_sd": round(b.robust_sd, 2), "dst_sources": self.sources_per_dst.get(dst, 1)}
        rows = [row(s, d, p, b) for (s, d, p), b in sorted(self.flows.items())]
        rows += [row(TOTAL, d, TOTAL, b) for d, b in sorted(self.dst_totals.items())]
        return rows

    @classmethod
    def from_rows(cls, rows: Iterable[dict]) -> "Baseline":
        flows, totals, srcs = {}, {}, {}
        for r in rows:
            b = FlowBaseline(float(r["med"]), float(r["p5"]), float(r["p95"]),
                             float(r["med_len"]), int(float(r["minutes"])))
            if r["src_ip"] == TOTAL:
                totals[r["dest_ip"]] = b
            else:
                flows[(r["src_ip"], r["dest_ip"], r["proto"])] = b
            srcs[r["dest_ip"]] = float(r.get("dst_sources", 1))
        return cls(flows, totals, srcs)


@dataclass
class Anomaly:
    time: datetime
    rule: str
    src_ip: str
    dst_ip: str
    proto: str
    value: float
    expected: float
    z: Optional[float]
    detail: str

    def as_row(self) -> dict:
        return {
            "_time": self.time.isoformat(), "rule": self.rule, "src_ip": self.src_ip,
            "dest_ip": self.dst_ip, "proto": self.proto, "value": self.value,
            "expected": self.expected, "z": self.z, "detail": self.detail,
        }


def _percentile(sorted_vals: Sequence[float], q: float) -> float:
    """Lineær persentil (q mellom 0 og 1) uten numpy."""
    if not sorted_vals:
        return 0.0
    pos = (len(sorted_vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def build_baseline(stats: Iterable[MinuteStats], min_minutes: int = 10) -> Baseline:
    """Lærer normalnivå fra oppsummeringer i en periode med normal drift."""
    per_minute: Dict[datetime, Dict[FlowKey, MinuteStats]] = defaultdict(dict)
    for s in stats:
        per_minute[s.minute][s.key] = s
    minutes = sorted(per_minute)
    keys = {k for m in per_minute.values() for k in m}

    def summarize(counts: List[int], lens: List[float]) -> FlowBaseline:
        counts = sorted(counts)
        return FlowBaseline(med=statistics.median(counts), p5=_percentile(counts, 0.05),
                            p95=_percentile(counts, 0.95), med_len=statistics.median(lens),
                            minutes=len(lens))

    flows: Dict[FlowKey, FlowBaseline] = {}
    for key in keys:
        present = [per_minute[m][key] for m in minutes if key in per_minute[m]]
        if len(present) < min_minutes:
            continue
        # minutter der paret mangler teller som 0 pakker
        counts = [per_minute[m][key].packets if key in per_minute[m] else 0 for m in minutes]
        flows[key] = summarize(counts, [s.avg_len for s in present])

    # all trafikk mot hvert mål (fanger flood fra nye/spoofede kilder)
    dsts = {k[1] for k in flows}
    dst_totals: Dict[str, FlowBaseline] = {}
    for dst in dsts:
        counts, lens = [], []
        for m in minutes:
            rows = [s for k, s in per_minute[m].items() if k[1] == dst]
            pk = sum(s.packets for s in rows)
            counts.append(pk)
            if pk:
                lens.append(sum(s.bytes for s in rows) / pk)
        if lens:
            dst_totals[dst] = summarize(counts, lens)

    srcs_per_dst: Dict[str, List[int]] = defaultdict(list)
    for m in minutes:
        by_dst: Dict[str, set] = defaultdict(set)
        for (src, dst, _p) in per_minute[m]:
            by_dst[dst].add(src)
        for dst, s in by_dst.items():
            srcs_per_dst[dst].append(len(s))
    sources = {dst: float(statistics.median(v)) for dst, v in srcs_per_dst.items()}
    return Baseline(flows, dst_totals, sources)


def detect(stats: Iterable[MinuteStats], baseline: Baseline, k: float = 4.0,
           scan_ports: int = 20, fan_in: int = 10, min_silent: float = 10.0) -> List[Anomaly]:
    """Kjører alle regler minutt for minutt. Returnerer avvik sortert på tid."""
    per_minute: Dict[datetime, List[MinuteStats]] = defaultdict(list)
    for s in stats:
        per_minute[s.minute].append(s)

    out: List[Anomaly] = []
    for minute in sorted(per_minute):
        rows = per_minute[minute]
        seen = {s.key for s in rows}

        new_by_dst: Dict[str, List[MinuteStats]] = defaultdict(list)
        for s in rows:
            b = baseline.flows.get(s.key)
            if b is None:
                new_by_dst[s.dst_ip].append(s)
                continue
            z = (s.packets - b.med) / b.robust_sd
            if abs(z) >= k:
                rule = "volum_hoy" if z > 0 else "volum_lav"
                out.append(Anomaly(minute, rule, s.src_ip, s.dst_ip, s.proto, s.packets, b.med, round(z, 2),
                                   f"{s.packets} pakker/min, normalt ca. {b.med:.0f}"))
            if s.packets >= 10 and b.med_len > 0:
                diff = abs(s.avg_len - b.med_len)
                if diff > max(0.2 * b.med_len, 32):
                    out.append(Anomaly(minute, "storrelse", s.src_ip, s.dst_ip, s.proto, round(s.avg_len, 1),
                                       b.med_len, None,
                                       f"snitt {s.avg_len:.0f} byte per pakke, normalt {b.med_len:.0f}"))

        # nye par; mange nye kilder mot samme mål slås sammen til ett avvik
        for dst, new in new_by_dst.items():
            if len(new) > 5:
                pk = sum(s.packets for s in new)
                out.append(Anomaly(minute, "ny_flyt", f"{len(new)} nye kilder", dst, "-", pk, 0, None,
                                   f"{len(new)} ukjente kilder mot {dst}, {pk} pakker"))
            else:
                for s in new:
                    out.append(Anomaly(minute, "ny_flyt", s.src_ip, s.dst_ip, s.proto, s.packets, 0, None,
                                       f"ukjent par {s.src_ip} -> {s.dst_ip} ({s.proto}), {s.packets} pakker"))

        # kjente par som er helt stille
        for key, b in baseline.flows.items():
            if key not in seen and b.med >= min_silent:
                src, dst, proto = key
                z = -b.med / b.robust_sd
                if abs(z) >= k:
                    out.append(Anomaly(minute, "taus", src, dst, proto, 0, b.med, round(z, 2),
                                       f"ingen pakker, normalt ca. {b.med:.0f} per min"))

        # skanning: mange ulike porter fra samme kilde
        ports_by_src: Dict[str, int] = defaultdict(int)
        hosts_by_src: Dict[str, set] = defaultdict(set)
        for s in rows:
            ports_by_src[s.src_ip] += s.dest_ports
            hosts_by_src[s.src_ip].add(s.dst_ip)
        for src, ports in ports_by_src.items():
            if ports >= scan_ports:
                out.append(Anomaly(minute, "skanning", src, ",".join(sorted(hosts_by_src[src])), "TCP",
                                   ports, 0, None, f"{ports} porter på {len(hosts_by_src[src])} verter"))

        # samlet volum mot hvert kjent mål (flood fra nye eller spoofede kilder)
        total_by_dst: Dict[str, int] = defaultdict(int)
        for s in rows:
            total_by_dst[s.dst_ip] += s.packets
        for dst, b in baseline.dst_totals.items():
            pk = total_by_dst.get(dst, 0)
            z = (pk - b.med) / b.robust_sd
            if z >= k:
                out.append(Anomaly(minute, "volum_hoy", TOTAL, dst, "-", pk, b.med, round(z, 2),
                                   f"totalt {pk} pakker/min mot {dst}, normalt ca. {b.med:.0f}"))

        # mange kilder mot samme mål
        srcs_by_dst: Dict[str, set] = defaultdict(set)
        for s in rows:
            srcs_by_dst[s.dst_ip].add(s.src_ip)
        for dst, srcs in srcs_by_dst.items():
            normal = baseline.sources_per_dst.get(dst, 1.0)
            if len(srcs) >= normal + fan_in:
                out.append(Anomaly(minute, "mange_kilder", f"{len(srcs)} kilder", dst, "-", len(srcs),
                                   normal, None, f"{len(srcs)} ulike kilder, normalt {normal:.0f}"))
    return out
