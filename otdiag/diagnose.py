"""Diagnose: fra mange enkeltavvik til én forståelig hendelse.

Statistikken (detect.py) sier at noe er rart, minutt for minutt. Diagnosen
1. grupperer avvik som hører sammen (samme mål, tett i tid) til én hendelse,
2. bestemmer angrepstype ut fra hvilke regler som slo ut,
3. kobler inn host events fra kildemaskinene (innlogging, prosesser, vedlikehold),
4. setter alvorlighet, sikkerhet og en forklaring på norsk.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .detect import Anomaly

SEVERITIES = ["info", "lav", "middels", "høy", "kritisk"]


@dataclass
class HostEvent:
    time: datetime
    host_ip: str
    kind: str                 # "innlogging", "prosess", "vedlikehold" eller "annet"
    detail: str
    user: Optional[str] = None
    suspicious: bool = False  # f.eks. ukjent prosess eller innlogging utenfor arbeidstid


@dataclass
class Incident:
    start: datetime
    end: datetime
    type: str
    severity: str
    target: str
    sources: List[str]
    confidence: float
    explanation: str
    rules: List[str]
    anomaly_count: int
    host_evidence: List[str] = field(default_factory=list)

    def as_row(self) -> dict:
        return {
            "_time": self.start.isoformat(), "end": self.end.isoformat(),
            "duration_min": round((self.end - self.start).total_seconds() / 60 + 1),
            "diagnose": self.type, "severity": self.severity, "target": self.target,
            "sources": ",".join(self.sources), "confidence": self.confidence,
            "explanation": self.explanation, "rules": ",".join(self.rules),
            "anomalies": self.anomaly_count, "host_evidence": " | ".join(self.host_evidence),
        }


def _bump(severity: str, steps: int) -> str:
    i = SEVERITIES.index(severity) + steps
    return SEVERITIES[max(0, min(i, len(SEVERITIES) - 1))]


def _cluster(anomalies: Sequence[Anomaly], gap: timedelta) -> List[List[Anomaly]]:
    """Slår sammen avvik med samme gruppenøkkel når de ligger maks `gap` fra hverandre.

    En skanning handler om kilden; alt annet handler om målet. Nye flyter fra en
    kilde som skanner samtidig, regnes som en del av skanningen.
    """
    scans: Dict[str, List[datetime]] = {}
    for a in anomalies:
        if a.rule == "skanning":
            scans.setdefault(a.src_ip, []).append(a.time)

    def group_key(a: Anomaly) -> Tuple[str, str]:
        if a.rule == "skanning":
            return ("kilde", a.src_ip)
        if a.rule == "ny_flyt" and any(abs(a.time - t) <= gap for t in scans.get(a.src_ip, [])):
            return ("kilde", a.src_ip)
        return ("mal", a.dst_ip)

    open_groups: Dict[Tuple[str, str], List[Anomaly]] = {}
    done: List[List[Anomaly]] = []
    for a in sorted(anomalies, key=lambda x: x.time):
        k = group_key(a)
        g = open_groups.get(k)
        if g is not None and a.time - g[-1].time <= gap:
            g.append(a)
        else:
            if g is not None:
                done.append(g)
            open_groups[k] = [a]
    done.extend(open_groups.values())
    return sorted(done, key=lambda g: g[0].time)


def _classify(rules: Set[str], group: List[Anomaly]) -> Tuple[str, str]:
    max_z = max((abs(a.z) for a in group if a.z is not None), default=0.0)
    target = group[0].dst_ip
    if "skanning" in rules:
        return "Rekognosering (portskanning)", "høy"
    if "mange_kilder" in rules and "volum_hoy" in rules:
        return "Distribuert flood fra mange (spoofede) kilder (DDoS)", "kritisk"
    if "volum_hoy" in rules and max_z >= 10:
        return "Flooding (DoS)", "kritisk"
    if "ny_flyt" in rules and (rules & {"storrelse", "volum_hoy"} or target.startswith("224.")):
        return "Mulig injeksjon av falske data", "kritisk"
    if "volum_hoy" in rules:
        return "Økt trafikk / mulig flooding", "høy"
    if rules & {"taus", "volum_lav"}:
        return "Node nede eller blokkert", "høy"
    if "storrelse" in rules:
        return "Endret innhold i trafikken (mulig manipulering)", "middels"
    if "ny_flyt" in rules:
        return "Ukjent kommunikasjon", "middels"
    if "mange_kilder" in rules:
        return "Uvanlig mange kilder", "middels"
    return "Uklassifisert avvik", "lav"


def diagnose(anomalies: Sequence[Anomaly], host_events: Sequence[HostEvent] = (),
             gap_s: int = 180, host_window_s: int = 600) -> List[Incident]:
    """Lager hendelser (Incident) av avvik + host events."""
    incidents: List[Incident] = []
    for group in _cluster(anomalies, timedelta(seconds=gap_s)):
        rules = {a.rule for a in group}
        start, end = group[0].time, group[-1].time
        sources = sorted({a.src_ip for a in group if a.src_ip != "*" and not a.src_ip.endswith("kilder")})
        spoofed = max((int(a.src_ip.split()[0]) for a in group if a.src_ip.endswith("kilder")), default=0)
        if "skanning" in rules:
            scanned = sorted({h for a in group if a.rule == "skanning" for h in a.dst_ip.split(",")})
            target = f"{len(scanned)} verter ({', '.join(scanned[:3])}{' ...' if len(scanned) > 3 else ''})"
        else:
            target = group[0].dst_ip
        itype, severity = _classify(rules, group)

        # host events på kildemaskinene rett før og under hendelsen
        win_start = start - timedelta(seconds=host_window_s)
        related = [h for h in host_events if h.host_ip in sources and win_start <= h.time <= end]
        evidence = [f"{h.time:%H:%M} {h.host_ip}: {h.detail}" for h in related]
        maintenance = [h for h in related if h.kind == "vedlikehold"]
        suspicious = [h for h in related if h.suspicious]

        confidence = 0.5 + 0.1 * min(len(rules), 3)
        notes = []
        if maintenance and not suspicious:
            itype, severity = "Planlagt vedlikehold (godartet)", "info"
            notes.append(f"Samtidig vedlikehold registrert på {maintenance[0].host_ip}"
                         f"{' av ' + maintenance[0].user if maintenance[0].user else ''}.")
            confidence += 0.15
        elif suspicious:
            severity = _bump(severity, 1)
            notes.append(f"Kilden {suspicious[0].host_ip} er trolig kompromittert: {suspicious[0].detail}.")
            confidence += 0.2

        minutes = int((end - start).total_seconds() // 60) + 1
        rule_text = ", ".join(sorted(rules))
        if sources:
            src_text = f"Kilde: {', '.join(sources[:3])}{' m.fl.' if len(sources) > 3 else ''}. "
        elif spoofed:
            src_text = f"Opptil {spoofed} ulike kildeadresser per minutt (trolig spoofet). "
        else:
            src_text = ""
        explanation = (f"{itype}. Mål: {target}. Varighet {minutes} min, {len(group)} avvik ({rule_text}). "
                       + src_text + " ".join(notes)).strip()

        incidents.append(Incident(
            start=start, end=end, type=itype, severity=severity, target=target, sources=sources,
            confidence=round(min(confidence, 0.95), 2), explanation=explanation,
            rules=sorted(rules), anomaly_count=len(group), host_evidence=evidence,
        ))
    return incidents
