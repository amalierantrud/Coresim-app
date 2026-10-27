"""Spiller av simulert coresim-trafikk LIVE til Splunk, med angrep når du vil.

Splunk må ha en TCP-input på porten (appen inf219_testdata setter opp port 9998).

Eksempler:
    python tools/replay.py                                  # bare normaldrift, til localhost:9998
    python tools/replay.py --attack flood@5m:3m             # flood etter 5 min, varer 3 min
    python tools/replay.py --attack scan@2m:2m --attack silent@6m:4m
    python tools/replay.py --stdout | head                  # se linjene uten Splunk

Angrepstyper: flood, scan, inject, silent, ddos, maintenance
Host events for scenariene skrives rett inn i appens lookup
(inf219_ot_anomaly/lookups/host_events.csv), så Splunk ser dem med en gang.
"""
import argparse
import csv
import random
import socket
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from otdiag.sim import DEFAULT_TARGETS, Attack, host_events_for, second_lines  # noqa: E402


def parse_duration(s: str) -> float:
    """'90s', '5m' eller '1.5m' -> minutter."""
    return float(s[:-1]) / 60 if s.endswith("s") else float(s.rstrip("m"))


def parse_attack(spec: str, now: datetime) -> Attack:
    """'flood@5m:3m' eller 'flood@5m:3m=224.10.10.110'"""
    kind, rest = spec.split("@")
    target = DEFAULT_TARGETS[kind]
    if "=" in rest:
        rest, target = rest.split("=")
    at, dur = rest.split(":")
    start = now + timedelta(seconds=round(parse_duration(at) * 60))
    return Attack(kind, start, parse_duration(dur), target)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=9998)
    ap.add_argument("--attack", action="append", default=[], help="type@start:varighet, f.eks. flood@5m:3m")
    ap.add_argument("--minutes", type=float, default=0, help="stopp etter så mange minutter (0 = aldri)")
    ap.add_argument("--stdout", action="store_true", help="skriv linjene til skjermen i stedet for Splunk")
    args = ap.parse_args()

    now = datetime.now().replace(microsecond=0)
    attacks = [parse_attack(a, now) for a in args.attack]
    for a in attacks:
        print(f"Planlagt: {a.kind} {a.start:%H:%M:%S}-{a.end:%H:%M:%S} mot {a.target}", file=sys.stderr)
    lookup = Path(__file__).resolve().parents[1] / "inf219_ot_anomaly" / "lookups" / "host_events.csv"
    if attacks and lookup.parent.exists():
        with open(lookup, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["time", "host_ip", "kind", "user", "suspicious", "detail"])
            w.writeheader()
            for h in host_events_for(attacks):
                w.writerow({**h, "time": int(h["time"].timestamp())})  # epoch: samme tid uansett tidssone
        print(f"Host events skrevet til {lookup}", file=sys.stderr)

    sock = None
    if not args.stdout:
        sock = socket.create_connection((args.host, args.port))
        print(f"Sender til {args.host}:{args.port} - Ctrl+C for å stoppe", file=sys.stderr)

    rng = random.Random()
    sec = now
    stop = now + timedelta(minutes=args.minutes) if args.minutes else None
    try:
        while stop is None or sec < stop:
            lines = second_lines(sec, attacks, rng)
            data = ("\n".join(lines) + "\n").encode()
            if sock:
                sock.sendall(data)
            else:
                sys.stdout.write(data.decode())
            for a in attacks:
                if a.start == sec:
                    print(f"{sec:%H:%M:%S} >>> {a.kind} starter mot {a.target}", file=sys.stderr)
            sec += timedelta(seconds=1)
            wait = (sec - datetime.now()).total_seconds()
            if wait > 0:
                time.sleep(wait)
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        if sock:
            sock.close()


if __name__ == "__main__":
    main()
