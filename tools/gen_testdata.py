"""Lager en testdatafil i coresim-format med normaldrift og innlagte angrep.

Eksempel:
    python tools/gen_testdata.py                       # 90 min, alle seks scenarier
    python tools/gen_testdata.py --minutes 30 --no-attacks

Lager i mappen testdata/:
    coresim_tcpdump.log   én tcpdump-linje per pakke (som index=anomaly_detection)
    attack_windows.csv    fasit: når hvert scenario skjedde
    host_events.csv       host events som hører til scenariene
"""
import argparse
import csv
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from otdiag.sim import DEFAULT_TARGETS, Attack, generate, host_events_for  # noqa: E402

SCENARIOS = ["scan", "flood", "inject", "silent", "ddos", "maintenance"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--start", default="2026-10-26T09:00", help="starttid (ISO), default 2026-10-26T09:00")
    ap.add_argument("--minutes", type=int, default=90, help="lengde i minutter (default 90)")
    ap.add_argument("--normal", type=int, default=40, help="minutter ren normaldrift først (til baseline)")
    ap.add_argument("--no-attacks", action="store_true", help="bare normaldrift")
    ap.add_argument("--out", default="testdata", help="mappe for filene")
    ap.add_argument("--seed", type=int, default=219)
    args = ap.parse_args()

    start = datetime.fromisoformat(args.start)
    attacks = []
    if not args.no_attacks:
        t = start + timedelta(minutes=args.normal)
        for kind in SCENARIOS:
            minutes = 5 if kind == "inject" else 3
            if t + timedelta(minutes=minutes) > start + timedelta(minutes=args.minutes):
                break
            attacks.append(Attack(kind, t, minutes, DEFAULT_TARGETS[kind]))
            t += timedelta(minutes=minutes + 5)

    out = Path(args.out)
    out.mkdir(exist_ok=True)
    n = 0
    with open(out / "coresim_tcpdump.log", "w", encoding="utf-8") as f:
        for line in generate(start, args.minutes, attacks, seed=args.seed):
            f.write(line + "\n")
            n += 1

    with open(out / "attack_windows.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["window_id", "attack_type", "expected", "start", "end", "target"])
        for i, a in enumerate(attacks, 1):
            w.writerow([f"W{i}", a.kind, 0 if a.kind == "maintenance" else 1,
                        a.start.isoformat(), a.end.isoformat(), a.target])

    with open(out / "host_events.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["time", "host_ip", "kind", "user", "suspicious", "detail"])
        w.writeheader()
        for h in host_events_for(attacks):
            w.writerow({**h, "time": h["time"].isoformat()})

    print(f"{n} linjer skrevet til {out / 'coresim_tcpdump.log'}")
    for a in attacks:
        print(f"  {a.kind:12} {a.start:%H:%M}-{a.end:%H:%M}  mål {a.target}")


if __name__ == "__main__":
    main()
