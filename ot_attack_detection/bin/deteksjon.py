"""Reglene som sammenligner nettverkstrafikk med baselinen.

Ren Python uten Splunk, så reglene kan testes og forklares for seg selv.
Splunk-kommandoen | finnavvik (finnavvik.py) bruker denne filen, og den kan kjøres alene fra kommandolinja.

Trafikken kommer inn som vinduer: én rad per strøm per 10 sekunder, med antall pakker (n)
og avsender-MAC-ene som ble sett. En strøm er avsender, mottaker, port og størrelse (len).
Fasiten er lookups/baseline_trafikk.csv, laget av det lagrede søket «Lag baseline».

Koden må virke på Python 3.9, som er versjonen i Splunk 9.4 på coresim.
"""

import csv
from collections import defaultdict

VINDU_SEKUNDER = 10

# For høy rate: grensen er det høyeste baselinen hadde i et vindu, ganger FAKTOR,
# men minst MARGIN pakker over. Margin hindrer alarm på små strømmer som hopper mellom 0 og 3.
FAKTOR = 1.5
MARGIN = 5

NY_STROM = "Ny strøm"
FEIL_MAC = "Feil MAC"
FOR_HOY_RATE = "For høy rate"
STROM_MANGLER = "Strøm mangler"


def strom_nokkel(rad):
    """Strømmen en rad hører til, som en tuppel av tekst (src_ip, dst_ip, dst_port, len)."""
    return (str(rad["src_ip"]), str(rad["dst_ip"]), str(rad["dst_port"]), str(rad["len"]))


def les_baseline(sti):
    """Leser baseline_trafikk.csv til en ordbok fra strøm til fasit."""
    baseline = {}
    with open(sti, newline="", encoding="utf-8") as f:
        for rad in csv.DictReader(f):
            baseline[strom_nokkel(rad)] = {
                "src_mac": rad["src_mac"],
                "snitt_10s": float(rad["snitt_10s"]),
                "min_10s": float(rad["min_10s"]),
                "maks_10s": float(rad["maks_10s"]),
            }
    return baseline


def tell_vinduer(pakker, sekunder=VINDU_SEKUNDER):
    """Gjør enkeltpakker om til vinduer, slik Splunk gjør med bin og stats.

    pakker: rader med tid (sekunder siden 1970), src_ip, dst_ip, dst_port, len og src_mac.
    Gir én rad per strøm per vindu med _time, n og src_mac (alle MAC-er, skilt med mellomrom).
    """
    antall = defaultdict(int)
    macer = defaultdict(set)
    for p in pakker:
        start = int(float(p["tid"]) // sekunder * sekunder)
        nokkel = (start,) + strom_nokkel(p)
        antall[nokkel] += 1
        if p.get("src_mac"):
            macer[nokkel].add(p["src_mac"])
    vinduer = []
    for nokkel in sorted(antall):
        start, src_ip, dst_ip, dst_port, lengde = nokkel
        vinduer.append({
            "_time": start, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "len": lengde,
            "n": antall[nokkel], "src_mac": " ".join(sorted(macer[nokkel])),
        })
    return vinduer


def rate_grense(fasit):
    """Høyeste normale antall pakker i et vindu før strømmen regnes som for høy."""
    return max(fasit["maks_10s"] * FAKTOR, fasit["maks_10s"] + MARGIN)


def sjekk_vindu(vindu, baseline):
    """Sjekker ett vindu for én strøm mot baselinen. Gir en liste med avvik (tom hvis alt er normalt)."""
    fasit = baseline.get(strom_nokkel(vindu))
    if fasit is None:
        return [_avvik(vindu, NY_STROM, vindu["n"], None, "Strømmen finnes ikke i baselinen")]

    avvik = []
    # Feil MAC: en kjent strøm sendt fra en annen maskin enn vanlig, slik spoofingen 29.09 ble gjort.
    # Hoppes over når MAC mangler, som i tcpdump-tekst uten -e.
    sette_macer = vindu.get("src_mac", "").split()
    fremmede = [m for m in sette_macer if m != fasit["src_mac"]]
    if fremmede:
        avvik.append(_avvik(vindu, FEIL_MAC, " ".join(fremmede), fasit["src_mac"],
                            "Sendt fra en annen MAC enn i baselinen"))

    grense = rate_grense(fasit)
    if vindu["n"] > grense:
        avvik.append(_avvik(vindu, FOR_HOY_RATE, vindu["n"], fasit["snitt_10s"],
                            "Over grensen på %g pakker per %d s" % (grense, VINDU_SEKUNDER)))
    return avvik


def finn_manglende(vinduer, baseline):
    """Finner strømmer som alltid er der i baselinen, men mangler i et vindu.

    Bare strømmer med min_10s over 0 tas med, siden de andre (for eksempel navneoppslag) er borte i perioder.
    Første og siste vindu hoppes over, fordi de bare er delvis med og kan mangle pakker uten at noe er galt.
    """
    tider = sorted({v["_time"] for v in vinduer})
    if len(tider) < 3:
        return []
    sett = defaultdict(set)
    for v in vinduer:
        sett[v["_time"]].add(strom_nokkel(v))

    faste = [s for s, fasit in baseline.items() if fasit["min_10s"] > 0]
    avvik = []
    for tid in tider[1:-1]:
        for strom in faste:
            if strom not in sett[tid]:
                vindu = dict(zip(("src_ip", "dst_ip", "dst_port", "len"), strom), _time=tid, n=0)
                avvik.append(_avvik(vindu, STROM_MANGLER, 0, baseline[strom]["snitt_10s"],
                                    "Ingen pakker i vinduet, men alltid til stede i baselinen"))
    return avvik


def sammenlign(vinduer, baseline):
    """Kjører alle reglene på en liste med vinduer. Gir alle avvik, sortert etter tid."""
    avvik = []
    for vindu in vinduer:
        avvik.extend(sjekk_vindu(vindu, baseline))
    avvik.extend(finn_manglende(vinduer, baseline))
    return sorted(avvik, key=lambda a: (a["_time"], a["type"], a["src_ip"], a["dst_ip"], a["dst_port"]))


def les_pakker_csv(sti):
    """Leser en pakkefil laget med tshark (samme format som testdata/capture.csv), bare UDP-pakkene."""
    pakker = []
    with open(sti, newline="") as f:
        for tid, mac, src_ip, dst_ip, dst_port, udp_len, _ in csv.reader(f):
            if dst_port and udp_len:
                pakker.append({"tid": tid, "src_mac": mac, "src_ip": src_ip, "dst_ip": dst_ip,
                               "dst_port": dst_port, "len": str(int(udp_len) - 8)})
    return pakker


def _avvik(vindu, type_, malt, normal, forklaring):
    return {
        "_time": vindu["_time"], "src_ip": vindu["src_ip"], "dst_ip": vindu["dst_ip"],
        "dst_port": vindu["dst_port"], "len": vindu["len"],
        "type": type_, "malt": malt, "normal": normal, "forklaring": forklaring,
    }


def _hovedprogram():
    """Kjør reglene på en pakkefil fra kommandolinja og skriv ut avvikene.

    python ot_attack_detection/bin/deteksjon.py testdata/capture.csv
    """
    import argparse
    import datetime
    import os
    import sys
    from collections import Counter

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")   # æøå i Windows-terminalen

    standard_baseline = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lookups", "baseline_trafikk.csv")
    p = argparse.ArgumentParser(description="Sammenlign en pakkefil med baselinen.")
    p.add_argument("pakkefil", help="CSV fra tshark, som testdata/capture.csv")
    p.add_argument("--baseline", default=standard_baseline, help="fasiten (standard: lookups/baseline_trafikk.csv)")
    p.add_argument("--alle", action="store_true", help="vis alle avvik, ikke bare et utvalg per type")
    args = p.parse_args()

    vinduer = tell_vinduer(les_pakker_csv(args.pakkefil))
    avvik = sammenlign(vinduer, les_baseline(args.baseline))

    print("%d vinduer à %d s, %d avvik" % (len(vinduer), VINDU_SEKUNDER, len(avvik)))
    for type_, antall in Counter(a["type"] for a in avvik).most_common():
        print("  %-15s %d" % (type_, antall))

    vis_per_type = None if args.alle else 5
    vist = Counter()
    for a in avvik:
        if vis_per_type is not None and vist[a["type"]] >= vis_per_type:
            continue
        vist[a["type"]] += 1
        tid = datetime.datetime.fromtimestamp(a["_time"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print("%s UTC  %-15s %s -> %s:%s (len %s)  målt %s, normalt %s" % (
            tid, a["type"], a["src_ip"], a["dst_ip"], a["dst_port"], a["len"], a["malt"], a["normal"]))
    if vis_per_type is not None:
        print("(viser maks %d per type, bruk --alle for alt)" % vis_per_type)


if __name__ == "__main__":
    _hovedprogram()
