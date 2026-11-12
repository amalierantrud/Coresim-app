"""Reglene som sammenligner nettverkstrafikk med baselinen, og diagnosen som tolker avvikene.

Ren Python uten Splunk, så reglene kan testes og forklares for seg selv.
Splunk-kommandoene | finnavvik (finnavvik.py) og | diagnoser (diagnoser.py) bruker denne filen,
og den kan kjøres alene fra kommandolinja.

To trinn:
1. sammenlign(): finner avvik per strøm per vindu (ny strøm, feil MAC, for høy eller lav rate, strøm mangler).
2. diagnoser(): ser på alle avvikene i samme vindu og gir mulige angrep (spoofing, flooding osv.).
   Navn, alvorlighet og MITRE-teknikk for hvert angrep står i lookups/angrepstyper.csv.

Trafikken kommer inn som vinduer: én rad per strøm per 10 sekunder, med antall pakker (n)
og avsender-MAC-ene som ble sett. En strøm er avsender, mottaker, port og størrelse (len).
Fasiten er lookups/baseline_trafikk.csv, laget av det lagrede søket «Lag baseline».

Koden må virke på Python 3.9, som er versjonen i Splunk 9.4 på coresim.
"""

import csv
from collections import defaultdict

VINDU_SEKUNDER = 10

# Rate: en strøm er et avvik når den er minst Z_GRENSE standardavvik fra snittet i baselinen (z-score).
# Mange strømmer har standardavvik 0, så MIN_STD er det minste vi regner med. Ellers ville én pakke gitt alarm.
# Med 4 og 2 må strømmen være mer enn 8 pakker fra snittet i et vindu.
Z_GRENSE = 4
MIN_STD = 2

NY_STROM = "Ny strøm"
FEIL_MAC = "Feil MAC"
FOR_HOY_RATE = "For høy rate"
FOR_LAV_RATE = "For lav rate"
STROM_MANGLER = "Strøm mangler"

# Mulige angrep. Kodene slås opp i lookups/angrepstyper.csv for navn, alvorlighet og MITRE.
SPOOFING = "spoofing"              # kjent strøm sendt fra feil MAC
FLOODING = "flooding"              # mange faste strømmer over rate-grensen samtidig
OKT_SENDING = "okt_sending"        # én strøm over grensen, men fra riktig MAC
REDUSERT_SENDING = "redusert_sending"  # fast strøm under grensen, men ikke helt borte
ENHET_STILLE = "enhet_stille"      # alle faste strømmer fra én avsender mangler
STROM_BORTE = "strom_borte"        # noen, men ikke alle, faste strømmer fra en avsender mangler
UKJENT_ENHET = "ukjent_enhet"      # ny strøm fra en avsender som ikke finnes i baselinen
SKANNING = "skanning"              # én avsender med mange nye mottakere eller porter
NY_FORBINDELSE = "ny_forbindelse"  # kjent avsender med en ny strøm

# Flooding: minst denne andelen av de faste strømmene er over grensen i samme vindu.
FLOOD_ANDEL = 0.5
# Skanning: minst så mange nye mottaker/port-par fra én avsender i samme vindu.
SKANN_GRENSE = 5


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
                "stdev_10s": float(rad["stdev_10s"]),
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


def z_score(n, fasit):
    """Hvor mange standardavvik n pakker er fra snittet i baselinen. Positiv over snittet, negativ under."""
    return (n - fasit["snitt_10s"]) / max(fasit["stdev_10s"], MIN_STD)


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

    z = z_score(vindu["n"], fasit)
    if z > Z_GRENSE:
        avvik.append(_avvik(vindu, FOR_HOY_RATE, vindu["n"], fasit["snitt_10s"],
                            "z = %.1f, grensen er %d" % (z, Z_GRENSE)))
    return avvik


def finn_lav_rate(vinduer, baseline):
    """Finner faste strømmer som sender for lite, men ikke er helt borte (det tar finn_manglende).

    Bare strømmer med min_10s over 0 tas med, siden de andre er borte i perioder.
    Første og siste vindu hoppes over, fordi de bare er delvis med og ellers ville sett ut som et fall.
    """
    tider = sorted({v["_time"] for v in vinduer})
    avvik = []
    for vindu in vinduer:
        if vindu["_time"] in tider[1:-1]:
            fasit = baseline.get(strom_nokkel(vindu))
            if fasit and fasit["min_10s"] > 0:
                z = z_score(vindu["n"], fasit)
                if z < -Z_GRENSE:
                    avvik.append(_avvik(vindu, FOR_LAV_RATE, vindu["n"], fasit["snitt_10s"],
                                        "z = %.1f, grensen er -%d" % (z, Z_GRENSE)))
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
    avvik.extend(finn_lav_rate(vinduer, baseline))
    avvik.extend(finn_manglende(vinduer, baseline))
    return sorted(avvik, key=lambda a: (a["_time"], a["type"], a["src_ip"], a["dst_ip"], a["dst_port"]))


def diagnoser(avvik, baseline):
    """Tolker avvikene fra sammenlign() som mulige angrep, ett vindu om gangen.

    Gir én rad per mulig angrep med _time, angrep (kode), src_ip, strom, bevis og avvik (antall avvik bak).
    Et avvik kan bare føre til ett angrep: feil MAC trumfer høy rate på samme strøm,
    og flooding trumfer økt sending på enkeltstrømmer i samme vindu.
    """
    faste = {s for s, fasit in baseline.items() if fasit["min_10s"] > 0}
    faste_per_avsender = defaultdict(set)
    for s in faste:
        faste_per_avsender[s[0]].add(s)
    kjente_avsendere = {s[0] for s in baseline}

    per_vindu = defaultdict(list)
    for a in avvik:
        per_vindu[a["_time"]].append(a)

    resultat = []
    for tid in sorted(per_vindu):
        liste = per_vindu[tid]
        av_type = defaultdict(list)
        for a in liste:
            av_type[a["type"]].append(a)
        hoy_rate = {strom_nokkel(a): a for a in av_type[FOR_HOY_RATE]}

        # Spoofing: en kjent strøm fra feil MAC. Har den samtidig for høy rate, er pakker satt inn i tillegg.
        spoofet = set()
        for a in av_type[FEIL_MAC]:
            strom = strom_nokkel(a)
            spoofet.add(strom)
            bevis = "Sendt fra %s, normalt %s" % (a["malt"], a["normal"])
            if strom in hoy_rate:
                bevis += "; %s pakker per %d s, normalt %s" % (hoy_rate[strom]["malt"], VINDU_SEKUNDER,
                                                             hoy_rate[strom]["normal"])
            resultat.append(_diagnose(tid, SPOOFING, a["src_ip"], _strom_tekst(strom), bevis,
                                      2 if strom in hoy_rate else 1))

        # Flooding hvis mange faste strømmer er over grensen samtidig, ellers økt sending per strøm.
        over = [s for s in hoy_rate if s not in spoofet]
        faste_over = [s for s in over if s in faste]
        if faste and len(faste_over) >= FLOOD_ANDEL * len(faste):
            avsendere = sorted({s[0] for s in faste_over})
            resultat.append(_diagnose(tid, FLOODING, " ".join(avsendere), "",
                                      "%d av %d faste strømmer over rate-grensen" % (len(faste_over), len(faste)),
                                      len(over)))
        else:
            for s in over:
                a = hoy_rate[s]
                resultat.append(_diagnose(tid, OKT_SENDING, a["src_ip"], _strom_tekst(s),
                                          "%s pakker per %d s, normalt %s" % (a["malt"], VINDU_SEKUNDER, a["normal"]),
                                          1))

        for a in av_type[FOR_LAV_RATE]:
            resultat.append(_diagnose(tid, REDUSERT_SENDING, a["src_ip"], _strom_tekst(strom_nokkel(a)),
                                      "%s pakker per %d s, normalt %s" % (a["malt"], VINDU_SEKUNDER, a["normal"]), 1))

        # Manglende strømmer, samlet per avsender: alle borte betyr at enheten er stille.
        mangler = defaultdict(list)
        for a in av_type[STROM_MANGLER]:
            mangler[a["src_ip"]].append(strom_nokkel(a))
        for src, strommer in sorted(mangler.items()):
            if set(strommer) >= faste_per_avsender[src]:
                resultat.append(_diagnose(tid, ENHET_STILLE, src, "",
                                          "Alle %d faste strømmer mangler" % len(strommer), len(strommer)))
            else:
                for s in strommer:
                    resultat.append(_diagnose(tid, STROM_BORTE, src, _strom_tekst(s),
                                              "Ingen pakker, men alltid til stede i baselinen", 1))

        # Nye strømmer, samlet per avsender: ukjent avsender, skanning eller ny forbindelse.
        nye = defaultdict(list)
        for a in av_type[NY_STROM]:
            nye[a["src_ip"]].append(strom_nokkel(a))
        for src, strommer in sorted(nye.items()):
            maal = {(s[1], s[2]) for s in strommer}
            if src not in kjente_avsendere:
                resultat.append(_diagnose(tid, UKJENT_ENHET, src, _strom_tekst(strommer[0]),
                                          "Avsenderen finnes ikke i baselinen, %d nye strømmer" % len(strommer),
                                          len(strommer)))
            elif len(maal) >= SKANN_GRENSE:
                resultat.append(_diagnose(tid, SKANNING, src, "",
                                          "%d nye mottaker/port-par i samme vindu" % len(maal), len(strommer)))
            else:
                for s in strommer:
                    resultat.append(_diagnose(tid, NY_FORBINDELSE, src, _strom_tekst(s),
                                              "Kjent avsender, ny strøm", 1))
    return resultat


def _strom_tekst(strom):
    src_ip, dst_ip, dst_port, lengde = strom
    return "%s → %s:%s (%s byte)" % (src_ip, dst_ip, dst_port, lengde)


def _diagnose(tid, angrep, src_ip, strom, bevis, antall):
    return {"_time": tid, "angrep": angrep, "src_ip": src_ip, "strom": strom, "bevis": bevis, "avvik": antall}


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
    baseline = les_baseline(args.baseline)
    avvik = sammenlign(vinduer, baseline)

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

    diagnoser_ = diagnoser(avvik, baseline)
    print("\nMulige angrep: %d" % len(diagnoser_))
    for angrep_, antall in Counter(x["angrep"] for x in diagnoser_).most_common():
        print("  %-15s %d vinduer" % (angrep_, antall))
    vist = Counter()
    for x in diagnoser_:
        if vis_per_type is not None and vist[x["angrep"]] >= vis_per_type:
            continue
        vist[x["angrep"]] += 1
        tid = datetime.datetime.fromtimestamp(x["_time"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        print("%s UTC  %-15s %s  %s  %s" % (tid, x["angrep"], x["src_ip"], x["strom"], x["bevis"]))


if __name__ == "__main__":
    _hovedprogram()
