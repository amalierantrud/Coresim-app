"""Lager ot_attack_detection/lookups/mitre_ics.csv og mitre_tiltak.csv fra MITRE ATT&CK for ICS.

Henter ics-attack.json fra MITRE sitt eget repo og skriver
- mitre_ics.csv: én rad per teknikk med navn, taktikker, en kort beskrivelse, MITRE sine tiltak (mitigations) og lenke.
- mitre_tiltak.csv: én rad per teknikk og tiltak, med MITRE sin egen tekst om hvordan tiltaket hjelper mot
  akkurat den teknikken (beskrivelsen på «mitigates»-koblingen), og lenke til tiltaket.
Avvik- og Detaljer-sidene slår opp her med mitre_id fra lookups/angrepstyper.csv.

Kjør fra coresim-app når MITRE har kommet med en ny versjon:
    python tools/lag_mitre_ics.py
Eller med en fil du har lastet ned selv:
    python tools/lag_mitre_ics.py --fil ics-attack.json
"""

import argparse
import csv
import json
import os
import re
import urllib.request

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
LOOKUPS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ot_attack_detection", "lookups")
UT = os.path.join(LOOKUPS, "mitre_ics.csv")
UT_TILTAK = os.path.join(LOOKUPS, "mitre_tiltak.csv")


def rens(tekst):
    """MITRE-tekst uten lenker og kildehenvisninger, på én linje."""
    tekst = re.sub(r"\(Citation:[^)]*\)", "", tekst or "")
    tekst = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", tekst)
    tekst = " ".join(tekst.split())
    return re.sub(r"\s+([.,;:])", r"\1", tekst)


def kort(tekst, setninger=2):
    """De første setningene i en MITRE-beskrivelse, uten lenker og kildehenvisninger."""
    biter = re.split(r"(?<=[.!?])\s+", rens(tekst))
    return " ".join(biter[:setninger])


def skriv_csv(sti, rader):
    with open(sti, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rader[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(rader)


def ekstern_id(objekt):
    for ref in objekt.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None, ""


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--fil", help="ics-attack.json lokalt i stedet for å hente den fra MITRE")
    args = p.parse_args()

    if args.fil:
        with open(args.fil, encoding="utf-8") as f:
            bunt = json.load(f)
    else:
        with urllib.request.urlopen(URL, timeout=60) as r:
            bunt = json.load(r)
    objekter = [o for o in bunt["objects"] if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    etter_id = {o["id"]: o for o in objekter}

    tiltak = {}
    koblinger = []   # (teknikk, tiltak, MITRE sin tekst for akkurat denne teknikken)
    for o in objekter:
        if o["type"] == "relationship" and o.get("relationship_type") == "mitigates":
            m = etter_id.get(o["source_ref"])
            t = etter_id.get(o["target_ref"])
            if m is not None:
                tiltak.setdefault(o["target_ref"], []).append(m["name"])
            if m is not None and t is not None:
                koblinger.append((t, m, o.get("description")))

    rader = []
    for o in objekter:
        if o["type"] != "attack-pattern":
            continue
        mitre_id, url = ekstern_id(o)
        if not mitre_id:
            continue
        taktikker = [f["phase_name"].replace("-", " ").title() for f in o.get("kill_chain_phases", [])
                     if f.get("kill_chain_name") == "mitre-ics-attack"]
        rader.append({
            "mitre_id": mitre_id,
            "mitre_navn_offisiell": o["name"],
            "taktikk": "; ".join(taktikker),
            "beskrivelse": kort(o.get("description")),
            "mitre_tiltak": "; ".join(sorted(set(tiltak.get(o["id"], [])))),
            "url": url,
        })
    rader.sort(key=lambda r: r["mitre_id"])

    tiltak_rader = []
    for t, m, tekst in koblinger:
        mitre_id, _ = ekstern_id(t)
        tiltak_id, tiltak_url = ekstern_id(m)
        if mitre_id and tiltak_id:
            tiltak_rader.append({
                "mitre_id": mitre_id,
                "tiltak_id": tiltak_id,
                "tiltak_navn": m["name"],
                # Teksten på koblingen sier hvordan tiltaket brukes mot denne teknikken. Mangler den, brukes tiltakets egen.
                "hvordan": rens(tekst) or kort(m.get("description")),
                "tiltak_url": tiltak_url,
            })
    tiltak_rader.sort(key=lambda r: (r["mitre_id"], r["tiltak_id"]))

    skriv_csv(UT, rader)
    skriv_csv(UT_TILTAK, tiltak_rader)
    versjon = next((o.get("x_mitre_version") for o in objekter if o["type"] == "x-mitre-collection"), "?")
    print("Skrev %d teknikker til %s og %d tiltak til %s (MITRE ICS-versjon %s)"
          % (len(rader), UT, len(tiltak_rader), UT_TILTAK, versjon))


if __name__ == "__main__":
    main()
