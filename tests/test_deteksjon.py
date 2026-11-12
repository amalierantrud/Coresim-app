"""Tester for reglene i ot_attack_detection/bin/deteksjon.py.

Kjør fra coresim-app:  python -m pytest tests
Testen mot angrepsopptaket hoppes over hvis testdata/capture.csv ikke finnes (den er ikke i Git).
"""

import csv
import os
import re
import sys

import pytest

ROT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROT, "ot_attack_detection", "bin"))

import deteksjon as d  # noqa: E402

BASELINE_CSV = os.path.join(ROT, "ot_attack_detection", "lookups", "baseline_trafikk.csv")
CAPTURE_CSV = os.path.join(ROT, "testdata", "capture.csv")

# En liten fasit med to strømmer: en fast som alltid sender 100 per vindu, og en ujevn som hopper mellom 0 og 3.
FAST = ("192.168.10.101", "224.10.10.101", "20111", "480")
UJEVN = ("192.168.10.80", "192.168.10.255", "137", "50")
BASELINE = {
    FAST: {"src_mac": "20:87:56:72:15:53", "snitt_10s": 100.0, "stdev_10s": 0.0, "min_10s": 100.0, "maks_10s": 100.0},
    UJEVN: {"src_mac": "00:0c:29:11:77:32", "snitt_10s": 0.5, "stdev_10s": 1.15, "min_10s": 0.0, "maks_10s": 3.0},
}


def vindu(strom, n, mac="", tid=0):
    src_ip, dst_ip, dst_port, lengde = strom
    return {"_time": tid, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port, "len": lengde,
            "n": n, "src_mac": mac}


def typer(avvik):
    return [a["type"] for a in avvik]


# --- én regel om gangen ---

def test_normal_trafikk_gir_ingen_avvik():
    assert d.sjekk_vindu(vindu(FAST, 100, "20:87:56:72:15:53"), BASELINE) == []


def test_ny_strom():
    ukjent = ("192.168.10.66", "224.10.10.66", "9999", "100")
    assert typer(d.sjekk_vindu(vindu(ukjent, 5), BASELINE)) == [d.NY_STROM]


def test_feil_mac_paa_kjent_strom():
    avvik = d.sjekk_vindu(vindu(FAST, 100, "20:87:56:72:15:53 3a:c8:54:cd:b5:e2"), BASELINE)
    assert typer(avvik) == [d.FEIL_MAC]
    assert avvik[0]["malt"] == "3a:c8:54:cd:b5:e2"


def test_manglende_mac_hoppes_over():
    # tcpdump-tekst uten MAC, som på coresim: MAC-regelen skal ikke slå ut
    assert d.sjekk_vindu(vindu(FAST, 100, ""), BASELINE) == []


def test_for_hoy_rate():
    assert d.sjekk_vindu(vindu(FAST, 108), BASELINE) == []          # z = 8 / 2 = 4, grensen må passeres
    assert typer(d.sjekk_vindu(vindu(FAST, 109), BASELINE)) == [d.FOR_HOY_RATE]


def test_z_score_bruker_stdev_naar_den_er_stor():
    fasit = {"snitt_10s": 100.0, "stdev_10s": 5.0}
    assert d.z_score(120, fasit) == 4
    assert d.z_score(80, fasit) == -4


def test_z_score_bruker_min_std_naar_stdev_er_liten():
    assert d.z_score(108, BASELINE[FAST]) == 4


def test_ujevn_strom_faar_ikke_alarm_paa_smaa_hopp():
    # Standardavviket er under MIN_STD, så grensen blir 0,5 + 4 * 2 = 8,5 pakker
    assert d.sjekk_vindu(vindu(UJEVN, 8), BASELINE) == []
    assert typer(d.sjekk_vindu(vindu(UJEVN, 9), BASELINE)) == [d.FOR_HOY_RATE]


def test_for_lav_rate():
    vinduer = [vindu(FAST, 100, tid=0), vindu(FAST, 92, tid=10), vindu(FAST, 91, tid=20), vindu(FAST, 100, tid=30)]
    avvik = d.finn_lav_rate(vinduer, BASELINE)
    assert [(a["type"], a["_time"], a["malt"]) for a in avvik] == [(d.FOR_LAV_RATE, 20, 91)]


def test_lav_rate_hoppes_over_i_kantene():
    # Første og siste vindu er bare delvis med, så der er det normalt med få pakker
    vinduer = [vindu(FAST, 40, tid=0), vindu(FAST, 100, tid=10), vindu(FAST, 40, tid=20)]
    assert d.finn_lav_rate(vinduer, BASELINE) == []


def test_ujevn_strom_kan_sende_lite_uten_avvik():
    vinduer = [vindu(UJEVN, 0, tid=t) for t in (0, 10, 20)]
    assert d.finn_lav_rate(vinduer, BASELINE) == []


def test_strom_mangler():
    # Vinduet 10 har trafikk, men ikke den faste strømmen
    vinduer = [vindu(FAST, 100, tid=0), vindu(UJEVN, 1, tid=10), vindu(FAST, 100, tid=20)]
    avvik = d.finn_manglende(vinduer, BASELINE)
    assert [(a["type"], a["_time"], a["dst_port"]) for a in avvik] == [(d.STROM_MANGLER, 10, "20111")]


def test_vindu_uten_noen_trafikk_kan_ikke_sjekkes():
    # Kjent svakhet: stopper ALL trafikk, finnes vinduet 20 ikke i det hele tatt, og regelen ser ingenting
    vinduer = [vindu(FAST, 100, tid=t) for t in (0, 10, 30, 40)]
    assert d.finn_manglende(vinduer, BASELINE) == []


def test_kanter_hoppes_over():
    # Første og siste vindu er bare delvis med, så der skal det ikke gi avvik selv om strømmen mangler
    vinduer = [vindu(UJEVN, 1, tid=0), vindu(FAST, 100, tid=10), vindu(UJEVN, 1, tid=20)]
    assert d.finn_manglende(vinduer, BASELINE) == []


def test_ujevn_strom_kan_mangle_uten_avvik():
    vinduer = [vindu(FAST, 100, tid=t) for t in (0, 10, 20)]
    assert d.finn_manglende(vinduer, BASELINE) == []


def test_tell_vinduer():
    pakker = [
        {"tid": "5.1", "src_ip": "a", "dst_ip": "b", "dst_port": "1", "len": "4", "src_mac": "m1"},
        {"tid": "9.9", "src_ip": "a", "dst_ip": "b", "dst_port": "1", "len": "4", "src_mac": "m2"},
        {"tid": "10.0", "src_ip": "a", "dst_ip": "b", "dst_port": "1", "len": "4", "src_mac": "m1"},
    ]
    assert [(v["_time"], v["n"], v["src_mac"]) for v in d.tell_vinduer(pakker)] == [(0, 2, "m1 m2"), (10, 1, "m1")]


def test_les_baseline():
    baseline = d.les_baseline(BASELINE_CSV)
    assert baseline[FAST]["src_mac"] == "20:87:56:72:15:53"
    assert baseline[FAST]["maks_10s"] == 100.0
    assert baseline[FAST]["stdev_10s"] == 0.0


# --- diagnose: fra avvik til mulige angrep ---

# Litt større fasit: .101 har to faste strømmer, .102 én fast, og .80 en ujevn.
FAST2 = ("192.168.10.101", "224.10.10.101", "20121", "996")
ANNEN = ("192.168.10.102", "224.10.10.102", "20211", "240")
BASELINE_D = dict(BASELINE)
BASELINE_D[FAST2] = {"src_mac": "20:87:56:72:15:53", "snitt_10s": 20.0, "stdev_10s": 0.0, "min_10s": 20.0, "maks_10s": 20.0}
BASELINE_D[ANNEN] = {"src_mac": "20:87:56:72:15:20", "snitt_10s": 100.0, "stdev_10s": 0.0, "min_10s": 100.0, "maks_10s": 100.0}


def avvik_for(vinduer):
    return d.sammenlign(vinduer, BASELINE_D)


def angrep(diagnoser):
    return sorted(x["angrep"] for x in diagnoser)


def test_feil_mac_og_hoy_rate_blir_spoofing():
    avvik = d.sjekk_vindu(vindu(FAST, 1000, "20:87:56:72:15:53 3a:c8:54:cd:b5:e2"), BASELINE_D)
    diagnoser = d.diagnoser(avvik, BASELINE_D)
    assert angrep(diagnoser) == [d.SPOOFING]          # ikke i tillegg økt sending på samme strøm
    assert diagnoser[0]["avvik"] == 2
    assert "3a:c8:54:cd:b5:e2" in diagnoser[0]["bevis"]


def test_hoy_rate_paa_en_strom_blir_okt_sending():
    avvik = d.sjekk_vindu(vindu(FAST, 1000), BASELINE_D)
    assert angrep(d.diagnoser(avvik, BASELINE_D)) == [d.OKT_SENDING]


def test_mange_strommer_over_grensen_blir_flooding():
    avvik = d.sjekk_vindu(vindu(FAST, 1000), BASELINE_D) + d.sjekk_vindu(vindu(ANNEN, 1000), BASELINE_D)
    assert angrep(d.diagnoser(avvik, BASELINE_D)) == [d.FLOODING]   # 2 av 3 faste strømmer


def test_lav_rate_blir_redusert_sending():
    vinduer = [vindu(s, n, tid=t) for t in (0, 20) for s, n in ((FAST, 100), (FAST2, 20), (ANNEN, 100))]
    vinduer += [vindu(FAST, 50, tid=10), vindu(FAST2, 20, tid=10), vindu(ANNEN, 100, tid=10)]
    diagnoser = d.diagnoser(avvik_for(vinduer), BASELINE_D)
    assert [(x["angrep"], x["strom"], x["_time"]) for x in diagnoser] == [(d.REDUSERT_SENDING, d._strom_tekst(FAST), 10)]


def test_alle_strommer_fra_en_avsender_mangler_blir_enhet_stille():
    vinduer = [vindu(s, n, tid=t) for t in (0, 20) for s, n in ((FAST, 100), (FAST2, 20), (ANNEN, 100))]
    vinduer += [vindu(ANNEN, 100, tid=10)]                            # .101 er borte i vinduet 10
    diagnoser = d.diagnoser(avvik_for(vinduer), BASELINE_D)
    assert [(x["angrep"], x["src_ip"], x["_time"]) for x in diagnoser] == [(d.ENHET_STILLE, "192.168.10.101", 10)]


def test_en_av_flere_strommer_mangler_blir_strom_borte():
    vinduer = [vindu(s, n, tid=t) for t in (0, 20) for s, n in ((FAST, 100), (FAST2, 20), (ANNEN, 100))]
    vinduer += [vindu(FAST, 100, tid=10), vindu(ANNEN, 100, tid=10)]  # bare FAST2 er borte
    diagnoser = d.diagnoser(avvik_for(vinduer), BASELINE_D)
    assert [(x["angrep"], x["strom"]) for x in diagnoser] == [(d.STROM_BORTE, d._strom_tekst(FAST2))]


def test_ny_strom_fra_ukjent_avsender_blir_ukjent_enhet():
    avvik = d.sjekk_vindu(vindu(("192.168.10.66", "224.10.10.101", "20111", "480"), 10), BASELINE_D)
    assert angrep(d.diagnoser(avvik, BASELINE_D)) == [d.UKJENT_ENHET]


def test_mange_nye_porter_fra_kjent_avsender_blir_skanning():
    avvik = []
    for port in range(1, 6):
        avvik += d.sjekk_vindu(vindu(("192.168.10.102", "192.168.10.120", str(port), "0"), 1), BASELINE_D)
    assert angrep(d.diagnoser(avvik, BASELINE_D)) == [d.SKANNING]


def test_en_ny_strom_fra_kjent_avsender_blir_ny_forbindelse():
    avvik = d.sjekk_vindu(vindu(("192.168.10.102", "192.168.10.120", "5900", "0"), 1), BASELINE_D)
    assert angrep(d.diagnoser(avvik, BASELINE_D)) == [d.NY_FORBINDELSE]


def test_angrepstyper_csv_har_alle_angrep():
    with open(os.path.join(ROT, "ot_attack_detection", "lookups", "angrepstyper.csv"), newline="", encoding="utf-8") as f:
        i_csv = {r["angrep"] for r in csv.DictReader(f)}
    i_koden = {d.SPOOFING, d.FLOODING, d.OKT_SENDING, d.REDUSERT_SENDING, d.ENHET_STILLE, d.STROM_BORTE,
               d.UKJENT_ENHET, d.SKANNING, d.NY_FORBINDELSE}
    assert i_csv == i_koden


def test_mitre_numrene_finnes_hos_mitre():
    # Fanger opp når MITRE erstatter en teknikk (slik T0856 ble T1692.002). Lag mitre_ics.csv på nytt med
    # python tools/lag_mitre_ics.py og rett numrene i angrepstyper.csv hvis denne feiler.
    lookups = os.path.join(ROT, "ot_attack_detection", "lookups")
    with open(os.path.join(lookups, "mitre_ics.csv"), newline="", encoding="utf-8") as f:
        hos_mitre = {r["mitre_id"] for r in csv.DictReader(f)}
    with open(os.path.join(lookups, "angrepstyper.csv"), newline="", encoding="utf-8") as f:
        vaare = {r["angrep"]: r["mitre_id"] for r in csv.DictReader(f)}
    assert {a: m for a, m in vaare.items() if m not in hos_mitre} == {}


def test_tiltakene_er_mitre_sine_tiltak_for_teknikken():
    # Hvert M-nummer i tiltak-kolonnen i angrepstyper.csv må være et tiltak MITRE oppgir mot akkurat den teknikken,
    # og hvert angrep må ha minst ett. Feiler den etter en ny MITRE-versjon, rett tiltakene ut fra mitre_tiltak.csv.
    lookups = os.path.join(ROT, "ot_attack_detection", "lookups")
    with open(os.path.join(lookups, "mitre_tiltak.csv"), newline="", encoding="utf-8") as f:
        hos_mitre = {(r["mitre_id"], r["tiltak_id"]) for r in csv.DictReader(f)}
    with open(os.path.join(lookups, "angrepstyper.csv"), newline="", encoding="utf-8") as f:
        rader = list(csv.DictReader(f))
    feil = {}
    for r in rader:
        numre = re.findall(r"M\d{4}", r["tiltak"])
        ukjente = [m for m in numre if (r["mitre_id"], m) not in hos_mitre]
        if not numre or ukjente:
            feil[r["angrep"]] = ukjente or "ingen M-nummer"
    assert feil == {}


# --- kjente angrep lagt inn i normal trafikk, med den ekte baselinen ---

EKTE = d.les_baseline(BASELINE_CSV)
OFFER = ("192.168.10.101", "224.10.10.101", "20111", "480")
ANGREPSVINDU = 50
ANDRE_MAC = "3a:c8:54:cd:b5:e2"


def normal_trafikk():
    """Seks vinduer der alle faste strømmer sender akkurat som i baselinen."""
    return [vindu(s, round(f["snitt_10s"]), f["src_mac"], tid=t)
            for t in range(0, 60, 10) for s, f in EKTE.items() if f["min_10s"] > 0]


def med_angrep(endre):
    """Normal trafikk der endre() får endre vinduet til offeret i angrepsvinduet."""
    vinduer = normal_trafikk()
    for v in vinduer:
        if v["_time"] == ANGREPSVINDU - 10 and d.strom_nokkel(v) == OFFER:
            endre(v)
    return d.diagnoser(d.sammenlign(vinduer, EKTE), EKTE)


def test_normal_trafikk_gir_ingen_falske_alarmer():
    assert d.sammenlign(normal_trafikk(), EKTE) == []


@pytest.mark.parametrize("ekstra, oppdaget", [(1, False), (8, False), (9, True), (50, True), (500, True)])
def test_hvor_lite_innsatte_pakker_oppdages(ekstra, oppdaget):
    # Med riktig MAC er det bare raten som avslører dem. Opp til 8 ekstra pakker per vindu slipper gjennom.
    def legg_til(v):
        v["n"] += ekstra
    assert angrep(med_angrep(legg_til)) == ([d.OKT_SENDING] if oppdaget else [])


@pytest.mark.parametrize("fjernet, oppdaget", [(1, False), (8, False), (9, True), (50, True)])
def test_hvor_lite_blokkerte_pakker_oppdages(fjernet, oppdaget):
    def ta_bort(v):
        v["n"] -= fjernet
    assert angrep(med_angrep(ta_bort)) == ([d.REDUSERT_SENDING] if oppdaget else [])


@pytest.mark.parametrize("ekstra", [1, 8, 500])
def test_feil_mac_oppdages_uansett_mengde(ekstra):
    def spoof(v):
        v["n"] += ekstra
        v["src_mac"] += " " + ANDRE_MAC
    assert angrep(med_angrep(spoof)) == [d.SPOOFING]


def test_kopiert_mac_og_lav_rate_slipper_gjennom():
    # Kjent svakhet: en angriper som også kopierer MAC-en og holder seg under grensen, gir ingen alarm
    def skjult(v):
        v["n"] += 8
    assert med_angrep(skjult) == []


def test_hele_enheten_stille():
    vinduer = [v for v in normal_trafikk() if not (v["_time"] == 20 and v["src_ip"] == OFFER[0])]
    diagnoser = d.diagnoser(d.sammenlign(vinduer, EKTE), EKTE)
    assert [(x["angrep"], x["src_ip"], x["_time"]) for x in diagnoser] == [(d.ENHET_STILLE, OFFER[0], 20)]


def test_flooding_paa_alle_faste_strommer():
    vinduer = normal_trafikk()
    for v in vinduer:
        if v["_time"] == 20:
            v["n"] += 500
    assert angrep(d.diagnoser(d.sammenlign(vinduer, EKTE), EKTE)) == [d.FLOODING]


# --- hele angrepsopptaket ---

SPOOF_START = 1790672480   # 2026-09-29 09:01:20 UTC
SPOOF_SLUTT = 1790672500   # 2026-09-29 09:01:40 UTC


@pytest.mark.skipif(not os.path.exists(CAPTURE_CSV), reason="testdata/capture.csv finnes ikke")
def test_spoofingen_i_capture_finnes_med_mac():
    pakker = []
    with open(CAPTURE_CSV, newline="") as f:
        for tid, mac, src_ip, dst_ip, dst_port, udp_len, _ in csv.reader(f):
            if dst_port and udp_len:
                pakker.append({"tid": tid, "src_mac": mac, "src_ip": src_ip, "dst_ip": dst_ip,
                               "dst_port": dst_port, "len": str(int(udp_len) - 8)})
    avvik = d.sammenlign(d.tell_vinduer(pakker), d.les_baseline(BASELINE_CSV))

    feil_mac = [a for a in avvik if a["type"] == d.FEIL_MAC]
    assert feil_mac, "spoofingen ble ikke funnet"
    for a in feil_mac:
        assert (a["src_ip"], a["dst_ip"], a["dst_port"]) == ("192.168.10.101", "224.10.10.101", "20111")
        assert a["malt"] == "3a:c8:54:cd:b5:e2"
        assert SPOOF_START <= a["_time"] < SPOOF_SLUTT

    assert not [a for a in avvik if a["type"] in (d.STROM_MANGLER, d.FOR_LAV_RATE)]

    # Ingen falske alarmer på rate: de eneste vinduene over grensen er de to med spoofing
    hoy_rate = [a for a in avvik if a["type"] == d.FOR_HOY_RATE]
    assert [(a["_time"], a["dst_port"]) for a in hoy_rate] == [(SPOOF_START, "20111"), (SPOOF_START + 10, "20111")]

    spoofing = [x for x in d.diagnoser(avvik, d.les_baseline(BASELINE_CSV)) if x["angrep"] == d.SPOOFING]
    assert [(x["_time"], x["src_ip"]) for x in spoofing] == [(SPOOF_START, "192.168.10.101"),
                                                            (SPOOF_START + 10, "192.168.10.101")]
