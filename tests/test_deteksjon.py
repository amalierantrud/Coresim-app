"""Tester for reglene i ot_attack_detection/bin/deteksjon.py.

Kjør fra coresim-app:  python -m pytest tests
Testen mot angrepsopptaket hoppes over hvis testdata/capture.csv ikke finnes (den er ikke i Git).
"""

import csv
import os
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
    FAST: {"src_mac": "20:87:56:72:15:53", "snitt_10s": 100.0, "min_10s": 100.0, "maks_10s": 100.0},
    UJEVN: {"src_mac": "00:0c:29:11:77:32", "snitt_10s": 0.5, "min_10s": 0.0, "maks_10s": 3.0},
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
    assert d.sjekk_vindu(vindu(FAST, 150), BASELINE) == []          # grensen er 100 * 1,5 = 150
    assert typer(d.sjekk_vindu(vindu(FAST, 151), BASELINE)) == [d.FOR_HOY_RATE]


def test_ujevn_strom_faar_margin():
    # 3 * 1,5 = 4,5 ville gitt alarm på 5 pakker, men marginen løfter grensen til 3 + 5 = 8
    assert d.sjekk_vindu(vindu(UJEVN, 8), BASELINE) == []
    assert typer(d.sjekk_vindu(vindu(UJEVN, 9), BASELINE)) == [d.FOR_HOY_RATE]


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


# --- diagnose: fra avvik til mulige angrep ---

# Litt større fasit: .101 har to faste strømmer, .102 én fast, og .80 en ujevn.
FAST2 = ("192.168.10.101", "224.10.10.101", "20121", "996")
ANNEN = ("192.168.10.102", "224.10.10.102", "20211", "240")
BASELINE_D = dict(BASELINE)
BASELINE_D[FAST2] = {"src_mac": "20:87:56:72:15:53", "snitt_10s": 20.0, "min_10s": 20.0, "maks_10s": 20.0}
BASELINE_D[ANNEN] = {"src_mac": "20:87:56:72:15:20", "snitt_10s": 100.0, "min_10s": 100.0, "maks_10s": 100.0}


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
    i_koden = {d.SPOOFING, d.FLOODING, d.OKT_SENDING, d.ENHET_STILLE, d.STROM_BORTE,
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

    assert not [a for a in avvik if a["type"] == d.STROM_MANGLER]

    spoofing = [x for x in d.diagnoser(avvik, d.les_baseline(BASELINE_CSV)) if x["angrep"] == d.SPOOFING]
    assert [(x["_time"], x["src_ip"]) for x in spoofing] == [(SPOOF_START, "192.168.10.101"),
                                                            (SPOOF_START + 10, "192.168.10.101")]
