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
