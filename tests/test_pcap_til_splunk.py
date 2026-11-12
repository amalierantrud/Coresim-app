"""Tester for fjerning av kopier i tools/pcap_til_splunk.py.

Kjør fra coresim-app:  python -m pytest tests
Testen mot det rensede angrepsopptaket hoppes over hvis testdata/capture_unik.csv ikke finnes (den er ikke i Git).
"""

import os
import sys

import pytest

ROT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROT, "tools"))
sys.path.insert(0, os.path.join(ROT, "ot_attack_detection", "bin"))

import deteksjon as d  # noqa: E402
import pcap_til_splunk as p  # noqa: E402

UNIK_CSV = os.path.join(ROT, "testdata", "capture_unik.csv")
BASELINE_PCAP = os.path.join(ROT, "testdata", "baseline.pcap")
BASELINE_CSV = os.path.join(ROT, "ot_attack_detection", "lookups", "baseline_trafikk.csv")


def pakke(tid, ip_id="0x0001", mac="20:87:56:72:15:53", sjekksum="0xaaaa"):
    return {"frame.time_epoch": "%.6f" % tid, "eth.src": mac, "ip.src": "192.168.10.101", "ip.dst": "224.10.10.101",
            "udp.dstport": "20111", "udp.length": "488", "frame.protocols": "eth:ethertype:ip:udp:data",
            "eth.dst": "01:00:5e:0a:0a:65", "ip.id": ip_id, "udp.checksum": sjekksum, "frame.len": "522"}


def med_kopier(tid, ip_id, antall=5, **kw):
    # Slik opptaket 29.09 ser ut: samme pakke flere ganger, ett mikrosekund imellom
    return [pakke(tid + i * 1e-6, ip_id, **kw) for i in range(antall)]


def test_fem_kopier_blir_en_pakke():
    pakker = med_kopier(0.0, "0x0001") + med_kopier(0.1, "0x0002") + med_kopier(0.2, "0x0003")
    ut = list(p.fjern_kopier(pakker))
    assert [x["ip.id"] for x in ut] == ["0x0001", "0x0002", "0x0003"]


def test_kopifaktor_finnes_selv():
    info = {}
    pakker = []
    for i in range(20):
        pakker += med_kopier(i * 0.1, "0x%04x" % i)
    list(p.fjern_kopier(pakker, info=info))
    assert info["kopifaktor"] == 5


def test_opptak_uten_kopier_endres_ikke():
    pakker = [pakke(i * 0.1, "0x%04x" % i) for i in range(20)]
    info = {}
    assert len(list(p.fjern_kopier(pakker, info=info))) == 20
    assert info["kopifaktor"] == 1


def test_replay_beholdes():
    # Angriperen sender samme pakke (lik IP-ID og sjekksum) om og om igjen. Hver sending har fem kopier i opptaket,
    # men sendingene kommer millisekunder fra hverandre og skal alle være med.
    pakker = []
    for i in range(10):
        pakker += med_kopier(1.0 + i * 0.005, "0xb162", mac="3a:c8:54:cd:b5:e2")
    assert len(list(p.fjern_kopier(pakker, kopifaktor=5))) == 10


def test_sendinger_tett_paa_hverandre_telles():
    # To sendinger rett etter hverandre blir én gruppe på 10 i opptaket, og skal bli to pakker
    pakker = med_kopier(1.0, "0xb162", antall=10, mac="3a:c8:54:cd:b5:e2")
    assert len(list(p.fjern_kopier(pakker, kopifaktor=5))) == 2


def test_pakker_uten_ip():
    arp = {"frame.time_epoch": "0", "eth.src": "00:10:f3:71:d7:6e", "ip.src": "", "ip.dst": "", "udp.dstport": "",
           "udp.length": "", "frame.protocols": "eth:ethertype:arp", "eth.dst": "ff:ff:ff:ff:ff:ff", "ip.id": "",
           "udp.checksum": "", "frame.len": "60"}
    pakker = [dict(arp, **{"frame.time_epoch": "%.6f" % (t + i * 1e-6)}) for t in (0.0, 1.0) for i in range(5)]
    assert len(list(p.fjern_kopier(pakker, kopifaktor=5))) == 2


@pytest.mark.skipif(not os.path.exists(BASELINE_PCAP), reason="testdata/baseline.pcap finnes ikke")
def test_baseline_gjennom_hele_kjeden_gir_ingen_avvik():
    # Normal trafikk fra pcap, gjennom kopifjerningen og reglene, skal ikke gi en eneste alarm.
    # Merk: baselinen er også fasiten, så dette viser at kjeden ikke lager falske alarmer selv,
    # ikke at reglene treffer godt på annen normal trafikk.
    info = {}
    pakker = list(p.fjern_kopier(p.les_pakker(BASELINE_PCAP, p.finn_tshark()), info=info))
    assert info["kopifaktor"] == 1
    assert len(pakker) == 56744
    rader = [{"tid": x["frame.time_epoch"], "src_mac": x["eth.src"], "src_ip": x["ip.src"], "dst_ip": x["ip.dst"],
              "dst_port": x["udp.dstport"], "len": str(int(x["udp.length"]) - 8)}
             for x in pakker if x["udp.dstport"] and x["udp.length"]]
    baseline = d.les_baseline(BASELINE_CSV)
    avvik = d.sammenlign(d.tell_vinduer(rader), baseline)
    assert avvik == []
    assert d.diagnoser(avvik, baseline) == []


@pytest.mark.skipif(not os.path.exists(UNIK_CSV), reason="testdata/capture_unik.csv finnes ikke")
def test_renset_opptak_gir_bare_spoofingen_som_rate_avvik():
    avvik = d.sammenlign(d.tell_vinduer(d.les_pakker_csv(UNIK_CSV)), d.les_baseline(BASELINE_CSV))
    rate = [a for a in avvik if a["type"] == d.FOR_HOY_RATE]
    assert [(a["_time"], a["dst_port"]) for a in rate] == [(1790672480, "20111"), (1790672490, "20111")]
    assert [a["_time"] for a in avvik if a["type"] == d.FEIL_MAC] == [1790672480, 1790672490]
