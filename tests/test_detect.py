from datetime import timedelta

from conftest import to_stats
from otdiag import Baseline, detect
from otdiag.sim import Attack, generate


def rules(anomalies):
    return {a.rule for a in anomalies}


def test_normal_traffic_gives_no_alarms(baseline, t_attack):
    stats = to_stats(generate(t_attack, 10, seed=7))
    assert detect(stats, baseline, k=4) == []


def test_flood_is_detected_with_high_z(baseline, t_attack):
    atk = [Attack("flood", t_attack + timedelta(minutes=1), 2, "224.10.10.101")]
    found = detect(to_stats(generate(t_attack, 4, atk, seed=7)), baseline, k=4)
    high = [a for a in found if a.rule == "volum_hoy"]
    assert high and max(a.z for a in high) > 10


def test_silent_node_is_detected(baseline, t_attack):
    atk = [Attack("silent", t_attack, 3, "192.168.10.104")]
    found = detect(to_stats(generate(t_attack, 3, atk, seed=7)), baseline, k=4)
    assert "taus" in rules(found)


def test_scan_is_detected(baseline, t_attack):
    atk = [Attack("scan", t_attack, 2)]
    assert "skanning" in rules(detect(to_stats(generate(t_attack, 2, atk, seed=7)), baseline, k=4))


def test_baseline_survives_round_trip_as_rows(baseline):
    again = Baseline.from_rows(baseline.to_rows())
    assert again.flows.keys() == baseline.flows.keys()
    assert again.dst_totals.keys() == baseline.dst_totals.keys()
