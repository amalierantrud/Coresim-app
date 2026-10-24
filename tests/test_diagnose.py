from datetime import timedelta

import pytest

from conftest import to_stats
from otdiag import HostEvent, detect, diagnose
from otdiag.sim import DEFAULT_TARGETS, Attack, generate, host_events_for


def run(baseline, start, kind, minutes=3):
    atk = [Attack(kind, start + timedelta(minutes=1), minutes, DEFAULT_TARGETS[kind])]
    stats = to_stats(generate(start, minutes + 2, atk, seed=11))
    hosts = [HostEvent(**h) for h in host_events_for(atk)]
    return diagnose(detect(stats, baseline, k=4), hosts)


@pytest.mark.parametrize("kind, expected_type, expected_severity", [
    ("scan", "Rekognosering", "høy"),
    ("flood", "Flooding", "kritisk"),
    ("inject", "injeksjon", "kritisk"),
    ("silent", "Node nede", "høy"),
    ("ddos", "DDoS", "kritisk"),
    ("maintenance", "vedlikehold", "info"),
])
def test_each_scenario_gets_one_correct_diagnosis(baseline, t_attack, kind, expected_type, expected_severity):
    incidents = run(baseline, t_attack, kind)
    assert len(incidents) == 1, [i.type for i in incidents]
    assert expected_type in incidents[0].type
    assert incidents[0].severity == expected_severity


def test_host_evidence_marks_flood_source_as_compromised(baseline, t_attack):
    (incident,) = run(baseline, t_attack, "flood")
    assert "kompromittert" in incident.explanation
    assert incident.host_evidence
