"""| otdiagnose  - fra avvik (+ host events) til hendelser med diagnose

Rader med feltet `rule` er avvik (fra otdetect / ot_alerts).
Rader med feltet `kind` er host events (fra makroen ot_host_events).
    `ot_alerts` earliest=-15m | append [`ot_host_events`] | otdiagnose
"""
import sys

import _otcommon as c
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch, validators

from otdiag import Anomaly, HostEvent, diagnose


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


@Configuration(required_fields=["_time", "rule", "src_ip", "dest_ip", "proto", "value", "expected", "z", "detail", "kind", "host_ip", "user", "suspicious"])
class OtDiagnose(EventingCommand, c.Buffered):
    gap = Option(require=False, default=180, validate=validators.Integer(0))

    def transform(self, records):
        if not self.collect(records):
            return
        anomalies, hosts = [], []
        for r in self._buf:
            if r.get("rule"):
                anomalies.append(Anomaly(
                    time=c.to_dt(r["_time"]), rule=r["rule"], src_ip=r.get("src_ip", ""),
                    dst_ip=r.get("dest_ip", ""), proto=r.get("proto", ""), value=_num(r.get("value")) or 0,
                    expected=_num(r.get("expected")) or 0, z=_num(r.get("z")), detail=r.get("detail", "")))
            elif r.get("kind"):
                hosts.append(HostEvent(
                    time=c.to_dt(r["_time"]), host_ip=r.get("host_ip", ""), kind=r["kind"],
                    detail=r.get("detail", ""), user=r.get("user") or None,
                    suspicious=str(r.get("suspicious", "")).lower() in ("1", "true", "ja")))
        for inc in diagnose(anomalies, hosts, gap_s=self.gap):
            row = inc.as_row()
            row["_time"] = c.to_epoch(inc.start)
            # ingen _raw: da bruker collect feltet _time som tidsstempel
            yield row


dispatch(OtDiagnose, sys.argv, sys.stdin, sys.stdout, __name__)
