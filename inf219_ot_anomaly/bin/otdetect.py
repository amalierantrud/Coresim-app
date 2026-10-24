"""| otdetect k=4  - statistisk deteksjon på rader fra ot_summary

Leser baseline fra lookups/ot_baseline.csv og returnerer ett avvik per rad.
    `ot_summary` earliest=-2m@m latest=-1m@m | otdetect k=4 | collect index=ot_alerts
"""
import csv
import os
import sys

import _otcommon as c
from splunklib.searchcommands import Configuration, EventingCommand, Option, dispatch, validators

from otdiag import Baseline, detect, minute_stats_from_row


@Configuration(required_fields=["_time", "src_ip", "dest_ip", "proto", "packets", "bytes", "dest_ports", "syn"])
class OtDetect(EventingCommand, c.Buffered):
    k = Option(require=False, default=4.0, validate=validators.Float(0))
    scan_ports = Option(require=False, default=20, validate=validators.Integer(1))

    def transform(self, records):
        if not self.collect(records):
            return
        with open(os.path.join(c.LOOKUPS, "ot_baseline.csv"), encoding="utf-8") as f:
            baseline = Baseline.from_rows(csv.DictReader(f))
        stats = [minute_stats_from_row(r) for r in self._buf]
        for a in detect(stats, baseline, k=self.k, scan_ports=self.scan_ports):
            row = a.as_row()
            row["_time"] = c.to_epoch(a.time)
            row["_raw"] = f"{a.rule}: {a.detail}"
            yield row


dispatch(OtDetect, sys.argv, sys.stdin, sys.stdout, __name__)
