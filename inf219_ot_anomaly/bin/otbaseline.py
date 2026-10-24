"""| otbaseline  - lærer normalnivå fra ot_summary og skriver lookups/ot_baseline.csv

Bruk på en periode med normal drift:
    `ot_summary` earliest=<start> latest=<slutt> | otbaseline
"""
import csv
import os
import sys

import _otcommon as c
from splunklib.searchcommands import Configuration, Option, ReportingCommand, dispatch, validators

from otdiag import build_baseline, minute_stats_from_row


@Configuration(requires_preop=False)
class OtBaseline(ReportingCommand, c.Buffered):
    min_minutes = Option(require=False, default=10, validate=validators.Integer(1))

    def reduce(self, records):
        if not self.collect(records):
            return
        stats = [minute_stats_from_row(r) for r in self._buf]
        baseline = build_baseline(stats, min_minutes=self.min_minutes)
        rows = baseline.to_rows()
        path = os.path.join(c.LOOKUPS, "ot_baseline.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["src_ip"])
            w.writeheader()
            w.writerows(rows)
        for r in rows:
            yield r


dispatch(OtBaseline, sys.argv, sys.stdin, sys.stdout, __name__)
