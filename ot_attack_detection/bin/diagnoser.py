"""Splunk-kommandoen | diagnoser.

Tar imot avvikene fra | finnavvik og gir tilbake mulige angrep (spoofing, flooding osv.), ett vindu om gangen.
Reglene ligger i deteksjon.diagnoser(). Navn, alvorlighet og MITRE hentes etterpå med lookups/angrepstyper.csv.

Bruk:
    ... | finnavvik
    | diagnoser
    | lookup angrepstyper.csv angrep OUTPUT navn alvorlighet mitre_id mitre_navn forklaring forste_steg tiltak
"""

import os
import sys

BIN = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN)

from splunklib.searchcommands import Configuration, Option, ReportingCommand, dispatch  # noqa: E402

import deteksjon  # noqa: E402


@Configuration(requires_preop=False)
class DiagnoserCommand(ReportingCommand):
    """Tolker avvik som mulige angrep og gir én rad per angrep per vindu."""

    baseline = Option(doc="Lookup-filen med fasiten, i appens lookups/", require=False,
                      default="baseline_trafikk.csv")

    # Splunk kjører først en map-fase. Uten denne sender splunklib ingen rader videre til reduce.
    @Configuration()
    def map(self, records):
        for r in records:
            yield r

    def reduce(self, records):
        # Samme som i finnavvik.py: Splunk sender radene i biter, og alle avvikene i et vindu må sees samtidig.
        if not hasattr(self, "_avvik"):
            self._avvik = []
        for r in records:
            self._avvik.append({
                "_time": int(float(r["_time"])), "type": r.get("type", ""),
                "src_ip": r.get("src_ip", ""), "dst_ip": r.get("dst_ip", ""),
                "dst_port": r.get("dst_port", ""), "len": r.get("len", ""),
                "malt": r.get("malt", ""), "normal": r.get("normal", ""),
            })
        if not self._finished:
            return

        fasit = deteksjon.les_baseline(os.path.join(BIN, "..", "lookups", os.path.basename(self.baseline)))
        for diagnose in deteksjon.diagnoser(self._avvik, fasit):
            yield diagnose


dispatch(DiagnoserCommand, sys.argv, sys.stdin, sys.stdout, __name__)
