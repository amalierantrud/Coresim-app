"""Splunk-kommandoen | finnavvik.

Tar imot vinduer (én rad per strøm per 10 sekunder) og gir tilbake avvikene fra baselinen.
Selve reglene ligger i deteksjon.py, så denne filen bare oversetter mellom Splunk og dem.

Bruk (alle pakker med port og lengde, også HSRP, som har egen protokoll men er UDP):
    `ot_data` src_ip=* dst_port=* len=*
    | bin _time span=10s
    | stats count AS n values(src_mac) AS src_mac by _time src_ip dst_ip dst_port len
    | eval src_mac=mvjoin(src_mac, " ")
    | finnavvik
"""

import os
import sys

BIN = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BIN)

from splunklib.searchcommands import Configuration, Option, ReportingCommand, dispatch  # noqa: E402

import deteksjon  # noqa: E402

# Sperre mot for store søk. Alle vinduene holdes i minnet, og på coresim (over 100 millioner pakker) kan
# All time gi millioner av vinduer. 300 000 tilsvarer omtrent ett døgn med trafikken der.
MAKS_VINDUER = 300000


@Configuration(requires_preop=False)
class FinnAvvikCommand(ReportingCommand):
    """Sammenligner vinduer med baselinen og gir én rad per avvik."""

    baseline = Option(doc="Lookup-filen med fasiten, i appens lookups/", require=False,
                      default="baseline_trafikk.csv")

    # Splunk kjører først en map-fase. Uten denne sender splunklib ingen rader videre til reduce.
    @Configuration()
    def map(self, records):
        for r in records:
            yield r

    def reduce(self, records):
        # Splunk sender radene i biter (maks 50 000 om gangen) og kaller reduce én gang per bit.
        # Reglene må se alle vinduene samtidig, ellers ser et vindu som deles mellom to biter ut som
        # om strømmer mangler. Derfor samles bitene, og reglene kjøres først når den siste kommer.
        if not hasattr(self, "_vinduer"):
            self._vinduer = []
        for r in records:
            self._vinduer.append({
                "_time": int(float(r["_time"])),
                "src_ip": r.get("src_ip", ""), "dst_ip": r.get("dst_ip", ""),
                "dst_port": r.get("dst_port", ""), "len": r.get("len", ""),
                "n": int(float(r.get("n") or 0)),
                "src_mac": r.get("src_mac") or "",
            })
            if len(self._vinduer) > MAKS_VINDUER:
                raise RuntimeError("For mange vinduer (over %d). Velg et kortere tidsrom, for eksempel én time."
                                   % MAKS_VINDUER)
        if not self._finished:
            return

        fasit = deteksjon.les_baseline(os.path.join(BIN, "..", "lookups", os.path.basename(self.baseline)))
        for avvik in deteksjon.sammenlign(self._vinduer, fasit):
            yield avvik


dispatch(FinnAvvikCommand, sys.argv, sys.stdin, sys.stdout, __name__)
