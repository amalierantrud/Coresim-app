"""Gjør en pcap-fil om til en CSV som Splunk kan lese (sourcetype capture_csv), og fjerner kopier av pakker.

tshark (Wireshark) leser pcap-filen, og bare feltene appen bruker tas med. Noen opptak har hver pakke flere ganger
(capture.pcap fra 29.09 har nesten alle pakker nøyaktig fem ganger, innen noen mikrosekunder), og da blir alle
rate-målinger feil.

Kopiene må skilles fra et angrep som sender samme pakke om og om igjen (replay). Spoofingen 29.09 sendte én og samme
pakke (lik IP-ID og sjekksum) over 20 000 ganger, og de gjentakelsene ER angrepet og skal være med. Derfor:
  1. Like pakker (samme avsender-MAC, IP-er, IP-ID, port, lengde og sjekksum, eller for pakker uten IP: samme avsender,
     mottaker, lengde og protokoll) som kommer innen KOPI_VINDU etter hverandre, samles i en gruppe.
  2. Opptakets kopifaktor er den vanligste gruppestørrelsen (5 i capture.pcap, 1 i et opptak uten kopier).
  3. En gruppe blir til gruppestørrelse / kopifaktor ekte pakker, avrundet og minst 1.
     En gruppe på 10 i capture.pcap er altså to sendinger fra angriperen, ikke én.

Bruk (fra coresim-app):
    python tools/pcap_til_splunk.py testdata/capture.pcap
    python tools/pcap_til_splunk.py opptak.pcap -o testdata/opptak.csv --behold-kopier

Last så opp CSV-en med Settings → Add Data, sourcetype capture_csv og indeks capture.
Kolonnene (uten overskrift): tid, src_mac, src_ip, dst_ip, dst_port, udp_len, protokoller.
"""

import argparse
import csv
import itertools
import os
import shutil
import subprocess
import sys
from collections import Counter, OrderedDict

# Like pakker innen så mange sekunder etter hverandre regnes som én gruppe. I capture.pcap kommer 99,9 % av kopiene
# innen 235 mikrosekunder, mens en enhet sender samme strøm tidligst etter noen millisekunder.
KOPI_VINDU = 0.0003
# Så mange pakker leses først for å finne opptakets kopifaktor.
PROVE = 50000

TSHARK_STEDER = [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe",
                 "/usr/bin/tshark", "/Applications/Wireshark.app/Contents/MacOS/tshark"]

# Feltene vi ber tshark om, i rekkefølge. De fire siste brukes bare til å kjenne igjen kopier.
FELTER = ["frame.time_epoch", "eth.src", "ip.src", "ip.dst", "udp.dstport", "udp.length", "frame.protocols",
          "eth.dst", "ip.id", "udp.checksum", "frame.len"]


def finn_tshark(oppgitt=None):
    for sti in [oppgitt, shutil.which("tshark")] + TSHARK_STEDER:
        if sti and os.path.exists(sti):
            return sti
    sys.exit("Fant ikke tshark. Installer Wireshark, eller oppgi stien med --tshark.")


def les_pakker(pcap, tshark):
    """Leser pakkene fra pcap-filen med tshark, én ordbok per pakke, i tidsrekkefølge."""
    kommando = [tshark, "-r", pcap, "-n", "-T", "fields", "-E", "separator=,", "-E", "occurrence=f"]
    for felt in FELTER:
        kommando += ["-e", felt]
    with subprocess.Popen(kommando, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as p:
        for linje in p.stdout:
            verdier = linje.rstrip("\r\n").split(",")
            if len(verdier) == len(FELTER):
                yield dict(zip(FELTER, verdier))
    if p.returncode not in (0, None):
        sys.exit("tshark feilet (kode %s) på %s" % (p.returncode, pcap))


def kopi_nokkel(pakke):
    """Det som må være likt for at to pakker er samme pakke."""
    if pakke["ip.id"]:
        return ("ip", pakke["eth.src"], pakke["ip.src"], pakke["ip.dst"], pakke["ip.id"], pakke["udp.dstport"],
                pakke["frame.len"], pakke["udp.checksum"])
    return ("annet", pakke["eth.src"], pakke["eth.dst"], pakke["frame.len"], pakke["frame.protocols"])


def grupper(pakker, vindu=KOPI_VINDU):
    """Samler like pakker som kommer innen vindu etter hverandre. Gir (første pakke, antall) per gruppe, i tidsrekkefølge."""
    aapne = OrderedDict()   # nøkkel -> [første pakke, antall, siste tid], eldste først
    for pakke in pakker:
        tid = float(pakke["frame.time_epoch"])
        # Grupper som ikke har fått en ny pakke innen vinduet, er ferdige
        while aapne:
            nokkel, (forste, antall, sist) = next(iter(aapne.items()))
            if tid - sist <= vindu:
                break
            aapne.popitem(last=False)
            yield forste, antall
        nokkel = kopi_nokkel(pakke)
        gruppe = aapne.get(nokkel)
        if gruppe is None:
            aapne[nokkel] = [pakke, 1, tid]
        else:
            gruppe[1] += 1
            gruppe[2] = tid
            aapne.move_to_end(nokkel)
    for forste, antall, _ in aapne.values():
        yield forste, antall


def finn_kopifaktor(gruppestorrelser):
    """Den vanligste gruppestørrelsen: hvor mange ganger opptaket har hver pakke."""
    return Counter(gruppestorrelser).most_common(1)[0][0] if gruppestorrelser else 1


def fjern_kopier(pakker, kopifaktor=None, info=None):
    """Gjør hver gruppe like pakker om til antall / kopifaktor ekte pakker (avrundet, minst 1).

    Er kopifaktor ikke oppgitt, finnes den fra de første PROVE pakkene. info får nøkkelen kopifaktor.
    """
    pakker = iter(pakker)
    if kopifaktor is None:
        prove = list(itertools.islice(pakker, PROVE))
        kopifaktor = finn_kopifaktor([antall for _, antall in grupper(prove)])
        pakker = itertools.chain(prove, pakker)
    if info is not None:
        info["kopifaktor"] = kopifaktor
    for forste, antall in grupper(pakker):
        for _ in range(max(1, int(antall / kopifaktor + 0.5))):
            yield forste


def skriv_csv(pakker, ut):
    """Skriver de sju kolonnene Splunk forventer (props.conf, [capture_csv]). Gir antall rader."""
    antall = 0
    with open(ut, "w", newline="", encoding="ascii") as f:
        w = csv.writer(f, lineterminator="\n")
        for p in pakker:
            w.writerow([p["frame.time_epoch"], p["eth.src"], p["ip.src"], p["ip.dst"], p["udp.dstport"],
                        p["udp.length"], p["frame.protocols"]])
            antall += 1
    return antall


def main():
    parser = argparse.ArgumentParser(description="Gjør en pcap-fil om til CSV for Splunk og fjerner kopier av pakker.")
    parser.add_argument("pcap", help="pcap-filen som skal leses")
    parser.add_argument("-o", "--ut", help="CSV-filen som lages (standard: samme navn som pcap-filen, .csv)")
    parser.add_argument("--behold-kopier", action="store_true", help="ikke fjern kopier")
    parser.add_argument("--kopifaktor", type=int, help="hvor mange ganger opptaket har hver pakke (standard: finnes selv)")
    parser.add_argument("--tshark", help="stien til tshark, hvis den ikke finnes automatisk")
    args = parser.parse_args()

    ut = args.ut or os.path.splitext(args.pcap)[0] + ".csv"
    tshark = finn_tshark(args.tshark)

    inn = 0

    def tell(pakker):
        nonlocal inn
        for p in pakker:
            inn += 1
            yield p

    info = {}
    pakker = tell(les_pakker(args.pcap, tshark))
    if not args.behold_kopier:
        pakker = fjern_kopier(pakker, args.kopifaktor, info)
    skrevet = skriv_csv(pakker, ut)

    print("Leste %d pakker, skrev %d til %s" % (inn, skrevet, ut))
    if not args.behold_kopier and inn:
        print("Kopifaktor %d: fjernet %d kopier (%.1f %%)." % (
            info["kopifaktor"], inn - skrevet, 100.0 * (inn - skrevet) / inn))


if __name__ == "__main__":
    main()
