"""Gjør Splunk-appen klar: kopierer otdiag inn i appen og henter splunklib.

Kjør etter hver endring i otdiag/ (og første gang):
    python tools/build_app.py

Lag en installerbar pakke til coresim (dist/inf219_ot_anomaly-<versjon>.tgz):
    python tools/build_app.py --package

otdiag/ i rot er "fasiten" for koden. Kopien i inf219_ot_anomaly/bin/otdiag og
bin/lib/ er generert og ligger i .gitignore.
"""
import argparse
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "inf219_ot_anomaly"
BIN = APP / "bin"


def copy_package():
    dst = BIN / "otdiag"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(ROOT / "otdiag", dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "sim.py"))
    print(f"otdiag kopiert til {dst.relative_to(ROOT)}")


def ensure_splunklib():
    """Henter splunklib fra kildepakken til splunk-sdk 2.x og legger mappen i bin/lib.

    splunk-sdk 3.x krever Python 3.13, men Splunk 9.4 (coresim) kjører Python 3.9,
    så vi bruker 2.x. Vi kopierer bare mappen splunklib/ (ren Python, ingen bygging).
    """
    target = BIN / "lib" / "splunklib"
    if target.exists():
        print("splunklib finnes allerede i bin/lib")
        return
    print("Henter splunk-sdk 2.1.0 ...")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.check_call([sys.executable, "-m", "pip", "download", "--quiet", "--no-deps",
                               "--no-binary", ":all:", "splunk-sdk==2.1.0", "-d", tmp])
        sdist = next(Path(tmp).glob("splunk*sdk-*.tar.gz"))
        with tarfile.open(sdist) as tar:
            members = [m for m in tar.getmembers() if "/splunklib/" in m.name and "/tests/" not in m.name]
            extra = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
            tar.extractall(tmp, members=members, **extra)
        src = next(Path(tmp).glob("splunk*sdk-*/splunklib"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, target)
    print(f"splunklib lagt i {target.relative_to(ROOT)}")


def package():
    version = re.search(r"version\s*=\s*(\S+)", (APP / "default" / "app.conf").read_text()).group(1)
    out = ROOT / "dist" / f"inf219_ot_anomaly-{version}.tgz"
    out.parent.mkdir(exist_ok=True)

    def skip(ti: tarfile.TarInfo):
        parts = Path(ti.name).parts
        if "local" in parts or "__pycache__" in parts or ti.name.endswith((".pyc", "local.meta")):
            return None
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = ""
        return ti

    with tarfile.open(out, "w:gz") as tar:
        tar.add(APP, arcname=APP.name, filter=skip)
    print(f"Pakke laget: {out.relative_to(ROOT)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", action="store_true", help="lag også .tgz til coresim")
    a = ap.parse_args()
    copy_package()
    ensure_splunklib()
    if a.package:
        package()
