# coresim-app – live OT-overvåking i Splunk (INF219 / NORCE)

Statistisk deteksjon og Python-diagnose av cyberangrep mot bore-simulatoren (coresim) på OpenLab.
Nettverkstrafikk (tcpdump fra `coresim-ws`) oppsummeres hvert minutt, sammenlignes med en
robust baseline, og Python-kode slår avvik og host events sammen til hendelser med type,
alvorlighet og forklaring. Et kontrollrom-dashboard viser resultatet live.

```
pakker (index=anomaly_detection)
  → OT 1: oppsummering per minutt          → index=ot_summary
  → OT 2: | otdetect   (Python, statistikk) → index=ot_alerts
  → OT 3: | otdiagnose (Python, diagnose)   → index=ot_incidents
  → dashboard «Kontrollrom»
```

## Mappestruktur

| Mappe | Innhold |
| --- | --- |
| `otdiag/` | **Python-pakken – selve algoritmen.** `features.py` (tcpdump → statistikk per minutt), `detect.py` (baseline og regler), `diagnose.py` (avvik + host events → hendelser), `sim.py` (simulert coresim-trafikk). Kun standardbiblioteket, så den kjører i Splunk. |
| `inf219_ot_anomaly/` | Splunk-appen som skal til coresim: regler for å lese tcpdump, makroer, planlagte søk, Python-kommandoene i `bin/` og dashboard. |
| `inf219_testdata/` | Liten app **kun for lokal testing**: indekser og TCP-input på port 9998. Skal ikke til coresim. |
| `tests/` | pytest-tester med kjente angrep. |
| `tools/` | `gen_testdata.py` (testdatafil), `replay.py` (live-avspilling til Splunk), `build_app.py` (gjør appen klar / pakker den). |
| `notebooks/` | Analyse og evaluering i Jupyter. |

`otdiag/` er fasiten for koden. `tools/build_app.py` kopierer den inn i `inf219_ot_anomaly/bin/otdiag`
og henter `splunklib` til `bin/lib` (begge ligger i `.gitignore`).

## Kom i gang (hver person)

1. **Python-miljø** (fra denne mappen):
   ```
   pip install -r requirements-dev.txt
   python -m pytest            # alle tester skal bli grønne
   python tools/build_app.py   # gjør Splunk-appen klar
   ```
2. **Egen Splunk i Docker** i en privat mappe (f.eks. `splunk-dev/`, ikke i Git). Legg til i `docker-compose.yml`:
   ```yaml
       ports:
         - "9998:9998"
       volumes:
         - C:/Users/<deg>/Desktop/coresim-app/inf219_ot_anomaly:/opt/splunk/etc/apps/inf219_ot_anomaly
         - C:/Users/<deg>/Desktop/coresim-app/inf219_testdata:/opt/splunk/etc/apps/inf219_testdata
   ```
   Så `docker compose down` og `docker compose up -d`. Sett tidssone i Splunk: *Preferences → Time zone → Europe/Oslo*.
3. **Send live-data** til Splunk:
   ```
   python tools/replay.py                          # normaldrift
   python tools/replay.py --attack flood@5m:3m     # flood etter 5 min, i 3 min
   ```
   Angrep: `flood`, `scan`, `inject`, `silent`, `ddos`, `maintenance`.
4. **Lær baseline**: la replay gå ~30 min uten angrep, slå på *OT 1 - Oppsummer per minutt*
   (Settings → Searches, reports, and alerts), og kjør så i Search:
   `` `ot_summary` earliest=-30m | otbaseline ``
5. **Slå på kjeden**: *OT 2 - Deteksjon* og *OT 3 - Diagnose*. Start et angrep med replay
   og følg med i dashboardet **Kontrollrom**.

## Endre koden

- Endret noe i `otdiag/`? Kjør `python -m pytest` og så `python tools/build_app.py` – Splunk bruker den nye koden ved neste søk.
- Endret en `.conf`-fil? `docker compose restart` i `splunk-dev`.
- Endret noe i Splunk-nettleseren (f.eks. dashboard)? Det havner i `local/`, som ikke er i Git. Kopier det til `default/`.

## Til coresim

1. `python tools/build_app.py --package` → `dist/inf219_ot_anomaly-<versjon>.tgz`
2. En admin oppretter indeksene `ot_summary`, `ot_alerts`, `ot_incidents` (se `inf219_testdata/default/indexes.conf`).
3. Installer pakken, bygg baseline på normaldrift, slå på søkene én og én.
4. `inf219_testdata` og utviklerlisensen skal **ikke** til coresim.

## Arbeidsflyt i Git

`main` = det som virker. Lag egen gren per oppgave (`git checkout -b diagnose-host-events`),
push og lag en merge request i GitLab som en annen ser over.
