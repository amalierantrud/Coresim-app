# coresim-app – OT Attack Detection

Splunk-app for å oppdage og diagnostisere cyberangrep mot borekontrollsystemet **coresim**.
Studentoppgave i INF219 for NORCE, høsten 2026.

**Gruppe 2:** Caroline, Amalie og Johannes
**NORCE-kontakter:** Fionn Iversen og Robert Ewald

## Mål

- Et dashboard i Splunk (Enterprise / Security) som viser og forklarer angrep
- En app for statistikkbasert deteksjon og diagnose
- Forslag til angrep som kan unngå statistikkbasert deteksjon

Ekte data ligger på NORCE sin Splunk på OpenLab (`splunk.coresim.no`). Hver av oss utvikler i sin egen lokale Splunk i Docker.

## Mappestruktur

```
coresim-app/
├── ot_attack_detection/                 Splunk-appen
│   ├── bin/
│   │   ├── deteksjon.py                 reglene for avvik og diagnosen av mulige angrep
│   │   ├── finnavvik.py                 søkekommandoen | finnavvik: avvik fra baselinen
│   │   ├── diagnoser.py                 søkekommandoen | diagnoser: avvik → mulige angrep
│   │   └── splunklib/                   Splunk sitt Python-SDK 2.1.1 (kopiert fra Splunk, ikke endret)
│   ├── default/
│   │   ├── app.conf                     navn, beskrivelse og versjon
│   │   ├── commands.conf                registrerer finnavvik og diagnoser
│   │   ├── indexes.conf                 indeksene baseline og capture
│   │   ├── macros.conf                  ot_data: hvor trafikken hentes fra (lokalt eller coresim)
│   │   ├── props.conf                   hvordan Splunk leser baseline-, angreps- og coresim-dataene
│   │   ├── savedsearches.conf           «Lag baseline»: lager lookups/baseline_trafikk.csv
│   │   └── data/ui/
│   │       ├── nav/default.xml          menyen i appen
│   │       └── views/
│   │           ├── oversikt.xml         dashboardet Oversikt: trafikken over tid
│   │           └── avvik.xml            dashboardet Avvik: avvik fra baselinen
│   └── lookups/
│       ├── baseline_trafikk.csv         fasiten: normal MAC og rate per strøm, fra baselinen
│       ├── angrepstyper.csv             navn, alvorlighet, MITRE og tiltak for hvert mulig angrep
│       └── mitre_ics.csv                MITRE ATT&CK for ICS: taktikk, beskrivelse, MITRE sine tiltak, lenke
├── tools/lag_mitre_ics.py               lager mitre_ics.csv fra MITRE sitt eget repo
├── tests/test_deteksjon.py              tester for reglene (python -m pytest tests)
├── docs/data.md                         kartlegging av dataene på coresim
├── splunk-dev/                          din lokale Splunk (ikke i Git, se under)
└── testdata/                            pcap- og datafiler fra NORCE (ikke i Git)
```

## Deteksjonen

Trafikken deles i 10-sekundersvinduer per strøm (avsender, mottaker, port, størrelse) og sammenlignes med
`lookups/baseline_trafikk.csv`. Reglene står i `bin/deteksjon.py`, og grensene (`FAKTOR`, `MARGIN`) øverst i filen.

Diagnosen ser på alle avvikene i samme vindu og tolker dem som mulige angrep:

| Når | Mulig angrep |
| --- | --- |
| Feil MAC på en kjent strøm | Spoofing |
| Minst halvparten av de faste strømmene over rate-grensen | Flooding |
| Én strøm over rate-grensen, riktig MAC | Økt sending |
| Alle faste strømmer fra én avsender mangler | Enhet sender ikke |
| Noen faste strømmer fra en avsender mangler | Strøm borte |
| Ny strøm fra en avsender som ikke er i baselinen | Ukjent enhet |
| Minst 5 nye mottaker/port-par fra én avsender | Skanning |
| Ny strøm fra en kjent avsender | Ny forbindelse |

Navn, alvorlighet, MITRE ATT&CK for ICS og tiltak står i `lookups/angrepstyper.csv` og kan endres uten å røre koden.
Taktikk, MITRE sine tiltak og lenke hentes fra `lookups/mitre_ics.csv`. Den lages på nytt med `python tools/lag_mitre_ics.py`
når MITRE kommer med en ny versjon. En test sjekker at alle MITRE-numrene i `angrepstyper.csv` fortsatt finnes,
siden MITRE av og til erstatter teknikker (i versjon 20 ble T0855 og T0856 til T1692.001 og T1692.002).

- **I Splunk:** dashboardet Avvik bruker kommandoene `| finnavvik` og `| diagnoser`.
- **Fra kommandolinja:** `python ot_attack_detection/bin/deteksjon.py testdata/capture.csv`
- **Tester:** `python -m pytest tests`

Kjent begrensning: `capture.pcap` har hver pakke omtrent fem ganger, så «For høy rate» slår ut på alt i det opptaket.

## Kom i gang

### 1. Clone repoet

```bash
git clone https://git.app.uib.no/Amalie.Sotvedt/coresim-app.git
```

Logg inn med UiB-brukernavnet ditt. Som passord bruker du et **Personal Access Token**, ikke det vanlige passordet.
Tokenet lager du på git.app.uib.no under _Preferences → Access tokens_, med `read_repository` og `write_repository` krysset av.

### 2. Lag din lokale Splunk i `splunk-dev/`

Du trenger Docker Desktop og din egen utviklerlisens fra [dev.splunk.com](https://dev.splunk.com/enterprise/dev_license/).
Lag mappen `splunk-dev` **inne i** `coresim-app`. Hele mappen er i `.gitignore`, siden den inneholder passord og lisens.

```
coresim-app/splunk-dev/
├── docker-compose.yml
├── .env
└── splunk.lic
```

**`splunk.lic`:** lisensfilen din, med akkurat dette navnet.

**`.env`:** passordet ditt (minst 8 tegn):

```
SPLUNK_PASSWORD=ditt-passord
```

**`docker-compose.yml`:**

```yaml
# Navnet bestemmer hva volumene (dataene) heter i Docker.
name: splunk-dev

services:
  splunk:
    image: splunk/splunk:latest
    # platform: linux/amd64   # Mac med M-brikke: fjern #, og slå på Rosetta i Docker Desktop
    container_name: splunk
    restart: unless-stopped
    ports:
      - "8000:8000"
      - "8088:8088"
    environment:
      SPLUNK_GENERAL_TERMS: --accept-sgt-current-at-splunk-com
      SPLUNK_START_ARGS: --accept-license
      SPLUNK_PASSWORD: ${SPLUNK_PASSWORD}
      SPLUNK_LICENSE_URI: /tmp/splunk.lic
    volumes:
      - ./splunk.lic:/tmp/splunk.lic:ro
      - splunk-var:/opt/splunk/var
      - splunk-etc:/opt/splunk/etc
      # Appen fra repoet. ".." er mappen over, altså coresim-app.
      - ../ot_attack_detection:/opt/splunk/etc/apps/ot_attack_detection

volumes:
  splunk-var:
  splunk-etc:
```

Stiene er relative, så filen er lik for alle uansett hvor repoet ligger.

### 3. Start Splunk

```bash
cd splunk-dev
docker compose up -d
docker compose logs -f splunk
```

Vent til det står `Ansible playbook complete` (3–5 min første gang), og trykk Ctrl+C. Splunk fortsetter å kjøre.

### 4. Sjekk

Åpne **http://localhost:8000** (husk `http://`) og logg inn som `admin` med passordet fra `.env`.
_OT Attack Detection_ skal ligge i app-menyen øverst til venstre, og under _Settings → Licensing_ skal lisensen stå som `valid`.

## Daglig bruk

Alle kommandoene kjøres i `coresim-app/splunk-dev`.

| Hva | Kommando |
| --- | --- |
| Stoppe (alt beholdes) | `docker compose stop` |
| Starte igjen | `docker compose start` |
| Starte på nytt (etter endring i en `.conf`-fil) | `docker compose restart` |
| Etter endring i `docker-compose.yml` | `docker compose up -d` |
| Se status | `docker ps` (vent på `healthy`) |
| Følge loggen live | `docker compose logs -f splunk` |

> **Pass på:** `docker compose down -v` sletter **alle** lokale data (indekser, opplastede testdata, brukere).

## Testdata

Den lokale Splunk-en er tom. Dataene ligger ikke i Git, så få filene fra gruppa og legg dem i `testdata/`.
Start Splunk på nytt først, så indeksene og sourcetypene fra appen finnes. Last så opp med _Settings → Add Data → Upload_:

| Fil | Hva | Sourcetype | Indeks |
| --- | --- | --- | --- |
| `baseline_clean.json` | Normaltrafikk fra NORCE, 21.10.2026 | `baseline_json` | `baseline` |
| `capture.csv` | Angrepsopptaket fra 29.09.2026 | `capture_csv` | `capture` |

`capture.csv` lages fra `capture.pcap` med tshark (Wireshark):

```powershell
& "C:\Program Files\Wireshark\tshark.exe" -r capture.pcap -n -T fields -E header=n -E separator=, -E occurrence=f -e frame.time_epoch -e eth.src -e ip.src -e ip.dst -e udp.dstport -e udp.length -e frame.protocols | Out-File -Encoding ascii capture.csv
```

Last opp hver fil bare én gang, ellers blir pakkene dobbelt opp.

## Pakke appen til coresim

Dashboardet henter pakkene med makroen `` `ot_data` `` (`default/macros.conf`). Den søker i både `index=capture` (lokalt)
og `index=anomaly_detection` (coresim). Hver Splunk har bare én av dem, så appen virker likt begge steder uten endringer.

Kjør i `coresim-app`:

```bash
mkdir -Force dist; tar -czf dist/ot_attack_detection.tgz --exclude=local --exclude=metadata/local.meta --exclude=lib --exclude=__pycache__ --exclude=default/indexes.conf ot_attack_detection
```

- `local/` og `local.meta` er dine egne innstillinger og skal ikke være med.
- `indexes.conf` er utelatt, så appen ikke lager indeksene `baseline` og `capture` på NORCE sin Splunk.

Installer med _Apps → Manage Apps → Install app from file_ (krever admin på coresim).
Velg et kort tidsrom på coresim, for eksempel én time: `anomaly_detection` har over 100 millioner pakker.

## Når du endrer appen

- Endringer i filene i `ot_attack_detection/` ser Splunk med en gang. Last inn siden på nytt, eller kjør `docker compose restart` etter endringer i `.conf`-filer.
- Endrer du noe i Splunk-nettsiden, lagres det i `ot_attack_detection/local/`. Den mappa kommer ikke med i Git. Kopier endringen til `default/` hvis resten av gruppa skal få den.
