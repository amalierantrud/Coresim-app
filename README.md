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
└── ot_attack_detection/            Splunk-appen
    └── default/
        ├── app.conf                navn, beskrivelse og versjon
        └── data/ui/nav/default.xml menyen i appen
```

Appen er foreløpig tom. Den har bare et navn og en søkeside, og vi bygger den opp ett steg om gangen.

## Kom i gang

### 1. Clone repoet

```bash
git clone https://git.app.uib.no/Amalie.Sotvedt/coresim-app.git
```

Logg inn med UiB-brukernavnet ditt. Som passord bruker du et **Personal Access Token**, ikke det vanlige passordet.
Tokenet lager du på git.app.uib.no under _Preferences → Access tokens_, med `read_repository` og `write_repository` krysset av.

### 2. Koble appen inn i din lokale Splunk

Du trenger en `splunk-dev`-mappe **utenfor** repoet med `docker-compose.yml`, `.env` (passord) og `splunk.lic` (din egen utviklerlisens).
I `docker-compose.yml` legger du til denne linjen under `volumes:`. Bytt ut stien med der du har clonet repoet:

```yaml
- C:/Users/<deg>/Desktop/coresim-app/ot_attack_detection:/opt/splunk/etc/apps/ot_attack_detection
```

Kjør deretter i `splunk-dev`:

```bash
docker compose up -d
```

### 3. Sjekk

Åpne **http://localhost:8000**. _OT Attack Detection_ skal ligge i app-menyen øverst til venstre.

## Når du endrer appen

- Endringer i filene i `ot_attack_detection/` ser Splunk med en gang. Last inn siden på nytt, eller kjør `docker compose restart` etter endringer i `.conf`-filer.
- Endrer du noe i Splunk-nettsiden, lagres det i `ot_attack_detection/local/`. Den mappa kommer ikke med i Git. Kopier endringen til `default/` hvis resten av gruppa skal få den.
