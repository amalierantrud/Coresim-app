# Data på coresim – første kartlegging

Oversikt over dataene på `splunk.coresim.no` (Splunk 9.4.2), laget 27.10.2026.
Bare lesende søk er brukt. Tallene er hentet med `| eventcount`, `| metadata` og `| tstats`,
og trafikkanalysen bruker én time (20.11.2025 kl. 12–13).

## Kort oppsummert
- Alle relevante data ligger i **tre indekser**: `anomaly_detection` (nettverkstrafikk), `main` (host events) og `dragos` (DRAGOS).
- **Nettverkstrafikken er et ferdig opptak** fra **18.–27. november 2025**, ikke en strøm som kommer inn nå. Søk må bruke det tidsrommet.
- Trafikken er **svært regelmessig**: noen få faste OT-enheter sender UDP-multicast med faste pakkestørrelser. Det er et godt utgangspunkt for statistikkbasert deteksjon.
- Ingen felt er pakket ut i nettverksdataene (`generic_single_line`). Å trekke ut IP-adresser, porter og lengde er første jobb for appen vår.

## Indekser

| Indeks | Hendelser | Tidsrom | Innhold |
| --- | --- | --- | --- |
| `anomaly_detection` | ~110,8 mill. | 17.11.2025 – 27.11.2025 | Nettverkspakker (tcpdump) fra `coresim-ws` |
| `main` | ~37,9 mill. | 2025 – i dag | Host events fra `coresim-ws` (journald, syslog, Unix-tilstand) |
| `dragos` | ~452 000 | 06.2026 – 10.2026 | Eiendeler, adresser og varsler fra DRAGOS |
| `itsi_*`, `summary`, `history`, `snmptrapd` | 0 | – | Tomme, ikke relevante |

## 1. `anomaly_detection` – nettverkstrafikk

| Felt | Verdi |
| --- | --- |
| host | `coresim-ws.openlab.local` (110,7 mill.), `localhost` (118 000, testing 17.11), `proxy.openlab.local` (7, test 08.2026) |
| source | `tcp:9998`: sendt inn over nettverket, ikke fra fil |
| sourcetype | `generic_single_line`: én linje er én hendelse, uten felt |

**Én hendelse er én pakke i tcpdump-format:**
```
2025-11-20 12:00:04.995562 IP 192.168.10.116.11611 > 224.10.10.116.21611: UDP, length 480
2025-11-20 12:00:04.978224 ARP, Request who-has 192.168.10.216 tell 192.168.10.120, length 46
```
Linja består av tidspunkt, protokoll, `avsender-IP.port > mottaker-IP.port`, transport og lengde.

**Volum per dag (coresim-ws):**

| Dag | Pakker | Per sekund |
| --- | --- | --- |
| 18.11 | 12,1 mill. | 140 |
| 19.11 | 13,3 mill. | 154 |
| 20.11 | 13,3 mill. | 154 |
| 21.11 | 12,3 mill. | 143 |
| 22.11–25.11 | ~11,5 mill. per dag | 133–134 |
| 26.11 | 9,8 mill. | 114 |
| 27.11 | 3,8 mill. (stopper 10:25) | – |

18.11 og 27.11 er ikke hele dager. Det er verdt å se nærmere på hvorfor 19.–20.11 har mer trafikk enn 22.–25.11
(for eksempel angrep, eller at simulatoren kjørte annerledes).

**Protokoller (én time):**

| Transport | Pakker | Andel |
| --- | --- | --- |
| UDP | 539 180 | 98,2 % |
| ARP | 6 635 | 1,2 % |
| STP | 3 595 | 0,7 % |
| IP / IP6 (annet) | 3 | ~0 % |

**Avsendere (én time):**

| Avsender | Pakker | Antall mottakere | Pakkelengder |
| --- | --- | --- | --- |
| 192.168.10.126 | 122 167 | 4 | 240, 30 |
| 192.168.10.116 | 72 007 | 1 | 480, 996 |
| 192.168.10.200 | 71 910 | 1 | 480 |
| 192.168.10.120 | 68 577 | 2 | 201, 4, 50 |
| 192.168.10.101 | 64 799 | 1 | 480, 996 |
| 192.168.10.110 | 50 400 | 1 | 240, 996 |
| 192.168.10.102 | 43 199 | 1 | 240, 996 |
| 192.168.10.104 | 43 199 | 1 | 240, 480 |
| 192.168.10.19 | 2 718 | 1 | 201, 210, 50 |
| 192.168.10.80 | 179 | 1 | 50 |
| 192.168.10.199 | 25 | 2 | 201, 24, 50 |

**Det vi ser:**
- Mottakerne er **multicast** (`224.10.10.x`), og hver enhet sender til «sin» gruppe (`.116` → `224.10.10.116`).
- Portene følger et mønster (`11611` → `21611`, `10011` → `20011`).
- Pakkestørrelsene er faste (240 / 480 / 996 byte), og antallet per time er nesten likt for flere enheter
  (`.102` og `.104` har begge 43 199, som er 12 per sekund). Det tyder på faste sendeintervaller.
- **Avvik fra dette mønsteret er det vi skal oppdage**, for eksempel en ny avsender, ny mottaker, ny port,
  uvanlig lengde, endret pakkerate eller mye ARP (skanning eller spoofing).

## 2. `main` – host events fra coresim-ws

Data samlet med Splunk Add-on for Unix/Linux og journald. Hosten er `coresim-ws`.

| Sourcetype | Hendelser | Hva det er |
| --- | --- | --- |
| `journald` | 33,6 mill. | Systemloggen (systemd) |
| `ps` | 855 000 | Prosesser som kjører |
| `syslog` | 841 000 | `/var/log/syslog`, `messages` osv. |
| `Unix:Service` | 522 000 | Tjenester og status |
| `netstat` | 427 000 | Åpne nettverkstilkoblinger |
| `top` | 427 000 | CPU og minne per prosess |
| `interfaces` | 427 000 | Nettverkskort og trafikktellere |
| `Unix:UserAccounts` | 222 000 | Brukerkontoer |
| `who` | 163 000 | Hvem som er logget inn |
| `Unix:ListeningPorts`, `openPorts` | ~190 000 | Porter som lytter |
| `lastlog`, `lsof` | ~128 000 | Siste innlogginger og åpne filer |

`/var/log/auth.log` (18 000) ligger også her, med innlogginger og sudo.
Dette er «host events» fra oppgaveteksten. De kan kobles mot nettverksavvik, for eksempel en ny prosess eller innlogging rett før trafikken endrer seg.

## 3. `dragos` – DRAGOS

| Sourcetype | Hendelser | Tidsrom | Innhold |
| --- | --- | --- | --- |
| `dragos:addresses` | 356 000 | 24.08 – 25.10.2026 | IP-/MAC-adresser DRAGOS har sett |
| `dragos:assetdata` | 91 000 | 24.08 – 25.10.2026 | Eiendeler (enheter) med detaljer |
| `dragos:assetzones` | 5 600 | 24.08 – 25.10.2026 | Hvilken sone enhetene tilhører |
| `dragos:notification` | 26 | 19.06 – 27.08.2026 | Varsler (JSON) |

De 26 varslene er alle av typen *Communication* med lav alvorlighet (0–1):
«New Communication Flow» (17), «New IP Address as Source» (5), «NetBIOS Query for New Name» (2),
«New Ethernet Address as Source» (1) og ett samlevarsel.
Eksempel: *Host 192.168.10.172 communicating via DCP-PFT to host 192.168.10.199 for the first time.*

DRAGOS-dataene er fra **2026**, mens nettverksopptaket er fra **november 2025**, så de kan ikke sammenlignes direkte.

## Åpne spørsmål (til NORCE)
1. Inneholder opptaket 18.–27.11.2025 angrep, og i så fall når? Uten fasit er det vanskelig å vurdere deteksjonen.
2. Hvilke enheter er `192.168.10.101`–`.126`, `.19`, `.80`, `.199` og `.200` i borekontrollsystemet?
3. Kommer det nye opptak, eller er november 2025 datasettet vi skal bruke?
4. Hva er DCP-PFT (protokollen DRAGOS nevner)?

## Søkene som ble brukt
```
| eventcount summarize=false index=* | stats sum(count) as count by index | sort - count

| metadata type=hosts index=anomaly_detection          (også type=sourcetypes / type=sources)

index=anomaly_detection host=coresim-ws.openlab.local earliest="11/20/2025:12:00:00" latest="11/20/2025:12:00:05"
| head 20 | table _time _raw

| tstats count where index=anomaly_detection host=coresim-ws.openlab.local by _time span=1d

index=anomaly_detection host=coresim-ws.openlab.local        (20.11.2025 12:00–13:00)
| rex "^\S+ \S+ (?<proto>[A-Z0-9]+),? (?:(?<src_ip>\d+\.\d+\.\d+\.\d+)\.(?<src_port>\d+) > (?<dst_ip>\d+\.\d+\.\d+\.\d+)\.(?<dst_port>\d+): (?<transport>\w+))?.*length (?<len>\d+)"
| stats count dc(dst_ip) as mottakere values(len) as lengder by src_ip | sort -count

index=dragos sourcetype="dragos:notification" | spath | stats count by type summary severity
```
