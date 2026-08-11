# Vaultwarden Agent Broker

Ein Torwächter zwischen KI-Agenten (Claude Code, Claude Desktop, eigene Skripte)
und deinem selbst gehosteten Vaultwarden.

Der Agent bekommt **nie** dein Master-Passwort und **nie** direkten Zugriff auf
den Tresor. Er fragt den Broker, der Broker setzt deine Regeln durch, fragt bei
dir per Push-Nachricht nach – und protokolliert jeden einzelnen Zugriff.

---

## Inhalt

1. [Konzept](#1-konzept)
2. [Vaultwarden vorbereiten](#2-vaultwarden-vorbereiten)
3. [Installation](#3-installation)
4. [Agent-Token anlegen](#4-agent-token-anlegen)
5. [Einbindung in Claude (MCP)](#5-einbindung-in-claude-mcp)
6. [Die REST-API direkt benutzen](#6-die-rest-api-direkt-benutzen)
7. [Das Dashboard](#7-das-dashboard)
8. [Sicherheitshinweise](#8-sicherheitshinweise)
9. [Fehlersuche](#9-fehlersuche)

---

## 1. Konzept

### Der Aufbau

```
   Claude / Agent                    dein Handy
        │                                 ▲
        │ MCP (stdio)                     │ ntfy-Push mit
        ▼                                 │ "Freigeben" / "Verweigern"
  ┌───────────┐                           │
  │  broker   │ ── HTTPS ──► ┌────────┐ ──┘
  │    mcp    │              │  ntfy  │
  └───────────┘              └────────┘
        │ HTTPS (Bearer-Token)
        ▼
  ┌────────────────────────────────────────────┐
  │  broker serve      Policies · Audit · Web  │
  └────────────────────────────────────────────┘
        │ HTTP, nur internes Docker-Netz
        ▼
  ┌────────────────────────────────────────────┐
  │  bw (offizielle Bitwarden CLI, serve-Modus)│
  └────────────────────────────────────────────┘
        │ HTTPS
        ▼
  ┌────────────────────────────────────────────┐
  │  Vaultwarden                               │
  └────────────────────────────────────────────┘
```

Wichtig an diesem Aufbau: **der Broker implementiert keine eigene
Bitwarden-Verschlüsselung**. Die gesamte Krypto bleibt in der offiziellen
Bitwarden CLI, die als Sidecar-Container läuft. Der Broker spricht mit ihr nur
über einfaches HTTP im internen Docker-Netz. Damit gibt es keine selbst
gebastelte Krypto, die stillschweigend kaputtgehen könnte.

### Die drei Policies

Pro Tresor-Eintrag steuerst du über ein **Custom Field namens `agent-policy`**,
was passieren soll. Das Feld pflegst du ganz normal in der Bitwarden-Oberfläche
(Web, App, Browser-Erweiterung) – es synchronisiert sich überallhin.

| Wert   | Bedeutung                                                              |
|--------|------------------------------------------------------------------------|
| `auto` | Der Agent bekommt den Wert sofort. Für Unkritisches.                   |
| `ask`  | Du bekommst eine Push-Nachricht und entscheidest. **Standard.**        |
| `deny` | Gesperrt. Immer. Ohne Nachfrage.                                       |

Einträge **ohne** dieses Feld fallen auf `default_policy` aus der `config.toml`
zurück (ausgeliefert mit `ask`).

### Wie eine Entscheidung zustande kommt

1. `agent-policy` des Eintrags, sonst `default_policy`.
2. Eine **Merken-Regel** (siehe Dashboard) kann `ask` → `auto` anheben.
3. Das **`max_policy` des Tokens** deckelt das Ergebnis danach wieder.

**`deny` gewinnt immer.** Weder eine Merken-Regel noch sonst etwas hebt ein
`deny` auf. Und ein Token mit `max_policy = ask` bekommt niemals `auto` – selbst
wenn am Eintrag `auto` steht.

### Was passiert bei `ask`?

1. Der Agent fragt einen Wert an, bekommt sofort **HTTP 202** und eine
   `request_id` zurück – noch keinen Wert.
2. Der Broker schickt dir eine ntfy-Push-Nachricht mit zwei Knöpfen:
   **Freigeben** und **Verweigern**. Das sind signierte Einmal-Links (HMAC),
   die nach der Entscheidung bzw. nach `request_ttl` (Standard 5 Minuten)
   wertlos sind. Parallel erscheint die Anfrage im Dashboard.
3. Der Agent fragt `GET /v1/requests/{id}` regelmäßig ab.
4. Nach deiner Freigabe holt der Broker den Wert **in genau diesem Moment**
   frisch aus dem Tresor und liefert ihn **genau einmal** aus.

> **Werte werden nie in der Broker-Datenbank gespeichert.** In SQLite stehen nur
> Metadaten: welcher Agent, welcher Eintrag, welche Feldnamen, wann, welches
> Ergebnis. Keine Passwörter.

### Warum kein Passwort in der `.env`

Der Sidecar startet **absichtlich gesperrt**. Auf dem Server liegt nur der
**API-Key** des agent-Kontos – damit kann sich die CLI zwar anmelden, den
Tresor aber **nicht entschlüsseln**. Zum Entschlüsseln braucht es das
Master-Passwort, und das gibst du **einmalig im Dashboard** ein.

Der Unterschied in der Praxis: Wer sich eine Kopie deiner `.env`, deiner
Backups oder deines Docker-Volumes besorgt, hat damit **nichts** in der Hand.
Ein Passwort in einer Umgebungsvariablen dagegen steht in
`docker inspect`, in jedem Compose-Dump und in jedem Backup – dauerhaft und
im Klartext.

Der Preis dafür: **Nach jedem Neustart des `bw`-Containers musst du einmal
entsperren.** Bis dahin antwortet die Agent-API mit `503` und der Broker
schickt dir genau eine ntfy-Erinnerung mit Link zum Dashboard.

So sieht der Ablauf aus:

```
Reboot / docker compose up
        │
        ▼
bw serve läuft, Tresor GESPERRT ──► /v1/* antwortet 503
        │                            ntfy: "Agent-Broker gesperrt"
        │
        │  du öffnest /admin und gibst das Master-Passwort ein
        ▼
Broker ruft POST /unlock beim Sidecar auf
        │
        ▼
Tresor offen ──► normaler Betrieb, periodischer Sync läuft wieder
```

Wer das nicht möchte, findet unter
[Auto-Unlock](#auto-unlock-optional-nicht-empfohlen) den Fallback per
Docker-Secret.

---

## 2. Vaultwarden vorbereiten

Der Broker meldet sich mit einem **eigenen, dedizierten Konto** an – nicht mit
deinem. Dieses Konto sieht ausschließlich das, was du ihm ausdrücklich in eine
Sammlung legst.

### 2.1 Agent-Konto anlegen

1. Falls die Registrierung geschlossen ist, im Vaultwarden-Adminpanel
   (`https://vault.DEINE-DOMAIN/admin`) eine **Einladung** an z.B.
   `agent@deine-domain.de` schicken. Alternativ kurzzeitig
   `SIGNUPS_ALLOWED=true` setzen.
2. Für dieses Konto ein **eigenes, langes Master-Passwort** vergeben und im
   eigenen Tresor ablegen. Du gibst es später **einmalig im Broker-Dashboard**
   ein – auf dem Server wird es nirgends hinterlegt.
3. **Kein 2FA** für dieses Konto aktivieren – der API-Key-Login der CLI käme
   sonst nicht durch.

### 2.2 Organisation und Sammlung anlegen

Mit deinem **normalen** Konto:

1. Neue Organisation anlegen, z.B. `AI`.
2. Darin eine Sammlung anlegen, z.B. `Agent-Zugriff`.
3. Das Konto `agent@...` als Mitglied einladen. Rolle: **User**. Beim Zugriff
   auf Sammlungen **nur** `Agent-Zugriff` auswählen, idealerweise als
   **schreibgeschützt** ("Kann nur lesen" / read only).
4. Einladung annehmen (im Postfach des agent-Kontos bzw. per Link) und im
   Adminpanel bestätigen.

Jetzt die Einträge, auf die Agenten zugreifen dürfen, in diese Sammlung
verschieben oder dorthin kopieren.

### 2.3 Custom Field setzen

Bei jedem Eintrag in der Sammlung: **Bearbeiten → Benutzerdefiniertes Feld
hinzufügen → Typ Text**, Name exakt `agent-policy`, Wert `auto`, `ask` oder
`deny`.

Das kannst du jederzeit ändern – der Broker synchronisiert standardmäßig alle
60 Sekunden und liest die Policy bei jeder Anfrage frisch.

### 2.4 API-Key des Agent-Kontos holen

Im Vaultwarden **als `agent@...` anmelden**:

> Einstellungen → Mein Konto → ganz unten **API-Schlüssel** ("API Key") →
> Master-Passwort eingeben → `client_id` und `client_secret` notieren.

Diese beiden Werte werden gleich zu `BW_CLIENTID` und `BW_CLIENTSECRET`.

---

## 3. Installation

### 3.1 Ablage

Das Broker-Verzeichnis gehört **in** dein bestehendes Vaultwarden-Verzeichnis –
so landen alle Container im selben Compose-Projekt und damit im selben Netz:

```
vaultwarden-vps/
├── docker-compose.yml
├── Caddyfile
├── .env
└── vw-agent-broker/          ← dieses Verzeichnis
    ├── docker-compose.agent.yml
    ├── Caddyfile.agent
    ├── config.toml
    └── .env.broker
```

### 3.2 DNS

Zwei zusätzliche A-Records (und ggf. AAAA) auf die IP deines VPS:

```
broker.DEINE-DOMAIN
ntfy.DEINE-DOMAIN
```

Ohne DNS kann Let's Encrypt keine Zertifikate ausstellen.

### 3.3 Konfiguration

```bash
cd /pfad/zu/vaultwarden-vps/vw-agent-broker

cp config.toml.example config.toml
cp .env.broker.example .env.broker

# Geheimnisse erzeugen
openssl rand -hex 32     # -> BROKER_SERVER_SECRET
openssl rand -base64 24  # -> BROKER_ADMIN_PASS
```

In `config.toml` mindestens anpassen:

* `public_url` → `https://broker.DEINE-DOMAIN`
* `ntfy_url` → `https://ntfy.DEINE-DOMAIN`
* `ntfy_topic` → ein Name deiner Wahl, z.B. `vault-agent`

Die Geheimnisse (`BROKER_ADMIN_PASS`, `BROKER_SERVER_SECRET`,
`BROKER_NTFY_TOKEN`) trägst du in `.env.broker` ein – sie überschreiben die
Werte aus der `config.toml`, damit dort nichts Vertrauliches steht.

In die **`.env` des Vaultwarden-Stacks** (eine Ebene höher) kommen dazu:

```ini
BROKER_DOMAIN=broker.deine-domain.de
NTFY_DOMAIN=ntfy.deine-domain.de

# API-Key des agent@-Kontos (aus Schritt 2.4).
# Damit meldet sich die CLI an - entschluesseln kann sie den Tresor damit
# NICHT. Das Master-Passwort kommt bewusst nicht hierher.
BW_CLIENTID=user.xxxxxxxxxxxxxxxxxxxx
BW_CLIENTSECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Bequemlichkeit: dann genügt künftig "docker compose up -d"
COMPOSE_FILE=docker-compose.yml:vw-agent-broker/docker-compose.agent.yml
```

### 3.4 Caddy erweitern

Ans **Ende** der bestehenden `Caddyfile` (im Vaultwarden-Verzeichnis) anhängen:

```caddyfile
# Zusatz-Konfigurationen (Agent-Stack)
import /etc/caddy/conf.d/*.caddy
```

> Diese Zeile erst hinzufügen, wenn der Agent-Stack auch wirklich mitgestartet
> wird: Findet Caddy keine passende Datei, verweigert es den Start.

### 3.5 Starten

```bash
cd /pfad/zu/vaultwarden-vps

docker compose -f docker-compose.yml \
               -f vw-agent-broker/docker-compose.agent.yml up -d --build
```

(Mit `COMPOSE_FILE` in der `.env` reicht `docker compose up -d --build`.)

Kontrolle:

```bash
docker compose logs -f bw broker
curl -s https://broker.DEINE-DOMAIN/healthz
# {"bw":"locked","locked":true,"status":"degraded"}
```

`locked` ist hier **richtig so** – der Tresor wird im nächsten Schritt
entsperrt.

### 3.6 Tresor entsperren

`https://broker.DEINE-DOMAIN/admin` öffnen. Ganz oben erscheint der Kasten
**🔒 Tresor gesperrt**. Dort das **Master-Passwort des agent-Kontos**
eingeben und auf *Entsperren* klicken.

Das Passwort geht in genau einem Aufruf an den bw-Sidecar. Es wird **nicht**
protokolliert, **nicht** ins Audit-Log geschrieben und **nirgends**
gespeichert – im Audit-Log steht nur das Ereignis `unlock`.

Danach:

```bash
curl -s https://broker.DEINE-DOMAIN/healthz
# {"bw":"unlocked","locked":false,"status":"ok"}
```

Dasselbe ist nach jedem Neustart des `bw`-Containers nötig. Der Broker
erinnert dich per ntfy daran, sobald er den gesperrten Zustand bemerkt.

### 3.7 ntfy absichern und abonnieren

ntfy ist bewusst auf `deny-all` gestellt – ohne Zugangsdaten geht nichts. Das
ist wichtig: **wer die Push-Nachricht lesen kann, kann auf "Freigeben" tippen.**

```bash
# Benutzer für dein Handy anlegen (interaktive Passwortabfrage)
docker compose exec ntfy ntfy user add ich

# Nur dieses eine Topic freigeben
docker compose exec ntfy ntfy access ich vault-agent rw

# Token für den Broker erzeugen -> in .env.broker als BROKER_NTFY_TOKEN
docker compose exec ntfy ntfy token add ich
```

Danach `docker compose up -d broker`, damit der Broker das Token übernimmt.

In der **ntfy-App** (Android/iOS): Topic `vault-agent` hinzufügen, als Server
`https://ntfy.DEINE-DOMAIN` eintragen und die Zugangsdaten von `ich` hinterlegen.

Test:

```bash
curl -u ich:DEIN-PASSWORT -d "Test" https://ntfy.DEINE-DOMAIN/vault-agent
```

### Auto-Unlock (optional, nicht empfohlen)

Wenn dir wichtiger ist, dass der Broker einen Reboot **ohne Handgriff**
übersteht, kannst du das Master-Passwort als Docker-Secret hinterlegen. Der
Sidecar entsperrt sich dann beim Start selbst.

> **Das ist bewusst nicht der Standardweg.** Damit liegt das Master-Passwort
> des agent-Kontos im Klartext auf der Platte des VPS – und landet in jedem
> Backup dieses Verzeichnisses. Wer Lesezugriff auf die Datei bekommt, kann
> die gesamte Sammlung entschlüsseln. Der Schutz des Dashboard-Unlocks
> besteht gerade darin, dass es diese Datei **nicht** gibt.
>
> Sinnvoll höchstens dann, wenn der VPS ohnehin vollverschlüsselt ist und du
> das Neustart-Verhalten wichtiger findest als die Kompromittierbarkeit im
> Ruhezustand.

Passwortdatei anlegen (ohne Zeilenumbruch am Ende) und wegsperren:

```bash
cd /pfad/zu/vaultwarden-vps/vw-agent-broker
printf '%s' 'master-passwort-des-agent-kontos' > bw_password.secret
chmod 600 bw_password.secret
```

In `docker-compose.agent.yml` die vorbereiteten Zeilen einkommentieren:

* beim Dienst `bw`: `BW_PASSWORD_FILE: /run/secrets/bw_password` und den
  `secrets:`-Block darunter,
* ganz unten den `secrets:`-Abschnitt mit
  `file: ./vw-agent-broker/bw_password.secret`.

Dann `docker compose up -d bw`. Im Log steht anschließend eine deutliche
Warnung, und `healthz` meldet direkt `unlocked`.

Die Datei gehört in `.gitignore` (`*.secret` ist bereits eingetragen) und
**nicht** in ein Backup, das den Server verlässt.

---

## 4. Agent-Token anlegen

Jeder Agent bekommt ein eigenes Token. In der Datenbank liegt nur der
SHA-256-Hash – das Token selbst siehst du **genau einmal**.

### Per Kommandozeile

```bash
docker compose exec broker broker --create-token claude-desktop
```

Mit Einschränkungen:

```bash
# Token darf nie "auto" bekommen, es wird IMMER nachgefragt
docker compose exec broker broker --create-token ci-runner --max-policy ask

# Token sieht nur bestimmte Sammlungen
docker compose exec broker broker --create-token web-agent \
    --collections 9f3c...,a12b...
```

Die Sammlungs-IDs findest du im Dashboard oder über `GET /v1/items` – dort steht
bei jedem Eintrag `collection_ids`.

### Per Dashboard

`https://broker.DEINE-DOMAIN/admin` → Abschnitt **Agent-Tokens** → Name
eintragen, optional Sammlungen und `max_policy` wählen → **Token anlegen**. Das
Token wird einmalig angezeigt.

Kompromittiertes Token? Im Dashboard **Widerrufen** – wirkt sofort.

---

## 5. Einbindung in Claude (MCP)

Das Binary bringt einen MCP-Server mit, der lediglich die REST-API weiterreicht.
Der Agent-Rechner braucht damit nur `BROKER_URL` und `BROKER_TOKEN` – niemals
Vault-Zugangsdaten.

### Claude Code

```bash
claude mcp add vaultwarden \
  --env BROKER_URL=https://broker.deine-domain.de \
  --env BROKER_TOKEN=DEIN-AGENT-TOKEN \
  -- /usr/local/bin/broker mcp
```

### Claude Desktop

In `claude_desktop_config.json`
(macOS: `~/Library/Application Support/Claude/`,
Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "vaultwarden": {
      "command": "/usr/local/bin/broker",
      "args": ["mcp"],
      "env": {
        "BROKER_URL": "https://broker.deine-domain.de",
        "BROKER_TOKEN": "DEIN-AGENT-TOKEN"
      }
    }
  }
}
```

Das Binary bekommst du entweder aus dem Container …

```bash
docker compose cp broker:/usr/local/bin/broker ./broker
```

… oder durch lokales Bauen mit `cargo build --release`
(`target/release/broker`).

### Die drei Tools

| Tool               | Zweck                                                          |
|--------------------|----------------------------------------------------------------|
| `list_credentials` | Liste aller sichtbaren Einträge. **Nie** Passwörter.           |
| `get_credential`   | Felder holen (`password`, `username`, `totp`, `notes`, `urls` oder ein Custom Field). Bei `ask` **wartet** der Aufruf auf deine Freigabe (Standard 120 s, per `timeout_seconds` änderbar). |
| `request_totp`     | Aktueller TOTP-Code.                                            |

Beim Namen genügt ein Teilstring: `"Hetzner"` findet `Hetzner Cloud`. Ist der
Name mehrdeutig, meldet das Tool die Kandidaten zurück, statt zu raten.

Ist der Tresor gesperrt, antworten alle drei Tools mit einer klaren Meldung
("Der Tresor des Agent-Kontos ist gesperrt …") – Claude sagt dir dann also,
dass du im Dashboard entsperren musst, statt kryptisch zu scheitern.

Im Gespräch sieht das dann so aus:

> **Du:** Log dich per SSH auf dem Hetzner-Server ein.
> **Claude:** *(ruft `get_credential` auf)* …
> **Dein Handy:** 🔔 Zugriff auf "Hetzner Server" – Agent "claude-desktop"
> möchte: password → **Freigeben** / **Verweigern**

---

## 6. Die REST-API direkt benutzen

```bash
TOKEN=dein-agent-token
BROKER=https://broker.deine-domain.de
```

**Einträge auflisten** (nie mit Passwörtern):

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BROKER/v1/items | jq
```

```json
{
  "items": [
    {
      "id": "6c2f…",
      "name": "Hetzner Server",
      "username": "root",
      "urls": ["https://console.hetzner.cloud"],
      "policy": "ask",
      "has_totp": true,
      "organization_id": "1a2b…",
      "collection_ids": ["9f3c…"]
    }
  ]
}
```

**Zugangsdaten anfragen:**

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"fields":["password","username","totp"]}' \
     $BROKER/v1/items/6c2f…/credentials
```

* `200` → `policy: auto`, Werte liegen bei.
* `202` → `request_id`, Push ist unterwegs.
* `403` → durch `deny` oder Sammlungs-Beschränkung gesperrt.
* `503` → `{"error":"Broker gesperrt - im Dashboard entsperren"}`. Betrifft
  **alle** `/v1`-Endpunkte, solange der Tresor zu ist.

**Ergebnis abholen** (nur einmal!):

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BROKER/v1/requests/DIE-REQUEST-ID
```

Antworten: `{"status":"pending"}`, `{"status":"approved","values":{…}}`,
`{"status":"denied"}`, `{"status":"expired"}` oder `{"status":"delivered"}`
(die Werte wurden bereits abgeholt).

**Gesundheitsprüfung** (ohne Token) – zeigt auch den Schloss-Zustand:

```bash
curl -s $BROKER/healthz
# {"bw":"unlocked","locked":false,"status":"ok"}
# {"bw":"locked","locked":true,"status":"degraded"}   <- entsperren noetig
```

**Audit-Log** (Dashboard-Zugangsdaten):

```bash
curl -s -u admin:PASSWORT "$BROKER/admin/audit?limit=50" | jq
```

---

## 7. Das Dashboard

`https://broker.DEINE-DOMAIN/admin`, geschützt per HTTP-Basic-Auth aus
`admin_user` / `admin_pass`.

* **🔒 Tresor gesperrt** – erscheint ganz oben, sobald der Sidecar gesperrt
  ist. Master-Passwort des agent-Kontos eingeben, *Entsperren*, fertig. Der
  Kasten verschwindet von selbst, sobald der Tresor offen ist.
* **Offene Anfragen** – freigeben oder verweigern. Beim Freigeben wählbar:
  *nur dieses Mal*, *+1 Stunde merken*, *+24 Stunden merken*, *immer merken*.
* **Merken-Regeln** – heben `ask` → `auto` an, immer nur für die Kombination
  Eintrag + Agent. `immer` landet **nur in der Broker-Datenbank**, dein
  Tresor-Eintrag bleibt unverändert. Jederzeit löschbar.
* **Agent-Tokens** – anlegen und widerrufen.
* **Audit-Log** – wer, was, wann, welcher Agent, welches Ergebnis.
* **Einstellungen** – die geltende Konfiguration zum Nachsehen.

Die Liste offener Anfragen aktualisiert sich alle 5 Sekunden von selbst.

---

## 8. Sicherheitshinweise

**Was der Broker gut kann**

* Das Agent-Konto sieht **nur die freigegebene Sammlung** – nicht deinen
  restlichen Tresor. Das ist die wichtigste Grenze, und sie wird von
  Vaultwarden durchgesetzt, nicht vom Broker.
* **Kein Master-Passwort auf dem Server.** Auf der Platte liegt nur der
  API-Key, der den Tresor nicht entschlüsseln kann. Das Master-Passwort
  existiert nur im Arbeitsspeicher des bw-Sidecars – ab dem Moment, in dem du
  im Dashboard entsperrst, bis zum nächsten Neustart. Es wird weder
  protokolliert noch ins Audit-Log noch in die Datenbank geschrieben; dort
  steht nur das Ereignis `unlock`.
* **Gesperrt heißt dicht.** Solange der Tresor zu ist, beantwortet der Broker
  jede `/v1`-Anfrage mit `503` – auch bei gültigem Token und `auto`-Policy.
* **`deny` gewinnt immer.** Keine Merken-Regel und kein Dashboard-Klick hebt es auf.
* **Werte werden nie persistiert.** Die SQLite-Datei enthält Metadaten und
  Token-*Hashes*, keine Passwörter. Ein Backup der Broker-DB ist damit
  ungefährlich.
* **Einmal-Auslieferung.** Ein freigegebener Wert wird genau einmal abgeholt;
  danach ist die Anfrage verbraucht.
* **Signierte Einmal-Links.** Die ntfy-Knöpfe sind HMAC-signiert, an genau eine
  Anfrage gebunden, nach der Entscheidung verbraucht und nach `request_ttl`
  wertlos.
* **Vollständiges Audit.** Jeder Auflistungs-, Anfrage-, Freigabe- und
  Auslieferungsvorgang wird protokolliert – auch fehlgeschlagene Anmeldungen.

**Worauf du achten musst**

* **Schütze das ntfy-Topic.** Wer die Nachricht lesen kann, kann freigeben.
  Deshalb `deny-all` und ein eigener Benutzer (Schritt 3.6). Bei ntfy.sh
  statt Selbsthosting: unbedingt einen langen, zufälligen Topic-Namen.
* **Der Broker ist öffentlich erreichbar** – das muss er sein, damit die
  Knöpfe aus der Push-Nachricht funktionieren. Der Schutz sind die Tokens.
  Optional lässt sich `/admin` im `Caddyfile.agent` zusätzlich auf dein
  Heimnetz begrenzen (auskommentierter Block).
* **`auto` mit Bedacht.** Ein `auto`-Eintrag wird ohne Rückfrage
  herausgegeben – auch wenn der Agent gerade etwas tut, das du nicht wolltest.
  Für alles Wichtige: `ask` lassen. Als Kompromiss eignen sich Merken-Regeln
  mit 1 h oder 24 h statt `immer`.
* **Ein Token pro Agent.** Dann lässt sich im Audit-Log unterscheiden, wer was
  wollte, und ein einzelnes Token gezielt widerrufen.
* **`max_policy = ask`** für alles, was unbeaufsichtigt läuft (CI, Cronjobs).
  Dann kommt garantiert nie etwas ohne deine Bestätigung heraus.
* **Der bw-Sidecar hält die Schlüssel im entsperrten Zustand im Speicher.**
  Wer dann Root auf dem VPS hat, kommt an die Sammlung. Der Broker schützt vor
  einem übereifrigen Agenten, nicht vor einem kompromittierten Server. Im
  gesperrten Zustand ist dort dagegen nichts zu holen.
* **Auto-Unlock hebelt genau das aus.** Wer die Datei aus dem Abschnitt
  [Auto-Unlock](#auto-unlock-optional-nicht-empfohlen) anlegt, legt das
  Master-Passwort im Klartext auf die Platte – dann gilt der Vorteil oben
  nicht mehr. Im Zweifel: Finger weg und lieber einmal pro Reboot tippen.
* **Port 8087 nie veröffentlichen.** Die Vault Management API der CLI ist
  völlig ungeschützt. In der mitgelieferten Compose-Datei ist sie korrekt nur
  über `expose` im internen Netz erreichbar.

---

## 9. Fehlersuche

**`healthz` meldet `"bw":"locked"` oder `"unreachable"`**

```bash
docker compose logs bw
```

`"locked"` ist nach jedem Start der **Normalfall** – einmal im Dashboard
entsperren. Bleibt es `"unauthenticated"` oder `"unreachable"`, stimmen meist
`BW_CLIENTID`/`BW_CLIENTSECRET` nicht oder das agent-Konto hat 2FA aktiv.
Nach Änderungen:

```bash
docker compose restart bw
```

Bei hartnäckigen Anmeldeproblemen den CLI-Zustand zurücksetzen:

```bash
docker compose down bw
docker volume rm <projekt>_bw_data
docker compose up -d bw
```

**Agents bekommen 503 "Broker gesperrt"**

Normalfall nach einem Neustart: im Dashboard entsperren (Abschnitt 3.6).
Prüfen lässt sich das mit `curl -s $BROKER/healthz` → `"locked": true`.

**Entsperren schlägt fehl**

Bei `Invalid master password` das Passwort des **agent-Kontos** verwenden,
nicht deines. Meldet der Broker stattdessen `bw nicht erreichbar`, läuft der
Sidecar nicht – `docker compose logs bw`.

**Push kommt nicht an**

* Stimmen `ntfy_url` (Basis-URL, **ohne** Topic) und `ntfy_topic`?
* Ist `BROKER_NTFY_TOKEN` gesetzt und hat der Benutzer `rw` auf dem Topic?
* Test: `curl -u ich:PW -d "Test" https://ntfy.DEINE-DOMAIN/vault-agent`
* Der Broker protokolliert Push-Fehler im Audit-Log unter `request`
  (Detail `ntfy=fehler: …`). Die Anfrage erscheint trotzdem im Dashboard –
  fällt der Push aus, kannst du dort immer noch freigeben.

**Knöpfe in der Nachricht tun nichts**

`public_url` muss von deinem Handy aus erreichbar sein und exakt zur echten
URL passen – die Links werden daraus gebaut.

**Neuer Eintrag taucht nicht auf**

Der Broker synchronisiert alle `sync_interval` Sekunden. Sofort erzwingen:

```bash
docker compose restart broker
```

Und prüfen, ob der Eintrag wirklich in der Sammlung liegt, die dem
agent-Konto freigegeben ist.

**`401 Token unbekannt`**

Token falsch kopiert oder widerrufen. Im Dashboard unter *Agent-Tokens*
nachsehen und notfalls ein neues anlegen.

**`429 Rate-Limit erreicht`**

Mehr als `rate_limit` Anfragen pro Minute mit einem Token. Wert in der
`config.toml` anheben oder den Agenten bremsen.
