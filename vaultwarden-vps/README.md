# Vaultwarden auf dem eigenen VPS – Umstieg von Dashlane

Dieses Paket enthält alles, um in etwa einer halben Stunde einen eigenen
Passwort-Server zu betreiben: Vaultwarden hinter einem Caddy-Reverse-Proxy mit
automatischem HTTPS, dazu Skripte für Einrichtung, Backup und Updates sowie
eine optionale fail2ban-Konfiguration.

## Überblick: warum Vaultwarden

Vaultwarden ist eine in Rust geschriebene, quelloffene Neuimplementierung der
Bitwarden-Server-API. Der offizielle Bitwarden-Server besteht aus einem knappen
Dutzend .NET-Containern plus MSSQL und will realistisch 2 GB RAM aufwärts.
Vaultwarden ist dagegen ein einziges statisch gelinktes Binary mit SQLite
darunter, das im Ruhezustand bei ungefähr 20 bis 50 MB Arbeitsspeicher liegt.
Ein VPS der kleinsten Klasse mit einem Kern und 1 GB RAM reicht für eine
Einzelperson oder eine Familie problemlos.

Der entscheidende Punkt für den Umstieg von Dashlane: Weil Vaultwarden die
Bitwarden-API spricht, funktionieren die ganz normalen, offiziellen
Bitwarden-Clients aus Play Store, App Store und den Browser-Stores. Man trägt
dort lediglich die eigene Server-URL ein. Es gibt also keine gebastelten
Drittanbieter-Apps, sondern gepflegte, auditierte Clients – nur eben mit dem
eigenen Server als Gegenstelle. Die Verschlüsselung passiert wie bei Dashlane
komplett auf dem Endgerät (AES-256, Schlüsselableitung per PBKDF2 oder Argon2id
aus dem Master-Passwort); der Server sieht ausschließlich Chiffrate.

Funktional bekommt man damit alles, was man von Dashlane gewohnt ist: Autofill
auf Android und im Browser, integrierter TOTP-Generator (der Zwei-Faktor-Codes
also gleich mitliefert), sichere Notizen, Zahlungsmittel und Identitäten,
Dateianhänge, geteilte Sammlungen für Familie oder Team, Passwortgenerator,
Passwort-Historie und einen Sicherheitsbericht über schwache oder mehrfach
verwendete Passwörter. Was Dashlane zusätzlich hat und hier fehlt, ist im
Wesentlichen das eingebaute VPN und das automatische Passwortwechseln auf
Webseiten.

Was in diesem Verzeichnis liegt:

- `docker-compose.yml` – die beiden Container (Vaultwarden, Caddy)
- `Caddyfile` – Reverse Proxy, TLS, Security-Header
- `.env.example` – kommentierte Vorlage für die Konfiguration
- `setup.sh` – Erstinstallation, idempotent
- `backup.sh` – konsistentes Backup mit Rotation
- `update.sh` – Images aktualisieren und aufräumen
- `fail2ban/` – optionale Sperrregeln gegen Anmeldeversuche

## Teil 1: Server aufsetzen

### DNS vorbereiten

Zuerst braucht die Instanz einen Namen. Bei der Domain-Verwaltung einen
A-Record anlegen, der auf die öffentliche IPv4-Adresse des VPS zeigt, zum
Beispiel `vault.example.de`. Wer IPv6 hat, legt zusätzlich einen AAAA-Record an.
Diesen Schritt zuerst machen, denn Let's Encrypt prüft beim Ausstellen des
Zertifikats, ob die Domain tatsächlich auf diesen Server zeigt. Bis die
Änderung überall sichtbar ist, können ein paar Minuten vergehen; prüfen lässt
sich das mit `dig +short vault.example.de`.

### Paket auf den Server bringen

Per SSH auf den VPS verbinden und das Verzeichnis hochladen. Vom eigenen
Rechner aus:

```
scp -r vaultwarden-vps root@DEINE-SERVER-IP:/opt/
```

Alternativ, falls das Paket in einem Git-Repository liegt:

```
ssh root@DEINE-SERVER-IP
apt update && apt install -y git
git clone https://example.de/dein/repo.git /opt/vaultwarden-vps
```

### Setup ausführen

```
cd /opt/vaultwarden-vps
chmod +x setup.sh backup.sh update.sh
./setup.sh
```

Das Skript prüft, ob Docker und das Compose-Plugin vorhanden sind, und
installiert sie andernfalls über das offizielle Skript von `get.docker.com`.
Danach legt es aus `.env.example` eine `.env` an und fragt interaktiv die Domain
und die E-Mail-Adresse für Let's Encrypt ab. Anschließend erzeugt es einen
kryptografisch zufälligen Admin-Token, hasht ihn mit Argon2id und trägt den
Hash in die `.env` ein. Falls eine Firewall per UFW aktiv ist, werden die Ports
80 und 443 freigegeben, und zum Schluss startet es die Container.

Der Token im Klartext landet in `admin-token.txt`. Diesen Wert braucht man für
die Anmeldung am Admin-Panel – also in den Passwort-Manager übernehmen (nach
dem ersten Login gerne in den Vault selbst) und die Datei danach löschen.

Ein Detail zur `.env`, das erfahrungsgemäß Ärger macht: Der Argon2-Hash sieht
aus wie `$argon2id$v=19$m=65540,t=3,p=4$...` und enthält damit Dollarzeichen.
Docker Compose liest die `.env` selbst ein und würde `$argon2id` oder `$v` als
Variablennamen interpretieren und durch nichts ersetzen – der Token stimmt dann
nie. Die Lösung ist, den Wert in **einfache** Anführungszeichen zu setzen, denn
darin findet keine Ersetzung statt. `setup.sh` macht das automatisch, und beim
manuellen Nachtragen muss man daran denken:

```
ADMIN_TOKEN='$argon2id$v=19$m=65540,t=3,p=4$c2FsdA$aGFzaA'
```

Ein Escapen mit doppelten Dollarzeichen ist hier weder nötig noch richtig.

### Zertifikat und erster Login

Caddy holt beim Start automatisch ein Let's-Encrypt-Zertifikat. Beobachten kann
man das mit `docker compose logs -f caddy`; im Erfolgsfall taucht dort eine
Zeile mit `certificate obtained successfully` auf. Danach ist
`https://vault.example.de` erreichbar. Dort auf "Konto erstellen" gehen und ein
Master-Passwort vergeben.

Zum Master-Passwort ein ernstes Wort: Es gibt keine Wiederherstellung. Wer es
verliert, verliert den Tresor. Eine Passphrase aus fünf bis sechs zufälligen
Wörtern ist gut merkbar und stark genug; zusätzlich sollte man sie einmal auf
Papier notieren und an einem sicheren Ort verwahren.

### Registrierung schließen

Solange `SIGNUPS_ALLOWED=true` gesetzt ist, kann sich jeder, der die URL kennt,
ein Konto anlegen. Deshalb direkt nach der eigenen Registrierung:

```
cd /opt/vaultwarden-vps
sed -i 's/^SIGNUPS_ALLOWED=.*/SIGNUPS_ALLOWED=false/' .env
docker compose up -d
```

Weitere Personen lassen sich danach jederzeit über das Admin-Panel einladen,
die globale Registrierung bleibt trotzdem zu.

### Admin-Panel

Unter `https://vault.example.de/admin` liegt die Serververwaltung: Benutzer
anlegen und einladen, Diagnose, Einstellungen zur Laufzeit ändern. Angemeldet
wird sich mit dem Klartext-Token aus `admin-token.txt`. Das Panel verwaltet den
Server, nicht die Passwörter – die eigentlichen Vault-Daten sind auch für den
Admin unlesbar.

## Teil 2: Daten aus Dashlane übernehmen

### Export

Der Export geht nur aus der Dashlane-Desktop-App oder der Web-App, nicht aus
der Mobil-App. In den Einstellungen findet sich der Punkt zum Datenexport, dort
"Daten exportieren nach .CSV" wählen. Dashlane fragt zur Bestätigung das
Master-Passwort ab und legt anschließend ein ZIP-Archiv beziehungsweise mehrere
CSV-Dateien ab – üblicherweise getrennt nach Logins, sicheren Notizen,
Zahlungsmitteln und persönlichen Daten.

Diese Dateien sind vollständig unverschlüsselter Klartext. Sie gehören daher
weder in die Cloud noch in den Mail-Anhang, sondern bleiben bis zum Import auf
dem lokalen Rechner und werden danach sofort gelöscht.

### Import

Im Browser das eigene Web-Vault unter `https://vault.example.de` öffnen,
anmelden und zu "Werkzeuge" (Tools) und dort "Daten importieren" gehen. Als
Format `Dashlane (csv)` auswählen, die Datei hochladen und importieren. Wer
mehrere CSV-Dateien aus dem Export hat, importiert sie nacheinander.

Wichtig: Der Import legt jedes Mal neue Einträge an und gleicht nichts ab. Wenn
also etwas schiefgeht, ist es einfacher, alle Einträge zu löschen und sauber neu
zu importieren, als Dubletten von Hand zu suchen.

Nach dem Import unbedingt kontrollieren, ob alles angekommen ist. Erfahrungsgemäß
gibt es drei Stellen, die Nacharbeit brauchen:

- **Gesperrte oder als besonders geschützt markierte Notizen** exportiert
  Dashlane teilweise gar nicht oder nur unvollständig. Diese Einträge vor dem
  Abschalten des Dashlane-Kontos einzeln durchsehen und bei Bedarf von Hand
  übertragen.
- **Zwei-Faktor-Seeds (TOTP)** wandern beim CSV-Export nicht mit. Sie müssen
  neu hinterlegt werden, siehe unten.
- **Dateianhänge** aus Dashlane sind nicht Teil des CSV-Exports und müssen
  einzeln heruntergeladen und im jeweiligen Bitwarden-Eintrag wieder angehängt
  werden.

### TOTP-Codes wieder einrichten

Bitwarden bringt einen eigenen Authenticator mit, der die
Zwei-Faktor-Zeitcodes direkt beim passenden Login erzeugt – genau wie Dashlane
Authenticator. Dafür den betreffenden Eintrag im Vault bearbeiten und im Feld
"Authenticator-Schlüssel (TOTP)" den Seed eintragen. Den bekommt man beim
Einrichten von 2FA auf der jeweiligen Webseite: Statt den QR-Code zu scannen,
klickt man auf "Schlüssel manuell eingeben" und kopiert die Zeichenkette. Auch
eine komplette `otpauth://`-URI wird akzeptiert. In der Android-App kann man
stattdessen den QR-Code direkt mit der Kamera scannen, das ist der bequemste
Weg.

Praktischer Ablauf: Bei jedem Dienst mit aktivem 2FA einmal in die
Sicherheitseinstellungen gehen, 2FA neu einrichten, den Seed in Bitwarden
hinterlegen und die neuen Wiederherstellungscodes als sichere Notiz im Vault
ablegen. Danach den alten Authenticator entfernen.

### CSV sicher löschen

Nach erfolgreichem Import die Exportdateien und den Papierkorb leeren. Unter
Linux und macOS:

```
shred -u ~/Downloads/dashlane-export*.csv
```

Unter Windows die Dateien löschen und den Papierkorb leeren; auf SSDs bringt
Überschreiben ohnehin wenig, entscheidend ist, dass die Datei nicht liegen
bleibt.

Das Dashlane-Konto selbst erst kündigen, wenn der neue Tresor mehrere Tage im
Alltag getestet wurde.

## Teil 3: Android einrichten

Aus dem Play Store die App **Bitwarden** installieren (Herausgeber: Bitwarden
Inc., nicht "Bitwarden Authenticator", das ist eine separate App).

Vor der Anmeldung muss die App auf den eigenen Server zeigen. Auf dem
Anmeldebildschirm oben die Region beziehungsweise den Server auswählen und dort
"Selbst gehostet" wählen. Als Server-URL `https://vault.example.de` eintragen,
speichern und sich danach ganz normal mit E-Mail und Master-Passwort anmelden.
Diese Einstellung muss vor dem ersten Login gesetzt werden, sonst versucht die
App sich gegen die Bitwarden-Cloud anzumelden.

Damit sich die App so anfühlt wie Dashlane, sind vier Einstellungen relevant.
Alle finden sich unter Einstellungen:

Unter **Autofill** den Punkt "Autofill-Dienste" aktivieren. Android fragt dann
nach der Berechtigung, Bitwarden als System-Autofill-Dienst zu setzen –
bestätigen. Direkt darunter "Inline-Autofill" einschalten: Damit erscheinen die
Vorschläge als Leiste direkt über der Tastatur, was dem Popup von Dashlane am
nächsten kommt. Der zusätzlich angebotene "Zugriffsdienst" beziehungsweise das
Overlay ist nur für Apps und Browser nötig, die den regulären Autofill-Rahmen
nicht unterstützen; er kostet etwas Akku und lässt sich zunächst weglassen.
Wenn Autofill in einzelnen Apps nicht anspringt, ist er der Hebel.

Unter **Konto-Sicherheit** die Option "Entsperren mit Biometrie" aktivieren.
Danach reicht der Fingerabdruck zum Öffnen des Tresors und zur Bestätigung beim
Ausfüllen; das Master-Passwort wird nur noch gelegentlich verlangt. Dort stellt
man auch die Sperrzeit ein – "nach 15 Minuten" oder "beim Sperren des
Bildschirms" ist ein vernünftiger Kompromiss.

Ebenfalls unter Autofill liegt **"TOTP automatisch kopieren"**. Ist das aktiv,
schreibt Bitwarden nach dem Ausfüllen von Benutzername und Passwort den
aktuellen 2FA-Code automatisch in die Zwischenablage. Auf der Folgeseite genügt
dann langes Antippen des Codefelds und "Einfügen". In den Einstellungen unter
"Sonstiges" lässt sich außerdem "Zwischenablage automatisch löschen" auf
beispielsweise 30 Sekunden stellen, damit der Code nicht liegen bleibt.

Sinnvoll ist zuletzt, unter Autofill auch die Option zum Speichern neuer
Zugangsdaten zu aktivieren, damit Bitwarden beim Anlegen eines Kontos in einer
App von sich aus fragt, ob es den Eintrag übernehmen soll.

Wer möchte, dass Änderungen sofort auf dem Handy ankommen statt erst beim
nächsten Öffnen der App, aktiviert serverseitig die Push-Unterstützung: auf
`https://bitwarden.com/host` kostenlos eine Installations-ID und einen Key
anfordern und beides in der `.env` unter `PUSH_ENABLED`,
`PUSH_INSTALLATION_ID` und `PUSH_INSTALLATION_KEY` eintragen. Über Bitwardens
Relay läuft dabei nur das Signal "es gibt etwas Neues", keine Tresordaten.

## Teil 4: Browser-Erweiterung

Die Erweiterung gibt es für Chrome, Edge, Firefox und Safari. Nach der
Installation zuerst im Anmeldedialog über die Server-Auswahl auf "Selbst
gehostet" wechseln und die eigene URL eintragen, dann anmelden.

In den Einstellungen der Erweiterung unter "Autofill" lohnen sich drei
Schalter. **"Autofill-Vorschläge auf Formularfeldern anzeigen"** blendet ein
kleines Inline-Menü direkt im Eingabefeld ein, aus dem man den passenden
Eintrag auswählt – das ist praktisch dasselbe Bedienmuster wie das
Dashlane-Popup im Feld. **"Autofill beim Laden der Seite"** füllt Anmeldedaten
automatisch aus, sobald die Seite geladen ist; das ergibt den bequemen
Auto-Login, funktioniert aber sinnvoll nur, wenn für die Domain genau ein
Eintrag existiert, und lässt sich pro Eintrag einzeln erlauben. Wer ganz sicher
gehen will, lässt die Option global aus und aktiviert sie nur bei einzelnen
Einträgen im Reiter "Weitere Optionen".

Für Zwei-Faktor-Codes gilt in der Erweiterung dasselbe Prinzip wie auf Android:
Nach dem Autofill landet der aktuelle TOTP-Code in der Zwischenablage
(Einstellung "TOTP automatisch kopieren"), und in vielen Fällen bietet das
Inline-Menü den Code auch direkt zum Einsetzen im 2FA-Feld an. Zusätzlich zeigt
das Popup der Erweiterung den laufenden Code samt Restzeit an.

Das wichtigste Tastenkürzel ist **Strg + Shift + L** (macOS: Cmd + Shift + L):
füllt den passenden Eintrag für die aktuelle Seite aus; mehrfaches Drücken
schaltet zwischen mehreren Treffern um. Mit **Strg + Shift + Y** öffnet sich
das Popup. Alle Kürzel lassen sich in der Browser-Verwaltung der Erweiterungen
umbelegen.

## Teil 5: Desktop und Web-Vault

Die Desktop-App für Windows, macOS und Linux gibt es unter
`bitwarden.com/download`, unter Linux auch als Flatpak oder Snap. Auch hier vor
dem Login die Region auf "Selbst gehostet" umstellen und die eigene URL
eintragen. Die App unterstützt Entsperren per Windows Hello, Touch ID oder
Fingerabdruck und kann sich mit der Browser-Erweiterung verbinden, sodass diese
sich mit über die Biometrie des Systems entsperren lässt.

Das Web-Vault unter der eigenen Domain ist der Ort für alles Umfangreichere:
Import und Export, Massenbearbeitung, Organisationen und Sammlungen anlegen,
Zwei-Faktor-Anmeldung einrichten und den Sicherheitsbericht ansehen. Für den
Alltag genügen Erweiterung und Handy-App.

## Teil 6: Struktur – von Dashlane-Sammlungen zu Ordnern

Dashlane sortiert Einträge in Sammlungen. In Bitwarden gibt es dafür zwei
Konzepte, die man nicht verwechseln sollte.

**Ordner** sind rein persönlich und dienen der eigenen Übersicht. Ein Eintrag
liegt in genau einem Ordner. Verschachtelung entsteht über Schrägstriche im
Namen: Ein Ordner namens `Arbeit/Kunden` erscheint als Unterordner von
`Arbeit`. Für den Umzug aus Dashlane ist das in aller Regel die passende
Entsprechung.

**Organisationen mit Sammlungen** sind das Gegenstück zum Sharing Center von
Dashlane. Man legt im Web-Vault eine Organisation an (in Vaultwarden ist das
kostenlos und ohne Nutzerlimit), erstellt darin Sammlungen wie "Familie" oder
"Haushalt", verschiebt Einträge dorthin und lädt andere Personen ein. Wer
Zugriff auf eine Sammlung hat, sieht deren Einträge in seinem eigenen Tresor,
inklusive Autofill. Berechtigungen lassen sich pro Sammlung auf "nur lesen"
oder "verstecktes Passwort" einstellen. Einladungen laufen über das Web-Vault
und – wenn kein SMTP konfiguriert ist – über die Bestätigung im Admin-Panel.

Zusätzlich helfen Favoriten (Stern-Symbol, erscheinen ganz oben) und die
Volltextsuche, die auch Notizen und benutzerdefinierte Felder durchsucht.

## Teil 7: Betrieb

### Backups

`backup.sh` zieht die SQLite-Datenbank sauber über `sqlite3 .backup` – ein
einfaches Kopieren der laufenden Datei würde beschädigte Sicherungen
produzieren – und packt sie zusammen mit Anhängen, Sends, dem
RSA-Signaturschlüssel, `config.json` sowie den Konfigurationsdateien in ein
Archiv unter `backups/`. Die letzten 14 Archive bleiben erhalten, ältere werden
automatisch entfernt.

Täglich um 3:30 Uhr per cron (`crontab -e`):

```
30 3 * * * /opt/vaultwarden-vps/backup.sh >> /var/log/vaultwarden-backup.log 2>&1
```

Entscheidend ist die Kopie außer Haus. Ein Backup, das nur auf demselben VPS
liegt, hilft bei einem Serverausfall nicht. Am Ende von `backup.sh` stehen
auskommentierte Beispielzeilen für `rclone`, `scp` und `rsync` sowie für eine
zusätzliche GPG-Verschlüsselung – eine davon aktivieren. Und: Ein Backup, das
man nie zurückgespielt hat, ist kein Backup. Einmal testweise auf einem zweiten
Server auspacken, `docker compose up -d` und prüfen, ob die Anmeldung geht.

Wiederherstellen geht so: Container stoppen (`docker compose down`), das Archiv
nach `vw-data/` entpacken, `db.sqlite3` an die richtige Stelle legen und wieder
starten.

Ergänzend kann jeder Nutzer im Web-Vault unter Werkzeuge einen verschlüsselten
Export seines persönlichen Tresors ziehen. Das ist die Rettungsleine, falls der
Server dauerhaft weg ist.

### Updates

```
cd /opt/vaultwarden-vps
./update.sh
```

Das Skript legt vorher ein Backup an, holt die neuen Images, startet die
Container neu und entfernt anschließend nicht mehr benötigte Images. Nötige
Datenbank-Migrationen führt Vaultwarden beim Start selbst aus. Ein Blick alle
paar Wochen genügt; Sicherheitsupdates werden im Vaultwarden-Repository
angekündigt.

Das Betriebssystem selbst nicht vergessen: `apt update && apt upgrade`,
idealerweise mit `unattended-upgrades` für Sicherheitspatches.

### fail2ban

Im Verzeichnis `fail2ban/` liegen eine Jail-Definition und zwei Filter, die
fehlgeschlagene Anmeldungen und Fehlversuche am Admin-Panel erkennen und die
IP-Adresse sperren. Die Einrichtung in Kurzform:

```
apt install -y fail2ban
cp fail2ban/vaultwarden.local               /etc/fail2ban/jail.d/vaultwarden.local
cp fail2ban/filter.d-vaultwarden.conf       /etc/fail2ban/filter.d/vaultwarden.conf
cp fail2ban/filter.d-vaultwarden-admin.conf /etc/fail2ban/filter.d/vaultwarden-admin.conf
# in jail.d/vaultwarden.local den logpath an das eigene Verzeichnis anpassen
systemctl restart fail2ban
fail2ban-client status vaultwarden
```

Damit das funktioniert, muss in der `.env` `LOG_FILE=/data/vaultwarden.log`
gesetzt sein (Standard in diesem Paket) und die echte Client-IP im Log landen.
Dafür sorgen `IP_HEADER=X-Real-IP` in der `.env` und die Zeile
`header_up X-Real-IP {remote_host}` im Caddyfile – ohne diese Kombination
protokolliert Vaultwarden nur die interne Docker-Adresse von Caddy, und
fail2ban würde den eigenen Reverse Proxy sperren.

### Sicherheitshinweise

Für das Vault-Konto selbst sollte Zwei-Faktor-Authentifizierung aktiv sein: im
Web-Vault unter Einstellungen und "Zweistufige Anmeldung", entweder per
Authenticator-App oder – deutlich komfortabler und phishing-resistent – per
Passkey beziehungsweise Hardware-Schlüssel (WebAuthn). Die
Wiederherstellungscodes ausdrucken und getrennt vom Server aufbewahren, denn
ohne sie und ohne zweiten Faktor sperrt man sich selbst aus.

Der Admin-Token ist der Generalschlüssel zur Serververwaltung. Er gehört nicht
in ein Git-Repository, nicht in eine Chat-Nachricht und idealerweise nur als
Argon2-Hash in die `.env`. Wer das Panel gar nicht braucht, kann die Zeile
`ADMIN_TOKEN` leeren – dann ist `/admin` vollständig deaktiviert.

Noch robuster wird es, wenn `/admin` nur aus dem eigenen Netz erreichbar ist.
Dafür im `Caddyfile` innerhalb des Site-Blocks die vorbereiteten Zeilen
einkommentieren und anpassen:

```
@admin_gesperrt {
	path /admin*
	not remote_ip 203.0.113.7 192.168.0.0/16
}
respond @admin_gesperrt "Not Found" 404
```

Danach `docker compose restart caddy`. Wer keine feste IP hat, kann
stattdessen `/admin` nur über einen WireGuard-Tunnel erreichbar machen oder das
Panel dauerhaft deaktiviert lassen und nur bei Bedarf kurz einschalten.

Zum VPS selbst gehören die üblichen Grundlagen: SSH-Login nur mit Schlüssel,
Passwort-Authentifizierung und direkter Root-Login abgeschaltet, UFW so
konfiguriert, dass außer SSH nur 80 und 443 offen sind. Falls der Anbieter eine
Cloud-Firewall im Webpanel hat, dort dieselben Regeln setzen. Und in der
Weboberfläche unter den Sicherheitseinstellungen die KDF-Einstellung des
eigenen Kontos auf Argon2id umstellen – das ist gegenüber PBKDF2 deutlich
widerstandsfähiger gegen Angriffe mit Grafikkarten.

Ein letzter Punkt zur Verfügbarkeit: Wenn der VPS ausfällt, ist der Tresor
nicht weg. Alle Clients halten eine lokale, verschlüsselte Kopie und
funktionieren offline weiter – nur Änderungen können dann nicht synchronisiert
werden.

## Teil 8: Was noch fehlt und wo Rust später weiterhilft

Zwei Dinge aus der Dashlane-Welt lassen sich mit diesem Setup nicht abbilden:
das mitgelieferte VPN (dafür wäre ein eigener WireGuard-Server auf demselben
VPS die naheliegende Ergänzung) und das automatische Ändern von Passwörtern auf
Webseiten. Auch das Dark-Web-Monitoring gibt es hier nicht eingebaut; die
Prüfung gegen bekannte Leaks über Have I Been Pwned ist im Sicherheitsbericht
des Web-Vaults aber enthalten.

Wer ohnehin in Richtung Rust unterwegs ist, findet an der Bitwarden-API einen
dankbaren Spielplatz. Die API ist dokumentiert, und mit `reqwest` und `serde`
ist ein kleiner Client schnell gebaut. Naheliegende eigene Werkzeuge wären ein
CLI, das Secrets für Deployments direkt aus dem Tresor zieht, statt sie in
`.env`-Dateien abzulegen; ein Prüf-Job, der den Bestand regelmäßig gegen die
k-Anonymity-API von Have I Been Pwned abgleicht und per E-Mail meldet; ein
Reporting-Tool, das die SQLite-Datenbank direkt liest und Kennzahlen über
Alter und Wiederverwendung von Passwörtern ausgibt; oder ein Wächter, der
Backups nicht nur anlegt, sondern automatisch in einem Wegwerf-Container
zurückspielt und verifiziert, dass die Datenbank tatsächlich öffnet.

Für den Einstieg lohnt ein Blick in die Vaultwarden-Quellen selbst: Das Projekt
nutzt Rocket als Web-Framework und Diesel als ORM und ist ein gut lesbares
Beispiel dafür, wie eine kompatible API-Reimplementierung sauber strukturiert
wird.

## Teil 9: Dashlane-Funktionen im Detail – was wo steckt

Ein kurzes Mapping der Funktionen aus deinen Screenshots auf das neue Setup.

**Passwort-Verlauf ("Verlauf anzeigen"):** Bitwarden führt pro Eintrag eine
Passwort-Historie. Öffne einen Login und scrolle nach unten zu
"Passwort-Historie" – dort stehen die alten Passwörter mit Datum, falls du
eines versehentlich überschreibst. Zusätzlich gibt es beim Bearbeiten den
Punkt "Gelöschte Elemente" (Papierkorb, 30 Tage) als zweites Netz.

**Passwortintegrität (der 88/100-Score):** Im Web-Vault unter Berichte findest
du die Berichte zu wiederverwendeten, schwachen und geleakten Passwörtern
(Have-I-Been-Pwned-Abgleich). Vaultwarden schaltet diese Premium-Berichte
kostenlos frei.

**Autofill überall (Logins, persönliche Daten, Kreditkarten):** Die
Browser-Erweiterung bietet das Inline-Menü nicht nur für Logins, sondern auch
für Identitäten (Name, E-Mail, Adresse – wie in deinem IG-Formular) und
Zahlungsmittel. In den Erweiterungs-Einstellungen unter Autofill:
"Autofill-Vorschläge auf Formularfeldern anzeigen" aktivieren und darunter
auch für Karten und Identitäten einschalten. Der Passwortgenerator erscheint
ebenfalls im Inline-Menü bei Registrierungsfeldern, und beim Absenden eines
neuen Logins fragt Bitwarden wie Dashlane "Soll ich das speichern?".

**Passkeys:** Die Erweiterung fängt WebAuthn-Anfragen ab und bietet an,
Passkeys im Tresor zu speichern und damit anzumelden – auch das synchronisiert
über deinen Server auf alle Geräte. Auf Android funktionieren Passkeys über
die Bitwarden-App als Passkey-Anbieter (Android-Einstellungen → Passwörter &
Konten → Bitwarden als bevorzugten Dienst wählen).

**2FA-QR-Code scannen:** Am Handy wie gewohnt – im Eintrag auf
"Authentifizierungsschlüssel einrichten" tippen und den QR-Code von deinem
Desktop-Bildschirm abscannen; durch den Sofort-Sync ist der TOTP-Generator
sekunden später auch im Browser und am Desktop verfügbar. Im Browser geht es
außerdem ohne Handy: Rechtsklick auf den QR-Code → Bild kopieren, dann im
Eintrag den Setup-Schlüssel einfügen – oder du nutzt die Kamera-Scan-Funktion
der Erweiterung, sofern dein Browser Kamerazugriff hat. (Ein eigenes
Rust-Tool, das den QR-Code direkt vom Bildschirm liest und in den Tresor
schreibt, steht auf der Ausbauliste – siehe Teil 8.)

**Sofortiger Sync zwischen App und Web:** Der Web-Vault liest immer live vom
Server. Damit die Android-App Änderungen sofort mitbekommt (statt beim
nächsten Öffnen), aktiviere Mobile Push: auf https://bitwarden.com/host eine
kostenlose Installation-ID + Key holen, in der `.env` bei `PUSH_ENABLED=true`,
`PUSH_INSTALLATION_ID` und `PUSH_INSTALLATION_KEY` eintragen und
`docker compose up -d` neu ausführen. Danach synct jede Änderung unmittelbar
auf alle Geräte.
