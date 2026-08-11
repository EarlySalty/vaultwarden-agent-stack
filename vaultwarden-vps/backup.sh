#!/usr/bin/env bash
#
# backup.sh - Konsistentes Backup der Vaultwarden-Daten.
#
# Wichtig: db.sqlite3 darf NICHT einfach kopiert werden, solange Vaultwarden
# laeuft - dabei entstehen kaputte Sicherungen (WAL/Journal nicht eingerechnet).
# Deshalb wird die Datenbank ueber "sqlite3 .backup" sauber herausgezogen.
#
# Reihenfolge der Versuche:
#   1. sqlite3 auf dem Host
#   2. sqlite3 in einem kurzlebigen Alpine-Container
#   3. Notfall: Container stoppen, kopieren, wieder starten
#
# Gesichert werden: Datenbank, attachments/, sends/, rsa_key* (Token-Signatur),
# config.json (Admin-Panel-Einstellungen) sowie .env, Caddyfile und
# docker-compose.yml zur schnellen Wiederherstellung.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DATA_DIR="$SCRIPT_DIR/vw-data"
BACKUP_DIR="$SCRIPT_DIR/backups"
KEEP=14                                  # Anzahl aufzubewahrender Sicherungen
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
ARCHIVE="$BACKUP_DIR/vaultwarden_${STAMP}.tar.gz"

info() { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

[ -d "$DATA_DIR" ] || fail "Datenverzeichnis $DATA_DIR nicht gefunden."
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/vwbackup.XXXXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT

# ----------------------------------------------------------------------------
# 1. Datenbank konsistent sichern
# ----------------------------------------------------------------------------

DB_SRC="$DATA_DIR/db.sqlite3"

if [ -f "$DB_SRC" ]; then
    if command -v sqlite3 >/dev/null 2>&1; then
        info "Sichere SQLite-Datenbank mit dem sqlite3 des Hosts ..."
        sqlite3 "$DB_SRC" ".backup '$STAGE/db.sqlite3'"
    elif command -v docker >/dev/null 2>&1 \
         && $SUDO docker run --rm -v "$DATA_DIR:/vwdata:ro" -v "$STAGE:/out" alpine:3 \
              sh -c 'apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /vwdata/db.sqlite3 ".backup /out/db.sqlite3"' 2>/dev/null; then
        info "SQLite-Datenbank ueber Alpine-Container gesichert."
    else
        warn "Kein sqlite3 verfuegbar - Notfallweg: Container wird kurz gestoppt."
        $SUDO docker compose stop vaultwarden >/dev/null
        cp "$DB_SRC" "$STAGE/db.sqlite3"
        $SUDO docker compose start vaultwarden >/dev/null
        info "Container laeuft wieder."
    fi
    ok "Datenbank gesichert ($(du -h "$STAGE/db.sqlite3" | cut -f1))."
else
    warn "db.sqlite3 nicht gefunden - laeuft die Instanz auf PostgreSQL/MySQL?"
    warn "Dann bitte zusaetzlich pg_dump bzw. mysqldump einplanen."
fi

# ----------------------------------------------------------------------------
# 2. Restliche Nutzdaten einsammeln
# ----------------------------------------------------------------------------

# rsa_key* : Signaturschluessel der Sitzungstokens. Fehlt er nach einem
#            Restore, muessen sich alle Clients neu anmelden.
for item in attachments sends config.json rsa_key.pem rsa_key.pub.pem rsa_key.der rsa_key.pub.der; do
    if [ -e "$DATA_DIR/$item" ]; then
        cp -a "$DATA_DIR/$item" "$STAGE/"
    fi
done

# Konfiguration mitsichern - macht ein Wiederaufsetzen auf einem neuen VPS trivial.
for cfg in .env Caddyfile docker-compose.yml; do
    [ -f "$SCRIPT_DIR/$cfg" ] && cp -a "$SCRIPT_DIR/$cfg" "$STAGE/$cfg"
done

# icon_cache wird bewusst NICHT gesichert (reiner Cache, baut sich neu auf).

# ----------------------------------------------------------------------------
# 3. Archiv schreiben
# ----------------------------------------------------------------------------

tar -czf "$ARCHIVE" -C "$STAGE" .
chmod 600 "$ARCHIVE"
ok "Backup erstellt: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"

# ----------------------------------------------------------------------------
# 4. Rotation - die letzten $KEEP Archive behalten
# ----------------------------------------------------------------------------

mapfile -t ALLE < <(ls -1t "$BACKUP_DIR"/vaultwarden_*.tar.gz 2>/dev/null || true)
if [ "${#ALLE[@]}" -gt "$KEEP" ]; then
    for alt in "${ALLE[@]:$KEEP}"; do
        rm -f -- "$alt"
        info "Altes Backup entfernt: $(basename "$alt")"
    done
fi
info "Vorhandene Sicherungen: $(ls -1 "$BACKUP_DIR"/vaultwarden_*.tar.gz 2>/dev/null | wc -l) (Aufbewahrung: $KEEP)"

# ----------------------------------------------------------------------------
# 5. Offsite-Kopie (dringend empfohlen!)
# ----------------------------------------------------------------------------
# Ein Backup, das nur auf demselben VPS liegt, ist bei Serververlust wertlos.
# Eine der folgenden Zeilen einkommentieren und anpassen:
#
#   rclone copy "$ARCHIVE" hetzner-box:vaultwarden/ --log-level NOTICE
#   scp "$ARCHIVE" backup@heim-nas:/volume1/backups/vaultwarden/
#   rsync -az "$ARCHIVE" backup@heim-nas:/volume1/backups/vaultwarden/
#
# Noch besser zusaetzlich verschluesseln, bevor es das Haus verlaesst:
#   gpg --batch --yes --symmetric --cipher-algo AES256 \
#       --passphrase-file /root/.vw-backup-pass "$ARCHIVE"
#   rclone copy "${ARCHIVE}.gpg" hetzner-box:vaultwarden/
#
# Hinweis: Das Archiv enthaelt die verschluesselte Vault-Datenbank UND die
# .env mit dem ADMIN_TOKEN - entsprechend behandeln.
# ----------------------------------------------------------------------------

ok "Fertig."
