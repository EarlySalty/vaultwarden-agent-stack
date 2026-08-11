#!/usr/bin/env bash
#
# update.sh - Holt neue Images, startet die Container neu und raeumt auf.
# Vaultwarden fuehrt noetige Datenbank-Migrationen beim Start selbst aus.
#
# Empfehlung: vorher ein Backup ziehen (macht dieses Skript automatisch,
# sofern backup.sh vorhanden ist).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

info() { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }

SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi
DC() { $SUDO docker compose "$@"; }

# 1. Sicherheitsnetz: Backup vor dem Update
if [ -x "$SCRIPT_DIR/backup.sh" ]; then
    info "Backup vor dem Update ..."
    "$SCRIPT_DIR/backup.sh" || warn "Backup fehlgeschlagen - Update wird trotzdem fortgesetzt."
else
    warn "backup.sh nicht gefunden oder nicht ausfuehrbar - es wird ohne Backup aktualisiert."
fi

# Aktuell laufende Image-IDs merken, um spaeter gezielt aufzuraeumen
OLD_IMAGES="$($SUDO docker image inspect --format '{{.Id}}' vaultwarden/server:latest caddy:2 2>/dev/null || true)"

# 2. Neue Images holen
info "Neue Images herunterladen ..."
DC pull

# 3. Container mit den neuen Images neu erstellen
info "Container neu starten ..."
DC up -d

# 4. Aufraeumen: nur noch verwaiste (dangling) Images entfernen.
#    "docker image prune -a" wird bewusst NICHT benutzt, damit keine anderen
#    Projekte auf dem VPS beschaedigt werden.
info "Alte, nicht mehr referenzierte Images entfernen ..."
$SUDO docker image prune -f >/dev/null || true

if [ -n "$OLD_IMAGES" ]; then
    while IFS= read -r img; do
        [ -n "$img" ] || continue
        # Schlaegt fehl, solange das Image noch benutzt wird - genau so gewollt.
        $SUDO docker image rm "$img" >/dev/null 2>&1 || true
    done <<<"$OLD_IMAGES"
fi

echo
DC ps
echo
ok "Update abgeschlossen."
info "Versionen pruefen:  docker compose logs --tail=30 vaultwarden"
