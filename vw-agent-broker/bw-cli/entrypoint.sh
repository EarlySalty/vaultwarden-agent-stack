#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Meldet die Bitwarden CLI am eigenen Vaultwarden an und startet die Vault
# Management API (`bw serve`).
#
# WICHTIG: Der Tresor startet bewusst im GESPERRTEN Zustand. Das Master-
# Passwort liegt nirgends auf dem Server - es wird einmalig ueber das
# Broker-Dashboard eingegeben (POST /admin/api/unlock -> POST /unlock).
# API-Key allein kann den Tresor NICHT entschluesseln.
#
# Erwartete Umgebungsvariablen:
#   VW_URL           https://vault.example.de   (eigener Vaultwarden)
#   BW_CLIENTID      user.xxxxxxxx              (API-Key des agent@-Kontos)
#   BW_CLIENTSECRET  ...                        (API-Key des agent@-Kontos)
#
# Optional (NICHT empfohlen, siehe BROKER.md "Auto-Unlock"):
#   BW_PASSWORD_FILE Pfad zu einer Datei (Docker-Secret) mit dem Master-
#                    Passwort. Ist sie gesetzt und lesbar, entsperrt der
#                    Sidecar sich beim Start selbst - bequem nach einem
#                    Reboot, aber das Passwort liegt dann auf der Platte.
# ---------------------------------------------------------------------------
set -euo pipefail

: "${VW_URL:?VW_URL fehlt (z.B. https://vault.example.de)}"
: "${BW_CLIENTID:?BW_CLIENTID fehlt - API-Key des agent-Kontos}"
: "${BW_CLIENTSECRET:?BW_CLIENTSECRET fehlt - API-Key des agent-Kontos}"

export BITWARDENCLI_APPDATA_DIR="${BITWARDENCLI_APPDATA_DIR:-/data}"
SERVE_HOST="${BW_SERVE_HOST:-0.0.0.0}"
SERVE_PORT="${BW_SERVE_PORT:-8087}"

log() { echo "[bw-sidecar] $*"; }

log "Server wird auf ${VW_URL} gesetzt"
bw config server "$VW_URL"

# `bw login --check` liefert != 0, wenn noch keine Sitzung existiert.
# Der Login-Zustand liegt in /data und ueberlebt Container-Neustarts.
if bw login --check >/dev/null 2>&1; then
  log "bereits angemeldet"
else
  log "Anmeldung per API-Key"
  # --apikey liest BW_CLIENTID / BW_CLIENTSECRET aus der Umgebung.
  bw login --apikey --quiet
fi

# ---------------------------------------------------------------------------
# Optionaler Auto-Unlock per Docker-Secret. Standardweg ist das Dashboard!
# ---------------------------------------------------------------------------
if [ -n "${BW_PASSWORD_FILE:-}" ] && [ -r "${BW_PASSWORD_FILE}" ]; then
  log "WARNUNG: Auto-Unlock aus ${BW_PASSWORD_FILE} - das Master-Passwort"
  log "         liegt damit auf der Platte. Empfohlen ist das Dashboard."
  # --passwordfile haelt das Passwort aus der Prozessliste heraus.
  if BW_SESSION="$(bw unlock --passwordfile "${BW_PASSWORD_FILE}" --raw)"; then
    export BW_SESSION
    log "Tresor automatisch entsperrt"
    bw sync >/dev/null || log "erster Sync fehlgeschlagen"
  else
    log "Auto-Unlock fehlgeschlagen - bitte im Dashboard entsperren"
  fi
else
  log "Tresor bleibt gesperrt - Entsperren im Broker-Dashboard unter /admin"
fi

log "starte bw serve auf ${SERVE_HOST}:${SERVE_PORT}"
# exec: bw wird PID 1 und bekommt SIGTERM von Docker direkt mit.
exec bw serve --hostname "$SERVE_HOST" --port "$SERVE_PORT"
