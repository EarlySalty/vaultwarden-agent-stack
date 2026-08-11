#!/usr/bin/env bash
#
# setup.sh - Erstinstallation und Aktualisierung der Konfiguration.
# Das Skript ist idempotent: Es kann beliebig oft ausgefuehrt werden und
# ueberschreibt keine bereits gesetzten Werte ohne Nachfrage.
#
# Aufruf auf dem VPS (als root oder mit sudo):
#   chmod +x setup.sh && ./setup.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"
ENV_EXAMPLE="$SCRIPT_DIR/.env.example"

# ----------------------------------------------------------------------------
# Hilfsfunktionen
# ----------------------------------------------------------------------------

info()  { printf '\033[1;34m[i]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
fail()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Ist ein Kommando vorhanden?
have() { command -v "$1" >/dev/null 2>&1; }

# sudo nur benutzen, wenn wir nicht schon root sind
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then
        SUDO="sudo"
    else
        fail "Bitte als root ausfuehren oder sudo installieren."
    fi
fi

# Setzt einen Schluessel in der .env.
# Bewusst NICHT mit sed umgesetzt: Werte wie der Argon2-Hash enthalten
# Sonderzeichen ($, /, &), die sed als Steuerzeichen interpretieren wuerde.
# Diese Variante schreibt den Wert absolut woertlich.
set_env_raw() {
    local key="$1" value="$2" tmp found=0 line
    tmp="$(mktemp)"
    while IFS= read -r line || [ -n "$line" ]; do
        if [ "${line:0:${#key}+1}" = "${key}=" ]; then
            printf '%s=%s\n' "$key" "$value" >>"$tmp"
            found=1
        else
            printf '%s\n' "$line" >>"$tmp"
        fi
    done <"$ENV_FILE"
    if [ "$found" -eq 0 ]; then
        printf '%s=%s\n' "$key" "$value" >>"$tmp"
    fi
    cat "$tmp" >"$ENV_FILE"
    rm -f "$tmp"
}

# Liest den aktuellen Wert eines Schluessels aus der .env (ohne Quotes zu werten)
get_env_raw() {
    local key="$1"
    grep -m1 "^${key}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true
}

# ----------------------------------------------------------------------------
# 1. Docker + Compose-Plugin sicherstellen
# ----------------------------------------------------------------------------

install_docker() {
    info "Docker wird installiert (offizielles Skript von get.docker.com) ..."
    if ! have curl; then
        if have apt-get; then
            $SUDO apt-get update -qq
            $SUDO apt-get install -y curl ca-certificates
        elif have dnf; then
            $SUDO dnf install -y curl ca-certificates
        else
            fail "curl fehlt und konnte nicht automatisch installiert werden."
        fi
    fi
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    $SUDO sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
    $SUDO systemctl enable --now docker 2>/dev/null || true
    ok "Docker installiert."
}

if have docker; then
    ok "Docker ist bereits vorhanden ($(docker --version 2>/dev/null || echo 'Version unbekannt'))."
else
    install_docker
fi

# Compose-Plugin pruefen ("docker compose", nicht das alte "docker-compose")
if ! $SUDO docker compose version >/dev/null 2>&1; then
    warn "Das Compose-Plugin fehlt - Nachinstallation wird versucht."
    if have apt-get; then
        $SUDO apt-get update -qq
        $SUDO apt-get install -y docker-compose-plugin || true
    elif have dnf; then
        $SUDO dnf install -y docker-compose-plugin || true
    fi
    $SUDO docker compose version >/dev/null 2>&1 \
        || fail "Compose-Plugin konnte nicht installiert werden. Bitte manuell nachziehen: https://docs.docker.com/compose/install/"
fi
ok "Docker Compose einsatzbereit ($($SUDO docker compose version --short 2>/dev/null || echo '?'))."

# Ab hier immer mit demselben Praefix arbeiten
DC() { $SUDO docker compose "$@"; }

# ----------------------------------------------------------------------------
# 2. .env anlegen und Domain / E-Mail abfragen
# ----------------------------------------------------------------------------

if [ ! -f "$ENV_FILE" ]; then
    [ -f "$ENV_EXAMPLE" ] || fail ".env.example nicht gefunden - bitte das komplette Paket hochladen."
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ok ".env aus .env.example erzeugt."
else
    info ".env existiert bereits - bestehende Werte werden uebernommen."
    chmod 600 "$ENV_FILE"
fi

CURRENT_DOMAIN="$(get_env_raw DOMAIN)"
CURRENT_EMAIL="$(get_env_raw ACME_EMAIL)"

# Domain abfragen, solange sie noch der Beispielwert ist
while [ -z "${CURRENT_DOMAIN:-}" ] || [ "$CURRENT_DOMAIN" = "vault.example.de" ]; do
    read -r -p "Domain fuer Vaultwarden (z.B. vault.example.de): " ANTWORT_DOMAIN
    ANTWORT_DOMAIN="$(printf '%s' "${ANTWORT_DOMAIN:-}" | tr -d '[:space:]')"
    # Nur echte Hostnamen zulassen - schuetzt gleichzeitig den sed-Aufruf unten
    if printf '%s' "$ANTWORT_DOMAIN" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$'; then
        CURRENT_DOMAIN="$ANTWORT_DOMAIN"
    else
        warn "Das sieht nicht nach einem gueltigen Hostnamen aus (ohne https://, ohne Slash)."
    fi
done

while [ -z "${CURRENT_EMAIL:-}" ] || [ "$CURRENT_EMAIL" = "admin@example.de" ]; do
    read -r -p "E-Mail-Adresse fuer Let's Encrypt: " ANTWORT_EMAIL
    ANTWORT_EMAIL="$(printf '%s' "${ANTWORT_EMAIL:-}" | tr -d '[:space:]')"
    if printf '%s' "$ANTWORT_EMAIL" | grep -Eq '^[^@[:space:]]+@[^@[:space:]]+\.[A-Za-z]{2,}$'; then
        CURRENT_EMAIL="$ANTWORT_EMAIL"
    else
        warn "Bitte eine gueltige E-Mail-Adresse eingeben."
    fi
done

# Domain und E-Mail sind durch die Regex-Pruefung frei von sed-Sonderzeichen,
# deshalb ist der sed-Ersatz hier unbedenklich. Als Trenner dient "|".
sed -i "s|^DOMAIN=.*|DOMAIN=${CURRENT_DOMAIN}|" "$ENV_FILE"
sed -i "s|^ACME_EMAIL=.*|ACME_EMAIL=${CURRENT_EMAIL}|" "$ENV_FILE"
sed -i "s|^VAULTWARDEN_DOMAIN=.*|VAULTWARDEN_DOMAIN=https://${CURRENT_DOMAIN}|" "$ENV_FILE"
ok "Domain: ${CURRENT_DOMAIN}   |   ACME-Mail: ${CURRENT_EMAIL}"

# ----------------------------------------------------------------------------
# 3. ADMIN_TOKEN erzeugen
# ----------------------------------------------------------------------------
#
# Ablauf:
#   1. Klartext-Token per openssl rand -base64 48
#   2. Daraus einen Argon2-PHC-Hash bauen (im offiziellen Vaultwarden-Image)
#   3. Hash in die .env schreiben - in EINFACHEN Anfuehrungszeichen.
#
# Warum einfache Anfuehrungszeichen? Der PHC-String sieht so aus:
#   $argon2id$v=19$m=65540,t=3,p=4$c2Fs...$aGFz...
# Docker Compose liest die .env selbst ein und wuerde "$argon2id" oder "$v"
# als Variablen interpretieren und durch Leerstring ersetzen. Innerhalb von
# ' ... ' findet diese Ersetzung nicht statt, der Wert bleibt exakt erhalten.
# Ein Escapen mit $$ ist dann weder noetig noch erlaubt.

CURRENT_TOKEN="$(get_env_raw ADMIN_TOKEN)"

if [ -n "${CURRENT_TOKEN:-}" ]; then
    info "ADMIN_TOKEN ist bereits gesetzt - bleibt unveraendert."
    info "Neu erzeugen? Zeile ADMIN_TOKEN in der .env leeren und ./setup.sh erneut starten."
else
    have openssl || fail "openssl fehlt (Paket 'openssl' installieren)."
    PLAIN_TOKEN="$(openssl rand -base64 48 | tr -d '\n')"

    info "Erzeuge Argon2-Hash fuer den Admin-Token ..."
    HASH_OUTPUT=""
    HASH_OUTPUT="$(printf '%s\n%s\n' "$PLAIN_TOKEN" "$PLAIN_TOKEN" \
        | $SUDO docker run --rm -i vaultwarden/server /vaultwarden hash --preset owasp 2>/dev/null || true)"
    # Vaultwarden gibt die Zeile bereits fertig aus, inklusive einfacher
    # Anfuehrungszeichen:  ADMIN_TOKEN='$argon2id$v=19$...'
    # Deshalb erst den PHC-String herausschneiden und dann eventuelle
    # Anfuehrungszeichen entfernen - sonst stuenden sie doppelt in der .env.
    # Der PHC-String selbst besteht nur aus [A-Za-z0-9+/=$,.-], enthaelt also
    # nie ein Anfuehrungszeichen.
    PHC_HASH="$(printf '%s\n' "$HASH_OUTPUT" | grep -o '\$argon2[^[:space:]]*' | tail -n1 | tr -d "'\"" || true)"

    # Plausibilitaetspruefung: gueltiger PHC-String?
    case "$PHC_HASH" in
        \$argon2*\$*\$*\$*\$*) : ;;
        *) PHC_HASH="" ;;
    esac

    if [ -n "$PHC_HASH" ]; then
        set_env_raw ADMIN_TOKEN "'${PHC_HASH}'"
        ok "ADMIN_TOKEN als Argon2-Hash gespeichert."
    else
        # Fallback: Klartext. Funktioniert genauso, ist aber auf der Platte lesbar.
        set_env_raw ADMIN_TOKEN "'${PLAIN_TOKEN}'"
        warn "Argon2-Hash konnte nicht erzeugt werden (Image noch nicht geladen oder kein TTY)."
        warn "Der Token liegt jetzt im KLARTEXT in der .env."
        warn "Spaeter nachholen:  docker run --rm -it vaultwarden/server /vaultwarden hash --preset owasp"
        warn "und den ausgegebenen Hash in einfachen Anfuehrungszeichen in die .env eintragen."
    fi

    # Klartext-Token merken - nur damit kann man sich spaeter unter /admin anmelden.
    printf '%s\n' "$PLAIN_TOKEN" >"$SCRIPT_DIR/admin-token.txt"
    chmod 600 "$SCRIPT_DIR/admin-token.txt"
    ok "Der Klartext-Token steht in admin-token.txt (sicher wegsichern, danach loeschen!)."
fi

chmod 600 "$ENV_FILE"

# ----------------------------------------------------------------------------
# 4. Firewall (UFW) oeffnen, falls aktiv
# ----------------------------------------------------------------------------

if have ufw && $SUDO ufw status 2>/dev/null | grep -qi '^Status: active'; then
    info "UFW ist aktiv - Ports 80 und 443 werden freigegeben."
    $SUDO ufw allow 80/tcp  >/dev/null 2>&1 || true
    $SUDO ufw allow 443/tcp >/dev/null 2>&1 || true
    $SUDO ufw allow 443/udp >/dev/null 2>&1 || true
    ok "UFW-Regeln gesetzt (80/tcp, 443/tcp, 443/udp)."
else
    info "UFW nicht aktiv oder nicht installiert - keine Firewall-Aenderung noetig."
    info "Bei Hetzner/Netcup/Contabo zusaetzlich die Cloud-Firewall im Webpanel pruefen."
fi

# ----------------------------------------------------------------------------
# 5. Verzeichnisse und Start
# ----------------------------------------------------------------------------

mkdir -p "$SCRIPT_DIR/vw-data" "$SCRIPT_DIR/backups"
chmod 700 "$SCRIPT_DIR/vw-data" "$SCRIPT_DIR/backups"
chmod +x "$SCRIPT_DIR/backup.sh" "$SCRIPT_DIR/update.sh" 2>/dev/null || true

info "Starte Container ..."
DC pull
DC up -d

echo
DC ps
echo

FINAL_DOMAIN="$(get_env_raw DOMAIN)"
SIGNUP_STATE="$(get_env_raw SIGNUPS_ALLOWED)"

cat <<EOF

============================================================
 Fertig. Naechste Schritte
============================================================

1. DNS pruefen: Ein A-Record fuer ${FINAL_DOMAIN} muss auf die
   oeffentliche IP dieses Servers zeigen. Erst dann kann Caddy ein
   Let's-Encrypt-Zertifikat ausstellen.
       dig +short ${FINAL_DOMAIN}
       curl -s ifconfig.me

2. Zertifikat-Ausstellung beobachten (dauert einige Sekunden):
       docker compose logs -f caddy

3. Konto anlegen:  https://${FINAL_DOMAIN}
   (Registrierung ist aktuell: SIGNUPS_ALLOWED=${SIGNUP_STATE})

4. DANACH unbedingt absichern:
       sed -i 's/^SIGNUPS_ALLOWED=.*/SIGNUPS_ALLOWED=false/' .env
       docker compose up -d

5. Admin-Panel:  https://${FINAL_DOMAIN}/admin
   Passwort = der Klartext-Token aus admin-token.txt

6. Backups einrichten (siehe README.md, Abschnitt "Betrieb"):
       ./backup.sh

EOF
