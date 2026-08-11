# Selbstgehosteter Passwort-Manager: Vaultwarden + AI-Agent-Broker

Kompletter Ersatz für Dashlane auf dem eigenen VPS — Sync zwischen Desktop,
Browser und Handy über den eigenen Server, plus eine in Rust gebaute
Freigabe-Schicht, mit der AI-Agents kontrolliert auf Zugangsdaten zugreifen
können.

## Die zwei Teile

**[`vaultwarden-vps/`](vaultwarden-vps/)** — der Server-Stack:
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) (Bitwarden-kompatibler
Server in Rust) hinter Caddy mit automatischem HTTPS. Enthält Setup-Skript
(installiert Docker, generiert Admin-Token), Backup- und Update-Skripte,
fail2ban-Vorlagen und eine ausführliche deutsche Anleitung inklusive
Dashlane-Migration (CSV-Import), Android-Einrichtung (Autofill über der
Tastatur mit Fingerabdruck, 2FA-Auto-Copy) und Browser-Extension-Setup
(Inline-Autofill, Auto-Login, Passkeys). Start: `README.md` im Ordner lesen,
DNS-Eintrag setzen, `./setup.sh` ausführen.

**[`vw-agent-broker/`](vw-agent-broker/)** — der Agent-Broker (Rust):
AI-Agents (z. B. Claude via MCP) erhalten Zugangsdaten nur über diesen Dienst.
Die Freigabe-Regel steht als Custom Field `agent-policy` (`auto`/`ask`/`deny`)
direkt im Vault-Eintrag; bei `ask` kommt eine ntfy-Push-Nachricht mit
Freigeben/Verweigern-Buttons. Dazu: Web-Dashboard mit Anfragen, Merken-Regeln,
Agent-Tokens und Audit-Log. Kein Master-Passwort auf der Platte — nach einem
Neustart wird der Tresor einmalig über das Dashboard entsperrt. Läuft als
Compose-Overlay auf dem Stack aus `vaultwarden-vps/`. Anleitung: `BROKER.md`.

## Reihenfolge

1. `vaultwarden-vps/` ausrollen, Konto anlegen, Dashlane importieren
2. Registrierung schließen (`SIGNUPS_ALLOWED=false`)
3. `vw-agent-broker/` nach `BROKER.md` dazustarten

## Sicherheit

In diesem Repository liegen nur Vorlagen (`.env.example`, `config.toml.example`)
— echte Secrets, Tresor-Daten und Backups gehören nie ins Repo und sind per
`.gitignore` ausgeschlossen.
