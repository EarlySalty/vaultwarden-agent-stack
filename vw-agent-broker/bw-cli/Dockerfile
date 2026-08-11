# ---------------------------------------------------------------------------
# Sidecar mit der OFFIZIELLEN Bitwarden CLI im Serve-Modus.
# Der Broker spricht nur ueber das interne Docker-Netz mit diesem Container -
# Port 8087 wird bewusst NICHT auf den Host veroeffentlicht.
# ---------------------------------------------------------------------------
FROM node:20-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Version bewusst offen ("latest"), damit Protokollaenderungen von Vaultwarden
# mitgenommen werden. Fuer reproduzierbare Builds hier eine Version anpinnen.
RUN npm install -g @bitwarden/cli \
 && npm cache clean --force

# Hier legt die CLI data.json mit dem (verschluesselten) Vault-Cache ab.
ENV BITWARDENCLI_APPDATA_DIR=/data

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && mkdir -p /data \
 && chown -R node:node /data

USER node
EXPOSE 8087

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8087/status || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
