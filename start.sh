#!/bin/bash
# Entrypoint for openhost-xmpp.
#
# We use /bin/bash (not /bin/sh) because Debian's /bin/sh is dash and
# ``wait -n`` is a bashism; we rely on it to notice the first child
# (prosody or the status sidecar) exiting so we can tear down the
# other and have OpenHost restart the container.
#
# On first boot we:
#   1. Work out the public zone domain ($OPENHOST_ZONE_DOMAIN +
#      $OPENHOST_APP_NAME → <app>.<zone>).
#   2. Render ``prosody.cfg.lua`` from the bundled template with that
#      domain baked in.
#   3. Generate a self-signed TLS cert/key pair for the zone.
#   4. Create an ``admin@<zone>`` account with a random password and
#      write the password to ``$OPENHOST_APP_DATA_DIR/admin_password.txt``
#      (chmod 600).
# On later boots we skip any step whose artifact already exists so the
# admin password, certs, and config survive restarts.
#
# Then we:
#   * Start the HTTP status sidecar on :8080 (satisfies the OpenHost
#     router's health-check requirement; the XMPP protocol lives on
#     the ``[[ports]]`` declared in openhost.toml).
#   * Exec prosody in the foreground.

set -euo pipefail

log() { printf '[start.sh] %s\n' "$*" >&2; }

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/var/lib/prosody}"
STATUS_PORT="${STATUS_PORT:-8080}"

mkdir -p "$DATA_DIR" "$DATA_DIR/certs" "$DATA_DIR/http_file_share" \
         "$DATA_DIR/plugins"

# --- resolve the zone-facing XMPP domain ------------------------------
#
# OpenHost serves the app at ``<app_name>.<zone_domain>`` by default.
# That subdomain IS the XMPP domain — user JIDs live as
# ``<user>@<app_name>.<zone_domain>``.  If the operator sets
# ``XMPP_DOMAIN`` explicitly (e.g. to host at the bare zone instead
# of the app subdomain) we honour that.
resolve_domain() {
    if [[ -n "${XMPP_DOMAIN:-}" ]]; then
        printf '%s' "$XMPP_DOMAIN"
        return
    fi
    if [[ -n "${OPENHOST_ZONE_DOMAIN:-}" ]]; then
        printf '%s.%s' "${OPENHOST_APP_NAME:-xmpp}" "$OPENHOST_ZONE_DOMAIN"
        return
    fi
    # Nothing useful set: fall back to a placeholder that's visibly
    # wrong so the first boot log makes the problem obvious instead of
    # silently working on localhost-only.
    printf 'xmpp.invalid.example'
}

DOMAIN="$(resolve_domain)"
ADMIN_JID="admin@${DOMAIN}"
CONFIG_FILE="$DATA_DIR/prosody.cfg.lua"
CERT_FILE="$DATA_DIR/certs/${DOMAIN}.crt"
KEY_FILE="$DATA_DIR/certs/${DOMAIN}.key"
ADMIN_PASSWORD_FILE="$DATA_DIR/admin_password.txt"

log "DOMAIN=$DOMAIN"
log "DATA_DIR=$DATA_DIR"

# --- render prosody.cfg.lua -----------------------------------------
#
# The rendered config is a per-boot output: we re-render every time
# so changes to the template (from image updates) actually take
# effect.  Only the stateful bits — accounts (SQLite), admin password,
# cert pair — persist across boots.
render_config() {
    local tmpl=/usr/local/share/openhost-xmpp/prosody.cfg.lua.template
    if [[ ! -f "$tmpl" ]]; then
        log "FATAL: template missing at $tmpl (image build bug?)"
        exit 1
    fi
    # Escape the placeholders' replacements for sed: the only tricky
    # character in paths and JIDs is ``/``.  Domain can't contain
    # special chars because it went through resolve_domain's sprintf.
    local esc_data_dir
    esc_data_dir=$(printf '%s' "$DATA_DIR" | sed -e 's/[\/&]/\\&/g')
    sed \
        -e "s/@@DOMAIN@@/${DOMAIN}/g" \
        -e "s|@@DATA_DIR@@|${esc_data_dir}|g" \
        -e "s/@@ADMIN_JID@@/${ADMIN_JID}/g" \
        "$tmpl" > "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    # Prosody must be able to read its config; running as the
    # ``prosody`` user (which the Debian package creates).  chgrp
    # so the group-readable mode above is enough.
    chown root:prosody "$CONFIG_FILE" 2>/dev/null || true
}

render_config
log "rendered $CONFIG_FILE"

# --- self-signed TLS cert bootstrap ----------------------------------
#
# Prosody won't start without a cert for the configured vhost.  We
# generate an ECDSA P-256 + SHA-256 self-signed cert on first boot.
# It covers the zone domain, conference.<zone>, and share.<zone> so
# MUC and http-file-share components can share the same cert.  The
# operator can overwrite ``<zone>.crt`` / ``<zone>.key`` with real
# certificates (Let's Encrypt etc.) and ``prosodyctl reload`` — the
# filenames stay the same so the config keeps working.
generate_self_signed_cert() {
    local cnf
    cnf=$(mktemp)
    cat > "$cnf" <<EOF
[req]
default_bits = 2048
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = ${DOMAIN}
O = OpenHost XMPP
[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = conference.${DOMAIN}
DNS.3 = share.${DOMAIN}
EOF
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -days 825 -config "$cnf" -extensions v3_req \
        >/dev/null 2>&1
    rm -f "$cnf"
    chmod 640 "$CERT_FILE" "$KEY_FILE"
    chown root:prosody "$CERT_FILE" "$KEY_FILE" 2>/dev/null || true
}

if [[ ! -s "$CERT_FILE" || ! -s "$KEY_FILE" ]]; then
    log "generating self-signed TLS cert for $DOMAIN (+ conference., share.)"
    generate_self_signed_cert
else
    log "reusing existing cert/key at $CERT_FILE"
fi

# Prosody needs to own the data dir so it can write accounts, archive,
# and file-share uploads.  The Debian package creates user+group both
# named ``prosody``.
chown -R prosody:prosody "$DATA_DIR"

# --- admin account + password ---------------------------------------
#
# prosodyctl adduser requires prosody to NOT be running (it writes
# the accounts table directly through the storage backend).  We
# invoke it with the rendered config via the ``--config`` flag.  The
# storage backend is SQLite here, so we just need the DB file at the
# configured path — which prosodyctl creates on first use.
create_admin_account() {
    local password
    # 24 chars of url-safe random (18 bytes → 24 base64 chars) plenty
    # strong and easy to copy-paste.
    password=$(openssl rand -base64 18 | tr -d '=+/' | cut -c1-24)
    # prosodyctl register <user> <host> <password>
    # Piped from stdin isn't supported; we pass it on the command line.
    # The DB file doesn't exist yet, so prosodyctl will create it with
    # the right schema on first touch.
    if prosodyctl --config "$CONFIG_FILE" register admin "$DOMAIN" "$password"; then
        printf '%s\n' "$password" > "$ADMIN_PASSWORD_FILE"
        chmod 600 "$ADMIN_PASSWORD_FILE"
        chown prosody:prosody "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
        log "created admin account; password saved to $ADMIN_PASSWORD_FILE"
        return 0
    fi
    log "ERROR: failed to create admin account"
    return 1
}

admin_account_exists() {
    # prosodyctl exposes no clean "does-this-user-exist" check.  Query
    # the SQLite DB directly — less fragile than parsing prosodyctl
    # output across releases.
    local db="$DATA_DIR/prosody.sqlite"
    if [[ ! -s "$db" ]]; then
        return 1
    fi
    local got
    got=$(sqlite3 "$db" \
        "SELECT COUNT(*) FROM prosody WHERE host='${DOMAIN}' AND user='admin' AND store='accounts';" \
        2>/dev/null || echo 0)
    [[ "$got" == "1" ]]
}

if ! admin_account_exists; then
    create_admin_account
else
    log "admin account already provisioned; skipping"
fi

# --- supervise prosody + the status sidecar --------------------------
#
# We want both processes alive for the container to be considered
# healthy.  ``wait -n`` returns as soon as either exits, at which point
# we kill the other and exit ourselves so OpenHost restarts the
# container.  ``set -e`` has to be off around ``wait -n`` so a
# non-zero exit doesn't abort the supervisor before we reach the
# cleanup — see openhost-miniflux/start.sh for the full rationale.
log "starting HTTP status sidecar on :$STATUS_PORT"
STATUS_PORT="$STATUS_PORT" python3 /usr/local/bin/status_server.py &
STATUS_PID=$!

log "starting prosody"
# ``prosody -F`` stays in the foreground; we want a child process
# under our shell so ``wait -n`` sees it.  ``--config`` takes the full
# path to the rendered config.
#
# Running as the ``prosody`` user — the package's default — via
# ``setpriv`` (util-linux) or su.  The Debian prosody package adds a
# ``/usr/lib/systemd/system/prosody.service`` that does this dance;
# we replicate the key parts here.  ``runuser`` ships with coreutils.
runuser -u prosody -g prosody -- \
    prosody -F --config "$CONFIG_FILE" &
PROSODY_PID=$!

# Forward SIGTERM / SIGINT to both children so ``docker stop`` gets a
# clean shutdown.  Prosody responds to SIGTERM by doing a clean
# shutdown of the SQL store and TLS sessions; the sidecar just exits.
trap 'kill -TERM "$PROSODY_PID" "$STATUS_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$PROSODY_PID" "$STATUS_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$PROSODY_PID" "$STATUS_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
