#!/bin/bash
# Entrypoint for openhost-xmpp.
#
# We use /bin/bash (not /bin/sh) because Debian's /bin/sh is dash and
# ``wait -n`` is a bashism; we rely on it to notice the first child
# (prosody or the status sidecar) exiting so we can tear down the
# other and have OpenHost restart the container.
#
# On every boot we:
#   1. Work out the XMPP domain ($XMPP_DOMAIN if set, else
#      ``<OPENHOST_APP_NAME>.<OPENHOST_ZONE_DOMAIN>``).
#   2. Render ``prosody.cfg.lua`` from the bundled template with that
#      domain baked in.  (Re-rendering every boot means template
#      updates in new image versions take effect automatically.)
# On first boot only we also:
#   3. Generate a self-signed TLS cert/key pair (``<domain>.crt`` and
#      ``<domain>.key``) under ``$OPENHOST_APP_DATA_DIR/certs/``.
#   4. Create an ``admin@<domain>`` Prosody account with a random
#      password and write the password to
#      ``$OPENHOST_APP_DATA_DIR/admin_password.txt`` (chmod 644 so
#      the zone owner can read it via the file-browser app — see the
#      comment on ``create_admin_account`` for the rootless-podman
#      reasoning).
# The cert, key, SQLite account DB, and password file all persist
# across restarts.
#
# Then we:
#   * Start the HTTP status sidecar on :8080 (satisfies the OpenHost
#     router's health-check requirement; the XMPP protocol lives on
#     the ``[[ports]]`` declared in openhost.toml).
#   * Start prosody in the foreground as a background job of this
#     shell, and use ``wait -n`` to supervise both children.  If
#     either exits the container exits too so OpenHost restarts it.

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
    # Sanitise the substitutions for sed.  Any of ``/``, ``&``, or the
    # delimiter character in the ``s`` command could corrupt the
    # substitution; we don't trust ``$XMPP_DOMAIN`` (operator-supplied
    # env var) so all three placeholders go through the same escaper.
    # We use ``|`` as the sed delimiter to avoid collisions with ``/``
    # in paths.
    local esc_data_dir esc_domain esc_admin_jid
    esc_data_dir=$(printf '%s' "$DATA_DIR" | sed -e 's/[|&\\]/\\&/g')
    esc_domain=$(printf '%s' "$DOMAIN" | sed -e 's/[|&\\]/\\&/g')
    esc_admin_jid=$(printf '%s' "$ADMIN_JID" | sed -e 's/[|&\\]/\\&/g')
    # Atomic write: stage the rendered config to ``.partial`` then
    # ``mv`` into place so a SIGKILL between shell-redirect truncation
    # and sed completion can't leave the container rebooting into an
    # empty or partial config.  (The cert-gen function uses the same
    # pattern for the same reason.)
    sed \
        -e "s|@@DOMAIN@@|${esc_domain}|g" \
        -e "s|@@DATA_DIR@@|${esc_data_dir}|g" \
        -e "s|@@ADMIN_JID@@|${esc_admin_jid}|g" \
        "$tmpl" > "$CONFIG_FILE.partial"
    mv "$CONFIG_FILE.partial" "$CONFIG_FILE"
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
# generate an RSA 2048 self-signed cert on first boot with SAN
# entries for the zone domain, conference.<zone>, and share.<zone>
# so MUC and http-file-share components can share the same cert.
# (RSA over ECDSA because a handful of older mobile XMPP clients
# still choke on ECDSA certs; the perf difference is negligible for
# personal-scale XMPP.)  The operator can overwrite ``<zone>.crt``
# / ``<zone>.key`` with real certificates (Let's Encrypt etc.) and
# ``prosodyctl reload`` — the filenames stay the same so the config
# keeps working.
generate_self_signed_cert() {
    local cnf
    cnf=$(mktemp)
    # Cleanup strategy: we can't use ``trap ... RETURN`` because
    # bash's RETURN trap is NOT scoped to this function — it
    # persists and fires on every subsequent function return in the
    # shell, and ``$cnf`` will be unset then (``set -u`` would
    # abort).  Instead, do a best-effort cleanup on both happy
    # (post-openssl) and sad (openssl failure via an explicit
    # trap-then-unset on ERR) paths.
    local _cleanup_cnf="$cnf"
    _cleanup() { rm -f "$_cleanup_cnf" "$KEY_FILE.partial" "$CERT_FILE.partial" 2>/dev/null || true; }
    trap _cleanup ERR

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
    # Write to ``.partial`` first so a crash mid-write doesn't leave a
    # half-written file that the boot-time guard mistakes for a
    # usable cert.  On success we atomically rename into place.
    # Leave openssl's stderr visible so a failure (bad config,
    # entropy starvation, permission error) shows up in the
    # container log rather than the script dying silently with no
    # diagnostic.  stdout is routine progress so we drop it.
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY_FILE.partial" -out "$CERT_FILE.partial" \
        -days 825 -config "$cnf" -extensions v3_req \
        >/dev/null
    mv "$KEY_FILE.partial" "$KEY_FILE"
    mv "$CERT_FILE.partial" "$CERT_FILE"
    rm -f "$cnf"
    trap - ERR
    chmod 640 "$CERT_FILE" "$KEY_FILE"
    # Ownership: we'd prefer root:prosody so the prosody user can
    # read but not overwrite its own private key.  In practice the
    # ``chown -R prosody:prosody "$DATA_DIR"`` below will flatten
    # this anyway under rootless podman (where the "root" user
    # inside the container maps to an unprivileged host uid).  We
    # leave the attempt in so on a Docker deployment where it sticks,
    # the private key stays protected from Prosody's own process.
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
#
# Under rootless podman the container's ``root`` is mapped to an
# unprivileged host uid that is NOT a member of any of the host's
# existing uid maps, so this chown can fail with "Operation not
# permitted" even though the data dir is 0o777 on the host.  In that
# case Prosody still works fine — the bind mount uses ``:idmap`` and
# the container's ``prosody`` user ends up owning the files via the
# usual container-internal UID.  Log a warning and move on rather
# than aborting the whole boot.
if ! chown -R prosody:prosody "$DATA_DIR" 2>/dev/null; then
    log "warning: chown -R prosody:prosody $DATA_DIR failed (expected under rootless podman with no idmap); continuing"
fi

# --- admin account + password ---------------------------------------
#
# prosodyctl adduser requires prosody to NOT be running (it writes
# the accounts table directly through the storage backend).  We
# invoke it with the rendered config via the ``--config`` flag.  The
# storage backend is SQLite here, so we just need the DB file at the
# configured path — which prosodyctl creates on first use.
create_admin_account() {
    local password
    # 24 hex chars of randomness = 96 bits.  We use hex rather than
    # base64 so the length is deterministic — stripping ``+/`` out
    # of base64 would silently shrink the password.  96 bits is well
    # over the threshold for offline-brute-force resistance on a
    # bcrypt-stretched hash in practical scenarios.
    password=$(openssl rand -hex 12)
    # Stage the password file BEFORE calling prosodyctl.  If
    # prosodyctl succeeds but the file write subsequently fails
    # (disk full / weird filesystem), we'd end up with an admin
    # account whose password we can never tell the operator —
    # recovering would mean manually deleting the SQLite row.
    # Writing first, then registering, avoids that.
    if ! printf '%s\n' "$password" > "$ADMIN_PASSWORD_FILE"; then
        log "ERROR: failed to write $ADMIN_PASSWORD_FILE"
        return 1
    fi
    # prosodyctl register <user> <host> <password>
    # Piped from stdin isn't supported; we pass it on the command
    # line.  ``ps aux`` exposure is accepted — this container runs
    # under OpenHost's single-tenant model with no adversarial
    # co-resident processes.  The DB file doesn't exist yet, so
    # prosodyctl will create it with the right schema on first
    # touch.
    if ! prosodyctl --config "$CONFIG_FILE" register admin "$DOMAIN" "$password"; then
        log "ERROR: prosodyctl register failed; rolling back password file"
        rm -f "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
        return 1
    fi
    # World-readable by design: the app's data directory is already
    # scoped to this app's container under OpenHost's data model,
    # and the zone owner (only entity with file-browser access)
    # needs to be able to read this file.  Under rootless podman
    # the xmpp container's ``prosody`` user maps to a different
    # subuid than file-browser's ``root``, so chmod 600 would
    # make the password inaccessible to the operator — we trade
    # filesystem-permission defence in depth for usability here.
    chmod 644 "$ADMIN_PASSWORD_FILE"
    chown prosody:prosody "$ADMIN_PASSWORD_FILE" 2>/dev/null || true
    log "created admin account; password saved to $ADMIN_PASSWORD_FILE"
    return 0
}

admin_account_exists() {
    # prosodyctl exposes no clean "does-this-user-exist" check.  Query
    # the SQLite DB directly — less fragile than parsing prosodyctl
    # output across releases.
    local db="$DATA_DIR/prosody.sqlite"
    if [[ ! -s "$db" ]]; then
        return 1
    fi
    # Untrusted ``$DOMAIN`` is hex-encoded and rebuilt inside SQL via
    # ``CAST(x'...' AS TEXT)`` so its value never touches the SQL
    # text.  This is more portable than ``-cmd '.param set :host'``
    # which only landed in modern sqlite3 CLIs.
    local domain_hex got stderr
    domain_hex=$(printf '%s' "$DOMAIN" | od -An -tx1 | tr -d ' \n')
    stderr=$(mktemp)
    # Leave stderr VISIBLE via a tempfile we inspect, rather than the
    # older ``2>/dev/null`` pattern that made "DB corrupt" indistinguishable
    # from "no row found" and triggered a confusing re-provisioning attempt.
    got=$(sqlite3 "$db" \
        "SELECT COUNT(*) FROM prosody WHERE host=CAST(x'${domain_hex}' AS TEXT) AND user='admin' AND store='accounts';" \
        2>"$stderr" || echo ERR)
    if [[ "$got" == "ERR" || ! -s "$stderr" ]]; then
        # Either sqlite3 exited non-zero (errors appear in $stderr),
        # or it succeeded but wrote nothing to stderr (typical case).
        # If there's any stderr content we log it — this is the
        # diagnostic the old ``2>/dev/null`` threw away.
        if [[ -s "$stderr" ]]; then
            log "warning: sqlite3 query failed:"
            sed 's/^/  /' "$stderr" | while IFS= read -r line; do log "$line"; done
        fi
    fi
    rm -f "$stderr"
    # ``$got`` may be empty if sqlite3 crashed entirely; treat that as
    # "no account" so we attempt (and then clearly fail) provisioning.
    [[ -n "$got" && "$got" != "ERR" && "$got" -gt 0 ]] 2>/dev/null
}

if ! admin_account_exists; then
    # Guard: ``set -e`` is deliberately suppressed inside ``if !``
    # branch bodies by bash, so we have to check the return value
    # explicitly.  A silent failure here would produce a running
    # container with no admin account and no admin_password.txt —
    # operators would discover the issue only when they tried to
    # log in.
    if ! create_admin_account; then
        log "FATAL: admin account provisioning failed; container will exit"
        exit 1
    fi
else
    log "admin account already provisioned; skipping"
    # Make sure an existing password file is operator-readable (see
    # create_admin_account's chmod comment for why 644).  This is
    # here so an image upgrade that introduced this convention can
    # fix up files created by an earlier version that used chmod 600.
    if [[ -f "$ADMIN_PASSWORD_FILE" ]]; then
        chmod 644 "$ADMIN_PASSWORD_FILE"
    fi
fi

# --- supervise prosody + the status sidecar --------------------------
#
# We want both processes alive for the container to be considered
# healthy.  ``wait -n`` returns as soon as either exits, at which point
# we kill the other and exit ourselves so OpenHost restarts the
# container.  ``set -e`` has to be off around ``wait -n`` so a
# non-zero exit doesn't abort the supervisor before we reach the
# cleanup — see openhost-miniflux/start.sh for the full rationale.
# Register the SIGTERM/SIGINT handler BEFORE backgrounding anything
# so a ``docker stop`` that arrives during the small window between
# first ``&`` and the ``trap`` below doesn't use bash's default
# handler (which just exits, leaving both children as orphans).  The
# trap references ``STATUS_PID`` and ``PROSODY_PID``; at this point
# neither is set yet, so we initialise them to empty strings and let
# the later ``kill -TERM "$PID"`` with an empty arg silently be a
# no-op if we somehow get a signal before the backgrounding.
STATUS_PID=""
PROSODY_PID=""
trap 'kill -TERM ${PROSODY_PID:-} ${STATUS_PID:-} 2>/dev/null; wait' TERM INT

log "starting HTTP status sidecar on :$STATUS_PORT"
STATUS_PORT="$STATUS_PORT" python3 /usr/local/bin/status_server.py &
STATUS_PID=$!

log "starting prosody"
# ``prosody -F`` stays in the foreground; we want a child process
# under our shell so ``wait -n`` sees it.  ``--config`` takes the full
# path to the rendered config.
#
# Running as the ``prosody`` user — the package's default — via
# ``runuser`` (part of ``util-linux``, which is in every Debian base
# image).
runuser -u prosody -g prosody -- \
    prosody -F --config "$CONFIG_FILE" &
PROSODY_PID=$!

set +e
wait -n "$PROSODY_PID" "$STATUS_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$PROSODY_PID" "$STATUS_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
