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
#   3. Symlink the platform's wildcard TLS cert (provided via
#      OPENHOST_TLS_CERT_PATH / OPENHOST_TLS_KEY_PATH) into the Prosody
#      certs directory.  The container exits immediately if these env vars
#      are missing or the files are unreadable — there is no self-signed
#      fallback, since a self-signed cert breaks s2s federation.
# On first boot only we also:
#   4. Create an ``admin@<domain>`` Prosody account with a random
#      password and write the password to
#      ``$OPENHOST_APP_DATA_DIR/admin_password.txt`` (chmod 644 so
#      the zone owner can read it via the file-browser app — see the
#      comment on ``create_admin_account`` for the rootless-podman
#      reasoning).
# The symlinked cert, SQLite account DB, and password file all persist
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
# ``export`` so the Python sidecar (and anything else we launch)
# sees the value without needing a per-invocation env prefix that a
# future refactor might accidentally drop.
export STATUS_PORT="${STATUS_PORT:-8080}"

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

# Platform-provided TLS cert paths (injected by OpenHost when [tls] cert = true).
# The platform cert covers <zone_domain> and *.<zone_domain>, so it is valid
# for the XMPP domain (<app_name>.<zone_domain>) without any extra ACME work.
# These vars are guaranteed to be set by the OpenHost runtime when [tls] cert
# = true is declared in openhost.toml — if they are absent the container
# exits with a clear error rather than silently falling back to a self-signed
# cert that would break s2s federation.
PLATFORM_CERT="${OPENHOST_TLS_CERT_PATH:-}"
PLATFORM_KEY="${OPENHOST_TLS_KEY_PATH:-}"

log "DOMAIN=$DOMAIN"
log "DATA_DIR=$DATA_DIR"

# --- render prosody.cfg.lua -----------------------------------------
#
# The rendered config is a per-boot output: we re-render every time
# so changes to the template (from image updates) actually take
# effect.  Only the stateful bits — accounts (SQLite), admin password,
# cert pair — persist across boots.
sed_escape() {
    # Escape ``|`` (our delimiter), ``&`` (sed's match-reference),
    # and ``\`` (the escape char itself) in the replacement side of
    # a ``sed`` substitution.  Newlines are intentionally NOT
    # escaped: sed on the invocation line treats a newline as a
    # command separator, so a value with an embedded newline will
    # produce a malformed sed command and abort the shell under
    # ``set -e``.  That's the desired outcome — we'd rather
    # short-circuit with a sed error than continue with a corrupted
    # config.  JIDs and paths never contain newlines in legitimate
    # use, so this edge case only bites if ``$XMPP_DOMAIN`` was set
    # to something bizarre by the operator.
    printf '%s' "$1" | sed -e 's/[|&\\]/\\&/g'
}

render_config() {
    local tmpl=/usr/local/share/openhost-xmpp/prosody.cfg.lua.template
    if [[ ! -f "$tmpl" ]]; then
        log "FATAL: template missing at $tmpl (image build bug?)"
        exit 1
    fi
    # Sanitise the substitutions for sed.  Any of ``|`` (our
    # delimiter), ``&``, or ``\`` could corrupt the substitution;
    # ``$XMPP_DOMAIN`` is operator-supplied so all three
    # placeholders go through the same escaper.  ``|`` as the sed
    # delimiter avoids collisions with ``/`` in paths.
    local esc_data_dir esc_domain esc_admin_jid
    esc_data_dir=$(sed_escape "$DATA_DIR")
    esc_domain=$(sed_escape "$DOMAIN")
    esc_admin_jid=$(sed_escape "$ADMIN_JID")
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

# --- platform TLS cert -------------------------------------------------------
#
# OpenHost injects OPENHOST_TLS_CERT_PATH and OPENHOST_TLS_KEY_PATH when
# [tls] cert = true is set in openhost.toml.  The platform enforces that the
# cert files exist before the container starts, so if these vars are absent or
# the files are unreadable here it indicates a misconfiguration — we exit
# immediately with a clear diagnostic rather than silently falling back to a
# self-signed cert that would break s2s federation.
#
# On every boot we symlink the platform cert into the Prosody certs directory
# so Prosody finds it at the expected path.  A symlink (not a copy) means the
# cert is always current: when OpenHost renews the wildcard cert the symlink
# keeps pointing at the live file and a container restart picks it up.
setup_platform_cert() {
    if [[ -z "$PLATFORM_CERT" || -z "$PLATFORM_KEY" ]]; then
        log "FATAL: OPENHOST_TLS_CERT_PATH / OPENHOST_TLS_KEY_PATH are not set."
        log "       Deploy this app on an OpenHost instance with TLS enabled."
        exit 1
    fi
    if [[ ! -r "$PLATFORM_CERT" ]]; then
        log "FATAL: platform cert not readable at $PLATFORM_CERT"
        exit 1
    fi
    if [[ ! -r "$PLATFORM_KEY" ]]; then
        log "FATAL: platform key not readable at $PLATFORM_KEY"
        exit 1
    fi
    # Atomic symlink replacement: write to a temp name then rename so a
    # SIGKILL mid-operation never leaves a dangling symlink.
    local tmp_cert="${CERT_FILE}.symlnk"
    local tmp_key="${KEY_FILE}.symlnk"
    if ! ln -sf "$PLATFORM_CERT" "$tmp_cert"; then
        log "FATAL: could not create symlink for platform cert ($tmp_cert)"
        exit 1
    fi
    if ! ln -sf "$PLATFORM_KEY" "$tmp_key"; then
        log "FATAL: could not create symlink for platform key ($tmp_key)"
        rm -f "$tmp_cert" 2>/dev/null || true
        exit 1
    fi
    mv "$tmp_cert" "$CERT_FILE"
    mv "$tmp_key" "$KEY_FILE"
    log "platform TLS cert symlinked: $PLATFORM_CERT -> $CERT_FILE"
}

setup_platform_cert

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
# prosodyctl register writes directly through the configured storage
# backend (SQLite here), so it requires prosody to NOT be running.
# We invoke it with the rendered config via the ``--config`` flag.
# The DB file doesn't need to exist yet; prosodyctl creates it on
# first use with the right schema.
create_admin_account() {
    local password
    # 24 hex chars of randomness = 96 bits.  We use hex rather than
    # base64 so the length is deterministic — stripping ``+/`` out
    # of base64 would silently shrink the password.  96 bits is well
    # over the threshold for offline-brute-force resistance on a
    # bcrypt-stretched hash in practical scenarios.
    #
    # ``openssl rand -hex 12`` emits 24 lowercase hex chars on
    # success.  We explicitly check the length because the caller
    # invokes this function under ``if !`` which suppresses
    # ``set -e`` throughout — a silent failure of openssl would
    # otherwise let us register an account with an empty password.
    if ! password=$(openssl rand -hex 12); then
        log "ERROR: openssl rand -hex 12 failed"
        return 1
    fi
    if [[ ${#password} -ne 24 ]]; then
        log "ERROR: openssl rand -hex 12 produced unexpected output (len=${#password})"
        return 1
    fi
    # Stage the password file BEFORE calling prosodyctl.  If
    # prosodyctl succeeds but the file write subsequently fails
    # (disk full / weird filesystem), we'd end up with an admin
    # account whose password we can never tell the operator —
    # recovering would mean manually deleting the SQLite row.
    # Writing first, then registering, avoids that.
    #
    # The write itself is atomic: write to ``.partial`` then ``mv``
    # into the final path, so a SIGKILL mid-``printf`` can't leave
    # an empty password file behind.  This matches the same pattern
    # used by render_config and generate_self_signed_cert.
    if ! printf '%s\n' "$password" > "$ADMIN_PASSWORD_FILE.partial"; then
        log "ERROR: failed to write $ADMIN_PASSWORD_FILE.partial"
        rm -f "$ADMIN_PASSWORD_FILE.partial" 2>/dev/null || true
        return 1
    fi
    if ! mv "$ADMIN_PASSWORD_FILE.partial" "$ADMIN_PASSWORD_FILE"; then
        log "ERROR: failed to mv $ADMIN_PASSWORD_FILE.partial into place"
        rm -f "$ADMIN_PASSWORD_FILE.partial" 2>/dev/null || true
        return 1
    fi
    # prosodyctl register <user> <host> <password> creates the
    # account non-interactively.  (The README's ``prosodyctl
    # adduser`` is the interactive variant, which would prompt the
    # operator — not what we want at container-boot time.)
    # Piped from stdin isn't supported by ``register``; we pass the
    # password on the command line.  ``ps aux`` exposure is
    # accepted — this container runs under OpenHost's
    # single-tenant model with no adversarial co-resident
    # processes.  The DB file doesn't exist yet, so prosodyctl
    # will create it with the right schema on first touch.
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
    local domain_hex account_count stderr
    domain_hex=$(printf '%s' "$DOMAIN" | od -An -tx1 | tr -d ' \n')
    if ! stderr=$(mktemp 2>/dev/null) || [[ -z "$stderr" ]]; then
        log "warning: mktemp failed; skipping admin-account existence check"
        return 1
    fi
    # Capture sqlite3 stderr to a tempfile instead of discarding it.
    # Any diagnostic — "database is locked", "no such table",
    # "permission denied" on the db file — gets surfaced to the
    # container log so the operator isn't debugging blind when
    # re-provisioning attempts unexpectedly fire.
    #
    # ``tr -d '\n'`` on the stdout in case sqlite3 outputs the count
    # followed by extra junk or newlines that would break the
    # arithmetic comparison below.
    account_count=$(sqlite3 "$db" \
        "SELECT COUNT(*) FROM prosody WHERE host=CAST(x'${domain_hex}' AS TEXT) AND user='admin' AND store='accounts';" \
        2>"$stderr" | tr -d '\n' || echo ERR)
    # Log anything sqlite3 wrote to stderr, regardless of whether it
    # exited zero.  The two cases we care about:
    #   * non-zero exit + stderr text    → hard query failure
    #   * zero exit + stderr text        → warning (deprecation, etc)
    # Both benefit from being visible.
    if [[ -s "$stderr" ]]; then
        log "sqlite3 diagnostic output:"
        while IFS= read -r line; do log "  $line"; done < "$stderr"
    fi
    rm -f "$stderr"
    # ``$account_count`` is "ERR" on non-zero sqlite3 exit, empty
    # if sqlite3 crashed outright, or a decimal count.  Also guard
    # against any non-numeric residue (``[[ ... -gt 0 ]]`` would
    # silently treat non-numeric as 0, but we want explicit intent).
    if [[ -z "$account_count" || "$account_count" == "ERR" ]]; then
        return 1
    fi
    if [[ ! "$account_count" =~ ^[0-9]+$ ]]; then
        log "warning: sqlite3 returned non-numeric value: $account_count"
        return 1
    fi
    (( account_count > 0 ))
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
    # Keep the existing password file mode in sync with what
    # create_admin_account sets on first boot (644, so the zone
    # owner can read it via file-browser under rootless podman).
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
python3 /usr/local/bin/status_server.py &
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
