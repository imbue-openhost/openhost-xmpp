#!/usr/bin/env python3
"""Tiny HTTP status sidecar for the OpenHost Prosody XMPP app.

The OpenHost router requires every app to answer HTTP on the manifest's
``port`` so it can health-check and serve a dashboard tile.  XMPP
itself is plain TCP on 5222 (STARTTLS), 5223 (direct-TLS), 5269/5270
(server-to-server) — none of which the router touches; those are
published directly via ``[[ports]]`` in ``openhost.toml``.

This module exposes two endpoints:

``GET /healthz``
    Returns ``200 ok`` iff something is listening on localhost:5222
    (the c2s STARTTLS port — the canonical "prosody is running"
    signal).  Returns ``503`` otherwise so the OpenHost dashboard
    correctly shows the app as crashed when Prosody fails to start.

``GET /``
    Serves a small HTML landing page listing the XMPP connect URIs
    (hostname derived from the ``Host`` / ``X-Forwarded-Host`` header),
    client recommendations, and administration pointers.  No secrets
    are rendered here — the admin password lives in
    ``$OPENHOST_APP_DATA_DIR/admin_password.txt``, accessible via the
    file-browser app.
"""

from __future__ import annotations

import html
import os
import re
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

def _load_port() -> int:
    """Read ``STATUS_PORT`` from env.  Empty string or unset → 8080.

    Any non-integer value gets a clear error before the HTTP server
    tries to bind.  We centralise this so the module-load path can't
    crash with a bare ``ValueError`` traceback when someone drops a
    typo into the manifest.
    """
    raw = os.environ.get("STATUS_PORT", "").strip() or "8080"
    try:
        port = int(raw)
    except ValueError:
        sys.stderr.write(f"[status] FATAL: STATUS_PORT={raw!r} is not an integer\n")
        sys.exit(1)
    if not 1 <= port <= 65535:
        sys.stderr.write(f"[status] FATAL: STATUS_PORT={raw!r} out of range\n")
        sys.exit(1)
    return port


PORT = _load_port()

# Prosody's c2s port.  Checking that this specific port is open is a
# more useful liveness signal than 5280 (HTTP) or 5269 (s2s) because
# it's the one a user-facing client actually needs.
PROBE_HOST = "127.0.0.1"
PROBE_PORT = 5222
PROBE_TIMEOUT_SECONDS = 1.0

# Permissive but safe hostname shape: labels of [A-Za-z0-9-] up to
# 63 chars, separated by dots, total up to 253 chars.  Values that
# don't match go through as "your-openhost-zone" instead of getting
# reflected in the landing page.
_VALID_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def _prosody_up() -> bool:
    """Return True iff something is listening on localhost:5222.

    Uses a short-timeout TCP connect rather than trying to speak XMPP
    so a tiny, non-XMPP-aware probe is enough — we're answering "is
    the process alive and bound to its c2s port" not "is the XMPP
    stream fully healthy".
    """
    try:
        with socket.create_connection((PROBE_HOST, PROBE_PORT), timeout=PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>XMPP Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
           Roboto, sans-serif; background:#0f1117; color:#e1e4e8;
           padding:40px; max-width:720px; margin:0 auto; line-height:1.4; }
    h1 { color:#fff; }
    h2 { color:#fff; margin-top:1.5em; }
    code { background:#0d1117; border:1px solid #30363d; padding:2px 6px;
           border-radius:4px; }
    .card { background:#161b22; border:1px solid #30363d; border-radius:8px;
            padding:16px 20px; margin:16px 0; }
    .status-ok { color:#2ea043; font-weight:600; }
    .status-bad { color:#f85149; font-weight:600; }
    ul { padding-left: 1.4em; }
    li { margin: 0.3em 0; }
    a { color:#58a6ff; }
  </style>
</head>
<body>
  <h1>Prosody XMPP Server</h1>

  <div class="card">
    <p>XMPP daemon status:
       <span class="@@STATUS_CLASS@@">@@STATUS_TEXT@@</span>
    </p>
  </div>

  <div class="card">
    <h2>Connecting</h2>
    <p>Point any XMPP client at <code>@@HOST@@</code>:</p>
    <ul>
      <li>Port <code>5222</code> (STARTTLS) for clients that negotiate
          encryption after connecting — most desktop / mobile clients.</li>
      <li>Port <code>5223</code> (direct TLS, XEP-0368) for clients on
          networks that strip or downgrade plaintext greetings.</li>
    </ul>
    <p>Self-signed certificate on first boot — accept it once in your
       client, or drop a real cert/key pair named
       <code>&lt;xmpp-domain&gt;.crt</code> +
       <code>&lt;xmpp-domain&gt;.key</code> into
       <code>$OPENHOST_APP_DATA_DIR/certs/</code> on your OpenHost
       host to replace it, then reload Prosody from the host:
       <code>oh app exec xmpp prosodyctl reload</code>.</p>
    <p>Recommended clients:
       <a href="https://conversations.im/">Conversations</a> (Android),
       <a href="https://dino.im/">Dino</a> (Linux),
       <a href="https://gajim.org/">Gajim</a> (cross-platform),
       <a href="https://monal-im.org/">Monal</a> (iOS/macOS).</p>
  </div>

  <div class="card">
    <h2>Account</h2>
    <p>Open registration is disabled.  The zone owner provisions
       accounts with:</p>
    <pre><code>oh app exec xmpp prosodyctl adduser user@@@HOST@@</code></pre>
    <p>An <code>admin@@@HOST@@</code> account is created on first
       boot; the password is written to <code>admin_password.txt</code>
       in the app's data directory.</p>
  </div>

  <div class="card">
    <h2>Federation</h2>
    <p>Server-to-server federation is enabled on port <code>5269</code>
       (STARTTLS) and <code>5270</code> (direct TLS).  Other servers
       reject self-signed certificates, so federation with strangers
       will fail until real certificates are in place.  Same-zone
       (user-to-user on your own server) works regardless.</p>
  </div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    # Route the default HTTP access log through stderr with a short tag
    # so container logs stay legible when interleaved with Prosody's.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        sys.stderr.write("[status] " + (fmt % args) + "\n")

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            if _prosody_up():
                self._respond(200, b"ok\n", "text/plain")
            else:
                self._respond(503, b"prosody-not-listening\n", "text/plain")
            return
        if path in ("/", "/index.html"):
            up = _prosody_up()
            # Prefer X-Forwarded-Host: inside the container the raw
            # Host header is the OpenHost router's loopback, which is
            # useless for a user pasting into a client.
            raw_host = (
                self.headers.get("X-Forwarded-Host")
                or self.headers.get("Host")
                or "your-openhost-zone"
            )
            # The header is attacker-controlled from the public
            # internet (``public_paths = ["/"]`` in openhost.toml
            # makes this endpoint reachable without auth).  Three
            # layers of defence before the value reaches the HTML:
            #
            #   1. Strip any port suffix — XMPP clients want a bare
            #      hostname for SRV lookup.
            #   2. Reject anything that isn't a plausible DNS label
            #      so a weird value (quotes, angle brackets, ...)
            #      can't leak even if the next step slips.
            #   3. html.escape() the final value before it goes into
            #      the template.  Belt, suspenders, and a backup pair
            #      of belt-suspenders.
            host = raw_host.split(":", 1)[0]
            if not _VALID_HOSTNAME_RE.match(host):
                host = "your-openhost-zone"
            host = html.escape(host, quote=True)
            body = (
                _HTML_TEMPLATE
                .replace("@@STATUS_CLASS@@", "status-ok" if up else "status-bad")
                .replace(
                    "@@STATUS_TEXT@@",
                    "running" if up else "not listening on 5222 (still starting?)",
                )
                .replace("@@HOST@@", host)
            ).encode("utf-8")
            self._respond(200, body, "text/html; charset=utf-8")
            return
        self._respond(404, b"not found\n", "text/plain")

    def _respond(self, code: int, body: bytes, content_type: str) -> None:
        # A client can disconnect at any point — not just during
        # ``wfile.write(body)``.  All of ``send_response``,
        # ``send_header``, and ``end_headers`` also write to the
        # socket and will raise ``BrokenPipeError`` /
        # ``ConnectionResetError`` / ``TimeoutError`` (all subclasses
        # of ``OSError``) when the client is gone.  Wrap the whole
        # response write in a single ``OSError`` catch so the
        # supervisor doesn't get a noisy traceback for every
        # half-connected client.
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass


def main() -> int:
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    except OSError as exc:
        # Typically "[Errno 98] Address already in use" if a zombie
        # previous instance hasn't released the port yet.  Surface a
        # clear error message instead of an unhandled traceback;
        # start.sh's ``wait -n`` will see us exit and take the
        # container down so OpenHost restarts it with a fresh bind.
        sys.stderr.write(f"[status] FATAL: cannot bind :{PORT}: {exc}\n")
        return 1
    sys.stderr.write(f"[status] listening on :{PORT}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
