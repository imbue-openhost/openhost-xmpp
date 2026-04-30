#!/usr/bin/env python3
"""HTTP sidecar for the openhost-xmpp app.

Three jobs:

1. ``GET /healthz`` — TCP-probe Prosody's c2s port (5222).  Returns
   200 ``ok`` while Prosody is listening, 503 otherwise.  The
   OpenHost router uses this to surface a green/red dashboard tile.
2. ``GET /``        — Public landing page describing how to point an
   XMPP client at the server.  No secrets.  When the request comes
   from the compute-space owner (per OpenHost's
   ``X-OpenHost-Is-Owner`` header), an extra "Manage users" card
   with a link to ``/users`` is appended; anonymous visitors never
   see that affordance.  Mirrors how ``openhost-gemini`` injects the
   editor link only for the owner.
3. Owner-only user-management surface for the XMPP server's
   accounts: ``GET /users`` (HTML page), and a small JSON API at
   ``/api/users`` (list / create) and ``/api/users/<username>``
   (delete / password reset).  The API talks to Prosody via
   ``prosodyctl shell …``, which connects to the running daemon's
   admin shell rather than writing the SQLite store directly — that
   lets us mutate accounts safely while Prosody is running, and
   keeps Prosody as the source of truth for SCRAM hashing rules.

The XMPP protocol itself is published directly on the host's
0.0.0.0 by OpenHost via ``[[ports]]`` in ``openhost.toml``.  This
sidecar only ever sees HTTP requests proxied through the OpenHost
router on its manifest ``port``.

Run from start.sh as::

    cd /usr/local/share/openhost-xmpp/sidecar
    uvicorn server:app --host 0.0.0.0 --port "$STATUS_PORT"
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.responses import JSONResponse
from starlette.responses import PlainTextResponse
from starlette.responses import Response
from starlette.routing import Route

logger = logging.getLogger("openhost-xmpp.sidecar")


# ----------------------------------------------------------------- config

PROBE_HOST = "127.0.0.1"
PROBE_PORT = 5222
PROBE_TIMEOUT_SECONDS = 1.0

# Where Prosody's data lives on the host.  Always ``$OPENHOST_APP_DATA_DIR``
# under OpenHost; the env-var fallback exists so unit tests can run the
# module against a tmp directory.
DATA_DIR = Path(os.environ.get("OPENHOST_APP_DATA_DIR", "/var/lib/prosody"))
PROSODY_CONFIG = DATA_DIR / "prosody.cfg.lua"

# The XMPP host this server is the canonical source for.  Set by
# start.sh (which already resolves it from $XMPP_DOMAIN or
# <APP_NAME>.<ZONE_DOMAIN>).  We need it both to render the landing
# page and to construct JIDs for prosodyctl.
#
# If unset (e.g. the sidecar is launched outside start.sh during
# development) we fall back to a placeholder so the module can still
# load — the user-management endpoints will fail loudly via prosodyctl
# rather than silently operating on the wrong host.
XMPP_DOMAIN = os.environ.get("XMPP_RESOLVED_DOMAIN", "").strip() or "your-openhost-zone"

# The bootstrap admin account that ``start.sh`` mints on first boot.
# We refuse to delete this account through the management UI: it's
# the only account in the rendered config's ``admins = { … }`` list,
# so nuking it would lock the operator out of ``prosodyctl shell``
# until they redeploy or hand-edit the config.  The README documents
# how to rotate the password and how to add additional admins.
ADMIN_LOCALPART = "admin"

PROSODYCTL_BIN = shutil.which("prosodyctl") or "/usr/bin/prosodyctl"

# Permissive but safe hostname shape — used to validate the host
# header reflected into the landing page so a hostile X-Forwarded-Host
# can't smuggle markup into the HTML.  RFC 1123 label rules.
_VALID_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# XMPP localpart restrictions per RFC 7622 are PRECIS-based and quite
# permissive (most printable codepoints).  We deliberately tighten to
# a conservative ASCII subset.  If a real user needs a Unicode JID we
# can loosen this; until then keeping the surface narrow stops a
# whole class of "creative input breaks our shell quoting" footguns
# even though we do quote properly downstream.
_VALID_LOCALPART_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")

# Password constraints.  XMPP servers using SCRAM-SHA-1 (Prosody's
# default) hash password length-independently, so the only floor we
# need is "long enough to resist online brute force".  8 is the
# usual lower bound.  The 128 cap is a sanity check; nobody types a
# 200-char XMPP password by hand and we'd rather reject than have
# the prosodyctl argv be megabytes.
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128


# ---------------------------------------------------------------- helpers

def _safe_hostname() -> str:
    """Return a sanitized version of ``XMPP_DOMAIN`` for embedding in
    HTML.  Anything that doesn't look like a real DNS name falls back
    to a clearly-wrong placeholder so the operator notices."""
    if _VALID_HOSTNAME_RE.match(XMPP_DOMAIN):
        return XMPP_DOMAIN
    return "your-openhost-zone"


async def _prosody_up() -> bool:
    """TCP-probe Prosody's c2s port.  Run the synchronous connect on
    a worker thread so the asyncio event loop doesn't block on the
    1 s timeout."""

    def _probe() -> bool:
        try:
            with socket.create_connection(
                (PROBE_HOST, PROBE_PORT), timeout=PROBE_TIMEOUT_SECONDS
            ):
                return True
        except OSError:
            return False

    return await asyncio.to_thread(_probe)


def _is_owner(request: Request) -> bool:
    """OpenHost's router adds ``X-OpenHost-Is-Owner: true`` on
    requests it has authenticated as the compute-space owner (see
    ``compute_space.web.routes.proxy._identity_headers``).  We use
    its presence as a single owner-vs-public signal everywhere.
    Requests that bypass the router and hit the sidecar's port
    directly arrive with no such header, so this defaults to deny."""
    return request.headers.get("X-OpenHost-Is-Owner", "").lower() == "true"


def _owner_only(request: Request) -> None:
    """Reject the request unless the caller is the owner.

    The xmpp app declares ``public_paths = ["/"]`` in its manifest
    so the public landing page works without a session.  The OpenHost
    router treats that entry as a prefix matching every URL, so any
    private routes have to do their own gate — that's what this
    helper is for, and the gemini app's editor uses the same pattern.

    HTML clients (Accept: text/html) get a 302 to the bare-zone
    ``/login`` so they can sign in and come back.  Everything else
    gets a 401 JSON with no body redirect, which is what an XHR /
    fetch from the management UI would expect.
    """
    if _is_owner(request):
        return
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        # X-Forwarded-Host is set by the OpenHost router on
        # legitimate requests, but a non-router request (someone
        # talking to the container's port directly, or a future
        # proxy bug) can supply any value.  Validate before
        # building the Location header — otherwise a bad value
        # could land an authenticated user on an attacker-chosen
        # domain.  On a malformed header we fall through to the
        # 401 below rather than redirecting.
        zone = (
            request.headers.get("X-Forwarded-Host", "")
            .split(",", 1)[0].strip().split(":", 1)[0]
        )
        if zone and "." in zone and _VALID_HOSTNAME_RE.match(zone):
            bare = zone.split(".", 1)[1]
            if _VALID_HOSTNAME_RE.match(bare):
                raise HTTPException(
                    302, headers={"location": f"https://{bare}/login"}
                )
    raise HTTPException(401, "this route requires an OpenHost session")


# --------------------------------------------------- prosodyctl wrapper

class ProsodyctlError(Exception):
    """Raised when a prosodyctl invocation exits non-zero or its
    output cannot be interpreted."""


def _run_prosodyctl(*args: str, timeout: float = 10.0) -> str:
    """Invoke ``prosodyctl --config <PROSODY_CONFIG> <args...>`` and
    return stdout as a stripped string.  Raises ``ProsodyctlError``
    on non-zero exit, including stderr in the exception message so
    the operator-visible API error is actionable.

    The timeout protects the asyncio event loop from a wedged
    daemon-shell connection — historically the most likely failure
    mode here is "prosody is up but ``mod_admin_shell`` is hung",
    not "prosodyctl returned the wrong answer".
    """
    cmd = [PROSODYCTL_BIN, "--config", str(PROSODY_CONFIG), *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ProsodyctlError(f"prosodyctl not found at {PROSODYCTL_BIN}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ProsodyctlError(
            f"prosodyctl timed out after {timeout}s on {' '.join(map(shlex.quote, cmd))}"
        ) from exc
    if result.returncode != 0:
        # Trim noisy stderr so the JSON error stays a reasonable size,
        # but include enough that "user not found" / "auth failed" /
        # "config error" stays diagnosable.
        stderr_tail = (result.stderr or "").strip()[-500:]
        stdout_tail = (result.stdout or "").strip()[-200:]
        raise ProsodyctlError(
            f"prosodyctl exited {result.returncode}: {stderr_tail or stdout_tail or '(no output)'}"
        )
    return (result.stdout or "").strip()


async def _list_users() -> list[str]:
    """Return localparts of every account on ``XMPP_DOMAIN``, sorted.

    ``prosodyctl shell user list <host>`` prints one bare-jid per
    line (e.g. ``alice@xmpp.example.org``); we parse that into the
    localpart list.  Surrounding output may contain shell prompts
    (``Prosody>``) when run interactively, but the one-shot
    ``shell <command>`` form skips those.
    """
    raw = await asyncio.to_thread(
        _run_prosodyctl, "shell", "user", "list", XMPP_DOMAIN
    )
    users: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("Prosody>", "OK:", "|")):
            # Defensive: skip prompt-ish or banner-ish lines we
            # didn't expect.  ``user list`` in modern Prosody emits
            # plain JIDs, but older shells wrapped output in pipes.
            continue
        # Lines look like ``alice@xmpp.example.org`` — pull out the
        # localpart.  If the @host doesn't match XMPP_DOMAIN the
        # account is on a different vhost (we only run one) and we
        # log + skip.
        if "@" not in line:
            continue
        local, _, host = line.partition("@")
        if host != XMPP_DOMAIN:
            logger.warning("ignoring user on unexpected host: %s", line)
            continue
        # Strip any trailing shell artifacts (a single ``)`` etc.).
        local = local.strip()
        if local:
            users.append(local)
    users.sort()
    return users


def _validate_localpart(value: Any) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, "username must be a string")
    if not _VALID_LOCALPART_RE.match(value):
        raise HTTPException(
            400,
            "username must be 1-64 chars of [a-z A-Z 0-9 . _ -]",
        )
    return value


def _validate_password(value: Any) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, "password must be a string")
    if len(value) < PASSWORD_MIN_LEN:
        raise HTTPException(400, f"password must be at least {PASSWORD_MIN_LEN} characters")
    if len(value) > PASSWORD_MAX_LEN:
        raise HTTPException(400, f"password must be at most {PASSWORD_MAX_LEN} characters")
    # Reject embedded NUL — the shell-quote layer would handle this
    # safely, but Prosody (and many tools) interpret NUL as
    # end-of-string which would silently truncate the password.
    if "\x00" in value:
        raise HTTPException(400, "password must not contain NUL bytes")
    return value


# ------------------------------------------------------ HTML rendering

_LANDING_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XMPP Server</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
            Roboto, sans-serif; background:#0f1117; color:#e1e4e8;
            padding:40px; max-width:720px; margin:0 auto; line-height:1.4; }}
    h1 {{ color:#fff; }}
    h2 {{ color:#fff; margin-top:1.5em; }}
    code {{ background:#0d1117; border:1px solid #30363d; padding:2px 6px;
            border-radius:4px; }}
    .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
             padding:16px 20px; margin:16px 0; }}
    .status-ok {{ color:#2ea043; font-weight:600; }}
    .status-bad {{ color:#f85149; font-weight:600; }}
    ul {{ padding-left: 1.4em; }}
    li {{ margin: 0.3em 0; }}
    a {{ color:#58a6ff; }}
  </style>
</head>
<body>
  <h1>Prosody XMPP Server</h1>

  <div class="card">
    <p>XMPP daemon status: <span class="{status_class}">{status_text}</span></p>
  </div>

  <div class="card">
    <h2>Connecting</h2>
    <p>Point any XMPP client at <code>{host}</code>:</p>
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
       <code>$OPENHOST_APP_DATA_DIR/certs/</code> and restart the
       app from the OpenHost dashboard to pick it up.</p>
    <p>Recommended clients:
       <a href="https://conversations.im/">Conversations</a> (Android),
       <a href="https://dino.im/">Dino</a> (Linux),
       <a href="https://gajim.org/">Gajim</a> (cross-platform),
       <a href="https://monal-im.org/">Monal</a> (iOS/macOS).</p>
  </div>

  <div class="card">
    <h2>Federation</h2>
    <p>Server-to-server federation is enabled on port <code>5269</code>
       (STARTTLS) and <code>5270</code> (direct TLS).  Other servers
       reject self-signed certificates, so federation with strangers
       will fail until real certificates are in place.  Same-zone
       (user-to-user on your own server) works regardless.</p>
  </div>{owner_section}
</body>
</html>
"""

_OWNER_SECTION = """

  <div class="card owner-card">
    <h2>You're signed in as the owner</h2>
    <p>Manage user accounts on this XMPP server:</p>
    <p><a class="cta" href="/users">Manage users</a></p>
    <p style="color:#8b949e; font-size:0.9em;">Only you see this card.
       Anonymous visitors get the public landing page above without
       any management links.</p>
  </div>
"""

_OWNER_STYLE = """
    .owner-card { border-color: #1f6feb; }
    .cta {
      display: inline-block; background:#1f6feb; color:#fff;
      text-decoration: none; padding: 8px 16px; border-radius: 6px;
      font-weight: 600;
    }
    .cta:hover { background:#388bfd; }
"""


_USERS_PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XMPP Users</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
           Roboto, sans-serif; background:#0f1117; color:#e1e4e8;
           padding:40px; max-width:720px; margin:0 auto; line-height:1.4; }
    h1 { color:#fff; }
    h2 { color:#fff; margin-top:1.5em; }
    a { color:#58a6ff; }
    code { background:#0d1117; border:1px solid #30363d; padding:2px 6px;
           border-radius:4px; }
    .card { background:#161b22; border:1px solid #30363d; border-radius:8px;
            padding:16px 20px; margin:16px 0; }
    table { width:100%; border-collapse: collapse; margin-top: 8px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; }
    th { color:#8b949e; font-weight: 500; font-size: 0.9em; text-transform: uppercase; }
    .row-jid { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .pill { display:inline-block; background:#161b22; border:1px solid #30363d;
            color:#8b949e; padding:1px 6px; border-radius:99px; font-size:0.8em; }
    button { background:#21262d; color:#c9d1d9; border:1px solid #30363d;
             border-radius:6px; padding:5px 10px; cursor:pointer; font-size:0.9em; }
    button:hover { background:#30363d; }
    button.danger { background:#21262d; color:#f85149; border-color:#f85149; }
    button.danger:hover { background:#3d1417; }
    button.primary { background:#238636; color:#fff; border-color:#238636; }
    button.primary:hover { background:#2ea043; }
    input { background:#0d1117; color:#e1e4e8; border:1px solid #30363d;
            border-radius:6px; padding:6px 8px; font: inherit; }
    input:focus { border-color:#1f6feb; outline: none; }
    .form-row { display:flex; gap:8px; margin-top:8px; align-items:center; }
    .form-row label { color:#8b949e; min-width:90px; }
    .msg-ok { color:#2ea043; }
    .msg-err { color:#f85149; }
    .nav { color:#8b949e; }
  </style>
</head>
<body>
  <p class="nav"><a href="/">&larr; Back to landing page</a></p>
  <h1>XMPP Users <span class="pill">@@@HOST@@</span></h1>
  <p>Manage accounts on this XMPP server. Only the OpenHost compute-space
     owner can see or use this page.</p>

  <div class="card">
    <h2>Create user</h2>
    <p>The new account's JID will be <code>&lt;username&gt;@@@HOST@@</code>.</p>
    <form id="create-form">
      <div class="form-row">
        <label for="new-username">Username</label>
        <input id="new-username" name="username" required autocomplete="off"
               pattern="[A-Za-z0-9._\\-]{1,64}" minlength="1" maxlength="64"
               placeholder="alice">
      </div>
      <div class="form-row">
        <label for="new-password">Password</label>
        <input id="new-password" name="password" type="password" required
               minlength="8" maxlength="128" autocomplete="new-password">
      </div>
      <div class="form-row">
        <button class="primary" type="submit">Create user</button>
        <span id="create-msg"></span>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>Existing users</h2>
    <p id="users-empty" style="color:#8b949e; display:none;">No accounts yet.</p>
    <table id="users-table" style="display:none;">
      <thead>
        <tr><th>Username</th><th>JID</th><th></th></tr>
      </thead>
      <tbody id="users-tbody"></tbody>
    </table>
    <p id="users-error" class="msg-err" style="display:none;"></p>
  </div>

  <script>
  (function () {
    "use strict";
    var XMPP_HOST = "@@HOST@@";
    var ADMIN_LOCALPART = "@@ADMIN_LOCALPART@@";

    function setMessage(el, text, ok) {
      el.textContent = text;
      el.className = ok ? "msg-ok" : "msg-err";
    }

    function escapeHtml(value) {
      // Defence-in-depth: every value we render through this script
      // came from the JSON API, which only ever returns localparts
      // matching ^[A-Za-z0-9._-]{1,64}$ (validated server-side).  We
      // still escape so any change to that contract doesn't open
      // an injection vector.
      return String(value).replace(/[&<>"']/g, function (c) {
        return ({"&": "&amp;", "<": "&lt;", ">": "&gt;",
                 '"': "&quot;", "'": "&#39;"}[c]);
      });
    }

    function renderUsers(users) {
      var tbody = document.getElementById("users-tbody");
      var empty = document.getElementById("users-empty");
      var table = document.getElementById("users-table");
      var error = document.getElementById("users-error");
      error.style.display = "none";
      tbody.innerHTML = "";
      if (!users.length) {
        empty.style.display = "";
        table.style.display = "none";
        return;
      }
      empty.style.display = "none";
      table.style.display = "";
      users.forEach(function (u) {
        var tr = document.createElement("tr");
        var localCell = document.createElement("td");
        localCell.textContent = u;
        var jidCell = document.createElement("td");
        jidCell.className = "row-jid";
        jidCell.textContent = u + "@" + XMPP_HOST;
        var actionsCell = document.createElement("td");
        actionsCell.style.textAlign = "right";

        var resetBtn = document.createElement("button");
        resetBtn.textContent = "Reset password";
        resetBtn.onclick = function () { resetPassword(u); };
        actionsCell.appendChild(resetBtn);

        if (u !== ADMIN_LOCALPART) {
          var delBtn = document.createElement("button");
          delBtn.className = "danger";
          delBtn.textContent = "Delete";
          delBtn.style.marginLeft = "8px";
          delBtn.onclick = function () { deleteUser(u); };
          actionsCell.appendChild(delBtn);
        } else {
          var note = document.createElement("span");
          note.className = "pill";
          note.style.marginLeft = "8px";
          note.textContent = "admin (protected)";
          actionsCell.appendChild(note);
        }
        tr.appendChild(localCell);
        tr.appendChild(jidCell);
        tr.appendChild(actionsCell);
        tbody.appendChild(tr);
      });
    }

    function loadUsers() {
      fetch("/api/users", {credentials: "same-origin"})
        .then(function (r) {
          return r.json().then(function (j) { return [r.ok, j]; });
        })
        .then(function (pair) {
          if (!pair[0]) {
            var error = document.getElementById("users-error");
            error.style.display = "";
            error.textContent = "Failed to load users: " +
              (pair[1].error || "unknown error");
            return;
          }
          renderUsers(pair[1].users || []);
        })
        .catch(function (err) {
          var error = document.getElementById("users-error");
          error.style.display = "";
          error.textContent = "Failed to load users: " + err;
        });
    }

    document.getElementById("create-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var username = document.getElementById("new-username").value;
      var password = document.getElementById("new-password").value;
      var msg = document.getElementById("create-msg");
      msg.textContent = "Creating…";
      msg.className = "";
      fetch("/api/users", {
        method: "POST",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({username: username, password: password})
      }).then(function (r) {
        return r.json().then(function (j) { return [r.ok, j]; });
      }).then(function (pair) {
        if (pair[0]) {
          setMessage(msg, "Created " + username + "@" + XMPP_HOST, true);
          document.getElementById("create-form").reset();
          loadUsers();
        } else {
          setMessage(msg, "Failed: " + (pair[1].error || "unknown error"), false);
        }
      }).catch(function (err) {
        setMessage(msg, "Network error: " + err, false);
      });
    });

    function deleteUser(username) {
      if (!window.confirm("Delete " + username + "@" + XMPP_HOST + "? This cannot be undone.")) {
        return;
      }
      fetch("/api/users/" + encodeURIComponent(username), {
        method: "DELETE",
        credentials: "same-origin"
      }).then(function (r) {
        if (r.status === 204) { loadUsers(); return; }
        return r.json().then(function (j) {
          window.alert("Delete failed: " + (j.error || ("HTTP " + r.status)));
        });
      }).catch(function (err) {
        window.alert("Delete failed: " + err);
      });
    }

    function resetPassword(username) {
      var pw = window.prompt("New password for " + username + "@" + XMPP_HOST +
                             " (8-128 chars):");
      if (pw === null) { return; }
      if (pw.length < 8) {
        window.alert("Password too short.");
        return;
      }
      fetch("/api/users/" + encodeURIComponent(username) + "/password", {
        method: "PUT",
        credentials: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({password: pw})
      }).then(function (r) {
        return r.json().then(function (j) { return [r.ok, j]; });
      }).then(function (pair) {
        if (pair[0]) {
          window.alert("Password updated.");
        } else {
          window.alert("Reset failed: " + (pair[1].error || "unknown error"));
        }
      }).catch(function (err) {
        window.alert("Reset failed: " + err);
      });
    }

    loadUsers();
  })();
  </script>
</body>
</html>
"""


def _render_landing(*, owner: bool, prosody_up: bool, host: str) -> str:
    body = _LANDING_TEMPLATE.format(
        status_class="status-ok" if prosody_up else "status-bad",
        status_text="running"
        if prosody_up
        else "not listening on 5222 (still starting?)",
        host=html.escape(host, quote=True),
        owner_section=_OWNER_SECTION if owner else "",
    )
    if owner:
        body = body.replace("</style>", _OWNER_STYLE + "  </style>", 1)
    return body


def _render_users_page(host: str) -> str:
    return (
        _USERS_PAGE_TEMPLATE
        .replace("@@HOST@@", html.escape(host, quote=True))
        .replace("@@ADMIN_LOCALPART@@", html.escape(ADMIN_LOCALPART, quote=True))
    )


# ----------------------------------------------------------------- handlers

async def landing(request: Request) -> HTMLResponse:
    owner = _is_owner(request)
    prosody_up = await _prosody_up()
    # Prefer X-Forwarded-Host: the raw Host header inside the
    # container is the OpenHost router's loopback, which a user
    # pasting into a client can't use.  Sanitise hard because the
    # value is attacker-controlled (the landing page is public).
    raw_host = (
        request.headers.get("X-Forwarded-Host")
        or request.headers.get("Host")
        or _safe_hostname()
    )
    host = raw_host.split(",", 1)[0].strip().split(":", 1)[0]
    if not _VALID_HOSTNAME_RE.match(host):
        host = _safe_hostname()
    body = _render_landing(owner=owner, prosody_up=prosody_up, host=host)
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


async def healthz(request: Request) -> Response:
    if await _prosody_up():
        return PlainTextResponse("ok\n")
    return PlainTextResponse("prosody-not-listening\n", status_code=503)


async def users_page(request: Request) -> HTMLResponse:
    _owner_only(request)
    body = _render_users_page(host=_safe_hostname())
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


async def list_users_api(request: Request) -> JSONResponse:
    _owner_only(request)
    try:
        users = await _list_users()
    except ProsodyctlError as exc:
        logger.error("list users via prosodyctl: %s", exc)
        raise HTTPException(502, f"prosodyctl: {exc}")
    return JSONResponse({"host": XMPP_DOMAIN, "users": users})


async def _read_json_body(request: Request) -> dict[str, Any]:
    raw = await request.body()
    # XMPP user-management bodies are tiny; cap aggressively to keep
    # malformed clients from forcing the sidecar to allocate.
    if len(raw) > 4096:
        raise HTTPException(413, "request body too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(400, f"invalid JSON body: {exc}")
    if not isinstance(data, dict):
        raise HTTPException(400, "JSON body must be an object")
    return data


async def create_user_api(request: Request) -> JSONResponse:
    _owner_only(request)
    data = await _read_json_body(request)
    username = _validate_localpart(data.get("username"))
    password = _validate_password(data.get("password"))
    jid = f"{username}@{XMPP_DOMAIN}"
    try:
        # ``prosodyctl shell user create <jid> <password>`` connects
        # to the running daemon's admin shell and creates the
        # account.  Exits non-zero with a descriptive stderr if the
        # user already exists, the host is wrong, or the daemon
        # isn't reachable; we surface that as the API error.
        await asyncio.to_thread(
            _run_prosodyctl, "shell", "user", "create", jid, password
        )
    except ProsodyctlError as exc:
        # ``user create`` does NOT distinguish "exists" from other
        # errors via exit code, so we sniff the message.  This
        # mirrors what the Prosody admin shell prints:
        # ``error: That user already exists``.  Anything else is a
        # 502 (prosody / config problem on our side).
        msg = str(exc).lower()
        if "already exists" in msg:
            raise HTTPException(409, f"user {jid} already exists")
        logger.error("create user %s via prosodyctl: %s", jid, exc)
        raise HTTPException(502, f"prosodyctl: {exc}")
    return JSONResponse(
        {"jid": jid, "username": username, "host": XMPP_DOMAIN},
        status_code=201,
    )


async def delete_user_api(request: Request) -> Response:
    _owner_only(request)
    username = _validate_localpart(request.path_params["username"])
    if username == ADMIN_LOCALPART:
        # See the comment on ADMIN_LOCALPART for why this is
        # protected.  The operator can change the admin password
        # via the reset-password endpoint, but cannot delete the
        # account from the management UI.
        raise HTTPException(
            400,
            f"refusing to delete the bootstrap admin account "
            f"({ADMIN_LOCALPART}@{XMPP_DOMAIN}); rotate its password instead",
        )
    jid = f"{username}@{XMPP_DOMAIN}"
    try:
        await asyncio.to_thread(
            _run_prosodyctl, "shell", "user", "delete", jid
        )
    except ProsodyctlError as exc:
        msg = str(exc).lower()
        if "not found" in msg or "no such user" in msg:
            raise HTTPException(404, f"user {jid} not found")
        logger.error("delete user %s via prosodyctl: %s", jid, exc)
        raise HTTPException(502, f"prosodyctl: {exc}")
    return Response(status_code=204)


async def reset_password_api(request: Request) -> JSONResponse:
    _owner_only(request)
    username = _validate_localpart(request.path_params["username"])
    data = await _read_json_body(request)
    password = _validate_password(data.get("password"))
    jid = f"{username}@{XMPP_DOMAIN}"
    try:
        await asyncio.to_thread(
            _run_prosodyctl, "shell", "user", "password", jid, password
        )
    except ProsodyctlError as exc:
        msg = str(exc).lower()
        if "not found" in msg or "no such user" in msg:
            raise HTTPException(404, f"user {jid} not found")
        logger.error("reset password for %s via prosodyctl: %s", jid, exc)
        raise HTTPException(502, f"prosodyctl: {exc}")
    return JSONResponse({"jid": jid, "ok": True})


# ----------------------------------------------------------------- error handler

async def http_exception_handler(request: Request, exc: HTTPException) -> Response:
    if 300 <= exc.status_code < 400:
        location = (exc.headers or {}).get("location", "")
        return Response(status_code=exc.status_code, headers={"location": location})
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
    return PlainTextResponse(str(exc.detail) + "\n", status_code=exc.status_code)


# ----------------------------------------------------------------- app

routes = [
    Route("/", landing),
    Route("/healthz", healthz),
    Route("/users", users_page),
    Route("/api/users", list_users_api, methods=["GET"]),
    Route("/api/users", create_user_api, methods=["POST"]),
    Route("/api/users/{username}", delete_user_api, methods=["DELETE"]),
    Route("/api/users/{username}/password", reset_password_api, methods=["PUT"]),
]


app: Starlette = Starlette(
    debug=False,
    routes=routes,
    exception_handlers={HTTPException: http_exception_handler},
)
