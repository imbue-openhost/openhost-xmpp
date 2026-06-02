#!/usr/bin/env python3
"""HTTP sidecar for the OpenHost Prosody XMPP app.

Serves two roles:

1. **Health check + public landing page** -- the OpenHost router requires
   every app to answer HTTP on the manifest's ``port`` so it can
   health-check and serve a dashboard tile.  Non-owners see a connect-
   instructions page; the ``/healthz`` endpoint is always public.

2. **Owner admin panel** -- when the ``X-OpenHost-Is-Owner: true`` header
   is present (set by the router after session verification and never
   forwardable from the public internet), the root page becomes a
   management dashboard with account CRUD and an embedded Converse.js
   XMPP web client.

All code is stdlib-only Python (no pip dependencies).
"""

from __future__ import annotations

import html
import json
import logging
import os
import re
import socket
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("status")
logging.basicConfig(
    level=logging.INFO,
    format="[status] %(message)s",
    stream=sys.stderr,
)

# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------


def _load_port() -> int:
    """Read ``STATUS_PORT`` from env.  Empty string or unset -> 8080."""
    raw = os.environ.get("STATUS_PORT", "").strip() or "8080"
    try:
        port = int(raw)
    except ValueError:
        log.critical("STATUS_PORT=%r is not an integer", raw)
        sys.exit(1)
    if not 1 <= port <= 65535:
        log.critical("STATUS_PORT=%r out of range", raw)
        sys.exit(1)
    return port


PORT = _load_port()

DATA_DIR = os.environ.get("OPENHOST_APP_DATA_DIR", "/var/lib/prosody")
CONFIG_FILE = os.path.join(DATA_DIR, "prosody.cfg.lua")
DB_PATH = os.path.join(DATA_DIR, "prosody.sqlite")

# Prosody's c2s port -- checking that this specific port is open is a
# more useful liveness signal than 5280 (HTTP) or 5269 (s2s).
PROBE_HOST = "127.0.0.1"
PROBE_PORT = 5222
PROBE_TIMEOUT_SECONDS = 1.0

# Hostname validation -- permissive but safe.
_VALID_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# Username validation: alphanumeric plus . _ - , max 64 chars.
_VALID_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")

# Maximum JSON body size we will read (64 KiB).
MAX_BODY_SIZE = 64 * 1024

# ---------------------------------------------------------------------------
# Domain resolution
# ---------------------------------------------------------------------------


def _resolve_domain() -> Optional[str]:
    """Determine the XMPP domain from environment or config file.

    Tries, in order:
      1. XMPP_DOMAIN env var
      2. Parse VirtualHost "..." from the rendered prosody.cfg.lua
      3. Returns None (caller should fall back to X-Forwarded-Host)
    """
    env_domain = os.environ.get("XMPP_DOMAIN", "").strip()
    if env_domain:
        return env_domain

    try:
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                m = re.match(r'^\s*VirtualHost\s+"([^"]+)"', line)
                if m:
                    return m.group(1)
    except OSError:
        pass

    return None


# Resolved once at startup; may be None if we need to use the Host header.
_STATIC_DOMAIN = _resolve_domain()


def get_domain(headers: Any) -> str:
    """Return the XMPP domain, using request headers as a last resort."""
    if _STATIC_DOMAIN:
        return _STATIC_DOMAIN
    raw_host = (
        headers.get("X-Forwarded-Host")
        or headers.get("Host")
        or "your-openhost-zone"
    )
    host = raw_host.split(",", 1)[0].strip().split(":", 1)[0]
    if not _VALID_HOSTNAME_RE.match(host):
        return "your-openhost-zone"
    return host


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def _prosody_up() -> bool:
    """Return True iff something is listening on localhost:5222."""
    try:
        with socket.create_connection(
            (PROBE_HOST, PROBE_PORT), timeout=PROBE_TIMEOUT_SECONDS
        ):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Owner detection
# ---------------------------------------------------------------------------


def _is_owner(headers: Any) -> bool:
    """Check whether the request comes from the zone owner.

    The OpenHost router strips all client-supplied X-OpenHost-* headers
    and only adds ``X-OpenHost-Is-Owner: true`` after verifying the
    session cookie, so this header is unforgeable.
    """
    return headers.get("X-OpenHost-Is-Owner", "").lower() == "true"


# ---------------------------------------------------------------------------
# Account management helpers
# ---------------------------------------------------------------------------


def _validate_username(username: str) -> Optional[str]:
    """Return an error message if the username is invalid, else None."""
    if not username:
        return "Username is required"
    if not _VALID_USERNAME_RE.match(username):
        return (
            "Username may only contain letters, digits, dots, "
            "underscores, and hyphens (max 64 chars)"
        )
    if ".." in username or "/" in username:
        return "Invalid username"
    return None


def _validate_password(password: str) -> Optional[str]:
    """Return an error message if the password is invalid, else None."""
    if not password or not isinstance(password, str):
        return "Password is required"
    if len(password) < 8:
        return "Password must be at least 8 characters"
    return None


def _list_accounts(domain: str) -> Tuple[list[str], Optional[str]]:
    """Query the Prosody SQLite DB for account usernames.

    Returns (accounts, error).  On success error is None; on failure
    accounts is empty and error describes what went wrong.
    """
    if not os.path.isfile(DB_PATH):
        return [], None  # DB not created yet, no accounts
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.execute(
                "SELECT DISTINCT user FROM prosody "
                "WHERE host=? AND store='accounts' ORDER BY user",
                (domain,),
            )
            return [row[0] for row in cur.fetchall()], None
    except sqlite3.Error as exc:
        log.error("SQLite error listing accounts: %s", exc)
        return [], f"Database error: {exc}"


def _run_prosodyctl(*args: str) -> Tuple[bool, str]:
    """Run a prosodyctl command via runuser and return (success, output)."""
    cmd = [
        "runuser",
        "-u",
        "prosody",
        "-g",
        "prosody",
        "--",
        "prosodyctl",
        "--config",
        CONFIG_FILE,
    ] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = (result.stdout + result.stderr).strip()
        if result.returncode == 0:
            return True, output
        return False, output or f"prosodyctl exited with code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "prosodyctl command timed out"
    except OSError as exc:
        return False, f"Failed to run prosodyctl: {exc}"


def _create_account(username: str, domain: str, password: str) -> Tuple[bool, str]:
    """Create (or update) an XMPP account via prosodyctl register."""
    return _run_prosodyctl("register", username, domain, password)


def _delete_account(username: str, domain: str) -> Tuple[bool, str]:
    """Delete an XMPP account via prosodyctl deluser.

    Falls back to direct SQLite deletion if prosodyctl fails or if
    its output contains error indicators (prosodyctl sometimes exits
    0 even when the admin shell socket is unavailable).
    """
    jid = f"{username}@{domain}"
    ok, output = _run_prosodyctl("deluser", jid)

    # prosodyctl deluser can exit 0 while printing an error about
    # the admin shell socket.  Detect this and fall through.
    if ok and "unable to connect" not in output.lower() and "error" not in output.lower():
        return True, output

    # Fallback: delete directly from the SQLite DB.
    log.info("prosodyctl deluser unsuccessful, trying direct DB deletion: %s", output)
    if not os.path.isfile(DB_PATH):
        return False, "Database file not found"
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            cur = conn.execute(
                "DELETE FROM prosody WHERE user=? AND host=?",
                (username, domain),
            )
            if cur.rowcount == 0:
                return False, f"Account {username} not found"
            conn.commit()
        return True, f"Deleted {username} via direct DB removal"
    except sqlite3.Error as exc:
        return False, f"DB deletion failed: {exc}"


def _change_password(
    username: str, domain: str, password: str
) -> Tuple[bool, str]:
    """Change an account password.

    Prosody 13's ``prosodyctl register`` is an upsert: if the account
    already exists it updates the password.  This avoids the interactive
    ``prosodyctl passwd`` command entirely.
    """
    return _run_prosodyctl("register", username, domain, password)


# ---------------------------------------------------------------------------
# HTML templates
# ---------------------------------------------------------------------------

# Public landing page (non-owner visitors)
_PUBLIC_HTML = """\
<!doctype html>
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
          encryption after connecting -- most desktop / mobile clients.</li>
      <li>Port <code>5223</code> (direct TLS, XEP-0368) for clients on
          networks that strip or downgrade plaintext greetings.</li>
    </ul>
    <p>Self-signed certificate on first boot -- accept it once in your
       client, or drop a real cert/key pair named
       <code>&lt;xmpp-domain&gt;.crt</code> +
       <code>&lt;xmpp-domain&gt;.key</code> into
       <code>$OPENHOST_APP_DATA_DIR/certs/</code> and restart the
       app from the OpenHost dashboard to pick the new cert up.</p>
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

# Owner admin dashboard
_ADMIN_HTML = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>XMPP Admin</title>
  <link rel="stylesheet" href="https://cdn.conversejs.org/dist/converse.min.css">
  <style>
    :root {
      --bg-primary: #0f1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #1c2128;
      --border: #30363d;
      --text-primary: #e1e4e8;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --accent-hover: #79b8ff;
      --danger: #f85149;
      --danger-hover: #ff6e66;
      --success: #2ea043;
      --warning: #d29922;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg-primary); color: var(--text-primary);
      height: 100vh; display: flex; flex-direction: column;
    }
    .header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 20px; background: var(--bg-secondary);
      border-bottom: 1px solid var(--border);
    }
    .header h1 { font-size: 16px; color: #fff; }
    .header .domain { color: var(--text-secondary); font-size: 13px; }
    .header .status { font-size: 12px; padding: 3px 8px; border-radius: 12px; }
    .header .status.ok { background: rgba(46,160,67,0.15); color: var(--success); }
    .header .status.bad { background: rgba(248,81,73,0.15); color: var(--danger); }
    .tabs {
      display: flex; background: var(--bg-secondary);
      border-bottom: 1px solid var(--border);
    }
    .tab {
      padding: 10px 24px; cursor: pointer; font-size: 14px;
      color: var(--text-secondary); border-bottom: 2px solid transparent;
      transition: color 0.15s, border-color 0.15s;
      user-select: none;
    }
    .tab:hover { color: var(--text-primary); }
    .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
    .tab-content { display: none; flex: 1; overflow: auto; }
    .tab-content.active { display: flex; flex-direction: column; }
    #chat-panel { flex: 1; position: relative; }
    #chat-panel.active { display: block; }

    /* Accounts tab */
    .accounts-container { padding: 20px; max-width: 800px; width: 100%; margin: 0 auto; }
    .section { margin-bottom: 24px; }
    .section h2 { font-size: 15px; color: #fff; margin-bottom: 12px; }
    .form-row {
      display: flex; gap: 8px; align-items: flex-end; flex-wrap: wrap;
    }
    .form-group { display: flex; flex-direction: column; gap: 4px; }
    .form-group label { font-size: 12px; color: var(--text-secondary); }
    .form-group input {
      background: var(--bg-tertiary); border: 1px solid var(--border);
      color: var(--text-primary); padding: 8px 12px; border-radius: 6px;
      font-size: 14px; outline: none; min-width: 180px;
    }
    .form-group input:focus { border-color: var(--accent); }
    button {
      padding: 8px 16px; border: none; border-radius: 6px;
      font-size: 13px; cursor: pointer; font-weight: 500;
      transition: background 0.15s;
    }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-danger { background: var(--danger); color: #fff; }
    .btn-danger:hover { background: var(--danger-hover); }
    .btn-secondary {
      background: var(--bg-tertiary); color: var(--text-primary);
      border: 1px solid var(--border);
    }
    .btn-secondary:hover { background: var(--border); }
    .btn-sm { padding: 5px 10px; font-size: 12px; }

    table { width: 100%; border-collapse: collapse; }
    th, td {
      text-align: left; padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }
    th { color: var(--text-secondary); font-size: 12px; font-weight: 600; text-transform: uppercase; }
    td { font-size: 14px; }
    tr:hover td { background: var(--bg-tertiary); }
    .actions { display: flex; gap: 6px; }

    .alert {
      padding: 10px 14px; border-radius: 6px; font-size: 13px;
      margin-bottom: 12px; display: none;
    }
    .alert.error { background: rgba(248,81,73,0.12); color: var(--danger); display: block; }
    .alert.success { background: rgba(46,160,67,0.12); color: var(--success); display: block; }
    .empty-state {
      text-align: center; padding: 40px 20px;
      color: var(--text-secondary); font-size: 14px;
    }
    .loading { text-align: center; padding: 20px; color: var(--text-secondary); }

    /* Password change modal */
    .modal-overlay {
      display: none; position: fixed; inset: 0;
      background: rgba(0,0,0,0.6); z-index: 1000;
      align-items: center; justify-content: center;
    }
    .modal-overlay.visible { display: flex; }
    .modal {
      background: var(--bg-secondary); border: 1px solid var(--border);
      border-radius: 10px; padding: 24px; min-width: 360px; max-width: 90vw;
    }
    .modal h3 { font-size: 16px; color: #fff; margin-bottom: 16px; }
    .modal .form-group { margin-bottom: 12px; }
    .modal .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }

    /* Converse.js overrides for dark embed */
    #conversejs { height: 100%; }
  </style>
</head>
<body>

<div class="header">
  <div>
    <h1>XMPP Admin</h1>
    <span class="domain" id="domainLabel"></span>
  </div>
  <span class="status @@STATUS_CLASS@@" id="statusBadge">@@STATUS_TEXT@@</span>
</div>

<div class="tabs">
  <div class="tab active" data-tab="accounts">Accounts</div>
  <div class="tab" data-tab="chat">Chat</div>
</div>

<div id="accounts-panel" class="tab-content active">
  <div class="accounts-container">
    <div id="alertBox" class="alert"></div>

    <div class="section">
      <h2>Create Account</h2>
      <form id="createForm" class="form-row" autocomplete="off">
        <div class="form-group">
          <label for="newUser">Username</label>
          <input type="text" id="newUser" placeholder="alice" required
                 pattern="[a-zA-Z0-9._-]+" maxlength="64" autocomplete="off">
        </div>
        <div class="form-group">
          <label for="newPass">Password</label>
          <input type="password" id="newPass" placeholder="min 8 characters"
                 required minlength="8" autocomplete="new-password">
        </div>
        <button type="submit" class="btn-primary" id="createBtn">Create</button>
      </form>
    </div>

    <div class="section">
      <h2>Accounts</h2>
      <div id="accountsLoading" class="loading">Loading accounts...</div>
      <table id="accountsTable" style="display:none">
        <thead>
          <tr><th>Username</th><th>JID</th><th style="width:180px">Actions</th></tr>
        </thead>
        <tbody id="accountsBody"></tbody>
      </table>
      <div id="emptyState" class="empty-state" style="display:none">
        No accounts found. Create one above.
      </div>
    </div>
  </div>
</div>

<div id="chat-panel" class="tab-content">
  <div id="conversejs-container" style="flex:1; height:100%; position:relative;"></div>
</div>

<!-- Password change modal -->
<div id="pwModal" class="modal-overlay">
  <div class="modal">
    <h3>Change Password</h3>
    <p style="font-size:13px; color:var(--text-secondary); margin-bottom:12px;">
      Changing password for <strong id="pwModalUser"></strong>
    </p>
    <div class="form-group">
      <label>New Password</label>
      <input type="password" id="pwModalInput" placeholder="min 8 characters"
             minlength="8" autocomplete="new-password">
    </div>
    <div class="modal-actions">
      <button class="btn-secondary" onclick="closePwModal()">Cancel</button>
      <button class="btn-primary" id="pwModalSave" onclick="doChangePassword()">Save</button>
    </div>
  </div>
</div>

<script>
  // ---- Configuration ----
  const XMPP_DOMAIN = '@@XMPP_DOMAIN@@';
  document.getElementById('domainLabel').textContent = XMPP_DOMAIN;

  // ---- Tab switching ----
  let converseLoaded = false;
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      const target = tab.getAttribute('data-tab');
      document.getElementById(target + '-panel').classList.add('active');
      if (target === 'chat' && !converseLoaded) {
        loadConverse();
      }
    });
  });

  // ---- Alert helper ----
  function showAlert(msg, type) {
    const box = document.getElementById('alertBox');
    box.textContent = msg;
    box.className = 'alert ' + type;
    setTimeout(() => { box.className = 'alert'; }, 5000);
  }

  // ---- Accounts CRUD ----
  async function loadAccounts() {
    document.getElementById('accountsLoading').style.display = 'block';
    document.getElementById('accountsTable').style.display = 'none';
    document.getElementById('emptyState').style.display = 'none';
    try {
      const resp = await fetch('/api/accounts');
      if (!resp.ok) throw new Error('Failed to load accounts');
      const data = await resp.json();
      const accounts = data.accounts || [];
      const tbody = document.getElementById('accountsBody');
      tbody.innerHTML = '';
      if (accounts.length === 0) {
        document.getElementById('emptyState').style.display = 'block';
      } else {
        accounts.forEach(user => {
          const tr = document.createElement('tr');
          const jid = user + '@' + XMPP_DOMAIN;

          const tdUser = document.createElement('td');
          tdUser.textContent = user;

          const tdJid = document.createElement('td');
          const code = document.createElement('code');
          code.textContent = jid;
          tdJid.appendChild(code);

          const tdActions = document.createElement('td');
          tdActions.className = 'actions';

          const pwBtn = document.createElement('button');
          pwBtn.className = 'btn-secondary btn-sm';
          pwBtn.textContent = 'Password';
          pwBtn.addEventListener('click', () => openPwModal(user));

          const delBtn = document.createElement('button');
          delBtn.className = 'btn-danger btn-sm';
          delBtn.textContent = 'Delete';
          delBtn.addEventListener('click', () => deleteAccount(user));

          tdActions.appendChild(pwBtn);
          tdActions.appendChild(delBtn);

          tr.appendChild(tdUser);
          tr.appendChild(tdJid);
          tr.appendChild(tdActions);
          tbody.appendChild(tr);
        });
        document.getElementById('accountsTable').style.display = 'table';
      }
    } catch (err) {
      showAlert('Error loading accounts: ' + err.message, 'error');
    } finally {
      document.getElementById('accountsLoading').style.display = 'none';
    }
  }

  function escHtml(s) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  document.getElementById('createForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = document.getElementById('createBtn');
    btn.disabled = true;
    const username = document.getElementById('newUser').value.trim();
    const password = document.getElementById('newPass').value;
    try {
      const resp = await fetch('/api/accounts', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password}),
      });
      const data = await resp.json();
      if (resp.ok) {
        showAlert('Account ' + username + ' created successfully', 'success');
        document.getElementById('newUser').value = '';
        document.getElementById('newPass').value = '';
        loadAccounts();
      } else {
        showAlert(data.error || 'Failed to create account', 'error');
      }
    } catch (err) {
      showAlert('Error: ' + err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  async function deleteAccount(username) {
    if (!confirm('Delete account ' + username + '@' + XMPP_DOMAIN + '? This cannot be undone.')) return;
    try {
      const resp = await fetch('/api/accounts/' + encodeURIComponent(username), {
        method: 'DELETE',
      });
      const data = await resp.json();
      if (resp.ok) {
        showAlert('Account ' + username + ' deleted', 'success');
        loadAccounts();
      } else {
        showAlert(data.error || 'Failed to delete account', 'error');
      }
    } catch (err) {
      showAlert('Error: ' + err.message, 'error');
    }
  }

  // ---- Password modal ----
  let pwModalUsername = '';
  function openPwModal(user) {
    pwModalUsername = user;
    document.getElementById('pwModalUser').textContent = user + '@' + XMPP_DOMAIN;
    document.getElementById('pwModalInput').value = '';
    document.getElementById('pwModal').classList.add('visible');
    document.getElementById('pwModalInput').focus();
  }
  function closePwModal() {
    document.getElementById('pwModal').classList.remove('visible');
    pwModalUsername = '';
  }
  async function doChangePassword() {
    const pw = document.getElementById('pwModalInput').value;
    if (pw.length < 8) { alert('Password must be at least 8 characters'); return; }
    try {
      const resp = await fetch('/api/accounts/' + encodeURIComponent(pwModalUsername) + '/password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pw}),
      });
      const data = await resp.json();
      if (resp.ok) {
        showAlert('Password changed for ' + pwModalUsername, 'success');
        closePwModal();
      } else {
        showAlert(data.error || 'Failed to change password', 'error');
      }
    } catch (err) {
      showAlert('Error: ' + err.message, 'error');
    }
  }
  // Allow Enter key in password modal
  document.getElementById('pwModalInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doChangePassword();
  });

  // ---- Converse.js lazy load ----
  function loadConverse() {
    converseLoaded = true;
    const container = document.getElementById('conversejs-container');
    container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-secondary)">Loading chat client...</div>';
    const script = document.createElement('script');
    script.src = 'https://cdn.conversejs.org/dist/converse.min.js';
    script.onload = () => {
      container.innerHTML = '';
      window.converse.initialize({
        bosh_service_url: 'https://' + XMPP_DOMAIN + ':5281/http-bind',
        websocket_url: 'wss://' + XMPP_DOMAIN + ':5281/xmpp-websocket',
        authentication: 'login',
        auto_login: false,
        view_mode: 'fullscreen',
        allow_registration: false,
        theme: 'concord',
        root: container,
      });
    };
    script.onerror = () => {
      container.innerHTML = '<div style="text-align:center;padding:40px;color:var(--danger)">Failed to load Converse.js from CDN. Check your network connection.</div>';
      converseLoaded = false;
    };
    document.head.appendChild(script);
  }

  // ---- Initial load ----
  loadAccounts();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    """HTTP request handler for the status sidecar and admin panel."""

    # Suppress the default Server header for minor hardening.
    server_version = "openhost-xmpp"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info(fmt, *args)

    # ---- Routing ----

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/healthz":
            self._handle_healthz()
        elif path in ("/", "/index.html"):
            self._handle_index()
        elif path == "/api/accounts":
            self._handle_list_accounts()
        else:
            self._respond(404, b"not found\n", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if path == "/api/accounts":
            self._handle_create_account()
        elif re.match(r"^/api/accounts/[^/]+/password$", path):
            username = path.split("/")[3]
            self._handle_change_password(username)
        else:
            self._respond(404, b"not found\n", "text/plain")

    def do_DELETE(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]

        if re.match(r"^/api/accounts/[^/]+$", path):
            username = path.split("/")[3]
            self._handle_delete_account(username)
        else:
            self._respond(404, b"not found\n", "text/plain")

    # ---- Endpoint handlers ----

    def _handle_healthz(self) -> None:
        if _prosody_up():
            self._respond(200, b"ok\n", "text/plain")
        else:
            self._respond(503, b"prosody-not-listening\n", "text/plain")

    def _handle_index(self) -> None:
        up = _prosody_up()
        status_class = "ok" if up else "bad"
        status_text = "running" if up else "not listening on 5222 (still starting?)"
        domain = get_domain(self.headers)
        safe_host = html.escape(domain, quote=True)

        if _is_owner(self.headers):
            # The domain goes into a JavaScript string literal, so
            # JSON-encode it (which handles any special chars properly)
            # then strip the surrounding quotes since the template
            # already has its own quotes around @@XMPP_DOMAIN@@.
            js_safe_domain = json.dumps(domain)[1:-1]
            body = (
                _ADMIN_HTML.replace("@@STATUS_CLASS@@", status_class)
                .replace("@@STATUS_TEXT@@", status_text)
                .replace("@@XMPP_DOMAIN@@", js_safe_domain)
            ).encode("utf-8")
        else:
            body = (
                _PUBLIC_HTML.replace("@@STATUS_CLASS@@", "status-ok" if up else "status-bad")
                .replace("@@STATUS_TEXT@@", status_text)
                .replace("@@HOST@@", safe_host)
            ).encode("utf-8")

        self._respond(200, body, "text/html; charset=utf-8")

    def _handle_list_accounts(self) -> None:
        if not self._require_owner():
            return
        domain = get_domain(self.headers)
        accounts, err = _list_accounts(domain)
        if err:
            self._respond_json(500, {"error": err, "accounts": []})
        else:
            self._respond_json(200, {"accounts": accounts})

    def _handle_create_account(self) -> None:
        if not self._require_owner():
            return
        body = self._read_json_body()
        if body is None:
            return

        username = body.get("username", "").strip() if isinstance(body.get("username"), str) else ""
        password = body.get("password", "") if isinstance(body.get("password"), str) else ""

        err = _validate_username(username)
        if err:
            self._respond_json(400, {"error": err})
            return
        err = _validate_password(password)
        if err:
            self._respond_json(400, {"error": err})
            return

        domain = get_domain(self.headers)
        ok, output = _create_account(username, domain, password)
        if ok:
            log.info("Created account %s@%s", username, domain)
            self._respond_json(201, {"ok": True, "message": f"Account {username} created"})
        else:
            log.warning("Failed to create account %s@%s: %s", username, domain, output)
            self._respond_json(500, {"error": f"Failed to create account: {output}"})

    def _handle_delete_account(self, username: str) -> None:
        if not self._require_owner():
            return

        # URL-decode the username
        from urllib.parse import unquote
        username = unquote(username)

        err = _validate_username(username)
        if err:
            self._respond_json(400, {"error": err})
            return

        domain = get_domain(self.headers)
        ok, output = _delete_account(username, domain)
        if ok:
            log.info("Deleted account %s@%s", username, domain)
            self._respond_json(200, {"ok": True, "message": f"Account {username} deleted"})
        else:
            log.warning("Failed to delete account %s@%s: %s", username, domain, output)
            self._respond_json(500, {"error": f"Failed to delete account: {output}"})

    def _handle_change_password(self, username: str) -> None:
        if not self._require_owner():
            return

        from urllib.parse import unquote
        username = unquote(username)

        err = _validate_username(username)
        if err:
            self._respond_json(400, {"error": err})
            return

        body = self._read_json_body()
        if body is None:
            return

        password = body.get("password", "") if isinstance(body.get("password"), str) else ""
        err = _validate_password(password)
        if err:
            self._respond_json(400, {"error": err})
            return

        domain = get_domain(self.headers)
        ok, output = _change_password(username, domain, password)
        if ok:
            log.info("Changed password for %s@%s", username, domain)
            self._respond_json(200, {"ok": True, "message": f"Password changed for {username}"})
        else:
            log.warning(
                "Failed to change password for %s@%s: %s", username, domain, output
            )
            self._respond_json(500, {"error": f"Failed to change password: {output}"})

    # ---- Helpers ----

    def _require_owner(self) -> bool:
        """Return True if the request is from the owner, else send 403."""
        if _is_owner(self.headers):
            return True
        self._respond_json(403, {"error": "Forbidden: owner access required"})
        return False

    def _read_json_body(self) -> Optional[dict]:
        """Read and parse JSON from the request body. Returns None on error."""
        content_length_str = self.headers.get("Content-Length", "0")
        try:
            content_length = int(content_length_str)
        except ValueError:
            self._respond_json(400, {"error": "Invalid Content-Length"})
            return None

        if content_length > MAX_BODY_SIZE:
            self._respond_json(413, {"error": "Request body too large"})
            return None

        if content_length <= 0:
            self._respond_json(400, {"error": "Empty request body"})
            return None

        try:
            raw = self.rfile.read(content_length)
        except OSError:
            self._respond_json(400, {"error": "Failed to read request body"})
            return None

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._respond_json(400, {"error": "Invalid JSON"})
            return None

        if not isinstance(data, dict):
            self._respond_json(400, {"error": "Expected a JSON object"})
            return None

        return data

    def _respond_json(self, code: int, data: dict) -> None:
        """Send a JSON response."""
        body = json.dumps(data, separators=(",", ":")).encode("utf-8")
        self._respond(code, body, "application/json")

    def _respond(self, code: int, body: bytes, content_type: str) -> None:
        """Send an HTTP response, handling broken connections gracefully."""
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (
            BrokenPipeError,
            ConnectionResetError,
            ConnectionAbortedError,
            TimeoutError,
        ):
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    except OSError as exc:
        log.critical("cannot bind :%d: %s", PORT, exc)
        return 1
    log.info("listening on :%d", PORT)
    if _STATIC_DOMAIN:
        log.info("XMPP domain: %s", _STATIC_DOMAIN)
    else:
        log.info("XMPP domain: will derive from Host header per request")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
