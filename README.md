Prosody XMPP server packaged as an OpenHost app.

## What you get

- **XMPP 1.0** with modern client-side extensions out of the box: MAM (message archive, synced across devices), carbons, stream management, CSI (mobile battery saver), PEP, bookmarks, vCard.
- **Multi-user chat** on `conference.<zone>` (XEP-0045 + MUC-MAM).
- **HTTP file sharing** on `share.<zone>` (XEP-0363) with a 100 MB per-file cap and 500 MB per-user-per-day quota.
- **Mobile push notifications** (XEP-0357) so Conversations / Monal get notified even when the app isn't running.
- **Self-signed TLS** on first boot — works with modern clients that XEP-0368 direct-TLS on port 5223. Federation to other servers will fail until you drop in a real certificate (see below).
- **Registration closed by default**. You provision accounts by hand.

## Ports

| Port       | Protocol | Purpose                                                                       |
|------------|----------|-------------------------------------------------------------------------------|
| 5222/tcp   | TCP      | c2s STARTTLS — what most XMPP clients try first                               |
| 5223/tcp   | TCP      | c2s direct TLS (XEP-0368) — recommended on hostile networks                   |
| 5269/tcp   | TCP      | s2s STARTTLS — server-to-server federation                                    |
| 5270/tcp   | TCP      | s2s direct TLS — XEP-0368 for federation                                      |
| 5280/tcp   | HTTP     | BOSH, XMPP-over-WebSocket, file-share downloads (plain HTTP)                  |
| 5281/tcp   | HTTPS    | Same as 5280 over TLS — what modern clients use for HTTP file transfer       |
| 8080/tcp   | HTTP     | Health-check + landing page exposed via the OpenHost router                   |

The XMPP + HTTP ports are declared in `[[ports]]` and published directly on the host's `0.0.0.0` by OpenHost — they bypass Caddy and the OpenHost router. On Hetzner the default firewall is open; on EC2 you'll need to amend the security group in `openhost-vm-manager` to allow inbound `5222, 5223, 5269, 5270, 5280, 5281`.

Ports 5280/5281 are required for **HTTP file transfer (XEP-0363)** to work — without them a client can upload a file but nobody else can download it. They're also used by web-based XMPP clients and by native clients that fall back to BOSH on networks that block non-443 TCP.

## Getting started

### 1. Deploy

```bash
oh app deploy https://github.com/imbue-openhost/openhost-xmpp --wait
```

### 2. Grab the admin password

First boot generates an `admin@<zone>` account. The password lands in `$OPENHOST_APP_DATA_DIR/admin_password.txt`:

```bash
oh app logs xmpp | grep admin_password
# Or via the file-browser app:
#   https://file-browser.<zone>/app_data/xmpp/admin_password.txt
```

### 3. Create user accounts

Because in-band registration is off, you create users with `prosodyctl`:

```bash
oh app exec xmpp prosodyctl adduser alice@xmpp.<zone>
oh app exec xmpp prosodyctl adduser bob@xmpp.<zone>
```

`prosodyctl` prompts for a password.

### 4. Point a client at the server

Any modern XMPP client works. Recommended:

- [Conversations](https://conversations.im/) (Android)
- [Dino](https://dino.im/) (Linux)
- [Gajim](https://gajim.org/) (Windows/Linux/macOS)
- [Monal](https://monal-im.org/) (iOS/macOS)

Enter a JID (`alice@xmpp.<zone>`), the password you set, and tell the client to connect. Self-signed cert → accept it once; your client caches the pinning and future connects are silent.

## Real TLS certificates

Self-signed is fine for personal-scale use among users who accept the cert once; **federation to other XMPP servers will fail** (their own TLS stack rejects self-signed). To federate, drop a real cert into the data dir:

```
$OPENHOST_APP_DATA_DIR/certs/<zone>.crt   # fullchain PEM
$OPENHOST_APP_DATA_DIR/certs/<zone>.key   # private key PEM
```

Then:

```bash
oh app exec xmpp prosodyctl reload
```

The easiest way to get a real cert today: DNS-01 with `acme.sh` / `certbot` / `lego` on a machine you control, then upload via the file-browser app.

## SRV records (needed for full discovery)

XMPP clients and federating servers discover your server via SRV records. OpenHost's CoreDNS only serves A / AAAA / ACME-challenge TXT today, so you need to add these at your parent DNS zone (wherever you manage `<zone>`):

```
_xmpp-client._tcp.xmpp.<zone>.    IN SRV 10 0 5222 xmpp.<zone>.
_xmpps-client._tcp.xmpp.<zone>.   IN SRV 10 0 5223 xmpp.<zone>.
_xmpp-server._tcp.xmpp.<zone>.    IN SRV 10 0 5269 xmpp.<zone>.
_xmpps-server._tcp.xmpp.<zone>.   IN SRV 10 0 5270 xmpp.<zone>.
```

Modern clients that honour XEP-0368 direct-TLS will still connect to `xmpp.<zone>:5223` without SRV records — the server just has to bind that port, which it does.

## Resources

The default `openhost.toml` asks for 256 MB RAM / 0.25 CPU. That's comfortable for a personal or family-sized server (dozens of active accounts). Bump `memory_mb` if you host a busy MUC or store large file-share quotas.

## Files

- `Dockerfile` — Debian 12 + Prosody 13 from upstream prosody.im + openssl + python3 for the status sidecar + tini for clean signal handling.
- `start.sh` — renders the config template, bootstraps self-signed certs and the admin account, supervises prosody + sidecar.
- `prosody.cfg.lua.template` — the Prosody config. Rendered on every boot with the zone hostname injected.
- `status_server.py` — tiny HTTP sidecar serving `/healthz` and a landing page on port 8080.
- `openhost.toml` — OpenHost manifest declaring the XMPP ports and requesting `app_data` storage.

## Data layout

`$OPENHOST_APP_DATA_DIR/` persists:

- `prosody.cfg.lua` — rendered config (rewritten on each boot from the template).
- `prosody.sqlite` — accounts, rosters, MAM archive, PEP pubsub, blocklists.
- `certs/<zone>.crt`, `certs/<zone>.key` — TLS material (self-signed or operator-supplied).
- `admin_password.txt` — one-time admin password from first boot.
- `http_file_share/` — uploaded files from XEP-0363 transfers.

All of these are included in OpenHost backups.

## Known limitations

- **No federated discovery without SRV records.** You add them manually at your parent zone.
- **No DANE / full TLSA.** Prosody supports it but we don't set it up — again a DNS plumbing gap that would go away once OpenHost's router lets apps register custom DNS records.
- **No external TURN / STUN for audio/video.** Jitsi Meet is the right OpenHost app for conferencing; this one is a text-first XMPP server.
- **`cloud_notify` push works** but relies on a public push relay the user's client negotiates with their device OS. No sketchy server-side secrets needed.
