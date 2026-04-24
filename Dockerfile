# Prosody XMPP server for OpenHost.
#
# Base image: Debian 12 (bookworm).  We pull Prosody 13 from the
# upstream prosody.im apt repo rather than Alpine's community
# package (pinned at 0.12.x) because several modules we enable
# — most notably ``cloud_notify`` for mobile push — only became core
# in Prosody 13.  openhost-jitsi uses the same upstream packages so
# this approach is already exercised in the OpenHost ecosystem.

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# --- base system + repository setup ---------------------------------
#
# We need:
#   * prosody 13 (from prosody.im's apt repo)
#   * a Lua 5.4 + luasec + cyrussasl stack big enough for the modules
#     we enable (cyrussasl pulls in SCRAM / DIGEST-MD5 support, lua-sec
#     provides TLS bindings; Prosody 13 uses LuaSec for its TLS stack,
#     not the alternative luaossl binding)
#   * openssl for the self-signed cert bootstrap in start.sh
#   * python3 for the tiny HTTP status sidecar
#   * tini so SIGTERM from Docker cleanly propagates to our supervisor
#     shell and both children
#   * curl/wget/ca-certs/lsb-release for downloading the apt sources
#     file at build time
#   * sqlite3 so the storage backend resolves without pulling in luarocks
#
# We use a single RUN layer to keep the image compact.  The
# post-install apt cleanup removes caches and the apt tool-set used
# just to bootstrap the repo.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release wget \
        openssl python3 tini sqlite3 \
 && wget -qO /etc/apt/sources.list.d/prosody.sources \
        https://prosody.im/downloads/repos/bookworm/prosody.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        prosody \
        lua5.4 lua-sec lua-dbi-sqlite3 lua-bitop lua-expat \
        lua-filesystem lua-socket lua-unbound lua-cyrussasl \
        lua-readline \
 && apt-get purge -y gnupg lsb-release wget \
 && apt-get autoremove -y --purge \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin

# Our wrapper bits.
COPY start.sh /usr/local/bin/start.sh
COPY status_server.py /usr/local/bin/status_server.py
COPY prosody.cfg.lua.template /usr/local/share/openhost-xmpp/prosody.cfg.lua.template
RUN chmod +x /usr/local/bin/start.sh /usr/local/bin/status_server.py

# Document the ports we bind.  Does NOT publish them — that's
# OpenHost's job, via ``[[ports]]`` in ``openhost.toml``.
#
# 5222   c2s STARTTLS
# 5223   c2s direct-TLS (XEP-0368)
# 5269   s2s STARTTLS
# 5270   s2s direct-TLS
# 5280   HTTP (BOSH, websocket, file-share downloads)
# 5281   HTTPS (same, over TLS)
# 8080   OpenHost router health / landing page sidecar
EXPOSE 5222/tcp 5223/tcp 5269/tcp 5270/tcp 5280/tcp 5281/tcp 8080/tcp

# tini as PID 1 so signals propagate cleanly through the supervisor
# shell to both prosody and the Python sidecar.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/start.sh"]
