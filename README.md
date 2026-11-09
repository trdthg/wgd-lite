# WGD Lite

A minimal, self-hosted WireGuard management stack: a single-file web UI plus a
small control API that talks to `wg`/`wg-quick` directly.

Built as a lean replacement for [WGDashboard](https://github.com/WGDashboard/WGDashboard)
on small boxes (~450MB RAM, single user). Only what a homelab actually needs:

- login (username/password, optional TOTP)
- tunnel management (create / rename / start / stop / raw config editing / delete)
- peer management (create with auto-generated keys & IP allocation / edit /
  enable-disable slider / delete / download client config)
- traffic monitoring (tunnel realtime, per-peer 10s-average rates, per-peer
  history with charts)

```
frontend/            single-file UI (Preact via CDN, no build step) + local mock server
backend/             Flask control API (~1500 lines, 5 dependencies)
  app.py             endpoints, auth, background threads
  wgcore.py          conf parsing, wg subprocess calls, SQLite, peer lifecycle
  wsgi.py            production entrypoint (waitress)
  systemd/           example service unit
  tests/             integration tests (run on the target server)
```

| | WGDashboard (v4.3.4) | WGD Lite |
|---|---|---|
| backend memory | ~151 MB | **~34 MB** (single process) |
| python deps | 17 | **5** (flask/bcrypt/waitress/pyotp/psutil) |
| endpoints | ~90 | **20** |
| frontend | Vue + Vite build chain | **one ~47 KB file** |

## Architecture

```
browser ── HTTPS ── Caddy ──┬─ /lite/*  → static files (frontend/index.html)
                            └─ /api/*   → reverse_proxy 127.0.0.1:51822 (wgd-api)
wgd-api ── exec ── wg / wg-quick        (tunnels live in the kernel, unaffected)
wgd-api ── sqlite ── wgdashboard.db     (peer metadata + traffic history,
                                         same file/schema as WGDashboard)
```

- The UI is served by Caddy as static files; the API is a separate process.
  Either can restart without touching the other.
- WireGuard tunnels themselves live in the kernel: stopping the API never
  brings tunnels down.

## Deploy

Assumes a Debian-ish box with Caddy already serving your domain, and wireguard
tools installed. The backend reuses WGDashboard's config/DB files, so if you
are migrating from WGDashboard your peers and traffic history carry over.

### 1. Backend

```bash
mkdir -p /opt/wgd-api && cd /opt/wgd-api
# copy backend/ here
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

`backend/systemd/wgd-api.service` is a working unit template — copy it to
`/etc/systemd/system/`, point the `Environment=` lines at your real paths, then:

```bash
systemctl daemon-reload && systemctl enable --now wgd-api
```

Environment variables:

| var | default | meaning |
|---|---|---|
| `WGD_INI` | `./wg-dashboard.ini` | config file (Account credentials, `[Peers]` defaults, `peer_tracking`) |
| `WGD_DB` | `./db/wgdashboard.db` | SQLite DB (upstream schema, reused as-is) |
| `WGD_CONF_DIR` | `/etc/wireguard` | where `*.conf` tunnels live |

The ini keys used: `Account.username/password/enable_totp/totp_key`,
`Peers.remote_endpoint/peer_global_DNS/peer_endpoint_allowed_ip/peer_mtu/peer_keep_alive`,
`WireGuardConfiguration.autostart/peer_tracking`.

### 2. Frontend

Drop `frontend/index.html` anywhere Caddy can serve, e.g.:

```caddy
wg.example.com {
	handle_path /lite/* {
		root * /opt/wgd-lite
		file_server
	}
	redir /lite /lite/ 308
	reverse_proxy 127.0.0.1:51822
}
```

(If you prefer, you can serve the UI from the backend and collapse Caddy to a
single `reverse_proxy` — see `frontend/index.html` notes.)

### 3. Config notes

- `peer_tracking = true` in the ini enables per-peer traffic history
  (backend samples running peers every ~60s into `<tunnel>_transfer` tables).
- On startup the API brings up tunnels listed in `autostart` and adopts any
  stray `*.conf` files (auto-creates missing tables/columns).
- Login sessions do not survive a backend restart (the signing key is random
  per boot, same as upstream).

## Local development (no WireGuard needed)

```bash
cd frontend && node mock-server.js   # fake API on :8787, any login works
# open http://localhost:8787/
```

## Tests

`backend/tests/test_integration.py` runs against a real server (it actually
calls `wg-quick`, creates/toggles/deletes a throwaway tunnel). Point it at a
directory with **copies** of your DB/conf:

```bash
export WGD_API_DIR=/opt/wgd-api        # where app.py lives on the server
# prepare copies first — see the header of the test file
python3 backend/tests/test_integration.py
```

59 checks: auth, tunnel lifecycle, peer lifecycle, conf→DB sync, restrict/
allow, client-config download, realtime + history endpoints.

## API summary

All responses: `{"status": bool, "message": str|null, "data": ...}`.
Auth: session cookie `authToken` (HttpOnly), set by `POST /api/authenticate`.

```
POST /api/authenticate                       GET  /api/validateAuthentication
GET  /api/signout
GET  /api/getWireguardConfigurations         GET  /api/protocolsEnabled
GET  /api/toggleWireguardConfiguration       POST /api/addWireguardConfiguration
POST /api/renameWireguardConfiguration       POST /api/deleteWireguardConfiguration
GET  /api/getWireguardConfigurationRawFile   POST /api/updateWireguardConfigurationRawFile
GET  /api/getWireguardConfigurationInfo      GET  /api/getAvailableIPs/<cfg>
POST /api/addPeers/<cfg>                     POST /api/updatePeerSettings/<cfg>
POST /api/deletePeers/<cfg>                  POST /api/restrictPeers/<cfg>
POST /api/allowAccessPeers/<cfg>             GET  /api/downloadPeer/<cfg>?id=
GET  /api/getWireguardConfigurationRealtimeTraffic
GET  /api/getPeerTraffics?configurationName=&id=&interval=
```

The contract is frozen by `backend/tests/` — any reimplementation (different
language, framework) that passes the same suite is a drop-in replacement.

## Notes / gotchas

- Per-peer rates in the UI are 10-second averages: the backend refreshes
  counters from `wg show` every 10s and the frontend diffs them.
- Traffic history only records peers with `status = running`.
- The `<tunnel>_transfer` tables grow ~8k rows/day/tunnel; prune with SQL
  when needed.
- Frontend pulls Preact/htm from esm.sh at runtime (3 requests). Fully
  self-hosting them is a documented option in the UI's own comments.
