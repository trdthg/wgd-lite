"""
wgd-api :: app.py
A minimal WireGuard control API, replacing WGDashboard's dashboard.py for
the wgd-lite front-end. Stage 1: auth + tunnel management.

Run:
    gunicorn -w 1 --threads 2 -b 127.0.0.1:51822 app:app

Environment:
    WGD_INI      path to wg-dashboard.ini   (default: ./wg-dashboard.ini)
    WGD_DB       path to wgdashboard.db     (default: ./db/wgdashboard.db)
    WGD_CONF_DIR wireguard conf dir         (default: /etc/wireguard)
"""
import hashlib
import ipaddress
import os
import secrets
from contextlib import contextmanager
from datetime import datetime, timedelta

import bcrypt
from flask import Flask, request, jsonify, session

import wgcore

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

INI_PATH = os.environ.get("WGD_INI", os.path.join(os.path.dirname(__file__), "wg-dashboard.ini"))
DB_PATH = os.environ.get("WGD_DB", os.path.join(os.path.dirname(__file__), "db", "wgdashboard.db"))
CONF_DIR = os.environ.get("WGD_CONF_DIR", "/etc/wireguard")

_ini = wgcore.read_ini(INI_PATH)

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)  # sessions die on restart (same as upstream)
app.permanent_session_lifetime = timedelta(days=31)


@contextmanager
def db():
    conn = wgcore.db_connect(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def tunnel(name: str) -> wgcore.Tunnel:
    return wgcore.Tunnel(name, CONF_DIR, DB_PATH, INI_PATH)


# ---------------------------------------------------------------------------
# response envelope + auth (same shape as upstream)
# ---------------------------------------------------------------------------

def respond(status=True, message=None, data=None, status_code=200):
    resp = jsonify({"status": status, "message": message, "data": data})
    resp.status_code = status_code
    return resp


WHITELIST = {"/api/authenticate", "/api/validateAuthentication"}


def is_initialized() -> bool:
    """True once an Account password exists in the ini."""
    return bool(_ini.get("Account", "password", fallback="").strip())


def write_account(username: str, password: str, remote_endpoint: str = None):
    """Persist credentials to the ini (preserving other sections), then
    refresh the in-memory copy so login works without a restart."""
    global _ini
    parser = wgcore.read_ini(INI_PATH)
    if not parser.has_section("Account"):
        parser.add_section("Account")
    parser.set("Account", "username", username)
    parser.set("Account", "password",
               bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode())
    if not parser.has_option("Account", "enable_totp"):
        parser.set("Account", "enable_totp", "false")
    if not parser.has_option("Account", "totp_key"):
        parser.set("Account", "totp_key", "")
    if remote_endpoint and not parser.get("Peers", "remote_endpoint", fallback="").strip():
        if not parser.has_section("Peers"):
            parser.add_section("Peers")
        parser.set("Peers", "remote_endpoint", remote_endpoint)
    with open(INI_PATH, "w") as f:
        parser.write(f)
    try:
        os.chmod(INI_PATH, 0o600)
    except OSError:
        pass
    _ini = parser


@app.before_request
def auth_req():
    if request.method.lower() == "options":
        return respond(True)
    if request.path in WHITELIST:
        return None
    # first-run bootstrap: no credentials configured yet -> allow setup
    if request.path == "/api/account" and not is_initialized():
        return None
    token = request.cookies.get("authToken")
    if token is None or token == "" or "username" not in session \
            or session["username"] != token or session.get("role") != "admin":
        return respond(False, "Unauthorized access.", None, 401)
    return None


# ---------------------------------------------------------------------------
# auth endpoints
# ---------------------------------------------------------------------------

@app.post("/api/authenticate")
def authenticate():
    data = request.get_json(silent=True) or {}
    username = _ini.get("Account", "username", fallback="admin")
    password_hash = _ini.get("Account", "password", fallback="")
    totp_enabled = _ini.get("Account", "enable_totp", fallback="false")

    valid = False
    try:
        valid = bcrypt.checkpw(data.get("password", "").encode("utf-8"),
                               password_hash.encode("utf-8"))
    except ValueError:
        valid = False
    data.setdefault("username", "")

    totp_valid = True
    if valid and totp_enabled.lower() in ("true", "1", "yes"):
        import pyotp
        code = str(data.get("totp", "")).strip()
        totp_valid = pyotp.TOTP(_ini.get("Account", "totp_key", fallback="")).verify(code, valid_window=1)

    if valid and data.get("username") == username and totp_valid:
        token = hashlib.sha256(
            f"{data['username']}{datetime.now()}{app.secret_key}".encode()).hexdigest()
        session["role"] = "admin"
        session["username"] = token
        session.permanent = True
        resp = respond(True, None, True)
        resp.set_cookie("authToken", token, httponly=True, samesite="Lax")
        return resp
    return respond(False, "Sorry, your username or password is incorrect.")


@app.get("/api/validateAuthentication")
def validate():
    token = request.cookies.get("authToken")
    ok = token is not None and token != "" and "username" in session \
        and session["username"] == token
    return respond(ok, None, {"initialized": is_initialized()})


@app.post("/api/account")
def account():
    """Single-user account endpoint, two modes:
    - uninitialized (no password in ini) -> create the first account
    - initialized -> change credentials (requires session + current password)
    """
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username:
        return respond(False, "Username is required")
    if len(password) < 8:
        return respond(False, "Password must be at least 8 characters")

    if is_initialized():
        token = request.cookies.get("authToken")
        if not token or session.get("username") != token:
            return respond(False, "Unauthorized access.", None, 401)
        try:
            current_ok = bcrypt.checkpw(
                str(data.get("current_password", "")).encode("utf-8"),
                _ini.get("Account", "password", fallback="").encode("utf-8"))
        except ValueError:
            current_ok = False
        if not current_ok:
            return respond(False, "Current password is incorrect")

    # auto-detect remote endpoint on first setup if it is still empty
    remote = None
    if not is_initialized():
        remote = (request.host or "").split(":")[0] or None

    write_account(username, password, remote)

    # keep the caller logged in after a successful change
    token = hashlib.sha256(f"{username}{datetime.now()}{app.secret_key}".encode()).hexdigest()
    session["role"] = "admin"
    session["username"] = token
    session.permanent = True
    resp = respond(True, None, {"username": username})
    resp.set_cookie("authToken", token, httponly=True, samesite="Lax")
    return resp


@app.get("/api/signout")
def signout():
    session.clear()
    resp = respond(True)
    resp.delete_cookie("authToken")
    return resp


# ---------------------------------------------------------------------------
# tunnel endpoints
# ---------------------------------------------------------------------------

@app.get("/api/getWireguardConfigurations")
def get_configurations():
    if not os.path.isdir(CONF_DIR):
        return respond(True, None, [])
    names = sorted(f[:-5] for f in os.listdir(CONF_DIR) if f.endswith(".conf"))
    out = []
    with db() as conn:
        for name in names:
            t = tunnel(name)
            try:
                # adopt stray conf files: upstream auto-creates tables on discovery
                if not wgcore.table_exists(conn, name):
                    wgcore.ensure_tables(conn, name)
                out.append(t.summary(conn))
            except (ValueError, OSError) as e:
                # invalid/unreadable conf (bad syntax, dangling symlink, perms):
                # log and skip instead of failing the whole listing
                app.logger.error("skipping conf %s: %s", name, e)
    return respond(True, None, out)


@app.get("/api/protocolsEnabled")
def protocols_enabled():
    return respond(True, None, wgcore.protocols_enabled())


@app.get("/api/toggleWireguardConfiguration")
def toggle_configuration():
    name = request.args.get("configurationName")
    t = tunnel(name)
    if not name or not t.exists():
        return respond(False, "Please provide a valid configuration name", None, 404)
    status, msg = t.toggle()
    return respond(status, msg, t.status())


@app.post("/api/addWireguardConfiguration")
def add_configuration():
    data = request.get_json(silent=True) or {}
    required = ["ConfigurationName", "Address", "ListenPort", "PrivateKey", "Protocol"]
    for key in required:
        if key not in data:
            return respond(False, "Please provide all required parameters.")

    if data.get("Protocol") not in wgcore.protocols_enabled():
        return respond(False, "Please provide a valid protocol: wg / awg.")

    name = str(data["ConfigurationName"])
    if not wgcore.regex_match(wgcore.NAME_RE, name) or name != os.path.basename(name):
        return respond(False, f"Configuration name \"{name}\" contains illegal characters")

    t = tunnel(name)
    if t.exists():
        return respond(False, f"Already have a configuration with the name \"{name}\"")
    with db() as conn:
        for other in _list_names():
            o = tunnel(other)
            oi = wgcore.parse_interface(o.configPath)
            if str(oi.get("ListenPort", "")) == str(data["ListenPort"]):
                return respond(False, f"Already have a configuration with the port \"{data['ListenPort']}\"")
            if oi.get("Address", "") == data["Address"]:
                return respond(False, f"Already have a configuration with the address \"{data['Address']}\"")
        status, msg = t.create(data, conn)
    return respond(status, msg)


@app.post("/api/renameWireguardConfiguration")
def rename_configuration():
    data = request.get_json(silent=True) or {}
    old = data.get("ConfigurationName")
    new = data.get("NewConfigurationName")
    t = tunnel(old) if old else None
    if not t or not t.exists():
        return respond(False, "Please provide the configuration name you want to rename", None, 404)
    if new and tunnel(new).exists():
        return respond(False, "Configuration name already exist", None, 400)
    with db() as conn:
        status, msg = t.rename(new, conn)
    return respond(status, msg)


@app.post("/api/deleteWireguardConfiguration")
def delete_configuration():
    data = request.get_json(silent=True) or {}
    name = data.get("ConfigurationName")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Please provide the configuration name you want to delete", None, 404)
    with db() as conn:
        status = t.delete(conn)
    return respond(status)


@app.get("/api/getWireguardConfigurationRawFile")
def get_raw_file():
    name = request.args.get("configurationName")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Please provide a valid configuration name", None, 404)
    return respond(True, None, {"path": t.configPath, "content": t.raw()})


@app.post("/api/updateWireguardConfigurationRawFile")
def update_raw_file():
    data = request.get_json(silent=True) or {}
    name = data.get("configurationName")
    raw = data.get("rawConfiguration")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Please provide a valid configuration name")
    if raw is None or len(raw) == 0:
        return respond(False, "Please provide content")
    status, msg = t.write_raw(raw)
    return respond(status, msg)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _list_names() -> list:
    if not os.path.isdir(CONF_DIR):
        return []
    return sorted(
        f[:-5] for f in os.listdir(CONF_DIR)
        if f.endswith(".conf") and os.path.isfile(os.path.join(CONF_DIR, f))
    )



# ---------------------------------------------------------------------------
# stage 2: peer + traffic endpoints
# ---------------------------------------------------------------------------

@app.get("/api/getWireguardConfigurationInfo")
def get_configuration_info():
    name = request.args.get("configurationName")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Please provide configuration name")
    with db() as conn:
        wgcore.ensure_tables(conn, name)
        wgcore.sync_peers_from_conf(conn, t)
        peers = wgcore.peer_list(conn, t, restricted=False)
        restricted = wgcore.peer_list(conn, t, restricted=True)
    return respond(True, None, {
        "configurationInfo": {"Status": t.status(), "Name": name},
        "configurationPeers": peers,
        "configurationRestrictedPeers": restricted,
    })


@app.get("/api/getAvailableIPs/<configName>")
def get_available_ips(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    with db() as conn:
        status, ips = t.available_ips(conn)
    return respond(status=status, data=ips)


@app.post("/api/addPeers/<configName>")
def add_peers(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    data = request.get_json(silent=True) or {}
    if data.get("bulkAdd"):
        return respond(False, "Bulk add is not supported by this API")

    defaults = wgcore.ini_peers_defaults(INI_PATH)
    with db() as conn:
        wgcore.ensure_tables(conn, configName)
        if wgcore.find_peer(conn, t, data.get("public_key", "") or "x")[0]:
            return respond(False, "This peer already exist")
        if not t.status():
            up_ok, up_msg = t.toggle()
            if not up_ok:
                return respond(False, "Cannot bring up tunnel: " + str(up_msg))
        try:
            ip_status, available = t.available_ips(conn)
        except ValueError:
            return respond(False, "Invalid configuration file: missing [Interface] section")

        public_key = data.get("public_key", "")
        private_key = data.get("private_key", "")
        if len(public_key) == 0:
            if len(private_key) == 0:
                private_key = wgcore.wg_genkey()
            public_key = wgcore.wg_pubkey(private_key)
        elif len(private_key) > 0:
            if wgcore.wg_pubkey(private_key) != public_key:
                return respond(False, "Provided Public Key does not match provided Private Key")

        allowed_ips = data.get("allowed_ips", [])
        if len(allowed_ips) == 0:
            if not ip_status or not any(available.values()):
                return respond(False, "No more available IP can assign")
            allowed_ips = [next(iter(available.values()))[0]]

        if data.get("allowed_ips_validation", True):
            try:
                networks = [ipaddress.ip_network(s.strip(), strict=False)
                            for s in t.summary(conn)["Address"].split(",")]
            except ValueError as e:
                return respond(False, str(e))
            for i in allowed_ips:
                try:
                    ap = ipaddress.ip_network(i, strict=False)
                except ValueError as e:
                    return respond(False, str(e))
                if not any(ap.version == n.version and ap.subnet_of(n) for n in networks):
                    return respond(False, f"This IP is not available: {i}")

        mtu = data.get("mtu")
        if not isinstance(mtu, int) or mtu < 0 or mtu > 1460:
            mtu = int(defaults["mtu"]) if defaults["mtu"].isdigit() else 0
        keepalive = data.get("keepalive")
        if not isinstance(keepalive, int) or keepalive < 0:
            keepalive = int(defaults["keepalive"]) if defaults["keepalive"].isdigit() else 0

        peers = [{
            "id": public_key,
            "private_key": private_key,
            "DNS": data.get("DNS", defaults["dns"]),
            "endpoint_allowed_ip": data.get("endpoint_allowed_ip", defaults["endpoint_allowed_ip"]),
            "name": data.get("name", ""),
            "allowed_ip": ",".join(allowed_ips),
            "mtu": mtu,
            "keepalive": keepalive,
            "notes": data.get("notes", ""),
            "preshared_key": data.get("preshared_key", ""),
        }]
        status, added, msg = wgcore.db_add_peers(conn, t, peers, defaults)
    return respond(status, msg, added)


@app.post("/api/updatePeerSettings/<configName>")
def update_peer_settings(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    data = request.get_json(silent=True) or {}
    pid = data.get("id", "")
    if len(pid) == 0:
        return respond(False, "Peer does not exist")
    with db() as conn:
        found, peer, restricted = wgcore.find_peer(conn, t, pid)
        if not found:
            return respond(False, "Peer does not exist")
        new = {
            "name": data.get("name", ""),
            "private_key": data.get("private_key", ""),
            "DNS": data.get("DNS", ""),
            "allowed_ip": data.get("allowed_ip", ""),
            "endpoint_allowed_ip": data.get("endpoint_allowed_ip", ""),
            "preshared_key": data.get("preshared_key", ""),
            "mtu": data.get("mtu"),
            "keepalive": data.get("keepalive"),
            "notes": data.get("notes", ""),
        }
        status, msg = wgcore.db_update_peer(conn, t, peer, new)
    return respond(status, msg)


@app.post("/api/deletePeers/<configName>")
def delete_peers(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist", None, 404)
    data = request.get_json(silent=True) or {}
    peers = data.get("peers", [])
    if len(peers) == 0:
        return respond(False, "Please specify one or more peers", None, 400)
    with db() as conn:
        status, msg = wgcore.db_delete_peers(conn, t, peers)
    return respond(status, msg)


@app.post("/api/restrictPeers/<configName>")
def restrict_peers(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    data = request.get_json(silent=True) or {}
    peers = data.get("peers", [])
    if len(peers) == 0:
        return respond(False, "Please specify one or more peers")
    with db() as conn:
        status, msg = wgcore.db_restrict_peers(conn, t, peers)
    return respond(status, msg)


@app.post("/api/allowAccessPeers/<configName>")
def allow_access_peers(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    data = request.get_json(silent=True) or {}
    peers = data.get("peers", [])
    if len(peers) == 0:
        return respond(False, "Please specify one or more peers")
    with db() as conn:
        status, msg = wgcore.db_allow_peers(conn, t, peers)
    return respond(status, msg)


@app.get("/api/downloadPeer/<configName>")
def download_peer(configName):
    t = tunnel(configName)
    if not t.exists():
        return respond(False, "Configuration does not exist")
    pid = request.args.get("id", "")
    with db() as conn:
        found, peer, restricted = wgcore.find_peer(conn, t, pid)
        if len(pid) == 0 or not found:
            return respond(False, "Peer does not exist")
        return respond(True, None, wgcore.download_peer(conn, t, INI_PATH, peer))


@app.get("/api/getWireguardConfigurationRealtimeTraffic")
def realtime_traffic():
    name = request.args.get("configurationName")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Configuration does not exist", None, 404)
    return respond(True, None, wgcore.realtime_traffic(t))


@app.get("/api/getWireguardConfigurationMonthlyTraffic")
def get_monthly_traffic():
    name = request.args.get("configurationName")
    t = tunnel(name) if name else None
    if not t or not t.exists():
        return respond(False, "Configuration does not exist", None, 404)
    now = datetime.now()
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    ms = month_start.strftime("%Y-%m-%d %H:%M:%S")
    with db() as conn:
        wgcore.ensure_tables(conn, name)
        cur = conn.cursor()
        cur.execute(f"SELECT id, total_receive, total_sent, cumu_receive, cumu_sent FROM '{name}'")
        current = cur.fetchall()

        def baseline(pid):
            # 1) 当月最早一个采样; 没有(整月没流量)则用上月最后一个采样;
            #    都没有(新 Peer)视为 0。
            cur.execute(f"SELECT (cumu_receive + total_receive) AS rx, "
                        f"(cumu_sent + total_sent) AS tx FROM '{name}_transfer' "
                        f"WHERE id = ? AND time >= ? ORDER BY time ASC LIMIT 1", (pid, ms))
            b = cur.fetchone()
            if b is None:
                cur.execute(f"SELECT (cumu_receive + total_receive) AS rx, "
                            f"(cumu_sent + total_sent) AS tx FROM '{name}_transfer' "
                            f"WHERE id = ? AND time < ? ORDER BY time DESC LIMIT 1", (pid, ms))
                b = cur.fetchone()
            if b is None:
                return 0.0, 0.0
            return (b["rx"] or 0.0, b["tx"] or 0.0)

        per = {}
        total_rx = total_tx = 0.0
        for r in current:
            b = baseline(r["id"])
            u_rx = max(0.0, (r["total_receive"] or 0) + (r["cumu_receive"] or 0) - b[0])
            u_tx = max(0.0, (r["total_sent"] or 0) + (r["cumu_sent"] or 0) - b[1])
            per[r["id"]] = {"receive": round(u_rx, 3), "sent": round(u_tx, 3)}
            total_rx += u_rx
            total_tx += u_tx
    return respond(True, None, {
        "month": month_start.strftime("%Y-%m"),
        "receive": round(total_rx, 3),
        "sent": round(total_tx, 3),
        "peers": per,
    })


@app.get("/api/getPeerTraffics")
def get_peer_traffics():
    name = request.args.get("configurationName")
    pid = request.args.get("id")
    if not name or not pid:
        return respond(False, "Please provide configurationName and id")
    interval = request.args.get("interval", 30)
    if not str(interval).isdigit():
        return respond(False, "Interval must be integers in minutes")
    t = tunnel(name)
    if not t.exists():
        return respond(False, "Peer does not exist", None, 404)
    with db() as conn:
        return respond(True, None, wgcore.peer_traffics(conn, t, pid, int(interval)))


# ---------------------------------------------------------------------------
# background threads (started by gunicorn.conf.py post_worker_init)
# ---------------------------------------------------------------------------

def _bg_refresh_loop():
    import time as _time
    counter = 0
    while True:
        _time.sleep(10)
        counter += 1
        try:
            tracking = False
            parser = wgcore.read_ini(INI_PATH)
            tracking = parser.get("WireGuardConfiguration", "peer_tracking",
                                  fallback="false").lower() in ("true", "1", "yes")
            with db() as conn:
                for name in _list_names():
                    t = tunnel(name)
                    if not t.exists():
                        continue
                    # adopt stray confs (upstream creates tables on discovery)
                    wgcore.ensure_tables(conn, name)
                    if not t.status():
                        continue
                    wgcore.refresh_handshakes(conn, t)
                    wgcore.refresh_transfer(conn, t)
                    wgcore.refresh_endpoints(conn, t)
                    wgcore.sync_peers_from_conf(conn, t)
                    if tracking and counter % 6 == 0:
                        wgcore.log_traffic(conn, t)
        except Exception as e:
            app.logger.error("bg refresh error: %s", e)


def _bg_autostart():
    import time as _time
    _time.sleep(5)
    try:
        for name in wgcore.get_autostart(INI_PATH):
            t = tunnel(name)
            if t.exists() and not t.status():
                ok, out = wgcore.wg_quick(t.Protocol, "up", name)
                app.logger.info("autostart %s: %s", name, "ok" if ok else out)
            with db() as conn:
                wgcore.ensure_tables(conn, name)
    except Exception as e:
        app.logger.error("autostart error: %s", e)


def start_threads():
    import threading
    threading.Thread(target=_bg_refresh_loop, daemon=True).start()
    threading.Thread(target=_bg_autostart, daemon=True).start()


if __name__ == "__main__":
    start_threads()
    app.run(host="127.0.0.1", port=51822, debug=False)
