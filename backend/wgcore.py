"""
wgd-api :: wgcore.py
Core WireGuard / config-file / database logic.
Ported (near-verbatim where it matters) from WGDashboard upstream modules,
so edge cases (counter rollover, restricted peers, conf parsing) keep working.

No ORM, no templates, no shell=True. Python stdlib + subprocess arg lists only.
"""
import configparser
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# validation helpers (ported from upstream Utilities.py)
# ---------------------------------------------------------------------------

def regex_match(regex: str, text) -> bool:
    return re.compile(regex).search(text) is not None


def string_to_boolean(value: str) -> bool:
    return (str(value).strip().replace(" ", "").lower() in ("yes", "true", "t", "1", 1))


def check_address(ips_str: str) -> bool:
    if len(ips_str) == 0:
        return False
    for ip in ips_str.split(","):
        try:
            ipaddress.ip_network(ip.strip(), strict=False)
        except ValueError:
            return False
    return True


def check_peer_key(peer_key: str) -> bool:
    return re.match(r"^[A-Za-z0-9+/]{43}=$", peer_key) is not None


# ---------------------------------------------------------------------------
# wg subprocess helpers (arg lists, never shell=True)
# ---------------------------------------------------------------------------

def wg_genkey() -> str:
    out = subprocess.check_output(["wg", "genkey"], stderr=subprocess.STDOUT)
    return out.decode().strip()


def wg_pubkey(private_key: str) -> str:
    out = subprocess.run(["wg", "pubkey"], input=private_key.encode(),
                         capture_output=True, check=True)
    return out.stdout.decode().strip()


def protocols_enabled() -> list:
    from shutil import which
    out = []
    if which("wg") is not None and which("wg-quick") is not None:
        out.append("wg")
    if which("awg") is not None and which("awg-quick") is not None:
        out.append("awg")
    return out


def interface_up(name: str) -> bool:
    """Interface exists in kernel? (uses /sys, lighter than psutil)"""
    return os.path.isdir(f"/sys/class/net/{name}")


def wg_quick(protocol: str, action: str, name: str) -> tuple:
    """wg-quick up/down. Returns (ok, output)."""
    try:
        out = subprocess.check_output([f"{protocol}-quick", action, name],
                                      stderr=subprocess.STDOUT)
        return True, out.decode().strip()
    except subprocess.CalledProcessError as exc:
        return False, exc.output.strip().decode("utf-8")


# ---------------------------------------------------------------------------
# conf file parsing (ported from upstream __parseConfigurationFile / getPeers)
# ---------------------------------------------------------------------------

INTERFACE_KEYS = ["PrivateKey", "Address", "ListenPort", "PreUp", "PostUp",
                  "PreDown", "PostDown", "SaveConfig", "Table", "MTU", "DNS"]


def read_conf_lines(path: str) -> list:
    with open(path, "r") as f:
        return [l.rstrip("\n") for l in f.readlines()]


def parse_interface(path: str) -> dict:
    """Parse the [Interface] section. Multiple same-key lines join with ', '
    (upstream semantics)."""
    fields = {k: "" for k in INTERFACE_KEYS}
    fields["SaveConfig"] = False
    lines = read_conf_lines(path)
    try:
        start = lines.index("[Interface]")
    except ValueError:
        raise ValueError(f"[Interface] section not found in {path}")
    for line in lines[start + 1:]:
        if line.strip() == "[Peer]" or line.strip().startswith("["):
            break
        split = re.split(r"\s*=\s*", line, 1)
        if len(split) != 2:
            continue
        key, value = split[0], split[1]
        if key not in INTERFACE_KEYS:
            continue
        if key == "SaveConfig":
            fields[key] = string_to_boolean(value)
        elif len(fields[key]) > 0:
            fields[key] = f"{fields[key]}, {value}"
        else:
            fields[key] = value
    fields["PublicKey"] = ""
    if fields["PrivateKey"]:
        try:
            fields["PublicKey"] = wg_pubkey(fields["PrivateKey"])
        except subprocess.CalledProcessError:
            pass
    return fields


PEER_KEYS = ["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
             "PersistentKeepalive", "Description"]


def parse_peers(path: str) -> list:
    """Parse [Peer] sections (conf is the source of truth for keys/routes)."""
    peers = []
    current = None
    for line in read_conf_lines(path):
        s = line.strip()
        if s.startswith("#") or s.startswith(";"):
            continue
        if s == "[Peer]":
            current = {"PublicKey": "", "PresharedKey": "", "AllowedIPs": "",
                       "Endpoint": "", "PersistentKeepalive": "", "notes": ""}
            peers.append(current)
            continue
        if current is None or len(s) == 0:
            continue
        split = re.split(r"\s*=\s*", line, 1)
        if len(split) != 2:
            continue
        key, value = split[0], split[1]
        if key in PEER_KEYS:
            current["notes" if key == "Description" else key] = value
    return peers


def write_interface_conf(path: str, data: dict):
    """Write a fresh [Interface]-only conf (used by addWireguardConfiguration).
    Mirrors upstream field set/order."""
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    parser["Interface"] = {
        "PrivateKey": data["PrivateKey"],
        "Address": data["Address"],
        "ListenPort": data["ListenPort"],
        "PreUp": str(data.get("PreUp", "")),
        "PreDown": str(data.get("PreDown", "")),
        "PostUp": str(data.get("PostUp", "")),
        "PostDown": str(data.get("PostDown", "")),
        "SaveConfig": "true",
    }
    with open(path, "w+") as f:
        parser.write(f)


# ---------------------------------------------------------------------------
# database (plain sqlite3, same schema/file as WGDashboard)
# ---------------------------------------------------------------------------

PEER_COLUMN_MAP = {
    "id": "TEXT PRIMARY KEY NOT NULL",
    "private_key": "TEXT",
    "DNS": "TEXT",
    "endpoint_allowed_ip": "TEXT",
    "name": "TEXT",
    "total_receive": "FLOAT",
    "total_sent": "FLOAT",
    "total_data": "FLOAT",
    "endpoint": "TEXT",
    "status": "TEXT",
    "latest_handshake": "TEXT",
    "allowed_ip": "TEXT",
    "cumu_receive": "FLOAT",
    "cumu_sent": "FLOAT",
    "cumu_data": "FLOAT",
    "mtu": "INTEGER",
    "keepalive": "INTEGER",
    "notes": "TEXT",
    "remote_endpoint": "TEXT",
    "preshared_key": "TEXT",
}

TRANSFER_COLUMN_MAP = {
    "id": "TEXT NOT NULL",
    "total_receive": "FLOAT",
    "total_sent": "FLOAT",
    "total_data": "FLOAT",
    "cumu_receive": "FLOAT",
    "cumu_sent": "FLOAT",
    "cumu_data": "FLOAT",
    "time": "DATETIME",
}

PEER_COLUMNS = ", ".join(f"'{k}' {v}" for k, v in PEER_COLUMN_MAP.items())
TRANSFER_COLUMNS = ", ".join(f"'{k}' {v}" for k, v in TRANSFER_COLUMN_MAP.items())


def db_connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def ensure_tables(conn: sqlite3.Connection, name: str):
    """Create the 4 per-tunnel tables (if missing) AND add any missing columns
    to existing tables - ported from upstream EnsureDatabaseIntegrity()."""
    cur = conn.cursor()
    for table, colmap in ((name, PEER_COLUMN_MAP),
                          (f"{name}_restrict_access", PEER_COLUMN_MAP),
                          (f"{name}_deleted", PEER_COLUMN_MAP),
                          (f"{name}_transfer", TRANSFER_COLUMN_MAP)):
        cur.execute(f"CREATE TABLE IF NOT EXISTS '{table}' ("
                    + ", ".join(f"'{k}' {v}" for k, v in colmap.items()) + ")")
        existing = {r[1] for r in cur.execute(f"PRAGMA table_info('{table}')")}
        for col, ctype in colmap.items():
            if col not in existing:
                cur.execute(f"ALTER TABLE '{table}' ADD COLUMN '{col}' {ctype}")
    cur.execute(f"CREATE INDEX IF NOT EXISTS 'idx_{name}_transfer_id_time' "
                f"ON '{name}_transfer'(id, time)")
    conn.commit()


def drop_tables(conn: sqlite3.Connection, name: str):
    cur = conn.cursor()
    for suffix in ("", "_restrict_access", "_deleted", "_transfer",
                   "_history_endpoint"):
        cur.execute(f"DROP TABLE IF EXISTS '{name}{suffix}'")
    cur.execute(f"DROP INDEX IF EXISTS 'idx_{name}_transfer_id_time'")
    conn.commit()


def copy_tables(conn: sqlite3.Connection, old: str, new: str):
    """Rename: INSERT INTO new SELECT * FROM old (upstream semantics)."""
    cur = conn.cursor()
    for suffix in ("", "_restrict_access", "_deleted", "_transfer"):
        cur.execute(f"INSERT INTO '{new}{suffix}' SELECT * FROM '{old}{suffix}'")
    conn.commit()


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def peer_usage(conn: sqlite3.Connection, name: str) -> dict:
    """Total DataUsage for the tunnel summary (sum over peers table)."""
    cur = conn.cursor()
    cur.execute(f"SELECT "
                f"COALESCE(SUM(total_receive + cumu_receive), 0) AS receive, "
                f"COALESCE(SUM(total_sent + cumu_sent), 0) AS sent "
                f"FROM '{name}'")
    row = cur.fetchone()
    receive = float(row["receive"]) if row else 0.0
    sent = float(row["sent"]) if row else 0.0
    return {"Total": receive + sent, "Sent": sent, "Receive": receive}


def peer_counts(conn: sqlite3.Connection, name: str) -> tuple:
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM '{name}'")
    total = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(*) FROM '{name}' WHERE status = 'running'")
    running = cur.fetchone()[0]
    return running, total


# ---------------------------------------------------------------------------
# autostart tracking in wg-dashboard.ini (compat with upstream)
# ---------------------------------------------------------------------------

def read_ini(path: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str
    parser.read(path)
    return parser


def save_ini(path: str, parser: configparser.RawConfigParser):
    with open(path, "w") as f:
        parser.write(f)


def get_autostart(ini_path: str) -> list:
    parser = read_ini(ini_path)
    val = parser.get("WireGuardConfiguration", "autostart", fallback="")
    return [x.strip() for x in val.split(",") if x.strip()]


def set_autostart(ini_path: str, names: list):
    parser = read_ini(ini_path)
    if not parser.has_section("WireGuardConfiguration"):
        parser.add_section("WireGuardConfiguration")
    parser.set("WireGuardConfiguration", "autostart", ", ".join(names))
    save_ini(ini_path, parser)


def add_autostart(ini_path: str, name: str):
    lst = get_autostart(ini_path)
    if name not in lst:
        lst.append(name)
        set_autostart(ini_path, lst)


def remove_autostart(ini_path: str, name: str):
    lst = get_autostart(ini_path)
    if name in lst:
        lst.remove(name)
        set_autostart(ini_path, lst)


# ---------------------------------------------------------------------------
# tunnel lifecycle
# ---------------------------------------------------------------------------

NAME_RE = r"^[a-zA-Z0-9_=\+\.\-]{1,15}$"


class Tunnel:
    """One tunnel = one conf file + 4 DB tables."""

    def __init__(self, name: str, conf_dir: str, db_path: str, ini_path: str,
                 protocol: str = "wg"):
        self.Name = os.path.basename(name)
        self.Protocol = protocol
        self.conf_dir = conf_dir if protocol == "wg" else "/etc/amnezia/amneziawg"
        self.configPath = os.path.join(self.conf_dir, f"{self.Name}.conf")
        self.db_path = db_path
        self.ini_path = ini_path

    # -- existence / status -------------------------------------------------
    def exists(self) -> bool:
        return os.path.isfile(self.configPath)

    def status(self) -> bool:
        return interface_up(self.Name)

    # -- summary (shape-compatible with upstream toJson) --------------------
    def summary(self, conn: sqlite3.Connection) -> dict:
        iface = parse_interface(self.configPath)
        up = self.status()
        connected, total = peer_counts(conn, self.Name)
        usage = peer_usage(conn, self.Name)
        return {
            "Status": up,
            "Name": self.Name,
            "PrivateKey": iface.get("PrivateKey", ""),
            "PublicKey": iface.get("PublicKey", ""),
            "Address": iface.get("Address", ""),
            "ListenPort": iface.get("ListenPort", ""),
            "PreUp": iface.get("PreUp", ""),
            "PostUp": iface.get("PostUp", ""),
            "PreDown": iface.get("PreDown", ""),
            "PostDown": iface.get("PostDown", ""),
            "SaveConfig": iface.get("SaveConfig", True),
            "DataUsage": usage,
            "ConnectedPeers": connected,
            "TotalPeers": total,
            "Protocol": self.Protocol,
            "Table": iface.get("Table", ""),
            "Info": {},
        }

    # -- toggle -------------------------------------------------------------
    def toggle(self) -> tuple:
        up = self.status()
        action = "down" if up else "up"
        ok, output = wg_quick(self.Protocol, action, self.Name)
        if not ok:
            return False, output
        if up:
            remove_autostart(self.ini_path, self.Name)
        else:
            add_autostart(self.ini_path, self.Name)
        return True, None

    # -- raw conf -----------------------------------------------------------
    def raw(self) -> str:
        with open(self.configPath, "r") as f:
            return f.read()

    def backup_conf(self) -> str:
        backup_dir = os.path.join(self.conf_dir, "WGDashboard_Backup")
        if not os.path.isdir(backup_dir):
            os.mkdir(backup_dir)
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        dest = os.path.join(backup_dir, f"{self.Name}_{stamp}.conf")
        shutil.copy(self.configPath, dest)
        return dest

    def write_raw(self, content: str) -> tuple:
        self.backup_conf()
        up = self.status()
        if up:
            ok, out = wg_quick(self.Protocol, "down", self.Name)
            if not ok:
                return False, out
        with open(self.configPath, "w") as f:
            f.write(content)
        ok, out = wg_quick(self.Protocol, "up", self.Name)
        if not ok:
            # restore backup and bring back up (upstream behavior)
            backups = sorted(
                (f for f in os.listdir(os.path.join(self.conf_dir, "WGDashboard_Backup"))
                 if f.startswith(self.Name + "_")),
                reverse=True)
            if backups:
                shutil.copy(os.path.join(self.conf_dir, "WGDashboard_Backup", backups[0]),
                            self.configPath)
            wg_quick(self.Protocol, "up", self.Name)
            return False, out
        return True, None

    # -- create / rename / delete -------------------------------------------
    def create(self, data: dict, conn: sqlite3.Connection) -> tuple:
        write_interface_conf(self.configPath, data)
        ensure_tables(conn, self.Name)
        return True, None

    def rename(self, new_name: str, conn: sqlite3.Connection) -> tuple:
        new_name = os.path.basename(new_name)
        if len(new_name) > 15 or not re.match(NAME_RE, new_name):
            return False, "Configuration name is either too long or contains an illegal character"
        new_name = new_name.replace("`", "")
        if self.status():
            self.toggle()
        ensure_tables(conn, new_name)
        copy_tables(conn, self.Name, new_name)
        shutil.copy(self.configPath, os.path.join(self.conf_dir, f"{new_name}.conf"))
        self.delete(conn)
        return True, None

    def delete(self, conn: sqlite3.Connection) -> tuple:
        if self.status():
            self.toggle()
        os.remove(self.configPath)
        drop_tables(conn, self.Name)
        return True, None

    # -- available IPs (ported from upstream getAvailableIP) ----------------
    def available_ips(self, conn: sqlite3.Connection) -> tuple:
        iface = parse_interface(self.configPath)
        address = iface.get("Address", "")
        if len(address) < 1:
            return False, None
        try:
            ifaces = {}
            for a in address.split(","):
                net = ipaddress.ip_network(a.strip(), strict=False)
                ifaces[str(net)] = net
        except ValueError:
            return False, None

        existing = set()
        cur = conn.cursor()
        for table in (self.Name, f"{self.Name}_restrict_access"):
            cur.execute(f"SELECT allowed_ip FROM '{table}'")
            for row in cur.fetchall():
                for pip in (row["allowed_ip"] or "").split(","):
                    parts = pip.strip().split("/")
                    if len(parts) != 2:
                        continue
                    try:
                        addr = ipaddress.ip_address(parts[0])
                    except ValueError:
                        continue
                    for net in ifaces.values():
                        if addr.version == net.version and addr in net:
                            existing.add(str(addr))
                            break

        available = {}
        for key, net in ifaces.items():
            # guard against enormous subnets (e.g. ::/64) - avoid materializing millions of hosts
            if net.num_addresses > 2 ** 16:
                available[key] = []
                continue
            available[key] = [str(h) for h in net.hosts()
                              if str(h) not in existing]
            if net.prefixlen in (31, 32) or net.version == 6 and net.prefixlen >= 127:
                available[key] = [str(a) for a in net
                                  if str(a) not in existing]
        return True, available


# ---------------------------------------------------------------------------
# peer runtime: wg show -> DB sync (ported from upstream bg thread functions)
# ---------------------------------------------------------------------------

PEER_FIELDS = ["id", "private_key", "DNS", "endpoint_allowed_ip", "name",
               "total_receive", "total_sent", "total_data", "endpoint",
               "status", "latest_handshake", "allowed_ip", "cumu_receive",
               "cumu_sent", "cumu_data", "mtu", "keepalive", "notes",
               "remote_endpoint", "preshared_key"]


def row_to_peer(row) -> dict:
    keys = set(row.keys())
    out = {}
    for k in PEER_FIELDS:
        v = row[k] if k in keys else None
        out[k] = v if v is not None else ("" if k in (
            "private_key", "DNS", "endpoint_allowed_ip", "name", "endpoint",
            "latest_handshake", "allowed_ip", "notes", "remote_endpoint",
            "preshared_key") else 0)
    return out


def wg_show(protocol: str, name: str, item: str) -> dict:
    out = subprocess.check_output([protocol, "show", name, item],
                                  stderr=subprocess.STDOUT)
    result = {}
    for line in out.decode().strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            result[parts[0]] = parts[1]
    return result


def ini_peers_defaults(ini_path: str) -> dict:
    parser = read_ini(ini_path)
    g = lambda k, d="": parser.get("Peers", k, fallback=d)
    return {
        "remote_endpoint": g("remote_endpoint"),
        "dns": g("peer_global_DNS", "1.1.1.1"),
        "endpoint_allowed_ip": g("peer_endpoint_allowed_ip", "0.0.0.0/0"),
        "mtu": g("peer_mtu"),
        "keepalive": g("peer_keep_alive"),
    }


def sync_peers_from_conf(conn, t):
    """Ported from upstream getPeers(): conf is source of truth for keys;
    DB holds metadata. Missing peers get default rows, allowed_ip is synced."""
    defaults = ini_peers_defaults(t.ini_path)
    cur = conn.cursor()
    for cp in parse_peers(t.configPath):
        pubkey = cp.get("PublicKey", "")
        if not pubkey:
            continue
        cur.execute("SELECT id FROM '" + t.Name + "' WHERE id = ?", (pubkey,))
        if cur.fetchone() is None:
            cur.execute(
                "INSERT INTO '" + t.Name + "' (id, private_key, DNS, endpoint_allowed_ip, "
                "name, total_receive, total_sent, total_data, endpoint, status, "
                "latest_handshake, allowed_ip, cumu_receive, cumu_sent, cumu_data, "
                "mtu, keepalive, notes, remote_endpoint, preshared_key) "
                "VALUES (?, ?, ?, ?, ?, 0, 0, 0, 'N/A', 'stopped', 'N/A', ?, 0, 0, 0, ?, ?, '', ?, ?)",
                (pubkey, "", defaults["dns"], defaults["endpoint_allowed_ip"],
                 cp.get("name", "") or "", cp.get("AllowedIPs", "") or "N/A",
                 int(defaults["mtu"]) if defaults["mtu"].isdigit() else None,
                 int(defaults["keepalive"]) if defaults["keepalive"].isdigit() else None,
                 defaults["remote_endpoint"], cp.get("PresharedKey", "")))
        else:
            cur.execute("UPDATE '" + t.Name + "' SET allowed_ip = ? WHERE id = ?",
                        (cp.get("AllowedIPs", "") or "N/A", pubkey))


def refresh_handshakes(conn, t):
    now = datetime.now()
    cur = conn.cursor()
    for pubkey, ts in wg_show(t.Protocol, t.Name, "latest-handshakes").items():
        try:
            hs_time = datetime.fromtimestamp(int(ts))
        except (ValueError, OverflowError):
            cur.execute("UPDATE '" + t.Name + "' SET latest_handshake = 'No Handshake', "
                        "status = 'stopped' WHERE id = ?", (pubkey,))
            continue
        delta = now - hs_time
        running = "running" if delta < timedelta(minutes=3) else "stopped"
        shown = str(delta).split(".", maxsplit=1)[0] if int(ts) > 0 else "No Handshake"
        cur.execute("UPDATE '" + t.Name + "' SET latest_handshake = ?, status = ? WHERE id = ?",
                    (shown, running, pubkey))


def refresh_transfer(conn, t):
    """Ported from upstream getPeersTransfer(): rollover detection with the
    0.999 accuracy check - when wg's counter resets (restart), the old total
    is folded into cumu_*."""
    cur = conn.cursor()
    out = subprocess.check_output([t.Protocol, "show", t.Name, "transfer"],
                                  stderr=subprocess.STDOUT)
    for line in out.decode().split("\n"):
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        pubkey, rx_s, tx_s = parts
        cur.execute("SELECT * FROM '" + t.Name + "' WHERE id = ?", (pubkey,))
        row = cur.fetchone()
        if row is None:
            continue
        total_sent = row["total_sent"] or 0
        total_receive = row["total_receive"] or 0
        cur_total_sent = float(tx_s) / (1024 ** 3)
        cur_total_receive = float(rx_s) / (1024 ** 3)
        cumulative_receive = (row["cumu_receive"] or 0) + total_receive
        cumulative_sent = (row["cumu_sent"] or 0) + total_sent
        if (total_sent * 0.999) <= cur_total_sent and (total_receive * 0.999) <= cur_total_receive:
            new_sent, new_receive = cur_total_sent, cur_total_receive
        else:
            cur.execute("UPDATE '" + t.Name + "' SET cumu_receive = ?, cumu_sent = ?, "
                        "cumu_data = ? WHERE id = ?",
                        (cumulative_receive, cumulative_sent,
                         cumulative_sent + cumulative_receive, pubkey))
            new_sent, new_receive = 0.0, 0.0
        if (row["total_receive"] or 0) != new_receive or (row["total_sent"] or 0) != new_sent:
            cur.execute("UPDATE '" + t.Name + "' SET total_receive = ?, total_sent = ?, "
                        "total_data = ? WHERE id = ?",
                        (new_receive, new_sent, new_receive + new_sent, pubkey))


def refresh_endpoints(conn, t):
    cur = conn.cursor()
    for pubkey, endpoint in wg_show(t.Protocol, t.Name, "endpoints").items():
        cur.execute("UPDATE '" + t.Name + "' SET endpoint = ? WHERE id = ?",
                    (endpoint, pubkey))


def log_traffic(conn, t):
    """Ported from upstream logPeersTraffic(): snapshot running peers."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM '" + t.Name + "' WHERE status = 'running'")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for row in cur.fetchall():
        cur.execute(
            "INSERT INTO '" + t.Name + "_transfer' (id, total_receive, total_sent, "
            "total_data, cumu_receive, cumu_sent, cumu_data, time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (row["id"], row["total_receive"], row["total_sent"], row["total_data"],
             row["cumu_receive"], row["cumu_sent"], row["cumu_data"], now))


def peer_list(conn, t, restricted: bool) -> list:
    table = t.Name + "_restrict_access" if restricted else t.Name
    cur = conn.cursor()
    cur.execute("SELECT * FROM '" + table + "'")
    return [row_to_peer(r) for r in cur.fetchall()]


def find_peer(conn, t, pubkey: str) -> tuple:
    """Returns (found, peer_dict, restricted: bool)."""
    cur = conn.cursor()
    for table, is_restricted in ((t.Name, False), (t.Name + "_restrict_access", True)):
        cur.execute("SELECT * FROM '" + table + "' WHERE id = ?", (pubkey,))
        row = cur.fetchone()
        if row is not None:
            return True, row_to_peer(row), is_restricted
    return False, None, False


def wg_set_peer(t, pubkey: str, allowed_ips: str, preshared_key: str):
    """`wg set` with PSK via temp file (ported; tempfile instead of CWD file)."""
    import tempfile
    psk_path = None
    try:
        if preshared_key:
            fd, psk_path = tempfile.mkstemp()
            with os.fdopen(fd, "w") as f:
                f.write(preshared_key)
        command = [t.Protocol, "set", t.Name, "peer", pubkey,
                   "allowed-ips", allowed_ips,
                   "preshared-key", psk_path if preshared_key else "/dev/null"]
        return subprocess.check_output(command, stderr=subprocess.STDOUT)
    finally:
        if psk_path and os.path.exists(psk_path):
            os.remove(psk_path)


def wg_save(t) -> tuple:
    try:
        subprocess.check_output([t.Protocol + "-quick", "save", t.Name],
                                stderr=subprocess.STDOUT)
        return True, None
    except subprocess.CalledProcessError:
        return False, "Internal server error"


# ---------------------------------------------------------------------------
# peer CRUD (ported from upstream addPeers / updatePeer / deletePeers /
# restrictPeers / allowAccessPeers)
# ---------------------------------------------------------------------------

def db_add_peers(conn, t, peers: list, defaults: dict) -> tuple:
    """peers: list of dicts with id/private_key/DNS/endpoint_allowed_ip/name/
    allowed_ip/mtu/keepalive/notes/preshared_key."""
    cleaned = {}
    for p in peers:
        allowed = p["allowed_ip"].replace(" ", "")
        if not check_address(allowed):
            return False, [], "Allowed IPs entry format is incorrect"
        if not check_peer_key(p["id"]):
            return False, [], "Peer key format is incorrect"
        cleaned[p["id"]] = allowed

    cur = conn.cursor()
    for p in peers:
        cur.execute(
            "INSERT INTO '" + t.Name + "' (id, private_key, DNS, endpoint_allowed_ip, "
            "name, total_receive, total_sent, total_data, endpoint, status, "
            "latest_handshake, allowed_ip, cumu_receive, cumu_sent, cumu_data, "
            "mtu, keepalive, notes, remote_endpoint, preshared_key) "
            "VALUES (?, ?, ?, ?, ?, 0, 0, 0, 'N/A', 'stopped', 'N/A', ?, 0, 0, 0, ?, ?, ?, ?, ?)",
            (p["id"], p["private_key"], p["DNS"], p["endpoint_allowed_ip"],
             p["name"], cleaned[p["id"]], p["mtu"], p["keepalive"],
             p.get("notes", ""), defaults["remote_endpoint"], p["preshared_key"]))

    added = []
    for p in peers:
        try:
            wg_set_peer(t, p["id"], cleaned[p["id"]], p["preshared_key"])
        except subprocess.CalledProcessError:
            return False, [], "Internal server error"
        added.append(p)

    ok, msg = wg_save(t)
    if not ok:
        return False, [], msg
    sync_peers_from_conf(conn, t)
    return True, added, None


def db_update_peer(conn, t, peer: dict, new: dict) -> tuple:
    """Ported from upstream Peer.updatePeer()."""
    if not check_address(new["endpoint_allowed_ip"]):
        return False, "Endpoint Allowed IPs format is incorrect"

    cur = conn.cursor()
    cur.execute("SELECT id, allowed_ip FROM '" + t.Name + "' WHERE id != ?",
                (peer["id"],))
    for row in cur.fetchall():
        other_ips = [i.strip() for i in (row["allowed_ip"] or "").split(",")]
        if new["allowed_ip"].replace(" ", "") in other_ips:
            return False, "Allowed IP already taken by another peer"

    if len(new["DNS"]) > 0:
        for d in new["DNS"].split(","):
            d = d.strip()
            if not check_address(d) and not regex_match(
                    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z]{0,61}[a-z]", d):
                return False, d + " does not appear to be a valid IP-address or FQDN"

    mtu = new["mtu"] if isinstance(new["mtu"], int) else 0
    keepalive = new["keepalive"] if isinstance(new["keepalive"], int) else 0
    if mtu not in range(0, 1461):
        return False, "MTU format is not correct"
    if keepalive < 0:
        return False, "Persistent Keepalive format is not correct"

    if len(new["private_key"]) > 0:
        try:
            pub = wg_pubkey(new["private_key"])
        except subprocess.CalledProcessError:
            return False, "Private key does not match with the public key"
        if pub != peer["id"]:
            return False, "Private key does not match with the public key"

    if not t.status():
        t.toggle()

    try:
        out = wg_set_peer(t, peer["id"],
                          new["allowed_ip"].replace(" ", ""),
                          new["preshared_key"])
        if len(out.decode().strip()) != 0:
            return False, "Internal server error"
        ok, msg = wg_save(t)
        if not ok:
            return False, msg
    except subprocess.CalledProcessError:
        return False, "Internal server error"

    cur.execute("UPDATE '" + t.Name + "' SET name = ?, private_key = ?, DNS = ?, "
                "endpoint_allowed_ip = ?, mtu = ?, keepalive = ?, notes = ?, "
                "preshared_key = ? WHERE id = ?",
                (new["name"], new["private_key"], new["DNS"],
                 new["endpoint_allowed_ip"], mtu, keepalive, new["notes"],
                 new["preshared_key"], peer["id"]))
    return True, None


def db_delete_peers(conn, t, pubkeys: list) -> tuple:
    cur = conn.cursor()
    if not t.status():
        t.toggle()
    deleted = 0
    failed = 0
    for pubkey in pubkeys:
        found, _, _ = find_peer(conn, t, pubkey)
        if not found:
            continue
        try:
            subprocess.check_output([t.Protocol, "set", t.Name, "peer", pubkey, "remove"],
                                    stderr=subprocess.STDOUT)
            cur.execute("DELETE FROM '" + t.Name + "' WHERE id = ?", (pubkey,))
            deleted += 1
        except subprocess.CalledProcessError:
            failed += 1
    ok, msg = wg_save(t)
    if not ok:
        return False, msg
    if deleted == 0 and failed == 0:
        return False, "No peer(s) to delete found"
    if deleted == len(pubkeys):
        return True, "Deleted " + str(deleted) + " peer(s)"
    return False, "Deleted " + str(deleted) + " peer(s) successfully. Failed to delete " + str(failed) + " peer(s)"


def db_restrict_peers(conn, t, pubkeys: list) -> tuple:
    cur = conn.cursor()
    if not t.status():
        t.toggle()
    count = 0
    for pubkey in pubkeys:
        found, _, _ = find_peer(conn, t, pubkey)
        if not found:
            continue
        try:
            subprocess.check_output([t.Protocol, "set", t.Name, "peer", pubkey, "remove"],
                                    stderr=subprocess.STDOUT)
            cur.execute("INSERT INTO '" + t.Name + "_restrict_access' "
                        "SELECT * FROM '" + t.Name + "' WHERE id = ?", (pubkey,))
            cur.execute("UPDATE '" + t.Name + "_restrict_access' SET status = 'stopped' "
                        "WHERE id = ?", (pubkey,))
            cur.execute("DELETE FROM '" + t.Name + "' WHERE id = ?", (pubkey,))
            count += 1
        except subprocess.CalledProcessError:
            pass
    ok, msg = wg_save(t)
    if not ok:
        return False, msg
    return True, "Restricted " + str(count) + " peer(s)"


def db_allow_peers(conn, t, pubkeys: list) -> tuple:
    cur = conn.cursor()
    if not t.status():
        t.toggle()
    count = 0
    for pubkey in pubkeys:
        cur.execute("SELECT * FROM '" + t.Name + "_restrict_access' WHERE id = ?", (pubkey,))
        row = cur.fetchone()
        if row is None:
            continue
        allowed = (row["allowed_ip"] or "").replace(" ", "")
        if not check_address(allowed):
            return False, "Allowed IPs entry format is incorrect"
        if not check_peer_key(row["id"]):
            return False, "Peer key format is incorrect"
        cur.execute("INSERT INTO '" + t.Name + "' SELECT * FROM "
                    "'" + t.Name + "_restrict_access' WHERE id = ?", (pubkey,))
        cur.execute("DELETE FROM '" + t.Name + "_restrict_access' WHERE id = ?", (pubkey,))
        try:
            wg_set_peer(t, row["id"], allowed, row["preshared_key"] or "")
        except subprocess.CalledProcessError:
            return False, "Internal server error"
        count += 1
    ok, msg = wg_save(t)
    if not ok:
        return False, msg
    return True, "Allowed " + str(count) + " peer(s)"


# ---------------------------------------------------------------------------
# client config download (ported from upstream Peer.downloadPeer, no Jinja)
# ---------------------------------------------------------------------------

def download_peer(conn, t, ini_path: str, peer: dict) -> dict:
    overrides = {}
    try:
        cur = conn.cursor()
        cur.execute("SELECT Info FROM ConfigurationsInfo WHERE ID = ?", (t.Name,))
        row = cur.fetchone()
        if row and row["Info"]:
            info = json.loads(row["Info"])
            overrides = info.get("OverridePeerSettings") or {}
    except (sqlite3.Error, ValueError):
        overrides = {}
    ovr = lambda k, fallback: (overrides.get(k) or fallback)

    filename = peer["name"] or "UntitledPeer"
    filename = "".join(filename.split(" "))
    filename = re.sub(r'[.,/?<>\\:*|"]', "", filename).rstrip(". ")
    if re.match(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", filename, re.IGNORECASE):
        filename = "file_" + filename
    final_name = "".join(c for c in filename if re.match("^[a-zA-Z0-9_=+.-]$", c))

    iface_conf = parse_interface(t.configPath)
    remote_endpoint = ovr("PeerRemoteEndpoint",
                          ini_peers_defaults(ini_path)["remote_endpoint"])
    lines = ["[Interface]"]
    iface = [
        ("PrivateKey", peer["private_key"]),
        ("Address", peer["allowed_ip"]),
        ("MTU", ovr("MTU", peer["mtu"])),
        ("DNS", ovr("DNS", peer["DNS"])),
    ]
    for key, val in iface:
        if val is not None and ((isinstance(val, str) and len(val) > 0) or
                                (isinstance(val, int) and val > 0)):
            lines.append(key + " = " + str(val))
    lines.append("")
    lines.append("[Peer]")
    peer_sec = [
        ("PublicKey", iface_conf.get("PublicKey", "")),
        ("AllowedIPs", ovr("EndpointAllowedIPs", peer["endpoint_allowed_ip"])),
        ("Endpoint", remote_endpoint + ":" + str(ovr("ListenPort", iface_conf.get("ListenPort", "")))),
        ("PersistentKeepalive", ovr("PersistentKeepalive", peer["keepalive"])),
        ("PresharedKey", peer["preshared_key"]),
    ]
    for key, val in peer_sec:
        if val is not None and ((isinstance(val, str) and len(val) > 0) or
                                (isinstance(val, int) and val > 0)):
            lines.append(key + " = " + str(val))

    return {"fileName": final_name, "file": "\n".join(lines) + "\n"}


# ---------------------------------------------------------------------------
# realtime traffic + history (ported)
# ---------------------------------------------------------------------------

def realtime_traffic(t) -> dict:
    """Ported from upstream getRealtimeTrafficUsage() (MB/s, 1s window)."""
    import psutil
    stats = psutil.net_io_counters(pernic=True, nowrap=True)
    if t.Name not in stats:
        return {"sent": 0, "recv": 0}
    recv1, sent1 = stats[t.Name].bytes_recv, stats[t.Name].bytes_sent
    time.sleep(1)
    stats = psutil.net_io_counters(pernic=True, nowrap=True)
    if t.Name not in stats:
        return {"sent": 0, "recv": 0}
    return {
        "sent": round((stats[t.Name].bytes_sent - sent1) / 1024 / 1024, 3),
        "recv": round((stats[t.Name].bytes_recv - recv1) / 1024 / 1024, 3),
    }


def peer_traffics(conn, t, pubkey: str, interval: int) -> list:
    """Ported from upstream Peer.getTraffics()."""
    end = datetime.now()
    start = end - timedelta(minutes=int(interval))
    cur = conn.cursor()
    cur.execute(
        "SELECT cumu_data, total_data, cumu_receive, total_receive, "
        "cumu_sent, total_sent, time FROM '" + t.Name + "_transfer' "
        "WHERE id = ? AND time <= ? AND time >= ? ORDER BY time",
        (pubkey, end.strftime("%Y-%m-%d %H:%M:%S"),
         start.strftime("%Y-%m-%d %H:%M:%S")))
    out = []
    for row in cur.fetchall():
        d = dict(row)
        d["time"] = str(d["time"])
        out.append(d)
    return out
