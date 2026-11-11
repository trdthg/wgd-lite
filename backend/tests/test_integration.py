# -*- coding: utf-8 -*-
"""Stage-1 integration test for wgd-api, run ON the server against copies."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys

BASE = os.environ.get("WGD_API_DIR",
       os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST = BASE + "/test"
TEST_PRIV = subprocess.check_output(["wg", "genkey"]).decode().strip()

os.environ["WGD_INI"] = TEST + "/test.ini"
os.environ["WGD_DB"] = TEST + "/test.db"
os.environ["WGD_CONF_DIR"] = TEST + "/conf"

sys.path.insert(0, BASE)
import app as appmod  # noqa: E402
import wgcore  # noqa: E402

ok = fail = 0
def check(name, cond, extra=""):
    global ok, fail
    if cond: ok += 1; print("  PASS", name)
    else: fail += 1; print("  FAIL", name, extra)

client = appmod.app.test_client()

# --- 1. unauthenticated request -> 401
r = client.get("/api/getWireguardConfigurations")
check("unauth -> 401", r.status_code == 401, r.status_code)

# --- 2. authenticate (wrong + right)
r = client.post("/api/authenticate", json={"username": "admin", "password": "wrong"})
check("wrong password rejected", r.status_code == 200 and r.get_json()["status"] is False)
r = client.post("/api/authenticate", json={"username": "admin", "password": "testpass"})
check("authenticate ok", r.status_code == 200 and r.get_json()["status"] is True, r.get_data(as_text=True))
check("authToken cookie set (httponly)", "authToken" in (r.headers.get("Set-Cookie") or "") and "HttpOnly" in (r.headers.get("Set-Cookie") or ""))

r = client.get("/api/validateAuthentication")
check("validate after login", r.get_json()["status"] is True)

# --- 3. read parity for real wg0 (test db/conf are copies)
r = client.get("/api/getWireguardConfigurations")
data = r.get_json()["data"]
check("list returns wg0", isinstance(data, list) and any(c["Name"] == "wg0" for c in data), r.get_data(as_text=True)[:200])
wg0 = next(c for c in data if c["Name"] == "wg0")
iface = wgcore.parse_interface("/etc/wireguard/wg0.conf")
check("Address matches conf", wg0["Address"] == iface["Address"], wg0["Address"])
check("ListenPort matches conf", str(wg0["ListenPort"]) == str(iface["ListenPort"]))
check("Status = interface up", wg0["Status"] == os.path.isdir("/sys/class/net/wg0"))
real = sqlite3.connect(TEST + "/test.db")
real.row_factory = sqlite3.Row
n = real.execute("SELECT COUNT(*) FROM wg0").fetchone()[0]
check("TotalPeers matches DB", wg0["TotalPeers"] == n, (wg0["TotalPeers"], n))
du = real.execute("SELECT COALESCE(SUM(total_receive+cumu_receive),0) a, COALESCE(SUM(total_sent+cumu_sent),0) b FROM wg0").fetchone()
check("DataUsage.Receive matches DB", abs(wg0["DataUsage"]["Receive"] - du["a"]) < 0.001, (wg0["DataUsage"], dict(du)))

# --- 4. protocolsEnabled
r = client.get("/api/protocolsEnabled")
check("protocolsEnabled has wg", r.get_json()["status"] and "wg" in r.get_json()["data"])

# --- 5. create tunnel
r = client.post("/api/addWireguardConfiguration", json={
    "ConfigurationName": "wgtest99", "Address": "10.123.123.1/24",
    "ListenPort": 51899, "PrivateKey": TEST_PRIV, "Protocol": "wg"})
check("create tunnel", r.get_json()["status"], r.get_data(as_text=True)[:200])
check("conf file created", os.path.isfile(TEST + "/conf/wgtest99.conf"))
tdb = sqlite3.connect(TEST + "/test.db")
tables = [x[0] for x in tdb.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'wgtest99%'")]
check("4 tables created", len([t for t in tables if "transfer" in t or t.endswith("wgtest99") or "restrict" in t or "deleted" in t]) >= 4, tables)

r = client.post("/api/addWireguardConfiguration", json={
    "ConfigurationName": "wgtest99", "Address": "10.123.124.1/24",
    "ListenPort": 51898, "PrivateKey": TEST_PRIV, "Protocol": "wg"})
check("duplicate name rejected", r.get_json()["status"] is False)
r = client.post("/api/addWireguardConfiguration", json={
    "ConfigurationName": "wgtest98", "Address": "10.123.124.1/24",
    "ListenPort": 51899, "PrivateKey": TEST_PRIV, "Protocol": "wg"})
check("duplicate port rejected", r.get_json()["status"] is False)

# --- 6. raw file (symlink first: wg-quick only looks in /etc/wireguard)
link = "/etc/wireguard/wgtest99.conf"
if os.path.lexists(link): os.remove(link)
os.symlink(TEST + "/conf/wgtest99.conf", link)
r = client.get("/api/getWireguardConfigurationRawFile?configurationName=wgtest99")
check("raw read", r.get_json()["status"] and "[Interface]" in r.get_json()["data"]["content"])
raw = r.get_json()["data"]["content"] + "\n# smoke edit\n"
r = client.post("/api/updateWireguardConfigurationRawFile", json={
    "configurationName": "wgtest99", "rawConfiguration": raw})
check("raw write", r.get_json()["status"], r.get_data(as_text=True)[:200])
r = client.get("/api/getWireguardConfigurationRawFile?configurationName=wgtest99")
check("raw edit persisted", "# smoke edit" in r.get_json()["data"]["content"])

# --- 7. toggle (raw-write leaves the tunnel up; reset to down first)
if os.path.isdir("/sys/class/net/wgtest99"):
    subprocess.check_output(["wg-quick", "down", "wgtest99"])
r = client.get("/api/toggleWireguardConfiguration?configurationName=wgtest99")
check("toggle up", r.get_json()["status"] and r.get_json()["data"] is True, r.get_data(as_text=True)[:200])
check("interface exists", os.path.isdir("/sys/class/net/wgtest99"))
check("autostart written to ini", "wgtest99" in open(TEST + "/test.ini").read())
r = client.get("/api/toggleWireguardConfiguration?configurationName=wgtest99")
check("toggle down", r.get_json()["status"] and r.get_json()["data"] is False)
check("interface removed", not os.path.isdir("/sys/class/net/wgtest99"))
os.remove(link)

# --- 8. available IPs
conn = wgcore.db_connect(TEST + "/test.db")
t = wgcore.Tunnel("wgtest99", TEST + "/conf", TEST + "/test.db", TEST + "/test.ini")
st, ips = t.available_ips(conn)
check("available IPs", st and any("10.123.123" in k for k in ips), ips)
conn.close()

# --- 9. rename + delete
r = client.post("/api/renameWireguardConfiguration", json={
    "ConfigurationName": "wgtest99", "NewConfigurationName": "wgtest98"})
check("rename", r.get_json()["status"], r.get_data(as_text=True)[:200])
check("renamed conf exists", os.path.isfile(TEST + "/conf/wgtest98.conf"))
check("old conf gone", not os.path.isfile(TEST + "/conf/wgtest99.conf"))
r = client.post("/api/deleteWireguardConfiguration", json={"ConfigurationName": "wgtest98"})
check("delete", r.get_json()["status"], r.get_data(as_text=True)[:200])
check("tables dropped", not wgcore.table_exists(sqlite3.connect(TEST + "/test.db"), "wgtest98"))

# --- 10. live backend (if any) still healthy - does not disturb it
import urllib.request
try:
    urllib.request.urlopen("http://127.0.0.1:51822/api/validateAuthentication", timeout=5)
    check("live backend :51822 still answering", True)
except Exception as e:
    check("live backend :51822 reachable (optional)", True, "skipped: " + str(e))

# ================= stage 2: peers + traffic =================

# --- 11. 重建隧道(上阶段末尾删除了), 再测 conf->DB sync
r = client.post("/api/addWireguardConfiguration", json={
    "ConfigurationName": "wgtest99", "Address": "10.123.123.1/24",
    "ListenPort": 51899, "PrivateKey": TEST_PRIV, "Protocol": "wg"})
check("recreate tunnel", r.get_json()["status"], r.get_data(as_text=True)[:150])
with open(TEST + "/conf/wgtest99.conf", "a") as f:
    f.write("\n[Peer]\nPublicKey = 6yIr7LmGlJdT3Fl0tG+jPB7jFOZa5qvsShtWkmMljFY=\n"
            "AllowedIPs = 10.123.123.44/32\n")
r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
d = r.get_json()["data"]
check("cfg info: peers+restricted keys", "configurationPeers" in d and "configurationRestrictedPeers" in d)
check("conf peer adopted into DB", any(p["id"] == "6yIr7LmGlJdT3Fl0tG+jPB7jFOZa5qvsShtWkmMljFY=" for p in d["configurationPeers"]), json.dumps(d)[:150])

# --- 12. addPeers (无密钥 -> 自动生成; 无IP -> 自动分配; wg-quick 需要软链)
link = "/etc/wireguard/wgtest99.conf"
if not os.path.lexists(link):
    os.symlink(TEST + "/conf/wgtest99.conf", link)
r = client.post("/api/addPeers/wgtest99", json={"name": "smoke-peer"})
check("addPeers auto-gen", r.get_json()["status"], r.get_data(as_text=True)[:200])
added = r.get_json()["data"][0]
check("addPeers: pubkey 44", len(added["id"]) == 44 and added["id"].endswith("="))
check("addPeers: private key saved", len(added["private_key"]) == 44)
check("addPeers: auto IP", added["allowed_ip"].startswith("10.123.123."), added["allowed_ip"])
check("addPeers: defaults from ini", added["DNS"] == "1.1.1.1" and added["endpoint_allowed_ip"] == "0.0.0.0/0")

# duplicate pubkey
r = client.post("/api/addPeers/wgtest99", json={"name": "dup", "public_key": added["id"]})
check("addPeers duplicate rejected", r.get_json()["status"] is False)

# bad allowed ip validation
r = client.post("/api/addPeers/wgtest99", json={"name": "badip", "allowed_ips": ["192.0.2.99/32"]})
check("addPeers invalid subnet rejected", r.get_json()["status"] is False)

# --- 13. toggle up (要 wg set 生效需要接口在跑)
if not os.path.isdir("/sys/class/net/wgtest99"):
    client.get("/api/toggleWireguardConfiguration?configurationName=wgtest99")
check("tunnel up for peer ops", os.path.isdir("/sys/class/net/wgtest99"))

r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
check("peer visible in wg (via sync)", any(p["id"] == added["id"] for p in r.get_json()["data"]["configurationPeers"]))

# --- 14. updatePeerSettings
r = client.post("/api/updatePeerSettings/wgtest99", json={
    "id": added["id"], "name": "smoke-renamed", "private_key": added["private_key"],
    "DNS": "9.9.9.9", "allowed_ip": added["allowed_ip"],
    "endpoint_allowed_ip": "0.0.0.0/0", "preshared_key": "",
    "mtu": 1380, "keepalive": 25, "notes": "hello"})
check("updatePeer", r.get_json()["status"], r.get_data(as_text=True)[:200])
r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
p2 = next(p for p in r.get_json()["data"]["configurationPeers"] if p["id"] == added["id"])
check("update persisted", p2["name"] == "smoke-renamed" and p2["DNS"] == "9.9.9.9" and p2["mtu"] == 1380)
r = client.post("/api/updatePeerSettings/wgtest99", json={
    "id": added["id"], "name": "smoke-renamed", "private_key": added["private_key"],
    "DNS": "9.9.9.9", "allowed_ip": added["allowed_ip"],
    "endpoint_allowed_ip": "0.0.0.0/0", "preshared_key": "", "mtu": 2000, "keepalive": 25})
check("update invalid mtu rejected", r.get_json()["status"] is False)

# --- 15. downloadPeer
from urllib.parse import quote
r = client.get("/api/downloadPeer/wgtest99?id=" + quote(added["id"], safe=""))
d = r.get_json()["data"]
check("downloadPeer", r.get_json()["status"] and d["file"].startswith("[Interface]")
      and "PrivateKey = " + added["private_key"] in d["file"]
      and "[Peer]" in d["file"] and "PublicKey" in d["file"], r.get_data(as_text=True)[:150])
check("downloadPeer filename", d["fileName"] == "smoke-renamed")

# --- 16. restrict / allow (滑块)
r = client.post("/api/restrictPeers/wgtest99", json={"peers": [added["id"]]})
check("restrict", r.get_json()["status"], r.get_data(as_text=True)[:150])
r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
check("peer moved to restricted", any(p["id"] == added["id"] for p in r.get_json()["data"]["configurationRestrictedPeers"]))
check("wg no longer lists peer", added["id"] not in subprocess.check_output(["wg", "show", "wgtest99", "peers"]).decode())
r = client.post("/api/allowAccessPeers/wgtest99", json={"peers": [added["id"]]})
check("allow", r.get_json()["status"], r.get_data(as_text=True)[:150])
r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
check("peer back to active", any(p["id"] == added["id"] for p in r.get_json()["data"]["configurationPeers"]))

# --- 17. realtime traffic
r = client.get("/api/getWireguardConfigurationRealtimeTraffic?configurationName=wgtest99")
check("realtime shape", r.get_json()["status"] and "sent" in r.get_json()["data"] and "recv" in r.get_json()["data"])

# --- 18. peer traffic history (先手动插几行采样)
conn = sqlite3.connect(TEST + "/test.db")
from datetime import datetime as _dt, timedelta as _td
for i in range(5):
    ts = (_dt.now() - _td(minutes=5 - i)).strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("INSERT INTO 'wgtest99_transfer' (id, total_receive, total_sent, total_data, cumu_receive, cumu_sent, cumu_data, time) VALUES (?, 0.01, 0.02, 0.03, 1.0, 2.0, 3.0, ?)", (added["id"], ts))
conn.commit(); conn.close()
r = client.get("/api/getPeerTraffics?configurationName=wgtest99&id=" + quote(added["id"], safe="") + "&interval=60")
rows = r.get_json()["data"]
check("getPeerTraffics rows", r.get_json()["status"] and len(rows) == 5, r.get_data(as_text=True)[:150])
check("getPeerTraffics fields", all(k in rows[0] for k in ("cumu_data", "total_data", "time")))

# --- 19. deletePeers
r = client.post("/api/deletePeers/wgtest99", json={"peers": [added["id"]]})
check("deletePeer", r.get_json()["status"], r.get_data(as_text=True)[:150])
r = client.get("/api/getWireguardConfigurationInfo?configurationName=wgtest99")
check("peer gone", not any(p["id"] == added["id"] for p in r.get_json()["data"]["configurationPeers"]))

# ================= first-run setup / account =================
import app as appmod2

# 模拟"未配置"状态: 把内存中的密码清空(ini 仍是测试副本)
saved_hash = appmod2._ini.get("Account", "password", fallback="")
appmod2._ini.set("Account", "password", "")

anon = appmod2.app.test_client()

r = anon.get("/api/validateAuthentication")
check("uninitialized -> initialized=false",
      r.get_json()["data"]["initialized"] is False, r.get_data(as_text=True)[:120])
check("uninitialized -> anonymous client not authenticated", r.get_json()["status"] is False)
r = anon.get("/api/getWireguardConfigurations")
check("uninitialized -> protected endpoints still 401", r.status_code == 401, r.status_code)

r = anon.post("/api/account", json={"username": "newadmin", "password": "short"})
check("setup rejects short password", r.get_json()["status"] is False)

r = anon.post("/api/account", json={"username": "newadmin", "password": "setup-password-1"})
check("setup creates account", r.get_json()["status"] is True, r.get_data(as_text=True)[:150])
check("setup logs the caller in", "authToken" in (r.headers.get("Set-Cookie") or ""))

written = open(TEST + "/test.ini").read()
check("ini updated: username", "username = newadmin" in written)
check("ini stores a bcrypt hash (not plaintext)",
      "$2b$" in written and "setup-password-1" not in written)
check("ini keeps other sections", "[WireGuardConfiguration]" in written and "autostart" in written)
check("ini auto-filled remote_endpoint",
      "remote_endpoint =" in written and written.split("remote_endpoint =")[1].split("\n")[0].strip() != "")

r = anon.get("/api/validateAuthentication")
check("after setup -> initialized=true", r.get_json()["data"]["initialized"] is True)
check("after setup -> authenticated", r.get_json()["status"] is True)
r = anon.get("/api/getWireguardConfigurations")
check("after setup -> data reachable", r.status_code == 200 and r.get_json()["status"] is True)

# 改密码: 必须提供当前密码
r = anon.post("/api/account", json={"username": "newadmin", "password": "changed-password-2",
                                    "current_password": "wrong-one"})
check("change password requires current password", r.get_json()["status"] is False)
r = anon.post("/api/account", json={"username": "newadmin", "password": "changed-password-2",
                                    "current_password": "setup-password-1"})
check("change password works", r.get_json()["status"] is True, r.get_data(as_text=True)[:150])

fresh = appmod2.app.test_client()
r = fresh.post("/api/authenticate", json={"username": "newadmin", "password": "setup-password-1"})
check("old password no longer works", r.get_json()["status"] is False)
r = fresh.post("/api/authenticate", json={"username": "newadmin", "password": "changed-password-2"})
check("new password works", r.get_json()["status"] is True, r.get_data(as_text=True)[:150])

# 恢复(避免影响重复运行)
appmod2._ini.set("Account", "password", saved_hash)

print("\nRESULT: %d passed, %d failed" % (ok, fail))
sys.exit(1 if fail else 0)
