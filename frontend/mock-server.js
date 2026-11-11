/*
 * Mock WGDashboard backend for previewing the WGD Lite UI without WireGuard.
 *   node mock-server.js        -> http://localhost:8787
 * Login: any username + any password.
 */
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8787;
const INDEX = path.join(__dirname, "index.html");
const API_KEY = process.env.API_KEY || "test-key-123";
let initialized = process.env.UNINITIALIZED !== "1";
let mockUser = { username: "admin", password: "testpass" };

// CORS mirrors the real backend: origins *, and wg-dashboard-apikey allowed.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "DELETE, POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, wg-dashboard-apikey",
};
const j = (res, obj, code) => {
  res.writeHead(code || 200, { "Content-Type": "application/json", ...CORS });
  res.end(JSON.stringify(obj));
};
const ok = (data, message) => ({ status: true, message: message || null, data: data === undefined ? null : data });
const err = (message, code) => ({ status: false, message, data: null, _code: code });

/* ---- fake data ---- */
let peers = [];
function seed() {
  peers = [];
  for (let i = 1; i <= 6; i++) {
    peers.push({
      id: "PUBKEY_" + i.toString().padStart(2, "0") + "=".repeat(4),
      private_key: "PRIVKEY_" + i,
      name: ["laptop", "phone", "tablet", "home-router", "work-pc", "spare"][i - 1],
      allowed_ip: "10.66.66." + (i + 1) + "/32",
      DNS: "1.1.1.1",
      endpoint_allowed_ip: "0.0.0.0/0",
      endpoint: i % 3 === 0 ? "—" : "203.0.113." + (10 + i) + ":51820",
      remote_endpoint: "203.0.113." + (10 + i) + ":51820",
      status: i % 4 === 0 ? "stopped" : "running",
      latest_handshake: i % 4 === 0 ? "No Handshake" : "0:0" + i + ":12",
      total_receive: +(Math.random() * 3).toFixed(3),
      total_sent: +(Math.random() * 3).toFixed(3),
      cumu_receive: +(Math.random() * 20).toFixed(3),
      cumu_sent: +(Math.random() * 20).toFixed(3),
      mtu: 1420,
      keepalive: 21,
      preshared_key: "",
      notes: "",
      restricted: false,
    });
  }
}
seed();

const realtime = { sent: 0.1, recv: 0.2 };

let tunnels = [
  { Name: "wg0", Status: true, Protocol: "wg", Address: "10.66.66.1/24", ListenPort: 51820,
    ConnectedPeers: 0, TotalPeers: 0, DataUsage: { Receive: 0, Sent: 0, Total: 0 },
    raw: "[Interface]\nPrivateKey = MOCKKEY0=\nAddress = 10.66.66.1/24\nListenPort = 51820\n\n[Peer]\n" },
  { Name: "wg1", Status: false, Protocol: "wg", Address: "10.67.67.1/24", ListenPort: 51821,
    ConnectedPeers: 0, TotalPeers: 0, DataUsage: { Receive: 0, Sent: 0, Total: 0 },
    raw: "[Interface]\nPrivateKey = MOCKKEY1=\nAddress = 10.67.67.1/24\nListenPort = 51821\n\n[Peer]\n" },
];

/* ---- routing ---- */
const server = http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  const p = u.pathname;

  // preflight
  if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }

  // two independent auth paths, like the real backend
  const cookieAuthed = process.env.ALWAYS_AUTH === "1" || /mock_auth=1/.test(req.headers.cookie || "");
  const keyOk = (req.headers["wg-dashboard-apikey"] || "") === API_KEY;
  const probeOk = cookieAuthed || keyOk;

  // static (serves any *.html next to this file, so index / index-preact can both be previewed)
  if (p === "/" || p.endsWith(".html")) {
    const name = p === "/" ? "index.html" : path.basename(p);
    const file = path.join(__dirname, name);
    if (fs.existsSync(file)) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(fs.readFileSync(file));
    }
  }

  const body = () =>
    new Promise((r) => {
      let d = "";
      req.on("data", (c) => (d += c));
      req.on("end", () => {
        try { r(JSON.parse(d || "{}")); } catch (e) { r({}); }
      });
    });

  (async () => {
    // ---- auth ----
    // NOTE: real backend's validateAuthentication only checks the session cookie,
    // NOT the API key — mirrored here on purpose.
    if (p === "/api/validateAuthentication") {
      const r = cookieAuthed ? ok(true) : err("Invalid authentication.");
      r.data = { initialized };
      return j(res, r);
    }
    if (p === "/api/account") {
      const b = await body();
      if (!initialized) {
        if (!b.username || !b.password || String(b.password).length < 8)
          return j(res, err("Username is required and password must be at least 8 characters"));
        mockUser = { username: b.username, password: b.password };
        initialized = true;
        res.setHeader("Set-Cookie", "mock_auth=1; Path=/; HttpOnly; SameSite=Lax");
        return j(res, ok({ username: b.username }));
      }
      if (!cookieAuthed) return j(res, err("Unauthorized access.", 401), 401);
      if (b.current_password !== mockUser.password) return j(res, err("Current password is incorrect"));
      if (!b.username || !b.password || String(b.password).length < 8)
        return j(res, err("Username is required and password must be at least 8 characters"));
      mockUser = { username: b.username, password: b.password };
      return j(res, ok({ username: b.username }));
    }
    if (p === "/api/authenticate") {
      const b = await body();
      if (!initialized) return j(res, err("Setup required"));
      if (b.username !== mockUser.username || b.password !== mockUser.password)
        return j(res, err("Sorry, your username or password is incorrect."));
      res.setHeader("Set-Cookie", "mock_auth=1; Path=/; HttpOnly; SameSite=Lax");
      return j(res, ok(true));
    }
    if (p === "/api/signout") {
      res.setHeader("Set-Cookie", "mock_auth=; Path=/; Max-Age=0");
      return j(res, ok(true));
    }
    if (!initialized || !probeOk) return j(res, err("Unauthorized access.", 401), 401);

    // ---- configs ----
    if (p === "/api/getWireguardConfigurations") {
      const active = peers.filter((x) => !x.restricted);
      const du = active.reduce(
        (a, x) => {
          a.Receive += x.cumu_receive + x.total_receive;
          a.Sent += x.cumu_sent + x.total_sent;
          return a;
        },
        { Receive: 0, Sent: 0, Total: 0 }
      );
      du.Total = du.Receive + du.Sent;
      const list = tunnels.map((t) => (t.Name === "wg0" ? { ...t, ConnectedPeers: active.filter((x) => x.status === "running").length, TotalPeers: active.length, DataUsage: du } : t));
      return j(res, ok(list));
    }
    if (p === "/api/protocolsEnabled") return j(res, ok(["wg"]));
    if (p === "/api/addWireguardConfiguration") {
      const b = await body();
      for (const req of ["ConfigurationName", "Address", "ListenPort", "PrivateKey", "Protocol"]) {
        if (!(req in b)) return j(res, err("Please provide all required parameters."));
      }
      if (tunnels.some((t) => t.Name === b.ConfigurationName)) return j(res, err("Already have a configuration with the name " + b.ConfigurationName));
      if (tunnels.some((t) => String(t.ListenPort) === String(b.ListenPort))) return j(res, err("Port in use"));
      if (tunnels.some((t) => t.Address === b.Address)) return j(res, err("Address in use"));
      tunnels.push({
        Name: b.ConfigurationName, Status: false, Protocol: b.Protocol, Address: b.Address,
        ListenPort: b.ListenPort, ConnectedPeers: 0, TotalPeers: 0,
        DataUsage: { Receive: 0, Sent: 0, Total: 0 },
        raw: "[Interface]\nPrivateKey = " + b.PrivateKey + "\nAddress = " + b.Address + "\nListenPort = " + b.ListenPort + "\n\n[Peer]\n",
      });
      return j(res, ok(null, "created"));
    }
    if (p === "/api/toggleWireguardConfiguration") {
      const name = u.searchParams.get("configurationName");
      const t = tunnels.find((x) => x.Name === name);
      if (!t) return j(res, err("Please provide a valid configuration name", 404), 404);
      t.Status = !t.Status;
      return j(res, ok(t.Status, "toggled"));
    }
    if (p === "/api/renameWireguardConfiguration") {
      const b = await body();
      const t = tunnels.find((x) => x.Name === b.ConfigurationName);
      if (!t) return j(res, err("Configuration does not exist", 404), 404);
      if (tunnels.some((x) => x.Name === b.NewConfigurationName)) return j(res, err("Name already exist"), 400);
      t.Name = b.NewConfigurationName; t.raw = t.raw.replace("wgX", b.NewConfigurationName);
      return j(res, ok(null, "renamed"));
    }
    if (p === "/api/deleteWireguardConfiguration") {
      const b = await body();
      const i = tunnels.findIndex((x) => x.Name === b.ConfigurationName);
      if (i < 0) return j(res, err("Configuration does not exist", 404), 404);
      tunnels.splice(i, 1);
      return j(res, ok(null, "deleted"));
    }
    if (p === "/api/getWireguardConfigurationRawFile") {
      const name = u.searchParams.get("configurationName");
      const t = tunnels.find((x) => x.Name === name);
      if (!t) return j(res, err("Configuration does not exist", 404), 404);
      return j(res, ok({ path: "/etc/wireguard/" + name + ".conf", content: t.raw }));
    }
    if (p === "/api/updateWireguardConfigurationRawFile") {
      const b = await body();
      const t = tunnels.find((x) => x.Name === b.configurationName);
      if (!t) return j(res, err("Configuration does not exist"), 404);
      if (!b.rawConfiguration) return j(res, err("Please provide content"));
      t.raw = b.rawConfiguration;
      return j(res, ok(null, "saved"));
    }
    if (p === "/api/getWireguardConfigurationInfo") {
      return j(res, ok({
        configurationInfo: {},
        configurationPeers: peers.filter((x) => !x.restricted),
        configurationRestrictedPeers: peers.filter((x) => x.restricted),
      }));
    }
    if (p.startsWith("/api/getAvailableIPs/")) {
      return j(res, ok({ "10.66.66.0/24": ["10.66.66.20/32", "10.66.66.21/32", "10.66.66.22/32"] }));
    }
    if (p.startsWith("/api/getWireguardConfigurationRealtimeTraffic")) {
      realtime.sent = Math.max(0, realtime.sent + (Math.random() - 0.5) * 0.4);
      realtime.recv = Math.max(0, realtime.recv + (Math.random() - 0.5) * 0.6);
      return j(res, ok({ sent: +realtime.sent.toFixed(2), recv: +realtime.recv.toFixed(2) }));
    }

    // ---- peer mutations ----
    if (p.startsWith("/api/addPeers/")) {
      const b = await body();
      const ip = (b.allowed_ips && b.allowed_ips[0]) || "10.66.66.99/32";
      const np = {
        id: "PUB_" + Math.random().toString(36).slice(2, 10),
        private_key: b.private_key || "GEN_" + Math.random().toString(36).slice(2, 8),
        name: b.name || "", allowed_ip: ip, DNS: b.DNS, endpoint_allowed_ip: b.endpoint_allowed_ip,
        endpoint: "—", remote_endpoint: "", status: "stopped", latest_handshake: "No Handshake",
        total_receive: 0, total_sent: 0, cumu_receive: 0, cumu_sent: 0,
        mtu: b.mtu, keepalive: b.keepalive, preshared_key: b.preshared_key || "", notes: b.notes || "",
        restricted: false,
      };
      peers.push(np);
      return j(res, ok([np], "Peer added"));
    }
    if (p.startsWith("/api/updatePeerSettings/")) {
      const b = await body();
      const x = peers.find((y) => y.id === b.id);
      if (!x) return j(res, err("Peer does not exist"));
      Object.assign(x, {
        name: b.name, allowed_ip: b.allowed_ip, DNS: b.DNS,
        endpoint_allowed_ip: b.endpoint_allowed_ip, mtu: b.mtu, keepalive: b.keepalive,
        preshared_key: b.preshared_key || "", notes: b.notes || "",
      });
      return j(res, ok(null, "Peer updated"));
    }
    if (p.startsWith("/api/restrictPeers/")) {
      const b = await body();
      (b.peers || []).forEach((id) => { const x = peers.find((y) => y.id === id); if (x) { x.restricted = true; x.status = "stopped"; } });
      return j(res, ok(null, "Peers disabled"));
    }
    if (p.startsWith("/api/allowAccessPeers/")) {
      const b = await body();
      (b.peers || []).forEach((id) => { const x = peers.find((y) => y.id === id); if (x) { x.restricted = false; x.status = "stopped"; } });
      return j(res, ok(null, "Peers enabled"));
    }
    if (p.startsWith("/api/deletePeers/")) {
      const b = await body();
      peers = peers.filter((x) => !(b.peers || []).includes(x.id));
      return j(res, ok(null, "Peers deleted"));
    }
    if (p.startsWith("/api/resetPeerData/")) {
      const b = await body();
      const x = peers.find((y) => y.id === b.id);
      if (x) { x.total_receive = x.total_sent = x.cumu_receive = x.cumu_sent = 0; }
      return j(res, ok(true));
    }
    if (p.startsWith("/api/downloadPeer/")) {
      const id = u.searchParams.get("id");
      const x = peers.find((y) => y.id === id);
      if (!x) return j(res, err("Peer does not exist"));
      return j(res, ok({
        fileName: x.name || "peer",
        file: "[Interface]\nPrivateKey = " + x.private_key + "\nAddress = " + x.allowed_ip +
              "\nDNS = " + x.DNS + "\n\n[Peer]\nPublicKey = SERVER_PUB\nAllowedIPs = " + x.endpoint_allowed_ip + "\n",
      }));
    }

    if (p === "/api/getPeerTraffics") {
      const iv = parseInt(u.searchParams.get("interval") || "60", 10);
      const now = Date.now();
      const rows = [];
      const pad2 = (n) => String(n).padStart(2, "0");
      for (let i = iv; i >= 0; i--) {
        const d = new Date(now - i * 60000);
        const time = d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) +
          " " + pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":00";
        const rx = 10 + (iv - i) * 0.02 + Math.random() * 0.01;
        const tx = 8 + (iv - i) * 0.015 + Math.random() * 0.01;
        rows.push({ cumu_receive: 0, total_receive: +rx.toFixed(3), cumu_sent: 0, total_sent: +tx.toFixed(3),
          cumu_data: 0, total_data: +(rx + tx).toFixed(3), time });
      }
      return j(res, ok(rows));
    }
    j(res, err("Not found: " + p, 404), 404);
  })().catch((e) => j(res, err(String(e && e.message || e)), 500));
});

server.listen(PORT, () => {
  console.log("WGD Lite mock running at http://localhost:" + PORT);
  console.log("Login with any username/password.");
});
