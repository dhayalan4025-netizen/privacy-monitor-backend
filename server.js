const express = require("express");
const { DatabaseSync } = require("node:sqlite");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "privacy.db");

const db = new DatabaseSync(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT,
    url TEXT,
    permission TEXT,
    api TEXT,
    detail TEXT,
    time INTEGER
  )
`);
// Add the device column if it does not exist yet (older databases)
try { db.exec("ALTER TABLE logs ADD COLUMN device TEXT"); } catch (e) {}
db.exec("CREATE INDEX IF NOT EXISTS idx_logs_device ON logs(device)");

const insertLog = db.prepare(
  "INSERT INTO logs (site, url, permission, api, detail, time, device) VALUES (?, ?, ?, ?, ?, ?, ?)"
);

app.use(express.json({ limit: "100kb" }));

app.use((req, res, next) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const cut = (v, n) => String(v == null ? "" : v).slice(0, n);

// Each user's extension creates a random device ID (UUID). That ID is the "login":
// you can only read data for a device ID you know.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const validDevice = (d) => typeof d === "string" && UUID.test(d);

app.post("/api/logs", (req, res) => {
  const e = req.body || {};
  if (!validDevice(e.device)) {
    return res.status(400).json({ error: "valid device id required" });
  }
  if (!e.site || !e.permission) {
    return res.status(400).json({ error: "site and permission are required" });
  }
  insertLog.run(
    cut(e.site, 255),
    cut(e.url, 1000),
    cut(e.permission, 50),
    cut(e.api, 100),
    cut(e.detail, 255),
    Number(e.time) || Date.now(),
    e.device
  );
  res.json({ ok: true });
});

app.get("/api/logs", (req, res) => {
  const device = req.query.device;
  if (!validDevice(device)) return res.status(400).json({ error: "valid device id required" });
  const rows = db
    .prepare("SELECT id, site, url, permission, api, detail, time FROM logs WHERE device = ? ORDER BY id DESC LIMIT 100")
    .all(device);
  res.json(rows);
});

const WEIGHTS = {
  camera: 30,
  microphone: 30,
  screen: 30,
  location: 25,
  clipboard: 15,
  notifications: 10
};

app.get("/api/stats", (req, res) => {
  const device = req.query.device;
  if (!validDevice(device)) return res.status(400).json({ error: "valid device id required" });

  const rows = db
    .prepare(
      `SELECT site,
              COUNT(*) AS requests,
              GROUP_CONCAT(DISTINCT permission) AS permissions,
              MAX(time) AS lastSeen
       FROM logs WHERE device = ? GROUP BY site`
    )
    .all(device);

  const out = rows.map((r) => {
    const perms = r.permissions ? String(r.permissions).split(",") : [];
    const score = Math.min(100, perms.reduce((s, p) => s + (WEIGHTS[p] || 5), 0));
    const level = score >= 60 ? "high" : score >= 30 ? "medium" : "low";
    return {
      site: r.site,
      requests: Number(r.requests),
      permissions: perms,
      lastSeen: Number(r.lastSeen),
      score: score,
      level: level
    };
  });
  res.json(out);
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/", (req, res) => {
  res.send("Privacy Monitor backend is running. Open the dashboard link from the extension popup.");
});

app.listen(PORT, () => console.log("Backend running on port " + PORT));
