const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const PORT = 8481;
const DB_FILE = 'users.db';
const DEV_PASSWORD = 'DivinedCreationInc2990!!@!!';
const SALT_ROUNDS = 10;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'super_secret_key',
  resave: false,
  saveUninitialized: true
}));

// DB Setup
const db = new sqlite3.Database(DB_FILE);
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    hwid TEXT,
    ip TEXT,
    status TEXT DEFAULT 'active',
    note TEXT
  )
`);

// Helper
function escape(text) {
  return (text || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

// Middleware for dev login
function requireLogin(req, res, next) {
  if (!req.session.loggedIn) return res.redirect('/login');
  next();
}

// === Admin Routes ===

app.get('/login', (req, res) => {
  res.send(`
    <h2>Dev Login</h2>
    <form method="POST">
      <input name="password" type="password" placeholder="Dev Password" required>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', (req, res) => {
  if (req.body.password === DEV_PASSWORD) {
    req.session.loggedIn = true;
    return res.redirect('/');
  }
  res.send('<p>Wrong password.</p><a href="/login">Try again</a>');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireLogin, (req, res) => {
  res.send(`
    <h2>Admin Panel</h2>
    <form method="POST" action="/create-user">
      <input name="username" placeholder="Username" required>
      <input name="password" placeholder="Password" required>
      <input name="note" placeholder="Note (optional)">
      <button>Create User</button>
    </form>
    <br>
    <form method="POST" action="/ban-user">
      <input name="username" placeholder="Username to Ban" required>
      <button>Ban</button>
    </form>
    <br>
    <form method="POST" action="/unban-user">
      <input name="username" placeholder="Username to Unban" required>
      <button>Unban</button>
    </form>
    <br><a href="/users">View Users</a>
    <br><a href="/logout">Logout</a>
  `);
});

app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).send("DB Error");
    let html = `<h2>Users</h2><table border="1"><tr><th>Username</th><th>Status</th><th>HWID</th><th>IP</th><th>Note</th></tr>`;
    rows.forEach(u => {
      html += `<tr>
        <td>${escape(u.username)}</td>
        <td>${escape(u.status)}</td>
        <td>${escape(u.hwid || 'N/A')}</td>
        <td>${escape(u.ip || 'N/A')}</td>
        <td>${escape(u.note || '')}</td>
      </tr>`;
    });
    html += `</table><br><a href="/">Back</a>`;
    res.send(html);
  });
});

app.post('/create-user', requireLogin, async (req, res) => {
  const { username, password, note = '' } = req.body;
  if (!username || !password) return res.send("Missing fields.");
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  db.run(`
    INSERT INTO users (username, password, note)
    VALUES (?, ?, ?)
    ON CONFLICT(username) DO UPDATE SET password=excluded.password, note=excluded.note
  `, [username, hash, note], err => {
    if (err) return res.send("DB error.");
    res.redirect('/');
  });
});

app.post('/ban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='banned' WHERE username=?", [username], () => res.redirect('/'));
});

app.post('/unban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='active' WHERE username=?", [username], () => res.redirect('/'));
});

// === API Routes ===

app.post('/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = req.ip;
  if (!username || !password) return res.status(400).json({ status: "error", message: "Username and password required." });

  db.get("SELECT status FROM users WHERE username=?", [username], async (err, row) => {
    if (row && row.status === "banned") return res.status(403).json({ status: "error", message: "You are banned." });
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run(`
      INSERT INTO users (username, password, hwid, ip)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET password=excluded.password, hwid=excluded.hwid, ip=excluded.ip
    `, [username, hash, hwid, ip], err2 => {
      if (err2) return res.status(500).json({ status: "error", message: "Database error." });
      res.json({ status: "success", message: "Registered." });
    });
  });
});

app.post('/login-user', (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = req.ip;
  if (!username || !password) return res.status(400).json({ status: "error", message: "Missing fields." });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, row) => {
    if (!row) return res.status(403).json({ status: "error", message: "Invalid credentials." });
    if (row.status === 'banned') return res.status(403).json({ status: "error", message: "Banned." });
    const valid = await bcrypt.compare(password, row.password);
    if (!valid) return res.status(403).json({ status: "error", message: "Invalid credentials." });
    if (row.hwid && row.hwid !== hwid) return res.status(403).json({ status: "error", message: "HWID mismatch." });
    db.run("UPDATE users SET ip=? WHERE username=?", [ip, username]);
    res.json({ status: "success", message: "Login successful." });
  });
});

// === Start Server ===
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
