const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');

const app = express();
const PORT = 8481;
const DB_FILE = 'users.db';
const DEV_PASSWORD = 'DivinedCreationInc2990!!@!!';
const SALT_ROUNDS = 10;
const LOG_FILE = 'logs.txt';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'super_secret_key',
  resave: false,
  saveUninitialized: true
}));

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      hwid TEXT,
      ip TEXT,
      status TEXT DEFAULT 'active',
      note TEXT,
      locked_hwid TEXT
    )
  `);
});

function escape(text) {
  return (text || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function logEvent(text) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(LOG_FILE, `[${timestamp}] ${text}\n`);
}

function requireLogin(req, res, next) {
  if (!req.session.loggedIn) return res.redirect('/login');
  next();
}

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
    res.redirect('/');
  } else {
    res.send('<p>Wrong password.</p><a href="/login">Try again</a>');
  }
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
    </form><br>

    <form method="POST" action="/ban-user">
      <input name="username" placeholder="Username to Ban" required>
      <button>Ban</button>
    </form><br>

    <form method="POST" action="/unban-user">
      <input name="username" placeholder="Username to Unban" required>
      <button>Unban</button>
    </form><br>

    <form method="POST" action="/delete-user">
      <input name="username" placeholder="Username to Delete" required>
      <button>Delete</button>
    </form><br>

    <a href="/users">View Users</a><br>
    <a href="/notifications">Notifications</a><br>
    <a href="/logout">Logout</a>
  `);
});

app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).send("DB Error");
    let html = `<h2>Users</h2><table border="1" style="border-collapse: collapse;"><tr>
      <th>Username</th><th>Status</th><th>HWID</th><th>IP</th><th>Note</th><th>Locked HWID</th><th>Actions</th>
    </tr>`;
    rows.forEach(u => {
      html += `<tr>
        <td>${escape(u.username)}</td>
        <td>${escape(u.status)}</td>
        <td>${escape(u.hwid || 'N/A')}</td>
        <td>${escape(u.ip || 'N/A')}</td>
        <td>${escape(u.note || '')}</td>
        <td>${escape(u.locked_hwid || 'None')}</td>
        <td>
          <form method="POST" action="/reset-password" style="display:inline">
            <input type="hidden" name="username" value="${u.username}">
            <input type="password" name="newpass" placeholder="New Pass" required>
            <button>Reset Password</button>
          </form>
          <form method="POST" action="/lock-account" style="display:inline">
            <input type="hidden" name="username" value="${u.username}">
            <button>Lock Account</button>
          </form>
        </td>
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
  db.run("UPDATE users SET status='banned' WHERE username=?", [username], err => {
    if (!err) logEvent(`User ${username} was banned.`);
    res.redirect('/');
  });
});

app.post('/unban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='active' WHERE username=?", [username], err => res.redirect('/'));
});

app.post('/delete-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("DELETE FROM users WHERE username=?", [username], err => res.redirect('/'));
});

app.post('/reset-password', requireLogin, async (req, res) => {
  const { username, newpass } = req.body;
  if (!newpass) return res.send("Missing new password.");
  const hash = await bcrypt.hash(newpass, SALT_ROUNDS);
  db.run("UPDATE users SET password=? WHERE username=?", [hash, username], err => res.redirect('/users'));
});

app.post('/lock-account', requireLogin, (req, res) => {
  const { username } = req.body;
  db.get("SELECT hwid FROM users WHERE username=?", [username], (err, row) => {
    if (err || !row || !row.hwid) return res.send("Cannot lock account: No HWID found.");
    db.run("UPDATE users SET locked_hwid=? WHERE username=?", [row.hwid, username], err2 => {
      if (!err2) logEvent(`Account ${username} locked to HWID ${row.hwid}`);
      res.redirect('/users');
    });
  });
});

app.get('/notifications', requireLogin, (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    if (err) return res.send("No logs yet.");
    res.send(`<h2>Notifications Log</h2><pre>${escape(data)}</pre><br><a href="/">Back</a>`);
  });
});

app.post('/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = req.ip;
  if (!username || !password || !hwid) return res.status(400).json({ status: "error", message: "Missing fields." });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, row) => {
    if (row && row.status === 'banned') {
      logEvent(`Banned user ${username} attempted to register.`);
      return res.status(403).json({ status: "error", message: "You are banned." });
    }
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const insertOrUpdate = row
      ? `UPDATE users SET password=?, hwid=?, ip=? WHERE username=?`
      : `INSERT INTO users (username, password, hwid, ip) VALUES (?, ?, ?, ?)`;

    if (row) {
      db.run(insertOrUpdate, [hash, hwid, ip, username], err2 => {
        if (err2) return res.status(500).json({ status: "error", message: "Database error." });
        res.json({ status: "success", message: "Registered (updated)." });
      });
    } else {
      db.run(insertOrUpdate, [username, hash, hwid, ip], err2 => {
        if (err2) return res.status(500).json({ status: "error", message: "Database error." });
        res.json({ status: "success", message: "Registered." });
      });
    }
  });
});

app.post('/login-user', (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = req.ip;
  if (!username || !password || !hwid) return res.status(400).json({ status: "error", message: "Missing fields." });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, row) => {
    if (err) return res.status(500).json({ status: "error", message: "Database error." });
    if (!row) return res.status(403).json({ status: "error", message: "Invalid credentials." });
    if (row.status === 'banned') {
      logEvent(`Banned user ${username} tried logging in.`);
      return res.status(403).json({ status: "error", message: "Banned." });
    }
    const valid = await bcrypt.compare(password, row.password);
    if (!valid) return res.status(403).json({ status: "error", message: "Invalid credentials." });

    if (row.locked_hwid && row.locked_hwid !== hwid) {
      db.run("UPDATE users SET status='banned' WHERE username=?", [username]);
      logEvent(`User ${username} banned for sharing credentials (HWID mismatch).`);
      return res.status(403).json({ status: "error", message: "HWID mismatch. You are now banned." });
    }

    if (!row.locked_hwid) {
      db.run("UPDATE users SET locked_hwid=? WHERE username=?", [hwid, username]);
      logEvent(`User ${username} HWID locked to ${hwid}`);
    }

    db.run("UPDATE users SET ip=?, hwid=? WHERE username=?", [ip, hwid, username]);
    logEvent(`User ${username} logged in from IP ${ip}`);

    res.json({ status: "success", message: "Login successful." });
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});