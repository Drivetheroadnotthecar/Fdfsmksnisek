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

// Middleware setup
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

  db.run(`
    CREATE TABLE IF NOT EXISTS banned (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      hwid TEXT,
      ip TEXT,
      reason TEXT,
      banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.all("PRAGMA table_info(users)", [], (err, columns) => {
    if (err) return console.error(err);
    if (!columns.some(c => c.name === 'locked_hwid')) {
      db.run("ALTER TABLE users ADD COLUMN locked_hwid TEXT", () => {
        console.log("✅ Added 'locked_hwid' column");
      });
    }
  });
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

function banUser(username, hwid, ip, reason = "Auto-ban: credential sharing") {
  db.run("UPDATE users SET status='banned' WHERE username=?", [username]);
  db.run("INSERT INTO banned (username, hwid, ip, reason) VALUES (?, ?, ?, ?)", [username, hwid, ip, reason]);
  logEvent(`User ${username} banned. Reason: ${reason}`);
}

function checkBanned(req, res, next) {
  const { username, hwid } = req.body;
  const ip = req.ip;

  db.get(
    `SELECT * FROM banned WHERE username = ? OR hwid = ? OR ip = ?`,
    [username, hwid, ip],
    (err, ban) => {
      if (err) return res.status(500).json({ status: "error", message: "Server error." });
      if (ban) {
        return res.status(403).json({ status: "error", message: `You are banned: ${ban.reason}` });
      }
      next();
    }
  );
}

// === Helper to wrap admin pages with styling and vine decoration ===
function renderPage(title, content) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escape(title)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=UnifrakturCook:wght@700&display=swap');
  body {
    background-color: #000;
    color: #ff1a1a;
    font-family: 'UnifrakturCook', cursive, monospace;
    margin: 0; padding: 0;
  }
  a {
    color: #ff4c4c;
    text-decoration: none;
  }
  a:hover {
    text-decoration: underline;
  }
  h2 {
    text-align: center;
    margin-top: 1em;
    text-shadow: 0 0 5px #ff1a1a;
  }
  form {
    margin: 1em auto;
    max-width: 600px;
    background: #1a0000;
    padding: 15px 20px;
    border-radius: 12px;
    border: 3px solid #ff1a1a;
    box-shadow: 0 0 10px #ff0000cc;
    position: relative;
  }
  form button {
    background-color: #ff1a1a;
    border: none;
    color: #000;
    font-weight: bold;
    padding: 8px 14px;
    margin-left: 10px;
    border-radius: 8px;
    cursor: pointer;
    transition: background-color 0.3s ease;
  }
  form button:hover {
    background-color: #ff4c4c;
  }
  input, select {
    font-family: 'Courier New', monospace;
    font-size: 16px;
    padding: 8px;
    border-radius: 8px;
    border: 2px solid #ff1a1a;
    width: 180px;
    margin-right: 5px;
    background-color: #330000;
    color: #ff9999;
  }
  table {
    margin: 1em auto;
    border-collapse: collapse;
    max-width: 90vw;
    width: 100%;
  }
  th, td {
    border: 2px solid #ff1a1a;
    padding: 8px 12px;
    text-align: center;
  }
  th {
    background-color: #330000;
  }
  td {
    background-color: #1a0000;
  }
  pre {
    background-color: #1a0000;
    color: #ff4c4c;
    max-height: 400px;
    overflow-y: auto;
    border: 3px solid #ff1a1a;
    padding: 15px;
    border-radius: 12px;
    max-width: 90vw;
    margin: 1em auto;
    font-family: 'Courier New', monospace;
  }

  /* Red vine border decoration around container */
  .vine-container {
    position: relative;
    padding: 25px 30px;
    border: 5px solid #ff1a1a;
    border-radius: 20px;
    max-width: 1000px;
    margin: 1em auto 2em auto;
    box-shadow: 0 0 20px #ff0000cc;
  }
  .vine-container::before, .vine-container::after {
    content: "";
    position: absolute;
    border: 3px solid transparent;
    pointer-events: none;
  }
  /* vine top-left */
  .vine-container::before {
    top: -25px;
    left: -25px;
    width: 80px;
    height: 80px;
    border-top: 3px solid #ff1a1a;
    border-left: 3px solid #ff1a1a;
    border-radius: 50% 0 0 0;
    box-shadow:
      5px 5px 0 #ff1a1a,
      15px 15px 0 #ff4c4c,
      30px 30px 0 #ff1a1a;
    transform: rotate(-15deg);
  }
  /* vine bottom-right */
  .vine-container::after {
    bottom: -25px;
    right: -25px;
    width: 80px;
    height: 80px;
    border-bottom: 3px solid #ff1a1a;
    border-right: 3px solid #ff1a1a;
    border-radius: 0 0 50% 0;
    box-shadow:
      -5px -5px 0 #ff1a1a,
      -15px -15px 0 #ff4c4c,
      -30px -30px 0 #ff1a1a;
    transform: rotate(15deg);
  }

  /* Responsive */
  @media (max-width: 700px) {
    form, table, pre {
      width: 95vw;
      margin: 1em auto;
    }
    input {
      width: 100%;
      margin: 5px 0;
    }
    form button {
      margin: 10px 0 0 0;
      width: 100%;
    }
    td, th {
      font-size: 14px;
      padding: 5px;
    }
  }
</style>
</head>
<body>
  <div class="vine-container">
  ${content}
  </div>
</body>
</html>
`;
}

// --- Admin Routes ---

app.get('/login', (req, res) => {
  res.send(renderPage("Dev Login", `
    <h2>Dev Login</h2>
    <form method="POST">
      <input name="password" type="password" placeholder="Dev Password" required>
      <button type="submit">Login</button>
    </form>
  `));
});

app.post('/login', (req, res) => {
  if (req.body.password === DEV_PASSWORD) {
    req.session.loggedIn = true;
    res.redirect('/');
  } else {
    res.send(renderPage("Login Failed", `
      <p>Wrong password.</p><a href="/login">Try again</a>
    `));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', requireLogin, (req, res) => {
  res.send(renderPage("Admin Panel", `
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
  `));
});

app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).send("DB Error");
    let html = `<h2>Users</h2><table border="1"><tr>
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
    res.send(renderPage("Users", html));
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
  db.get("SELECT hwid, ip FROM users WHERE username=?", [username], (err, row) => {
    if (err || !row) return res.redirect('/');
    banUser(username, row.hwid, row.ip);
    res.redirect('/');
  });
});

app.post('/unban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='active' WHERE username=?", [username], err => {
    if (!err) {
      db.run("DELETE FROM banned WHERE username=?", [username]);
      logEvent(`User ${username} unbanned.`);
    }
    res.redirect('/');
  });
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
    if (err) data = "No logs yet.";
    const html = `
      <h2>Notifications Log</h2>
      <pre>${escape(data)}</pre>
      <form method="POST" action="/clear-logs" onsubmit="return confirm('Clear all logs? This cannot be undone.')">
        <button type="submit" style="background:#ff1a1a; color:#000; font-weight:bold; padding:10px 20px; border:none; border-radius:8px; cursor:pointer;">Clear Logs</button>
      </form><br>
      <a href="/">Back</a>
    `;
    res.send(renderPage("Notifications", html));
  });
});

app.post('/clear-logs', requireLogin, (req, res) => {
  fs.writeFile(LOG_FILE, '', err => {
    if (err) {
      logEvent("Failed to clear logs: " + err.message);
    } else {
      logEvent("Logs cleared by admin.");
    }
    res.redirect('/notifications');
  });
});

// --- API ---

app.post('/register', checkBanned, async (req, res) => {
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

app.post('/login-user', checkBanned, (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = req.ip;
  if (!username || !password || !hwid) return res.status(400).json({ status: "error", message: "Missing fields." });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (err) return res.status(500).json({ status: "error", message: "Database error." });
    if (!user) return res.status(403).json({ status: "error", message: "Invalid credentials." });
    if (user.status === 'banned') {
      logEvent(`Banned user ${username} tried logging in.`);
      return res.status(403).json({ status: "error", message: "Banned." });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(403).json({ status: "error", message: "Invalid credentials." });

    if (user.locked_hwid && user.locked_hwid !== hwid) {
      banUser(user.username, user.locked_hwid, ip, "Credential sharing detected");
      db.get("SELECT username FROM users WHERE locked_hwid = ?", [hwid], (err2, otherUser) => {
        if (otherUser && otherUser.username !== user.username) {
          banUser(otherUser.username, hwid, ip, "Credential sharing detected (second user)");
        }
      });
      return res.status(403).json({
        status: "error",
        message: "[SECURITY] Account locked to a different HWID. You gave your credentials away. Auto-banning both accounts."
      });
    }

    if (!user.locked_hwid) {
      db.run("UPDATE users SET locked_hwid=? WHERE username=?", [hwid, username]);
      logEvent(`User ${username} locked to HWID ${hwid}`);
    }

    db.run("UPDATE users SET ip=?, hwid=? WHERE username=?", [ip, hwid, username]);
    logEvent(`User ${username} logged in from IP ${ip}`);

    res.json({ status: "success", message: "Login successful." });
  });
});

app.use((req, res) => {
  if (req.path.startsWith("/login-user") || req.path.startsWith("/register")) {
    return res.status(404).json({ status: "error", message: "API route not found." });
  }
  res.redirect('/login');
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server running on http://0.0.0.0:${PORT}`);
});
