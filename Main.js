const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8481;
const DB_FILE = path.join(__dirname, 'users.db');
const LOG_FILE = path.join(__dirname, 'logs.txt');
const DEV_PASSWORD = 'JakeH989!!';
const SALT_ROUNDS = 10;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'super_secret_key',
  resave: false,
  saveUninitialized: false
}));

// Initialize DB & create table if needed
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

// Escape HTML helper
function escapeHTML(text) {
  return (text || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

// Log events with timestamp
function logEvent(text) {
  const timestamp = new Date().toISOString();
  fs.appendFileSync(LOG_FILE, `[${timestamp}] ${text}\n`);
}

// Remove ::ffff: prefix from IPv4-mapped IPv6 addresses
function cleanIP(ip) {
  if (!ip) return 'N/A';
  if (ip.startsWith('::ffff:')) return ip.substring(7);
  return ip;
}

// Middleware to require admin login
function requireLogin(req, res, next) {
  if (!req.session.loggedIn) return res.redirect('/login');
  next();
}

// Render full HTML page with styling and scripts
function renderPage(title, content, extraScripts = '') {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHTML(title)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=UnifrakturCook:wght@700&display=swap');
  body {
    background-color: #000;
    color: #ff1a1a;
    font-family: 'UnifrakturCook', cursive, monospace;
    margin: 0; padding: 0;
    background-image: url("data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIwIiBoZWlnaHQ9IjEyMCIgdmlld0JveD0iMCAwIDEyMCAxMjAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgICA8cGF0aCBkPSJNNjAgMTRjMjQuNCAwIDQ0IDE5LjYgNDQgNDQgMCAxNC4zLTcuNiAyNi44LTE5LjQgMzQuMyAxLjIgMy4xIDQuNCAxNS41IDQuNCAxNS41cy0xMi42LTEuNi0yMy4gMS43Yy0xMC40IDMuMi0xMi43IDguNi0xMi43IDguNmwtLjQtNy40Yy0uNi03LjcgMTQuOS02IDE0LjktNiAxMi0xIDE4LjUtNyAxOC41LTcgMCAxNi01IDE4LTE3IDAtMTAgNi0xNiAxMi0xNiA2LjMgMCAxMy42IDIuMSAxOC40IDUuMyAyLjUtMy4zIDQuNC03LjcgNC40LTEyLjYgMC0xMC0xMy0xOC0zMC0xOC0xNi41IDAtMzAgOC03IDhsLTExLTloLjN6IiBmaWxsPSIjZjAwMDAwIiBmaWx0ZXI9InVybCgjcmVkX3NoYWRvdykiLz4KICAgIDxmaWx0ZXIgaWQ9InJlZF9zaGFkb3ciPgogICAgICA8ZmVUdXJidWxlbmNlIGJhc2VGcmVxdWVuY3lJbj0iZnJvbmQiIG51bU9jdGF2ZXM9IjEiIG51bUN5Y2xlcz0iMiIgdHVyYnVsZW5jZVRlcm1zPSIwLjYiLz4KICAgIDwvZmlsdGVyPgo8L3N2Zz4=");
    background-repeat: repeat;
    background-position: center;
    background-size: 120px 120px;
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
    border-collapse: collapse;
    max-width: 100%;
    width: 100%;
  }
  th, td {
    border: 2px solid #ff1a1a;
    padding: 8px 12px;
    text-align: center;
    word-break: break-word;
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
  .vine-container {
    position: relative;
    padding: 25px 30px;
    border: 5px solid #ff1a1a;
    border-radius: 20px;
    max-width: 1000px;
    margin: 1em auto 2em auto;
    box-shadow: 0 0 20px #ff0000cc;
    background-color: rgba(26,0,0,0.85);
  }
  .vine-container::before, .vine-container::after {
    content: "";
    position: absolute;
    border: 3px solid transparent;
    pointer-events: none;
  }
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
  .users-table-container {
    max-height: 70vh;
    overflow-y: auto;
    margin: 1em 0;
  }
  .table-wrapper {
    overflow-x: auto;
  }
  #searchInput {
    font-family: 'Courier New', monospace;
    font-size: 18px;
    padding: 10px;
    border-radius: 10px;
    border: 2px solid #ff1a1a;
    width: 300px;
    margin: 10px auto;
    display: block;
    background-color: #330000;
    color: #ff9999;
    text-align: center;
  }
  @media (max-width: 700px) {
    form, pre, .vine-container {
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
    #searchInput {
      width: 90%;
    }
  }
</style>
</head>
<body>
  <div class="vine-container">
    ${content}
  </div>
  ${extraScripts}
</body>
</html>
`;
}

// --- Routes ---

// Login page
app.get('/login', (req, res) => {
  res.send(renderPage("Admin Login", `
    <h2>Admin Login</h2>
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Dev Password" required />
      <button type="submit">Login</button>
    </form>
  `));
});

app.post('/login', (req, res) => {
  const pass = req.body.password || '';
  if (pass === DEV_PASSWORD) {
    req.session.loggedIn = true;
    res.redirect('/');
  } else {
    res.send(renderPage("Admin Login", `
      <h2>Wrong Password</h2>
      <a href="/login">Try Again</a>
    `));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Admin panel home
app.get('/', requireLogin, (req, res) => {
  res.send(renderPage("Admin Panel", `
    <h2>Admin Panel</h2>
    <form method="POST" action="/create-user">
      <input name="username" placeholder="Username" required />
      <input name="password" placeholder="Password" required />
      <input name="note" placeholder="Note (optional)" />
      <button>Create / Update User</button>
    </form><br>

    <form method="POST" action="/ban-user">
      <input name="username" placeholder="Username to Ban" required />
      <button>Ban User</button>
    </form><br>

    <form method="POST" action="/unban-user">
      <input name="username" placeholder="Username to Unban" required />
      <button>Unban User</button>
    </form><br>

    <form method="POST" action="/delete-user">
      <input name="username" placeholder="Username to Delete" required />
      <button>Delete User</button>
    </form><br>

    <a href="/users">View Users</a><br>
    <a href="/notifications">Notifications</a><br>
    <a href="/logout">Logout</a>
  `));
});

// Users list with search
app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT * FROM users ORDER BY username", [], (err, rows) => {
    if (err) return res.status(500).send("DB error");

    let tableRows = rows.map(u => `
      <tr>
        <td>${escapeHTML(u.username)}</td>
        <td>${escapeHTML(u.status)}</td>
        <td>${escapeHTML(u.hwid || 'N/A')}</td>
        <td>${escapeHTML(cleanIP(u.ip))}</td>
        <td>${escapeHTML(u.note || '')}</td>
        <td>${escapeHTML(u.locked_hwid || 'None')}</td>
        <td>
          <form method="POST" action="/reset-password" style="display:inline;">
            <input type="hidden" name="username" value="${escapeHTML(u.username)}" />
            <input type="password" name="newpass" placeholder="New Pass" required />
            <button>Reset Password</button>
          </form>
          <form method="POST" action="/lock-account" style="display:inline;">
            <input type="hidden" name="username" value="${escapeHTML(u.username)}" />
            <button>Lock HWID</button>
          </form>
        </td>
      </tr>
    `).join('');

    const html = `
      <h2>Users</h2>
      <input type="text" id="searchInput" placeholder="Search users..." autocomplete="off" />
      <div class="users-table-container table-wrapper">
        <table border="1" id="usersTable">
          <thead>
            <tr>
              <th>Username</th>
              <th>Status</th>
              <th>HWID</th>
              <th>IP</th>
              <th>Note</th>
              <th>Locked HWID</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>${tableRows}</tbody>
        </table>
      </div>
      <br><a href="/">Back</a>
    `;

    const script = `
      <script>
        const searchInput = document.getElementById('searchInput');
        const tbody = document.querySelector('#usersTable tbody');

        searchInput.addEventListener('input', () => {
          const filter = searchInput.value.toLowerCase();
          for (const row of tbody.rows) {
            const text = row.innerText.toLowerCase();
            row.style.display = text.includes(filter) ? '' : 'none';
          }
        });
      </script>
    `;

    res.send(renderPage("Users", html, script));
  });
});

// Create or update user
app.post('/create-user', requireLogin, async (req, res) => {
  const { username, password, note = '' } = req.body;
  if (!username || !password) return res.send("Missing username or password.");

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run(`
      INSERT INTO users (username, password, note)
      VALUES (?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET password=excluded.password, note=excluded.note
    `, [username, hash, note], err => {
      if (err) return res.send("DB error.");
      res.redirect('/');
    });
  } catch {
    res.send("Error hashing password.");
  }
});

// Ban user
app.post('/ban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='banned' WHERE username=?", [username], err => {
    if (!err) logEvent(`User ${username} was banned.`);
    res.redirect('/');
  });
});

// Unban user
app.post('/unban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='active' WHERE username=?", [username], err => res.redirect('/'));
});

// Delete user
app.post('/delete-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("DELETE FROM users WHERE username=?", [username], err => res.redirect('/'));
});

// Reset password
app.post('/reset-password', requireLogin, async (req, res) => {
  const { username, newpass } = req.body;
  if (!newpass) return res.send("Missing new password.");

  try {
    const hash = await bcrypt.hash(newpass, SALT_ROUNDS);
    db.run("UPDATE users SET password=? WHERE username=?", [hash, username], err => res.redirect('/users'));
  } catch {
    res.send("Error hashing new password.");
  }
});

// Lock HWID to current HWID value
app.post('/lock-account', requireLogin, (req, res) => {
  const { username } = req.body;
  db.get("SELECT hwid FROM users WHERE username=?", [username], (err, row) => {
    if (err || !row || !row.hwid) return res.send("Cannot lock: No HWID found.");
    db.run("UPDATE users SET locked_hwid=? WHERE username=?", [row.hwid, username], err2 => {
      if (!err2) logEvent(`User ${username} locked to HWID ${row.hwid}`);
      res.redirect('/users');
    });
  });
});

// Register API for client key registration
app.post('/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  const ip = cleanIP(req.ip);
  if (!username || !password || !hwid) {
    return res.status(400).json({ status: "error", message: "Missing fields." });
  }

  // Check if user is banned or locked
  db.get("SELECT status, locked_hwid FROM users WHERE username=?", [username], async (err, user) => {
    if (err) return res.status(500).json({ status: "error", message: "DB error." });
    if (!user) return res.status(400).json({ status: "error", message: "User not found." });
    if (user.status === 'banned') return res.status(403).json({ status: "error", message: "User banned." });
    if (user.locked_hwid && user.locked_hwid !== hwid) {
      return res.status(403).json({ status: "error", message: "HWID locked." });
    }

    // Verify password
    db.get("SELECT password FROM users WHERE username=?", [username], async (e, row) => {
      if (e || !row) return res.status(400).json({ status: "error", message: "User not found." });
      const match = await bcrypt.compare(password, row.password);
      if (!match) return res.status(401).json({ status: "error", message: "Invalid password." });

      // Update HWID and IP if changed
      db.run("UPDATE users SET hwid=?, ip=? WHERE username=?", [hwid, ip, username], (err2) => {
        if (err2) return res.status(500).json({ status: "error", message: "DB update error." });

        logEvent(`User logged in: ${username} (HWID: ${hwid}, IP: ${ip})`);
        res.json({ status: "ok", message: "Registered and authenticated." });
      });
    });
  });
});

// Logs API for notifications polling
app.get('/api/logs', requireLogin, (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    if (err) return res.send('');
    res.set('Content-Type', 'text/plain');
    res.send(data);
  });
});

// Notifications page with auto beep on new logs
app.get('/notifications', requireLogin, (req, res) => {
  const beepBase64 = 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAIlYAAESsAAACABAAZGF0YQAAAAA='; // tiny silent beep

  const content = `
    <h2>Notifications Log</h2>
    <pre id="logContent"></pre>
    <a href="/">Back</a>
    <script>
      const logEl = document.getElementById('logContent');
      const beep = new Audio('${beepBase64}');
      let lastLength = 0;

      async function pollLogs() {
        try {
          const res = await fetch('/api/logs');
          const text = await res.text();
          if (text.length > lastLength) {
            beep.play().catch(() => {});
            logEl.textContent = text;
            logEl.scrollTop = logEl.scrollHeight;
            lastLength = text.length;
          }
        } catch (e) {
          console.error('Fetch logs error:', e);
        }
        setTimeout(pollLogs, 10000);
      }
      pollLogs();
    </script>
  `;

  res.send(renderPage('Notifications', content));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
