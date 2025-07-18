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

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: 'super_secret_key',
  resave: false,
  saveUninitialized: true
}));

// DB Init + migrate locked_hwid column
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

  db.all("PRAGMA table_info(users)", [], (err, cols) => {
    if (err) return console.error(err);
    if (!cols.find(c => c.name === 'locked_hwid')) {
      db.run("ALTER TABLE users ADD COLUMN locked_hwid TEXT", () => {
        console.log("✅ Added 'locked_hwid' column");
      });
    }
  });
});

// Utilities

function escapeHtml(text) {
  return (text || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

function logEvent(text) {
  const time = new Date().toISOString();
  fs.appendFileSync(LOG_FILE, `[${time}] ${text}\n`);
}

function requireLogin(req, res, next) {
  if (!req.session.loggedIn) return res.redirect('/login');
  next();
}

function renderPage(title, content, extraScripts = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${escapeHtml(title)}</title>
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
  a { color: #ff4c4c; text-decoration: none; }
  a:hover { text-decoration: underline; }
  h2 { text-align: center; margin-top: 1em; text-shadow: 0 0 5px #ff1a1a; }
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
</html>`;
}

// === Admin Routes ===

// Login Page
app.get('/login', (req, res) => {
  res.send(renderPage("Dev Login", `
    <h2>Dev Login</h2>
    <form method="POST" action="/login">
      <input name="password" type="password" placeholder="Dev Password" required />
      <button type="submit">Login</button>
    </form>
  `));
});

app.post('/login', (req, res) => {
  if (req.body.password === DEV_PASSWORD) {
    req.session.loggedIn = true;
    res.redirect('/');
  } else {
    res.send(renderPage("Dev Login", `
      <p style="color:#f00;text-align:center;">Wrong password.</p>
      <a href="/login">Try again</a>
    `));
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Admin panel home
app.get('/', requireLogin, (req, res) => {
  res.send(renderPage("Admin Panel", `
    <h2>Admin Panel</h2>
    <form method="POST" action="/create-user">
      <input name="username" placeholder="Username" required />
      <input name="password" placeholder="Password" required />
      <input name="note" placeholder="Note (optional)" />
      <button>Create User</button>
    </form><br>

    <form method="POST" action="/ban-user">
      <input name="username" placeholder="Username to Ban" required />
      <button>Ban</button>
    </form><br>

    <form method="POST" action="/unban-user">
      <input name="username" placeholder="Username to Unban" required />
      <button>Unban</button>
    </form><br>

    <form method="POST" action="/delete-user">
      <input name="username" placeholder="Username to Delete" required />
      <button>Delete</button>
    </form><br>

    <a href="/users">View Users</a><br>
    <a href="/notifications">Notifications</a><br>
    <a href="/logout">Logout</a>
  `));
});

// View users with search filter
app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err) return res.status(500).send("DB error");

    let html = `
      <h2>Users</h2>
      <input type="text" id="searchInput" placeholder="Search users by username, status, note..." autocomplete="off" />
      <div class="users-table-container table-wrapper">
      <table border="1" id="usersTable">
        <thead>
          <tr>
            <th>Username</th><th>Status</th><th>HWID</th><th>IP</th><th>Note</th><th>Locked HWID</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
    `;

    rows.forEach(u => {
      html += `<tr>
        <td>${escapeHtml(u.username)}</td>
        <td>${escapeHtml(u.status)}</td>
        <td>${escapeHtml(u.hwid || 'N/A')}</td>
        <td>${escapeHtml(u.ip || 'N/A')}</td>
        <td>${escapeHtml(u.note || '')}</td>
        <td>${escapeHtml(u.locked_hwid || 'None')}</td>
        <td>
          <form method="POST" action="/reset-password" style="display:inline">
            <input type="hidden" name="username" value="${escapeHtml(u.username)}" />
            <input type="password" name="newpass" placeholder="New Pass" required />
            <button>Reset Password</button>
          </form>
          <form method="POST" action="/lock-account" style="display:inline">
            <input type="hidden" name="username" value="${escapeHtml(u.username)}" />
            <button>Lock Account</button>
          </form>
        </td>
      </tr>`;
    });

    html += `</tbody></table></div><br><a href="/">Back</a>`;

    const script = `
<script>
  const searchInput = document.getElementById('searchInput');
  const tbody = document.getElementById('usersTable').getElementsByTagName('tbody')[0];

  searchInput.addEventListener('input', () => {
    const filter = searchInput.value.toLowerCase();
    for (let row of tbody.rows) {
      const text = row.innerText.toLowerCase();
      row.style.display = text.includes(filter) ? '' : 'none';
    }
  });
</script>`;

    res.send(renderPage("Users", html, script));
  });
});

// Admin actions

app.post('/create-user', requireLogin, async (req, res) => {
  const { username, password, note = '' } = req.body;
  if (!username || !password) return res.send("Missing fields.");

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    db.run(`
      INSERT INTO users (username, password, note)
      VALUES (?, ?, ?)
      ON CONFLICT(username) DO UPDATE SET password=excluded.password, note=excluded.note
    `, [username, hash, note], (err) => {
      if (err) return res.send("DB error.");
      res.redirect('/');
    });
  } catch {
    res.send("Server error.");
  }
});

app.post('/ban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='banned' WHERE username=?", [username], (err) => {
    if (!err) logEvent(`User ${username} was banned.`);
    res.redirect('/');
  });
});

app.post('/unban-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("UPDATE users SET status='active' WHERE username=?", [username], () => res.redirect('/'));
});

app.post('/delete-user', requireLogin, (req, res) => {
  const { username } = req.body;
  db.run("DELETE FROM users WHERE username=?", [username], () => res.redirect('/'));
});

app.post('/reset-password', requireLogin, async (req, res) => {
  const { username, newpass } = req.body;
  if (!newpass) return res.send("Missing new password.");

  try {
    const hash = await bcrypt.hash(newpass, SALT_ROUNDS);
    db.run("UPDATE users SET password=? WHERE username=?", [hash, username], () => res.redirect('/users'));
  } catch {
    res.send("Server error.");
  }
});

app.post('/lock-account', requireLogin, (req, res) => {
  const { username } = req.body;
  db.get("SELECT hwid FROM users WHERE username=?", [username], (err, row) => {
    if (err || !row || !row.hwid) return res.send("Cannot lock account: No HWID found.");

    db.run("UPDATE users SET locked_hwid=? WHERE username=?", [row.hwid, username], (err2) => {
      if (!err2) logEvent(`Account ${username} locked to HWID ${row.hwid}`);
      res.redirect('/users');
    });
  });
});

// Notifications with live polling and clear logs
app.get('/notifications', requireLogin, (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    const logs = err ? "No logs yet." : escapeHtml(data);

    const html = `
      <h2>Notifications Log</h2>
      <pre id="logContent">${logs}</pre>
      <form method="POST" action="/clear-logs" style="text-align:center; margin-top: 1em;">
        <button type="submit">Clear Logs</button>
      </form>
      <button id="toggleSoundBtn" style="margin-top:1em; background:#ff1a1a; color:#000; border:none; padding:10px; border-radius:8px; cursor:pointer;">Enable Sound</button>
    `;

    const script = `
<script>
  const logContent = document.getElementById('logContent');
  const toggleSoundBtn = document.getElementById('toggleSoundBtn');
  let soundEnabled = false;
  let lastLength = logContent.textContent.length;
  const beep = new Audio('data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEAIlYAAESsAAACABAAZGF0YQAAAAA=');

  toggleSoundBtn.onclick = () => {
    soundEnabled = !soundEnabled;
    toggleSoundBtn.textContent = soundEnabled ? 'Disable Sound' : 'Enable Sound';
  };

  async function pollLogs() {
    try {
      const res = await fetch('/api/logs');
      const text = await res.text();
      if (text.length > lastLength && soundEnabled) beep.play();
      lastLength = text.length;
      logContent.textContent = text;
      logContent.scrollTop = logContent.scrollHeight;
    } catch {}
    setTimeout(pollLogs, 2000);
  }

  pollLogs();
</script>`;

    res.send(renderPage("Notifications", html, script));
  });
});

app.post('/clear-logs', requireLogin, (req, res) => {
  fs.writeFile(LOG_FILE, '', (err) => {
    if (err) return res.send("Error clearing logs.");
    res.redirect('/notifications');
  });
});

// API route to fetch logs for polling
app.get('/api/logs', requireLogin, (req, res) => {
  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    res.type('text/plain').send(err ? "No logs." : data);
  });
});

// === API Routes ===

// Register API
app.post('/api/register', async (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) return res.json({ status: 'error', message: 'Missing fields.' });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, row) => {
    if (err) return res.json({ status: 'error', message: 'DB error.' });
    if (row) return res.json({ status: 'error', message: 'User already exists.' });

    try {
      const hash = await bcrypt.hash(password, SALT_ROUNDS);
      const ip = req.ip.replace(/^::ffff:/, '');

      db.run("INSERT INTO users (username, password, hwid, ip) VALUES (?, ?, ?, ?)", [username, hash, hwid, ip], (err2) => {
        if (err2) return res.json({ status: 'error', message: 'DB error inserting.' });
        logEvent(`New user registered: ${username} from IP ${ip} with HWID ${hwid}`);
        res.json({ status: 'success', message: 'Registered.' });
      });
    } catch {
      res.json({ status: 'error', message: 'Server error.' });
    }
  });
});

// Login API
app.post('/api/login', (req, res) => {
  const { username, password, hwid } = req.body;
  if (!username || !password || !hwid) return res.json({ status: 'error', message: 'Missing fields.' });

  db.get("SELECT * FROM users WHERE username=?", [username], async (err, user) => {
    if (err) return res.json({ status: 'error', message: 'DB error.' });
    if (!user) return res.json({ status: 'error', message: 'Invalid username or password.' });
    if (user.status === 'banned') return res.json({ status: 'error', message: 'User banned.' });

    try {
      const passMatch = await bcrypt.compare(password, user.password);
      if (!passMatch) return res.json({ status: 'error', message: 'Invalid username or password.' });

      const ip = req.ip.replace(/^::ffff:/, '');

      // HWID checks
      if (user.locked_hwid && user.locked_hwid !== hwid) {
        return res.json({ status: 'error', message: 'Account locked to different HWID.' });
      }

      // Track HWID changes (allow max 2 HWIDs)
      let hwids = (user.hwid || '').split(',');
      if (!hwids.includes(hwid)) {
        hwids.push(hwid);
      }
      if (hwids.length > 2) {
        db.run("UPDATE users SET status='banned' WHERE username=?", [username]);
        logEvent(`User ${username} auto-banned for exceeding HWID limit.`);
        return res.json({ status: 'error', message: 'User banned for HWID abuse.' });
      }

      db.run("UPDATE users SET hwid=?, ip=? WHERE username=?", [hwids.join(','), ip, username]);
      logEvent(`User ${username} logged in from IP ${ip} with HWID ${hwid}`);

      res.json({ status: 'success', message: 'Logged in.' });
    } catch {
      res.json({ status: 'error', message: 'Server error.' });
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server listening at http://0.0.0.0:${PORT}`);
});
