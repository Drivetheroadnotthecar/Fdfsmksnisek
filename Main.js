const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

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

// DB Init
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
      locked_hwid TEXT,
      ban_reason TEXT
    )
  `);

  db.all("PRAGMA table_info(users)", [], (err, columns) => {
    if (err) return console.error(err);
    if (!columns.some(col => col.name === "locked_hwid")) {
      db.run("ALTER TABLE users ADD COLUMN locked_hwid TEXT");
    }
    if (!columns.some(col => col.name === "ban_reason")) {
      db.run("ALTER TABLE users ADD COLUMN ban_reason TEXT");
    }
  });
});

// Helpers
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

function renderPage(title, content) {
  return `<!DOCTYPE html>
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
    max-width: 850px;
    background: #1a0000;
    padding: 15px 25px;
    border-radius: 15px;
    border: 3px solid #ff1a1a;
    box-shadow: 0 0 12px #ff0000cc;
    position: relative;
  }
  form button, button {
    background-color: #ff1a1a;
    border: none;
    color: #000;
    font-weight: bold;
    padding: 10px 18px;
    margin-left: 10px;
    border-radius: 12px;
    cursor: pointer;
    transition: background-color 0.3s ease;
  }
  form button:hover, button:hover {
    background-color: #ff4c4c;
  }
  input, select {
    font-family: 'Courier New', monospace;
    font-size: 16px;
    padding: 10px;
    border-radius: 12px;
    border: 2px solid #ff1a1a;
    width: 250px;
    margin-right: 10px;
    background-color: #330000;
    color: #ff9999;
  }
  input.search {
    width: 400px;
  }
  table {
    border-collapse: collapse;
    width: 100%;
  }
  th, td {
    border: 2px solid #ff1a1a;
    padding: 10px 14px;
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
    border-radius: 15px;
    max-width: 95vw;
    margin: 1em auto;
    font-family: 'Courier New', monospace;
  }
  .vine-container {
    position: relative;
    padding: 35px 40px;
    border: 5px solid #ff1a1a;
    border-radius: 25px;
    max-width: 1100px;
    margin: 1.5em auto 2.5em auto;
    box-shadow: 0 0 20px #ff0000cc;
    background-color: rgba(26,0,0,0.9);
  }
  .vine-container::before, .vine-container::after {
    content: "";
    position: absolute;
    border: 3px solid transparent;
    pointer-events: none;
  }
  .vine-container::before {
    top: -30px;
    left: -30px;
    width: 90px;
    height: 90px;
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
    bottom: -30px;
    right: -30px;
    width: 90px;
    height: 90px;
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
    max-height: 65vh;
    overflow-y: auto;
    margin-top: 1em;
  }
  .table-wrapper {
    overflow-x: auto;
  }
  /* Autocomplete dropdown */
  .autocomplete-items {
    position: absolute;
    border: 1px solid #ff1a1a;
    border-bottom: none;
    border-top: none;
    z-index: 99;
    top: 48px;
    left: 0;
    right: 0;
    background-color: #1a0000;
    max-height: 180px;
    overflow-y: auto;
    border-radius: 0 0 10px 10px;
  }
  .autocomplete-items div {
    padding: 8px 10px;
    cursor: pointer;
    color: #ff4c4c;
  }
  .autocomplete-items div:hover {
    background-color: #ff1a1a;
    color: #000;
  }
  /* Responsive */
  @media (max-width: 900px) {
    form, .vine-container {
      max-width: 95vw;
      padding: 20px;
    }
    input, input.search {
      width: 100%;
      margin-bottom: 10px;
    }
    form button, button {
      width: 100%;
      margin: 8px 0 0 0;
    }
    td, th {
      font-size: 14px;
      padding: 8px;
    }
  }
</style>
</head>
<body>
  <div class="vine-container">
  ${content}
  </div>
<script>
  function autocomplete(inp, arr) {
    let currentFocus;
    inp.addEventListener("input", function() {
      const val = this.value;
      closeAllLists();
      if (!val) { return false;}
      currentFocus = -1;
      const list = document.createElement("DIV");
      list.setAttribute("id", this.id + "autocomplete-list");
      list.setAttribute("class", "autocomplete-items");
      this.parentNode.appendChild(list);
      for (let i = 0; i < arr.length; i++) {
        if (arr[i].substr(0, val.length).toUpperCase() === val.toUpperCase()) {
          const item = document.createElement("DIV");
          item.innerHTML = "<strong>" + arr[i].substr(0, val.length) + "</strong>";
          item.innerHTML += arr[i].substr(val.length);
          item.innerHTML += "<input type='hidden' value='" + arr[i] + "'>";
          item.addEventListener("click", function() {
            inp.value = this.getElementsByTagName("input")[0].value;
            closeAllLists();
            document.getElementById('searchForm').submit();
          });
          list.appendChild(item);
        }
      }
    });
    inp.addEventListener("keydown", function(e) {
      let list = document.getElementById(this.id + "autocomplete-list");
      if (list) list = list.getElementsByTagName("div");
      if (e.keyCode === 40) {
        currentFocus++;
        addActive(list);
      } else if (e.keyCode === 38) {
        currentFocus--;
        addActive(list);
      } else if (e.keyCode === 13) {
        e.preventDefault();
        if (currentFocus > -1) {
          if (list) list[currentFocus].click();
        }
      }
    });
    function addActive(list) {
      if (!list) return false;
      removeActive(list);
      if (currentFocus >= list.length) currentFocus = 0;
      if (currentFocus < 0) currentFocus = (list.length - 1);
      list[currentFocus].classList.add("autocomplete-active");
    }
    function removeActive(list) {
      for (let i = 0; i < list.length; i++) {
        list[i].classList.remove("autocomplete-active");
      }
    }
    function closeAllLists(elmnt) {
      const items = document.getElementsByClassName("autocomplete-items");
      for (let i = 0; i < items.length; i++) {
        if (elmnt !== items[i] && elmnt !== inp) {
          items[i].parentNode.removeChild(items[i]);
        }
      }
    }
    document.addEventListener("click", function (e) {
      closeAllLists(e.target);
    });
  }
</script>
</body>
</html>`;
}

// === Admin Routes ===

// Login page
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
    res.send(renderPage("Dev Login", '<p>Wrong password.</p><a href="/login">Try again</a>'));
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Home page with create user form, banned users link, and search bar with autocomplete
app.get('/', requireLogin, (req, res) => {
  db.all("SELECT username FROM users", [], (err, rows) => {
    if (err) rows = [];
    const usernames = rows.map(r => r.username);
    res.send(renderPage("Admin Panel", `
      <h2>Admin Panel</h2>

      <form method="POST" action="/create-user" style="margin-bottom: 2em;">
        <input name="username" placeholder="Username" required>
        <input name="password" placeholder="Password" required>
        <button>Create / Update User</button>
      </form>

      <form id="searchForm" method="GET" action="/search-user" autocomplete="off" style="position: relative; margin-bottom: 2em;">
        <input id="searchInput" class="search" type="text" name="username" placeholder="Search Username..." required>
        <button type="submit">Search User</button>
      </form>

      <button onclick="window.location.href='/banned-users'" style="margin-bottom: 1.5em;">View Banned Users</button>
      <button onclick="window.location.href='/users'">View All Users</button>

      <script>autocomplete(document.getElementById('searchInput'), ${JSON.stringify(usernames)});</script>
    `));
  });
});

// Create or update user
app.post('/create-user', requireLogin, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.send("Missing fields.");
  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  db.run(`
    INSERT INTO users (username, password)
    VALUES (?, ?)
    ON CONFLICT(username) DO UPDATE SET password=excluded.password
  `, [username, hash], err => {
    if (err) return res.send("DB error.");
    res.redirect('/');
  });
});

// Users page: list all users with action button to view details
app.get('/users', requireLogin, (req, res) => {
  db.all("SELECT username, status, hwid, ip, note, locked_hwid FROM users ORDER BY username COLLATE NOCASE ASC", [], (err, rows) => {
    if (err) return res.status(500).send("DB Error");
    let html = `
      <h2>Users</h2>
      <div class="users-table-container table-wrapper">
      <table border="1">
        <thead>
          <tr>
            <th>Username</th><th>Status</th><th>HWID</th><th>IP</th><th>Note</th><th>Locked HWID</th><th>Actions</th>
          </tr>
        </thead><tbody>
    `;
    rows.forEach(u => {
      html += `<tr>
        <td>${escape(u.username)}</td>
        <td>${escape(u.status)}</td>
        <td>${escape(u.hwid || 'N/A')}</td>
        <td>${escape(u.ip || 'N/A')}</td>
        <td>${escape(u.note || '')}</td>
        <td>${escape(u.locked_hwid || 'None')}</td>
        <td>
          <button onclick="window.location.href='/user-detail?search=${encodeURIComponent(u.username)}'">Details</button>
        </td>
      </tr>`;
    });
    html += `</tbody></table></div><br><button onclick="window.location.href='/'">Back to Home</button>`;
    res.send(renderPage("Users List", html));
  });
});

// User detail page: Search by username/HWID/IP & actions (lock/unlock/ban/unban/reset password)
app.get('/user-detail', requireLogin, (req, res) => {
  const search = (req.query.search || '').trim();
  if (!search) {
    return res.send(renderPage("User Detail Search", `
      <h2>Search User by Username, HWID or IP</h2>
      <form method="GET">
        <input name="search" placeholder="Enter username, HWID, or IP" required>
        <button>Search</button>
      </form>
      <br><button onclick="window.location.href='/users'">Back to Users</button>
    `));
  }
  // Search user by username OR hwid OR ip
  db.get(`SELECT * FROM users WHERE username = ? OR hwid = ? OR ip = ? COLLATE NOCASE`, [search, search, search], (err, user) => {
    if (err) return res.send(renderPage("Error", "DB Error."));
    if (!user) {
      return res.send(renderPage("User Not Found", `
        <h2>No user found for "${escape(search)}"</h2>
        <button onclick="window.location.href='/user-detail'">Search Again</button>
        <button onclick="window.location.href='/users'">Back to Users</button>
      `));
    }

    // Render user info & actions
    res.send(renderPage(`User Detail - ${escape(user.username)}`, `
      <h2>User Detail: ${escape(user.username)}</h2>
      <pre>
Username: ${escape(user.username)}
Status: ${escape(user.status)}
HWID: ${escape(user.hwid || 'N/A')}
IP: ${escape(user.ip || 'N/A')}
Note: ${escape(user.note || '')}
Locked HWID: ${escape(user.locked_hwid || 'None')}
Ban Reason: ${escape(user.ban_reason || 'None')}
Password Hash: ${escape(user.password)}
      </pre>

      <form method="POST" action="/user-action" style="margin-top: 1em;">
        <input type="hidden" name="username" value="${escape(user.username)}">
        
        <label>
          Lock HWID to:
          <input name="lock_hwid" placeholder="Enter HWID to lock" value="${escape(user.locked_hwid || '')}">
          <button type="submit" name="action" value="lock-hwid">Lock HWID</button>
        </label>
      </form>
      <form method="POST" action="/user-action" style="margin-top: 1em;">
        <input type="hidden" name="username" value="${escape(user.username)}">
        <button type="submit" name="action" value="unlock-hwid">Unlock HWID</button>
      </form>
      <form method="POST" action="/user-action" style="margin-top: 1em;">
        <input type="hidden" name="username" value="${escape(user.username)}">
        <label>
          Ban Reason (leave blank to clear):
          <input name="ban_reason" placeholder="Reason for ban" value="${escape(user.ban_reason || '')}">
          <button type="submit" name="action" value="ban">Ban User</button>
        </label>
      </form>
      <form method="POST" action="/user-action" style="margin-top: 1em;">
        <input type="hidden" name="username" value="${escape(user.username)}">
        <button type="submit" name="action" value="unban">Unban User</button>
      </form>
      <form method="POST" action="/user-action" style="margin-top: 1em;">
        <input type="hidden" name="username" value="${escape(user.username)}">
        <label>
          Reset Password:
          <input name="new_password" placeholder="New password">
          <button type="submit" name="action" value="reset-password">Reset Password</button>
        </label>
      </form>

      <br><button onclick="window.location.href='/users'">Back to Users</button>
      <button onclick="window.location.href='/'">Back to Home</button>
    `));
  });
});

// User action handler
app.post('/user-action', requireLogin, async (req, res) => {
  const { username, action, lock_hwid, ban_reason, new_password } = req.body;
  if (!username || !action) return res.send("Missing fields.");

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.send("User not found.");

    switch(action) {
      case 'lock-hwid':
        if (!lock_hwid) return res.send("Missing HWID to lock.");
        db.run("UPDATE users SET locked_hwid = ? WHERE username = ?", [lock_hwid.trim(), username], (e) => {
          if (e) return res.send("DB error locking HWID.");
          logEvent(`HWID locked for user ${username} to ${lock_hwid.trim()}`);
          res.redirect(`/user-detail?search=${encodeURIComponent(username)}`);
        });
        break;
      case 'unlock-hwid':
        db.run("UPDATE users SET locked_hwid = NULL WHERE username = ?", [username], (e) => {
          if (e) return res.send("DB error unlocking HWID.");
          logEvent(`HWID unlocked for user ${username}`);
          res.redirect(`/user-detail?search=${encodeURIComponent(username)}`);
        });
        break;
      case 'ban':
        db.run("UPDATE users SET status = 'banned', ban_reason = ? WHERE username = ?", [ban_reason ? ban_reason.trim() : 'No reason given', username], (e) => {
          if (e) return res.send("DB error banning user.");
          logEvent(`User banned: ${username} Reason: ${ban_reason || 'No reason given'}`);
          res.redirect(`/user-detail?search=${encodeURIComponent(username)}`);
        });
        break;
      case 'unban':
        db.run("UPDATE users SET status = 'active', ban_reason = NULL WHERE username = ?", [username], (e) => {
          if (e) return res.send("DB error unbanning user.");
          logEvent(`User unbanned: ${username}`);
          res.redirect(`/user-detail?search=${encodeURIComponent(username)}`);
        });
        break;
      case 'reset-password':
        if (!new_password) return res.send("Missing new password.");
        const hash = await bcrypt.hash(new_password, SALT_ROUNDS);
        db.run("UPDATE users SET password = ? WHERE username = ?", [hash, username], (e) => {
          if (e) return res.send("DB error resetting password.");
          logEvent(`Password reset for user ${username}`);
          res.redirect(`/user-detail?search=${encodeURIComponent(username)}`);
        });
        break;
      default:
        res.send("Unknown action.");
    }
  });
});

// Banned users page: list banned users with unban buttons
app.get('/banned-users', requireLogin, (req, res) => {
  db.all("SELECT username, ban_reason FROM users WHERE status = 'banned' ORDER BY username COLLATE NOCASE ASC", [], (err, rows) => {
    if (err) return res.send("DB error.");
    let html = `
      <h2>Banned Users</h2>
      <div class="users-table-container table-wrapper">
      <table border="1">
        <thead><tr><th>Username</th><th>Ban Reason</th><th>Actions</th></tr></thead><tbody>
    `;
    rows.forEach(u => {
      html += `<tr>
        <td>${escape(u.username)}</td>
        <td>${escape(u.ban_reason || '')}</td>
        <td>
          <form method="POST" action="/user-action" style="margin:0;">
            <input type="hidden" name="username" value="${escape(u.username)}">
            <button type="submit" name="action" value="unban">Unban</button>
          </form>
        </td>
      </tr>`;
    });
    html += `</tbody></table></div><br><button onclick="window.location.href='/'">Back to Home</button>`;
    res.send(renderPage("Banned Users", html));
  });
});

// Logs page: show logs with clear button
app.get('/logs', requireLogin, (req, res) => {
  let logs = "";
  try {
    logs = fs.readFileSync(LOG_FILE, 'utf8');
  } catch {
    logs = "No logs found.";
  }
  res.send(renderPage("Logs", `
    <h2>Logs</h2>
    <pre>${escape(logs)}</pre>
    <form method="POST" action="/clear-logs" style="text-align:center;">
      <button type="submit">Clear Logs</button>
    </form>
    <button onclick="window.location.href='/'" style="margin-top: 1em;">Back to Home</button>
  `));
});
app.post('/clear-logs', requireLogin, (req, res) => {
  fs.writeFileSync(LOG_FILE, '');
  res.redirect('/logs');
});

// Start server
app.listen(PORT, () => {
  console.log(`Admin panel running on http://localhost:${PORT}`);
});
