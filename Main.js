const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const path = require('path');

const app = express();
const PORT = 8481;
const DEV_PASSWORD = 'DivinedCreationInc2990!!@!!';
const DB_FILE = 'users.db';

const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
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
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'super_secret_key',
    resave: false,
    saveUninitialized: true
}));

const loginTemplate = `
<!DOCTYPE html>
<html><head><title>Dev Login</title></head><body>
<h2>Developer Access</h2>
<form method="POST" action="/login">
    <input name="password" type="password" placeholder="Enter Dev Password" required autofocus>
    <button type="submit">Enter</button>
</form>
<% if (error) { %><p style="color:red"><%= error %></p><% } %>
</body></html>
`;

const adminTemplate = `
<!DOCTYPE html>
<html><head><title>Admin Panel</title></head><body>
<form action="/logout" method="get" style="float:right;"><button type="submit">Logout</button></form>
<h2>Admin Panel</h2>
<form method="POST" action="/create-user">
    <input name="username" placeholder="Username" required>
    <input name="password" placeholder="Password" required>
    <input name="note" placeholder="Note (optional)">
    <button type="submit">Create User</button>
</form><br>
<form method="POST" action="/ban-user">
    <input name="username" placeholder="Username to Ban" required>
    <button type="submit">Ban User</button>
</form><br>
<form method="POST" action="/unban-user">
    <input name="username" placeholder="Username to Unban" required>
    <button type="submit">Unban User</button>
</form><br>
<a href="/all-users">View All Users</a>
</body></html>
`;

function render(html, params = {}) {
    return html.replace(/<%=(.*?)%>/g, (_, key) => params[key.trim()] || '')
               .replace(/<% if \((.*?)\) { %>(.*?)<% } %>/gs, (_, condition, content) => {
                   return params[condition.trim()] ? content : '';
               });
}

function loginRequired(req, res, next) {
    if (!req.session.loggedIn) return res.redirect('/login');
    next();
}

app.get('/login', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/');
    res.send(render(loginTemplate));
});

app.post('/login', (req, res) => {
    if (req.body.password === DEV_PASSWORD) {
        req.session.loggedIn = true;
        return res.redirect('/');
    }
    res.send(render(loginTemplate, { error: "Wrong dev password" }));
});

app.get('/logout', loginRequired, (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

app.get('/', loginRequired, (req, res) => {
    res.send(adminTemplate);
});

app.post('/create-user', loginRequired, (req, res) => {
    const { username, password, note = '' } = req.body;
    db.run("INSERT OR REPLACE INTO users (username, password, note) VALUES (?, ?, ?)", [username, password, note]);
    res.redirect('/');
});

app.post('/ban-user', loginRequired, (req, res) => {
    const { username } = req.body;
    db.get("SELECT hwid, ip FROM users WHERE username=?", [username], (err, row) => {
        if (row) {
            if (row.hwid) db.run("UPDATE users SET status='banned' WHERE hwid=?", [row.hwid]);
            if (row.ip) db.run("UPDATE users SET status='banned' WHERE ip=?", [row.ip]);
        }
        db.run("UPDATE users SET status='banned' WHERE username=?", [username]);
        res.redirect('/');
    });
});

app.post('/unban-user', loginRequired, (req, res) => {
    const { username } = req.body;
    db.get("SELECT hwid, ip FROM users WHERE username=?", [username], (err, row) => {
        if (row) {
            if (row.hwid) db.run("UPDATE users SET status='active' WHERE hwid=?", [row.hwid]);
            if (row.ip) db.run("UPDATE users SET status='active' WHERE ip=?", [row.ip]);
        }
        db.run("UPDATE users SET status='active' WHERE username=?", [username]);
        res.redirect('/');
    });
});

app.get('/all-users', loginRequired, (req, res) => {
    db.all("SELECT username, password, hwid, ip, status, note FROM users", (err, rows) => {
        let html = `<h2>Registered Users</h2><table border="1"><tr><th>Username</th><th>Password</th><th>HWID</th><th>IP</th><th>Status</th><th>Note</th></tr>`;
        rows.forEach(r => {
            html += `<tr><td>${r.username}</td><td>${r.password}</td><td>${r.hwid || 'N/A'}</td><td>${r.ip || 'N/A'}</td><td>${r.status}</td><td>${r.note || ''}</td></tr>`;
        });
        html += "</table><br><a href='/'>Back to Admin</a>";
        res.send(html);
    });
});

app.post('/register', (req, res) => {
    const { username, password, hwid } = req.body;
    const ip = req.ip;
    db.get("SELECT status FROM users WHERE username=?", [username], (err, row) => {
        if (row && row.status === "banned") return res.status(403).json({ status: "error", message: "You are banned." });
        db.run("INSERT OR REPLACE INTO users (username, password, hwid, ip) VALUES (?, ?, ?, ?)",
            [username, password, hwid, ip]);
        res.json({ status: "success", message: "Registered successfully." });
    });
});

app.post('/login-user', (req, res) => {
    const { username, password, hwid } = req.body;
    const ip = req.ip;
    db.get("SELECT password, hwid, ip, status FROM users WHERE username=?", [username], (err, row) => {
        if (!row) return res.status(403).json({ status: "error", message: "Invalid credentials." });
        if (row.status === "banned") return res.status(403).json({ status: "error", message: "User is banned." });
        if (row.password === password && (row.hwid === hwid || !row.hwid || row.ip === ip)) {
            if (row.ip !== ip) db.run("UPDATE users SET ip=? WHERE username=?", [ip, username]);
            return res.json({ status: "success", message: "Login successful." });
        }
        return res.status(403).json({ status: "error", message: "Invalid credentials or HWID/IP mismatch." });
    });
});

// 🔥 Important: bind to 0.0.0.0 so external traffic works
app.listen(PORT, '0.0.0.0', () => console.log(`✅ Server running at http://0.0.0.0:${PORT}`));
