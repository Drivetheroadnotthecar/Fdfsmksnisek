// FULL AUTH SERVER with locked_hwid support and SQLite auto-migration

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 8481;
const DB_FILE = 'users.db';

// Setup middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: 'super_secret_key',
    resave: false,
    saveUninitialized: true
}));

// Init DB
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        hwid TEXT,
        ip TEXT,
        banned INTEGER DEFAULT 0,
        notes TEXT,
        locked_hwid TEXT
    )`);
});

// Auto-migration to add missing column
function ensureColumnExists(columnName, columnType) {
    db.all("PRAGMA table_info(users)", [], (err, columns) => {
        if (err) return console.error(err);
        const exists = columns.some(col => col.name === columnName);
        if (!exists) {
            db.run(`ALTER TABLE users ADD COLUMN ${columnName} ${columnType}`);
            console.log(`✅ Added column: ${columnName}`);
        }
    });
}

ensureColumnExists('locked_hwid', 'TEXT');

// API routes
app.post('/register', async (req, res) => {
    const { username, password, hwid } = req.body;
    if (!username || !password || !hwid) return res.json({ status: 'error', message: 'Missing fields.' });

    const hash = await bcrypt.hash(password, 10);
    const ip = req.ip;

    db.run("INSERT INTO users (username, password, hwid, ip, locked_hwid) VALUES (?, ?, ?, ?, ?)",
        [username, hash, hwid, ip, hwid],
        err => {
            if (err) return res.json({ status: 'error', message: 'Username taken or database error.' });
            res.json({ status: 'success', message: 'User registered.' });
        });
});

app.post('/login-user', async (req, res) => {
    const { username, password, hwid } = req.body;
    if (!username || !password || !hwid) return res.json({ status: 'error', message: 'Missing fields.' });

    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.json({ status: 'error', message: 'User not found.' });
        if (user.banned) return res.json({ status: 'error', message: 'You are banned.' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.json({ status: 'error', message: 'Invalid password.' });

        if (user.locked_hwid && user.locked_hwid !== hwid) {
            return res.json({ status: 'error', message: 'HWID mismatch. You may be banned.' });
        }

        db.run("UPDATE users SET hwid = ?, ip = ?, locked_hwid = ? WHERE username = ?",
            [hwid, req.ip, hwid, username]);

        res.json({ status: 'success', message: 'Login successful.' });
    });
});

app.post('/ban-user', (req, res) => {
    const { username, reason } = req.body;
    if (!username) return res.json({ status: 'error', message: 'Missing username.' });

    db.run("UPDATE users SET banned = 1, notes = ? WHERE username = ?", [reason || 'Manual ban', username], err => {
        if (err) return res.json({ status: 'error', message: 'Failed to ban.' });
        res.json({ status: 'success', message: 'User banned.' });
    });
});

app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});