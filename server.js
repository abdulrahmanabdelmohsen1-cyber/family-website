require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'family.sqlite'));
db.pragma('journal_mode = WAL'); db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE NOT NULL, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('admin','member')), created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, note TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS resets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, note TEXT DEFAULT '', status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL DEFAULT 'post', title TEXT NOT NULL, body TEXT NOT NULL, pinned INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, room TEXT NOT NULL DEFAULT 'family', body TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, details TEXT DEFAULT '', event_date TEXT NOT NULL, location TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS recipes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, ingredients TEXT NOT NULL, instructions TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, assigned_to TEXT DEFAULT '', due_date TEXT DEFAULT '', done INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS memories(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, story TEXT DEFAULT '', image_url TEXT DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS polls(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, question TEXT NOT NULL, options TEXT NOT NULL, votes TEXT DEFAULT '{}', created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
if (!db.prepare('SELECT id FROM users WHERE username=?').get(adminUsername)) {
  const initialPassword = process.env.ADMIN_PASSWORD || 'admin';
  db.prepare("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,'admin')")
    .run(adminUsername, 'Family Admin', bcrypt.hashSync(initialPassword, 12));
  console.log(`Initial administrator: ${adminUsername}. ${process.env.ADMIN_PASSWORD ? 'Password is from ADMIN_PASSWORD in .env.' : 'TEMPORARY PASSWORD IS admin — change it immediately.'}`);
}
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
const sessionSecret = process.env.SESSION_SECRET || 'development-only-change-this-secret-before-deployment';
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  name: 'family.sid', secret: sessionSecret, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Please wait 15 minutes and try again.' } });
const clean = v => typeof v === 'string' ? v.trim() : '';
const safeUser = u => ({ id: u.id, username: u.username, displayName: u.display_name, role: u.role, createdAt: u.created_at });
function auth(req, res, next) {
  if (!req.session.uid) return res.status(401).json({ error: 'Please sign in to access your family space.' });
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.session.uid);
  if (!user) { req.session.destroy(() => {}); return res.status(401).json({ error: 'Your session expired. Please sign in again.' }); }
  req.user = user; next();
}
function admin(req, res, next) { if (req.user.role !== 'admin') return res.status(403).json({ error: 'This feature is only available to the family administrator.' }); next(); }
app.get('/api/health', (req, res) => res.json({ ok: true }));
app.post('/api/login', loginLimiter, (req, res) => {
  const username = clean(req.body.username), password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Username or password is incorrect.' });
  req.session.regenerate(err => { if (err) return res.status(500).json({ error: 'Could not start a secure session.' }); req.session.uid = user.id; req.session.save(e => e ? res.status(500).json({ error: 'Could not save your session.' }) : res.json({ user: safeUser(user) })); });
});
app.get('/api/me', auth, (req, res) => res.json({ user: safeUser(req.user) }));
app.post('/api/logout', (req, res) => req.session.destroy(err => { res.clearCookie('family.sid'); if (err) return res.status(500).json({ error: 'Sign out failed.' }); res.json({ ok: true }); }));
app.post('/api/request-account', loginLimiter, (req, res) => {
  const username = clean(req.body.username), displayName = clean(req.body.displayName), password = String(req.body.password || ''), note = clean(req.body.note);
  if (username.length < 3 || username.length > 30 || !/^[a-zA-Z0-9_.-]+$/.test(username)) return res.status(400).json({ error: 'Username must be 3–30 characters and use letters, numbers, dots, dashes or underscores.' });
  if (displayName.length < 2 || displayName.length > 60 || password.length < 8) return res.status(400).json({ error: 'Enter your name and a password of at least 8 characters.' });
  if (db.prepare('SELECT id FROM users WHERE username=?').get(username) || db.prepare('SELECT id FROM requests WHERE username=? COLLATE NOCASE').get(username)) return res.status(409).json({ error: 'That username is already used or waiting for approval.' });
  db.prepare('INSERT INTO requests(username,display_name,password_hash,note) VALUES(?,?,?,?)').run(username, displayName, bcrypt.hashSync(password, 12), note.slice(0, 300));
  res.json({ ok: true, message: 'Your request has been sent to the family administrator for approval.' });
});
app.post('/api/request-reset', loginLimiter, (req, res) => {
  const username = clean(req.body.username), note = clean(req.body.note);
  const user = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (user) db.prepare('INSERT INTO resets(user_id,note) VALUES(?,?)').run(user.id, note.slice(0, 300));
  res.json({ ok: true, message: 'If that account exists, a password-reset request has been sent to the administrator.' });
});
app.post('/api/change-password', auth, (req, res) => {
  const oldPassword = String(req.body.oldPassword || ''), newPassword = String(req.body.newPassword || '');
  if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  if (!bcrypt.compareSync(oldPassword, req.user.password_hash)) return res.status(400).json({ error: 'Current password is incorrect.' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newPassword, 12), req.user.id); res.json({ ok: true });
});
app.get('/api/dashboard', auth, (req, res) => {
  const all = sql => db.prepare(sql).all();
  res.json({ user: safeUser(req.user), settings: Object.fromEntries(all('SELECT key,value FROM settings')),
    announcements: all("SELECT p.*,u.display_name AS author FROM posts p JOIN users u ON p.user_id=u.id WHERE p.kind='announcement' ORDER BY p.pinned DESC,p.id DESC LIMIT 40"),
    posts: all("SELECT p.*,u.display_name AS author FROM posts p JOIN users u ON p.user_id=u.id WHERE p.kind='post' ORDER BY p.id DESC LIMIT 40"),
    messages: all("SELECT m.*,u.display_name AS author FROM messages m JOIN users u ON m.user_id=u.id WHERE m.room='family' ORDER BY m.id DESC LIMIT 100").reverse(),
    events: all('SELECT e.*,u.display_name AS author FROM events e JOIN users u ON e.user_id=u.id ORDER BY e.event_date LIMIT 60'),
    recipes: all('SELECT r.*,u.display_name AS author FROM recipes r JOIN users u ON r.user_id=u.id ORDER BY r.id DESC LIMIT 60'),
    tasks: all('SELECT t.*,u.display_name AS author FROM tasks t JOIN users u ON t.user_id=u.id ORDER BY t.done,t.due_date LIMIT 100'),
    memories: all('SELECT m.*,u.display_name AS author FROM memories m JOIN users u ON m.user_id=u.id ORDER BY m.id DESC LIMIT 60'),
    polls: all('SELECT p.*,u.display_name AS author FROM polls p JOIN users u ON p.user_id=u.id ORDER BY p.id DESC LIMIT 30')
  });
});
app.post('/api/posts', auth, (req, res) => {
  const title = clean(req.body.title), body = clean(req.body.body), kind = req.body.kind === 'announcement' ? 'announcement' : 'post';
  if (!title || !body) return res.status(400).json({ error: 'A title and message are required.' });
  if (title.length > 120 || body.length > 5000) return res.status(400).json({ error: 'Title or message is too long.' });
  if (kind === 'announcement' && req.user.role !== 'admin') return res.status(403).json({ error: 'Only the admin can publish announcements.' });
  db.prepare('INSERT INTO posts(user_id,kind,title,body) VALUES(?,?,?,?)').run(req.user.id, kind, title, body); res.json({ ok: true });
});
app.post('/api/posts/:id/pin', auth, admin, (req, res) => { db.prepare('UPDATE posts SET pinned=1-pinned WHERE id=?').run(Number(req.params.id)); res.json({ ok: true }); });
app.delete('/api/posts/:id', auth, (req, res) => { const p = db.prepare('SELECT * FROM posts WHERE id=?').get(Number(req.params.id)); if (!p) return res.status(404).json({ error: 'Post not found.' }); if (req.user.role !== 'admin' && p.user_id !== req.user.id) return res.status(403).json({ error: 'You cannot delete this post.' }); db.prepare('DELETE FROM posts WHERE id=?').run(p.id); res.json({ ok: true }); });
app.post('/api/messages', auth, (req, res) => { const body = clean(req.body.body); if (!body || body.length > 3000) return res.status(400).json({ error: 'Message must be 1–3000 characters.' }); db.prepare("INSERT INTO messages(user_id,room,body) VALUES(?,'family',?)").run(req.user.id, body); res.json({ ok: true }); });
app.post('/api/events', auth, (req, res) => { const title = clean(req.body.title), date = clean(req.body.eventDate); if (!title || !/^\d{4}-\d{2}-\d{2}/.test(date)) return res.status(400).json({ error: 'Event title and valid date are required.' }); db.prepare('INSERT INTO events(user_id,title,details,event_date,location) VALUES(?,?,?,?,?)').run(req.user.id, title, clean(req.body.details), date, clean(req.body.location)); res.json({ ok: true }); });
app.post('/api/recipes', auth, (req, res) => { const title = clean(req.body.title), ingredients = clean(req.body.ingredients), instructions = clean(req.body.instructions); if (!title || !ingredients || !instructions) return res.status(400).json({ error: 'Fill in recipe name, ingredients and instructions.' }); db.prepare('INSERT INTO recipes(user_id,title,ingredients,instructions) VALUES(?,?,?,?)').run(req.user.id, title, ingredients, instructions); res.json({ ok: true }); });
app.post('/api/tasks', auth, (req, res) => { const title = clean(req.body.title); if (!title) return res.status(400).json({ error: 'Task title is required.' }); db.prepare('INSERT INTO tasks(user_id,title,assigned_to,due_date) VALUES(?,?,?,?)').run(req.user.id, title, clean(req.body.assignedTo), clean(req.body.dueDate)); res.json({ ok: true }); });
app.post('/api/tasks/:id/toggle', auth, (req, res) => { db.prepare('UPDATE tasks SET done=1-done WHERE id=?').run(Number(req.params.id)); res.json({ ok: true }); });
app.post('/api/memories', auth, (req, res) => { const title = clean(req.body.title); if (!title) return res.status(400).json({ error: 'Memory title is required.' }); const imageUrl = clean(req.body.imageUrl); if (imageUrl && !/^https:\/\//i.test(imageUrl)) return res.status(400).json({ error: 'Image links must start with https://.' }); db.prepare('INSERT INTO memories(user_id,title,story,image_url) VALUES(?,?,?,?)').run(req.user.id, title, clean(req.body.story), imageUrl); res.json({ ok: true }); });
app.post('/api/polls', auth, (req, res) => { const question = clean(req.body.question), options = (Array.isArray(req.body.options) ? req.body.options : []).map(clean).filter(Boolean).slice(0, 8); if (!question || options.length < 2 || new Set(options).size !== options.length) return res.status(400).json({ error: 'Add a question and at least two different options.' }); db.prepare("INSERT INTO polls(user_id,question,options,votes) VALUES(?,?,?,'{}')").run(req.user.id, question, JSON.stringify(options)); res.json({ ok: true }); });
app.post('/api/polls/:id/vote', auth, (req, res) => { const poll = db.prepare('SELECT * FROM polls WHERE id=?').get(Number(req.params.id)); if (!poll) return res.status(404).json({ error: 'Poll not found.' }); const options = JSON.parse(poll.options), votes = JSON.parse(poll.votes || '{}'), choice = clean(req.body.choice); if (!options.includes(choice)) return res.status(400).json({ error: 'Invalid choice.' }); votes[String(req.user.id)] = choice; db.prepare('UPDATE polls SET votes=? WHERE id=?').run(JSON.stringify(votes), poll.id); res.json({ ok: true }); });
app.get('/api/admin/requests', auth, admin, (req, res) => res.json({
  requests: db.prepare('SELECT id,username,display_name,note,created_at FROM requests ORDER BY id DESC').all(),
  resets: db.prepare("SELECT r.id,r.note,r.created_at,u.username,u.display_name FROM resets r JOIN users u ON r.user_id=u.id WHERE r.status='pending' ORDER BY r.id DESC").all(),
  users: db.prepare('SELECT id,username,display_name,role,created_at FROM users ORDER BY id').all()
}));
app.post('/api/admin/requests/:id/approve', auth, admin, (req, res) => { const r = db.prepare('SELECT * FROM requests WHERE id=?').get(Number(req.params.id)); if (!r) return res.status(404).json({ error: 'Request not found.' }); try { db.prepare("INSERT INTO users(username,display_name,password_hash,role) VALUES(?,?,?,'member')").run(r.username, r.display_name, r.password_hash); db.prepare('DELETE FROM requests WHERE id=?').run(r.id); res.json({ ok: true }); } catch { res.status(409).json({ error: 'Could not approve this request.' }); } });
app.delete('/api/admin/requests/:id', auth, admin, (req, res) => { db.prepare('DELETE FROM requests WHERE id=?').run(Number(req.params.id)); res.json({ ok: true }); });
app.post('/api/admin/resets/:id/temporary-password', auth, admin, (req, res) => { const password = String(req.body.password || ''); if (password.length < 8) return res.status(400).json({ error: 'Temporary password must be at least 8 characters.' }); const r = db.prepare("SELECT * FROM resets WHERE id=? AND status='pending'").get(Number(req.params.id)); if (!r) return res.status(404).json({ error: 'Reset request not found.' }); db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(password, 12), r.user_id); db.prepare("UPDATE resets SET status='done' WHERE id=?").run(r.id); res.json({ ok: true, message: 'Temporary password set. Share it privately with the member; it is not emailed automatically.' }); });
app.post('/api/admin/users/:id/role', auth, admin, (req, res) => { const role = req.body.role; if (!['admin','member'].includes(role)) return res.status(400).json({ error: 'Invalid role.' }); if (Number(req.params.id) === req.user.id && role !== 'admin') return res.status(400).json({ error: 'You cannot remove your own admin role.' }); db.prepare('UPDATE users SET role=? WHERE id=?').run(role, Number(req.params.id)); res.json({ ok: true }); });
app.delete('/api/admin/users/:id', auth, admin, (req, res) => { if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'You cannot delete your own admin account.' }); db.prepare('DELETE FROM users WHERE id=?').run(Number(req.params.id)); res.json({ ok: true }); });
app.post('/api/admin/settings', auth, admin, (req, res) => { for (const [key, value] of Object.entries(req.body || {})) { if (['familyName','welcomeMessage'].includes(key) && typeof value === 'string') db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, value.slice(0, 200)); } res.json({ ok: true }); });
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Something went wrong on the server.' }); });
app.listen(PORT, () => console.log(`Our Family Home running at http://localhost:${PORT}`));
