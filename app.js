import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import path from 'path';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

const db = new Database(':memory:');

function initDatabase() {
  console.log('Initializing database...');

  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
  )`);

  const insertUser = db.prepare(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`);
  insertUser.run('user1', 'password1', 'user');
  insertUser.run(process.env.ADMIN_USERNAME, process.env.ADMIN_PASSWORD, 'admin');

  console.log('Database initialized successfully!');
}

initDatabase();

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: 'weak-secret',
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: false,
    maxAge: 365 * 24 * 60 * 60 * 1000,
    sameSite: false
  }
}));

app.get('/debug', (req, res) => {
  res.json({
    environment: process.env,
    session: req.session,
    headers: req.headers,
    userAgent: req.get('User-Agent')
  });
});

app.get('/', (req, res) => {
  if (req.session.user) {
    return req.session.user.role === 'admin' 
      ? res.redirect('/admin') 
      : res.redirect('/user');
  }

  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?')
      .get(username, password);
    
    if (user) {
      req.session.user = { username: user.username, role: user.role };

      return user.role === 'admin' 
        ? res.redirect('/admin') 
        : res.redirect('/user');
    }
    
    res.redirect('/login?error=1');
  } catch (err) {
    console.error(err);
    res.redirect('/login?error=1');
  }
});

app.get('/user', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'user') {
    return res.redirect('/login');
  }

  res.sendFile(path.join(__dirname, 'views', 'user.html'));
});

app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/login');
  }

  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'reset-password.html'));
});

app.post('/reset-password', (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      return res.redirect('/reset-password?error=user_not_found');
    }
    
    const conflictUser = db.prepare('SELECT username FROM users WHERE password = ? AND username != ?')
      .get(password, username);
    
    if (conflictUser) {
      return res.redirect(`/reset-password?error=password_in_use&conflict_user=${encodeURIComponent(conflictUser.username)}`);
    }
    
    db.prepare('UPDATE users SET password = ? WHERE username = ?')
      .run(password, username);
    
    res.redirect('/reset-password?success=1');
  } catch (err) {
    console.error('Reset password error:', err);
    res.redirect('/reset-password?error=1');
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
