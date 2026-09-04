// Бэкенд приложения "Я и собака": регистрация/вход по почте и паролю + хранение профилей собак.
// Простой Node.js/Express сервер + PostgreSQL. Написан специально под это приложение,
// без лишних зависимостей — так проще передать другому разработчику при необходимости.

require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const COOKIE_NAME = 'token';

// --- Подключение к базе данных ---
const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT ? Number(process.env.PGPORT) : 5432,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dogs (
      id TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT DEFAULT '',
      dob TEXT DEFAULT '',
      photo TEXT,
      sort_order INTEGER DEFAULT 0,
      PRIMARY KEY (user_id, id)
    );
  `);
}

// --- Middleware ---
app.use(express.json({ limit: '8mb' })); // фото собак приходят как base64, им нужен запас
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

function setAuthCookie(res, userId) {
  const token = jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'not_authenticated' });
  }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// --- Авторизация ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    if (!isValidEmail(email)) return res.status(400).json({ error: 'invalid_email' });
    if (password.length < 6) return res.status(400).json({ error: 'weak_password' });

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(409).json({ error: 'email_taken' });

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
      [email, hash]
    );
    const userId = result.rows[0].id;
    setAuthCookie(res, userId);
    res.json({ email });
  } catch (e) {
    console.error('register error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String((req.body && req.body.email) || '').trim().toLowerCase();
    const password = String((req.body && req.body.password) || '');
    const result = await pool.query('SELECT id, password_hash FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'invalid_credentials' });
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
    setAuthCookie(res, user.id);
    res.json({ email });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/auth/me', async (req, res) => {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'not_authenticated' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [payload.uid]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'not_authenticated' });
    res.json({ email: result.rows[0].email });
  } catch (e) {
    res.status(401).json({ error: 'not_authenticated' });
  }
});

// --- Профили собак ---
app.get('/api/dogs', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, dob, photo FROM dogs WHERE user_id = $1 ORDER BY sort_order ASC, id ASC',
      [req.userId]
    );
    res.json({ dogs: result.rows });
  } catch (e) {
    console.error('get dogs error', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Полная синхронизация: клиент присылает весь список собак, сервер полностью его перезаписывает.
// Проще и надёжнее для маленького личного списка, чем набор отдельных create/update/delete ручек.
app.post('/api/dogs/sync', requireAuth, async (req, res) => {
  const dogs = Array.isArray(req.body && req.body.dogs) ? req.body.dogs : [];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM dogs WHERE user_id = $1', [req.userId]);
    for (let i = 0; i < dogs.length; i++) {
      const d = dogs[i] || {};
      const id = String(d.id || ('d' + Date.now() + '_' + i));
      const name = String(d.name || '');
      const dob = String(d.dob || '');
      const photo = d.photo ? String(d.photo) : null;
      await client.query(
        'INSERT INTO dogs (id, user_id, name, dob, photo, sort_order) VALUES ($1,$2,$3,$4,$5,$6)',
        [id, req.userId, name, dob, photo, i]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error('sync dogs error', e);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

// Отдаём фронтенд для всех остальных путей (одностраничное приложение)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log('Сервер запущен, порт ' + PORT));
  })
  .catch((e) => {
    console.error('Не удалось подключиться к базе данных при старте:', e);
    process.exit(1);
  });
