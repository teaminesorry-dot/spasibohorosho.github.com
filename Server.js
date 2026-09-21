// server.js — Express API + статика
import express from 'express';
import session from 'express-session';
import bcrypt from 'bcrypt';
import db from './db.js';

const app = express();

app.set('trust proxy', true);
app.use(express.json({ limit: '2mb' }));
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 3600 * 1000 }
}));

const requireAdmin = (req, res, next) =>
  req.session.isAdmin ? next() : res.status(401).json({ error: 'Только для админа' });

const clientIp = req =>
  (req.headers['x-forwarded-for']?.split(',')[0] || req.ip || '').trim();

// ---------- AUTH ----------
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res.status(400).json({ error: 'Введи логин и пароль' });

  const row = db.prepare('SELECT * FROM admins WHERE username = ?')
    .get(username.trim());

  // bcrypt.compare против фейкового хеша, чтобы не палить существование юзера по времени
  const hash = row?.password_hash || '$2b$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidin';
  const ok = bcrypt.compareSync(password, hash);

  if (!row || !ok)
    return res.status(401).json({ error: 'Неверный логин или пароль' });

  req.session.isAdmin = true;
  req.session.adminUser = row.username;
  res.json({ ok: true, username: row.username });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  res.json({
    isAdmin: !!req.session.isAdmin,
    username: req.session.adminUser || null
  });
});

// ---------- УПРАВЛЕНИЕ АДМИНАМИ ----------
app.get('/api/admin/users', requireAdmin, (req, res) => {
  res.json(db.prepare(
    'SELECT id, username, created_at FROM admins ORDER BY id'
  ).all());
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const username = (req.body?.username || '').trim();
  const password = (req.body?.password || '').trim();
  if (username.length < 3)
    return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Пароль минимум 6 символов' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)')
      .run(username, hash);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Такой логин уже есть' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const total = db.prepare('SELECT COUNT(*) AS c FROM admins').get().c;
  if (total <= 1)
    return res.status(400).json({ error: 'Нельзя удалить последнего админа' });
  const row = db.prepare('SELECT username FROM admins WHERE id = ?').get(id);
  if (row && row.username === req.session.adminUser)
    return res.status(400).json({ error: 'Нельзя удалить себя' });
  db.prepare('DELETE FROM admins WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/admin/change-password', requireAdmin, (req, res) => {
  const { old_password, new_password } = req.body || {};
  if (!new_password || new_password.length < 6)
    return res.status(400).json({ error: 'Новый пароль минимум 6 символов' });
  const row = db.prepare('SELECT * FROM admins WHERE username = ?')
    .get(req.session.adminUser);
  if (!row || !bcrypt.compareSync(old_password || '', row.password_hash))
    return res.status(401).json({ error: 'Неверный текущий пароль' });
  const hash = bcrypt.hashSync(new_password, 10);
  db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(hash, row.id);
  res.json({ ok: true });
});

// ---------- ПРЕДМЕТЫ ----------
app.get('/api/subjects', (req, res) => {
  res.json(db.prepare('SELECT name FROM subjects ORDER BY name').all().map(r => r.name));
});

app.post('/api/subjects', requireAdmin, (req, res) => {
  const name = (req.body?.name || '').trim();
  if (name.length < 2) return res.status(400).json({ error: 'Слишком короткое' });
  try {
    db.prepare('INSERT INTO subjects (name) VALUES (?)').run(name);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Уже есть' });
  }
});

app.delete('/api/subjects/:name', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM subjects WHERE name = ?').run(req.params.name);
  res.json({ ok: true });
});

// ---------- УНИВЕРСАЛЬНЫЙ CRUD ----------
function crud(table, fields) {
  const getOne = db.prepare(`SELECT * FROM ${table} WHERE id = ?`);
  return {
    list: (req, res) => {
      res.json(db.prepare(`SELECT * FROM ${table} ORDER BY created_at DESC`).all());
    },
    get: (req, res) => {
      const row = getOne.get(req.params.id);
      if (!row) return res.status(404).json({ error: 'Не найдено' });
      res.json(row);
    },
    create: (req, res) => {
      const vals = fields.map(f => (req.body?.[f] || '').toString().trim());
      if (vals.some(v => v.length < 2))
        return res.status(400).json({ error: 'Заполни все поля' });
      try {
        const placeholders = fields.map(() => '?').join(',');
        const info = db.prepare(
          `INSERT INTO ${table} (${fields.join(',')}, author) VALUES (${placeholders}, ?)`
        ).run(...vals, req.session.adminUser || 'admin');
        res.json({ ok: true, id: info.lastInsertRowid });
      } catch {
        res.status(409).json({ error: 'Такая запись уже есть' });
      }
    },
    remove: (req, res) => {
      db.prepare(`DELETE FROM ${table} WHERE id = ?`).run(req.params.id);
      res.json({ ok: true });
    }
  };
}

const dzCrud = crud('dz', ['subject', 'title', 'content']);
app.get('/api/dz', dzCrud.list);
app.get('/api/dz/:id', dzCrud.get);
app.post('/api/dz', requireAdmin, dzCrud.create);
app.delete('/api/dz/:id', requireAdmin, dzCrud.remove);

const kCrud = crud('konspekty', ['subject', 'title', 'content']);
app.get('/api/konspekty', kCrud.list);
app.get('/api/konspekty/:id', kCrud.get);
app.post('/api/konspekty', requireAdmin, kCrud.create);
app.delete('/api/konspekty/:id', requireAdmin, kCrud.remove);

const otvCrud = crud('otv', ['subject', 'topic', 'content']);
app.get('/api/otv', otvCrud.list);
app.get('/api/otv/:id', otvCrud.get);
app.post('/api/otv', requireAdmin, otvCrud.create);
app.delete('/api/otv/:id', requireAdmin, otvCrud.remove);

const olCrud = crud('olympiads', ['name', 'content']);
app.get('/api/olympiads', olCrud.list);
app.get('/api/olympiads/:id', olCrud.get);
app.post('/api/olympiads', requireAdmin, olCrud.create);
app.delete('/api/olympiads/:id', requireAdmin, olCrud.remove);

// ---------- VPN ----------
app.get('/api/vpn', (req, res) => {
  res.json(db.prepare('SELECT id, name, key FROM vpn_keys ORDER BY id').all());
});

app.post('/api/vpn', requireAdmin, (req, res) => {
  const { name, key } = req.body || {};
  if (!key) return res.status(400).json({ error: 'Ключ пустой' });
  try {
    db.prepare('INSERT INTO vpn_keys (name, key) VALUES (?, ?)')
      .run(name || `VPN #${Date.now()}`, key);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: 'Такой ключ уже есть' });
  }
});

app.delete('/api/vpn/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM vpn_keys WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- ПОДДЕРЖКА ----------
app.post('/api/support', (req, res) => {
  const { name, contact, message } = req.body || {};
  if (!message || message.trim().length < 3)
    return res.status(400).json({ error: 'Сообщение слишком короткое' });
  db.prepare('INSERT INTO support (name, contact, message) VALUES (?, ?, ?)')
    .run((name || '').trim(), (contact || '').trim(), message.trim());
  res.json({ ok: true });
});

app.get('/api/support', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM support ORDER BY created_at DESC').all());
});

app.delete('/api/support/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM support WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ---------- ШПАРГАЛКА: УРАВНЕНИЯ ----------
function parseSide(side) {
  side = side.replace(/\s+/g, '');
  if (side && !'+-'.includes(side[0])) side = '+' + side;
  const terms = side.match(/[+-][^+-]+/g) || [];
  let a = 0, b = 0;
  for (const t of terms) {
    const sign = t[0] === '-' ? -1 : 1;
    const body = t.slice(1);
    if (!body) continue;
    if (/[a-zA-Zа-яА-Я]/.test(body)) {
      const nums = body.replace(/[a-zA-Zа-яА-Я]/g, '');
      if (nums === '' || nums === '+') a += sign;
      else if (nums === '-') a -= sign;
      else a += sign * (nums.includes('.') ? parseFloat(nums) : parseInt(nums, 10));
    } else {
      b += sign * (body.includes('.') ? parseFloat(body) : parseInt(body, 10));
    }
  }
  return [a, b];
}

const fmt = n => Number.isInteger(n) ? String(n) : String(n);

app.post('/api/solve/equation', (req, res) => {
  const eq = (req.body?.equation || '').toString().replace(/\s+/g, '');
  if (!eq.includes('=')) return res.status(400).json({ error: "Нет знака '='" });
  const [left, right] = eq.split('=', 2);
  let a1, b1, a2, b2;
  try { [a1, b1] = parseSide(left); [a2, b2] = parseSide(right); }
  catch (e) { return res.status(400).json({ error: 'Ошибка разбора: ' + e.message }); }

  const A = a1 - a2, B = b1 - b2;
  const lines = [`📝 Уравнение: ${left} = ${right}`, ''];
  lines.push(`Шаг 2. Приводим подобные: ${fmt(A)}x + ${fmt(B)} = 0`);
  lines.push(`Шаг 3. Переносим число: ${fmt(A)}x = ${fmt(-B)}`);
  if (A === 0) {
    lines.push(B === 0 ? '✅ x — любое число' : '❌ Решений нет');
  } else {
    const x = -B / A;
    lines.push(`Шаг 4. x = ${fmt(-B)} / ${fmt(A)}`);
    lines.push(`✅ Ответ: x = ${fmt(x)}`);
  }
  res.json({ result: lines.join('\n') });
});

// ---------- STEPIK / ЯНДЕКС УЧЕБНИК ----------
app.post('/api/stepik', (req, res) => {
  const { name, email, password, consent } = req.body || {};
  if (!consent) return res.status(400).json({ error: 'Нужно согласие' });
  if (!email || !password)
    return res.status(400).json({ error: 'Заполни почту и пароль' });
  const ip = clientIp(req);
  const ua = req.headers['user-agent'] || '';
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO stepik
    (user_name, email, password, consent_at, ip, user_agent)
    VALUES (?, ?, ?, ?, ?, ?)`).run(name || '', email, password, now, ip, ua);
  db.prepare(`INSERT INTO consents
    (user_name, service, consent_text, ip, user_agent)
    VALUES (?, ?, ?, ?, ?)`).run(
      name || '', 'stepik',
      'Согласен передать почту и пароль Stepik владельцу сайта для помощи с заданиями',
      ip, ua);
  res.json({ ok: true });
});

app.post('/api/yakids', (req, res) => {
  const { name, login, password, consent } = req.body || {};
  if (!consent) return res.status(400).json({ error: 'Нужно согласие' });
  if (!login || !password)
    return res.status(400).json({ error: 'Заполни логин и пароль' });
  const ip = clientIp(req);
  const ua = req.headers['user-agent'] || '';
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO yakids
    (user_name, login, password, consent_at, ip, user_agent)
    VALUES (?, ?, ?, ?, ?, ?)`).run(name || '', login, password, now, ip, ua);
  db.prepare(`INSERT INTO consents
    (user_name, service, consent_text, ip, user_agent)
    VALUES (?, ?, ?, ?, ?)`).run(
      name || '', 'yakids',
      'Согласен передать логин и пароль Яндекс.Учебник владельцу сайта для помощи с заданиями',
      ip, ua);
  res.json({ ok: true });
});

app.get('/api/admin/stepik', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM stepik ORDER BY created_at DESC').all());
});

app.get('/api/admin/yakids', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM yakids ORDER BY created_at DESC').all());
});

app.get('/api/admin/consents', requireAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM consents ORDER BY created_at DESC').all());
});

app.delete('/api/stepik', (req, res) => {
  const { email, password } = req.body || {};
  const row = db.prepare('SELECT * FROM stepik WHERE email = ? AND password = ?')
    .get(email, password);
  if (!row) return res.status(404).json({ error: 'Не найдено' });
  db.prepare('DELETE FROM stepik WHERE id = ?').run(row.id);
  res.json({ ok: true });
});

app.delete('/api/yakids', (req, res) => {
  const { login, password } = req.body || {};
  const row = db.prepare('SELECT * FROM yakids WHERE login = ? AND password = ?')
    .get(login, password);
  if (!row) return res.status(404).json({ error: 'Не найдено' });
  db.prepare('DELETE FROM yakids WHERE id = ?').run(row.id);
  res.json({ ok: true });
});

// ---------- ЭКСПОРТ JSON ----------
const EXPORT_TABLES = {
  dz: 'dz',
  konspekty: 'konspekty',
  otv: 'otv',
  olympiads: 'olympiads',
  vpn: 'vpn_keys',
  subjects: 'subjects',
  support: 'support',
  stepik: 'stepik',
  yakids: 'yakids',
  consents: 'consents',
  admins: 'admins'
};

app.get('/api/admin/export/:table', requireAdmin, (req, res) => {
  const table = EXPORT_TABLES[req.params.table];
  if (!table) return res.status(404).json({ error: 'Нет такой таблицы' });

  let rows = db.prepare(`SELECT * FROM ${table} ORDER BY id`).all();

  // пароли админов наружу не отдаём
  if (table === 'admins') rows = rows.map(({ password_hash, ...rest }) => rest);

  const payload = {
    table: req.params.table,
    exported_at: new Date().toISOString(),
    count: rows.length,
    items: rows
  };

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const filename = `${req.params.table}_${stamp}.json`;

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(payload, null, 2));
});

app.get('/api/admin/export-all', requireAdmin, (req, res) => {
  const out = { exported_at: new Date().toISOString(), tables: {} };
  for (const [key, table] of Object.entries(EXPORT_TABLES)) {
    let rows = db.prepare(`SELECT * FROM ${table} ORDER BY id`).all();
    if (table === 'admins') rows = rows.map(({ password_hash, ...rest }) => rest);
    out.tables[key] = rows;
  }
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition',
    `attachment; filename="full-backup_${stamp}.json"`);
  res.send(JSON.stringify(out, null, 2));
});

// ---------- ЗАПУСК ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 http://localhost:${PORT}`));
