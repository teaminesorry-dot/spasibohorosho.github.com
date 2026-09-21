// seed.js — начальные предметы + первый админ
import bcrypt from 'bcrypt';
import db from './db.js';

const DEFAULT_SUBJECTS = [
  'Алгебра', 'Геометрия', 'Русский язык', 'Литература',
  'История', 'Обществознание', 'Физика', 'Химия',
  'Биология', 'География', 'Английский язык', 'Информатика'
];

const insertSubj = db.prepare('INSERT OR IGNORE INTO subjects (name) VALUES (?)');
for (const s of DEFAULT_SUBJECTS) insertSubj.run(s);
console.log('✅ Предметы залиты:', DEFAULT_SUBJECTS.length);

// Первый админ — из env или дефолт
const username = (process.env.ADMIN_USER || 'admin').trim();
const password = process.env.ADMIN_PASS || 'change_me';

const exists = db.prepare('SELECT id FROM admins WHERE username = ?').get(username);
if (exists) {
  console.log('ℹ️  Админ уже есть:', username);
} else {
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)')
    .run(username, hash);
  console.log('✅ Админ создан:', username);
  if (password === 'change_me') {
    console.log('⚠️  Пароль по умолчанию! Смени: node seed.js с ADMIN_PASS=...');
  }
}
