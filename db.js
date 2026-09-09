const path = require('path');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || `file:${process.env.DB_PATH || path.join(__dirname, 'obra.db')}`,
  authToken: process.env.TURSO_AUTH_TOKEN
});

let readyPromise = null;
function ensureReady() {
  if (!readyPromise) {
    readyPromise = (async () => {
      await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        username      TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'cliente',
        status        TEXT NOT NULL DEFAULT 'ativo',
        created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime')),
        last_login    TEXT
      );
      `);
      await seedAdmin();
    })().catch((e) => { readyPromise = null; throw e; });
  }
  return readyPromise;
}

function rowToUser(r) {
  if (!r) return null;
  return { id: r.id, name: r.name, username: r.username, role: r.role, status: r.status, created_at: r.created_at, last_login: r.last_login };
}

async function findUserByUsername(username) {
  await ensureReady();
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [username] });
  return rowToUser(r.rows[0]);
}

async function getUserByUsernameForAuth(username) {
  await ensureReady();
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [username] });
  return r.rows[0] || null;
}

async function findUserById(id) {
  await ensureReady();
  const r = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] });
  return rowToUser(r.rows[0]);
}

async function listUsers() {
  await ensureReady();
  const r = await db.execute('SELECT * FROM users ORDER BY id');
  return r.rows.map(rowToUser);
}

async function createUser({ name, username, password, role = 'cliente' }) {
  await ensureReady();
  const hash = await bcrypt.hash(password, 10);
  await db.execute({
    sql: 'INSERT INTO users (name, username, password_hash, role) VALUES (?, ?, ?, ?)',
    args: [name, username, hash, role]
  });
  return findUserByUsername(username);
}

async function setUserStatus(id, status) {
  await ensureReady();
  await db.execute({ sql: 'UPDATE users SET status = ? WHERE id = ?', args: [status, id] });
}

async function deleteUser(id) {
  await ensureReady();
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [id] });
}

async function getPasswordHash(id) {
  await ensureReady();
  const r = await db.execute({ sql: 'SELECT password_hash FROM users WHERE id = ?', args: [id] });
  return r.rows[0] ? r.rows[0].password_hash : null;
}

async function updatePassword(id, hash) {
  await ensureReady();
  await db.execute({ sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [hash, id] });
}

async function touchLogin(id) {
  await ensureReady();
  await db.execute({ sql: "UPDATE users SET last_login = datetime('now','localtime') WHERE id = ?", args: [id] });
}

async function countAdminsActive() {
  await ensureReady();
  const r = await db.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'ativo'");
  return Number(r.rows[0].n);
}

async function seedAdmin() {
  const r = await db.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'");
  if (Number(r.rows[0].n) > 0) return;
  const username = process.env.ADMIN_USER || 'admin';
  const password = process.env.ADMIN_PASS || 'admin123';
  const hash = await bcrypt.hash(password, 10);
  await db.execute({
    sql: 'INSERT INTO users (name, username, password_hash, role) VALUES (?, ?, ?, ?)',
    args: ['Administrador', username, hash, 'admin']
  });
  console.log('\n=====================================================');
  console.log('  Admin criado:');
  console.log(`    usuário: ${username}`);
  console.log(`    senha:   ${password}`);
  console.log('  Acesse /admin depois de logar.');
  console.log('  Troque a senha em produção. Ajuste via env');
  console.log('  ADMIN_USER / ADMIN_PASS se quiser definir antes.');
  console.log('=====================================================\n');
}

module.exports = {
  db,
  ensureReady,
  findUserByUsername,
  getUserByUsernameForAuth,
  findUserById,
  listUsers,
  createUser,
  setUserStatus,
  deleteUser,
  getPasswordHash,
  updatePassword,
  touchLogin,
  countAdminsActive,
  seedAdmin,
  rowToUser
};