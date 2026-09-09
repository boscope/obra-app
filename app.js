const path = require('path');
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const db = require('./db');

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

const SESSION_SECRET = process.env.SESSION_SECRET || 'troque-esta-chave-antes-de-publicar';

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieSession({
  name: 'sid',
  secret: SESSION_SECRET,
  httpOnly: true,
  sameSite: 'lax',
  maxAge: 1000 * 60 * 60 * 24 * 7
}));

const asyncH = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function authed(req) {
  if (!req.session.userId) return null;
  const u = await db.findUserById(req.session.userId);
  if (!u || u.status !== 'ativo') return null;
  return u;
}

async function admin(req) {
  const u = await authed(req);
  return u && u.role === 'admin' ? u : null;
}

function servePublic(file) {
  return path.join(__dirname, 'public', file);
}

/* ---------- páginas ---------- */

app.get('/login', asyncH(async (req, res) => {
  if (await authed(req)) return res.redirect('/');
  res.sendFile(servePublic('login.html'));
}));

app.get('/', asyncH(async (req, res) => {
  const u = await authed(req);
  if (!u) return res.redirect('/login');
  res.sendFile(servePublic('calculadora.html'));
}));

app.get('/ceramica', asyncH(async (req, res) => {
  const u = await authed(req);
  if (!u) return res.redirect('/login');
  res.sendFile(servePublic('ceramica.html'));
}));

app.get('/admin', asyncH(async (req, res) => {
  const u = await admin(req);
  if (!u) {
    if (await authed(req)) return res.status(403).send('<h2>Sem permissão — você não é admin.</h2><a href="/">Voltar</a>');
    return res.redirect('/login');
  }
  res.sendFile(servePublic('admin.html'));
}));

/* ---------- API de autenticação ---------- */

app.post('/api/login', asyncH(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Informe usuário e senha.' });
  const u = await db.getUserByUsernameForAuth(String(username).trim());
  if (!u) return res.status(401).json({ error: 'Usuário não encontrado.' });
  if (u.status === 'pausado') return res.status(403).json({ error: 'Acesso pausado. Entre em contato com o administrador.' });
  if (!bcrypt.compareSync(String(password), u.password_hash)) return res.status(401).json({ error: 'Senha incorreta.' });
  req.session.userId = u.id;
  db.touchLogin(u.id);
  res.json({ ok: true, user: db.rowToUser(u) });
}));

app.post('/api/logout', (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.get('/api/me', asyncH(async (req, res) => {
  const u = await authed(req);
  res.json({ user: u ? { id: u.id, name: u.name, username: u.username, role: u.role, status: u.status } : null });
}));

/* ---------- API de admin ---------- */

async function requireAdmin(req, res, next) {
  if (!(await admin(req))) return res.status(403).json({ error: 'Acesso restrito ao admin.' });
  next();
}

app.get('/api/admin/users', requireAdmin, asyncH(async (req, res) => {
  res.json({ users: await db.listUsers() });
}));

app.post('/api/admin/users', requireAdmin, asyncH(async (req, res) => {
  const { name, username, password, role } = req.body || {};
  if (!name || !username || !password) return res.status(400).json({ error: 'Nome, usuário e senha são obrigatórios.' });
  if (String(password).length < 4) return res.status(400).json({ error: 'Senha deve ter pelo menos 4 caracteres.' });
  if (String(role) !== 'admin' && String(role) !== 'cliente') return res.status(400).json({ error: 'Papel inválido.' });
  if (await db.findUserByUsername(String(username).trim())) return res.status(409).json({ error: 'Já existe um usuário com esse nome de acesso.' });
  const user = await db.createUser({ name: String(name).trim(), username: String(username).trim(), password: String(password), role });
  res.json({ ok: true, user });
}));

app.post('/api/admin/users/:id/status', requireAdmin, asyncH(async (req, res) => {
  const id = Number(req.params.id);
  const u = await db.findUserById(id);
  if (!u) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const status = req.body.status;
  if (status !== 'ativo' && status !== 'pausado') return res.status(400).json({ error: 'Status inválido.' });
  const me = await admin(req);
  if (me.id === id) return res.status(400).json({ error: 'Você não pode pausar o próprio acesso.' });
  await db.setUserStatus(id, status);
  res.json({ ok: true, user: await db.findUserById(id) });
}));

app.delete('/api/admin/users/:id', requireAdmin, asyncH(async (req, res) => {
  const id = Number(req.params.id);
  const u = await db.findUserById(id);
  if (!u) return res.status(404).json({ error: 'Usuário não encontrado.' });
  const me = await admin(req);
  if (me.id === id) return res.status(400).json({ error: 'Você não pode excluir o próprio usuário.' });
  await db.deleteUser(id);
  res.json({ ok: true });
}));

app.post('/api/admin/me/password', requireAdmin, asyncH(async (req, res) => {
  const me = await admin(req);
  const { current, next } = req.body || {};
  if (!current || !next) return res.status(400).json({ error: 'Preencha a senha atual e a nova senha.' });
  if (String(next).length < 4) return res.status(400).json({ error: 'A nova senha deve ter pelo menos 4 caracteres.' });
  const hash = await db.getPasswordHash(me.id);
  if (!bcrypt.compareSync(String(current), hash)) return res.status(401).json({ error: 'Senha atual incorreta.' });
  await db.updatePassword(me.id, bcrypt.hashSync(String(next), 10));
  res.json({ ok: true });
}));

/* ---------- fim ---------- */

module.exports = app;