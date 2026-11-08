'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { WebSocketServer } = require('ws');

const scrypt = promisify(crypto.scrypt);

// ---------- Configuration ----------
const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
// Set TRUST_PROXY=1 only when running behind your own reverse proxy (Caddy, nginx, etc.)
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// Accounts listed here are admins. Example: ADMIN_USERS=alice,bob node server.js
const ADMINS = new Set((process.env.ADMIN_USERS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const BACKUP_FILE = DATA_FILE + '.bak';
const AUDIT_FILE = path.join(DATA_DIR, 'audit.log');
const PUBLIC_DIR = path.join(__dirname, 'public');

const MAX_TEXT = 500, MAX_TOPIC = 120, MAX_LOG = 500, MAX_ROOMS = 50;
const MAX_ACCOUNTS = 5000;
const MAX_IMAGE_CHARS = 2_000_000;          // about 1.5 MB per picture
const MAX_TOTAL_IMAGE_CHARS = 150_000_000;  // about 110 MB of pictures on the server
const IMAGE_UPLOADS_PER_HOUR = 30;
const SESSION_S = 30 * 24 * 3600;
const MIN_GAP_MS = 800;
const LOGIN_LOCK_MS = 60 * 1000;
const AUTH_PER_IP_PER_MIN = 20;
const MAX_CONN_PER_IP = 20;
const MAX_HASHES_IN_FLIGHT = 4;
const HEARTBEAT_MS = 30 * 1000;
const BACKUP_EVERY_MS = 3600 * 1000;
const RESERVED = ['system', 'admin', 'mod', 'nightshift'];
const NAME_RE = /^[a-zA-Z0-9_-]{1,20}$/;
const ROOM_RE = /^#[a-z0-9_-]{1,30}$/;
const REACTIONS = ['+1', '<3', 'ha', '!!', '?'];
const CONTROL_RE = /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;
const SCRYPT_OPTS = { N: 16384, r: 8, p: 1 };
const DUMMY_SALT = '00'.repeat(16);
const DUMMY_HASH = '00'.repeat(64);

const clean = s => String(s ?? '').replace(CONTROL_RE, '').trim();
const newId = () => crypto.randomBytes(8).toString('hex');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Date.now();

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store'
};
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8'
};

// ---------- Database ----------
function freshDb() {
  return {
    users: {},
    sessions: {},
    rooms: { '#lobby': { topic: 'General chat.', creator: null, pinned: null, messages: [] } }
  };
}

const isDb = d => d && d.users && d.sessions && d.rooms;

function loadDb() {
  if (!fs.existsSync(DATA_FILE)) return freshDb();
  try {
    const d = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (isDb(d)) return d;
  } catch (e) {}
  // The main file is unreadable: fall back to the last backup, or refuse to start.
  try {
    const d = JSON.parse(fs.readFileSync(BACKUP_FILE, 'utf8'));
    if (isDb(d)) {
      console.error('data/db.json was unreadable; starting from data/db.json.bak');
      return d;
    }
  } catch (e) {}
  throw new Error('data/db.json is unreadable and no valid backup exists. Fix or restore the file before starting.');
}

const db = loadDb();
for (const key of ADMINS) if (db.users[key]) db.users[key].admin = true;

let lastBackup = 0;
function writeNow() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db), { mode: 0o600 });
  if (fs.existsSync(DATA_FILE) && now() - lastBackup > BACKUP_EVERY_MS) {
    fs.copyFileSync(DATA_FILE, BACKUP_FILE);
    fs.chmodSync(BACKUP_FILE, 0o600);
    lastBackup = now();
  }
  fs.renameSync(tmp, DATA_FILE);
  fs.chmodSync(DATA_FILE, 0o600); // enforce owner-only even where umask or mount options differ
}

let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { writeNow(); } catch (e) { console.error('save failed:', e.message); }
  }, 150);
}

function audit(actor, action, detail) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    fs.appendFileSync(AUDIT_FILE, JSON.stringify({ t: new Date().toISOString(), actor, action, detail }) + '\n', { mode: 0o600 });
    fs.chmodSync(AUDIT_FILE, 0o600);
  } catch (e) {}
}

// ---------- Passwords ----------
let hashesInFlight = 0;
async function withHashSlot(fn) {
  if (hashesInFlight >= MAX_HASHES_IN_FLIGHT) {
    const e = new Error('busy');
    e.code = 'BUSY';
    throw e;
  }
  hashesInFlight++;
  try { return await fn(); } finally { hashesInFlight--; }
}

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(pw, salt, 64, SCRYPT_OPTS);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}

async function checkPassword(pw, saltHex, hashHex) {
  const got = await scrypt(pw, Buffer.from(saltHex, 'hex'), 64, SCRYPT_OPTS);
  const want = Buffer.from(hashHex, 'hex');
  return want.length === got.length && crypto.timingSafeEqual(got, want);
}

// ---------- Sessions (token is random; only its SHA-256 is stored) ----------
function createSession(key) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.sessions[sha256(token)] = { user: key, exp: now() + SESSION_S * 1000 };
  persist();
  return token;
}

function userForToken(token) {
  if (typeof token !== 'string' || !token) return null;
  const s = db.sessions[sha256(token)];
  if (!s || s.exp < now()) return null;
  return db.users[s.user] || null;
}

function dropSession(token) {
  if (typeof token === 'string' && token) delete db.sessions[sha256(token)];
  persist();
}

setInterval(() => {
  for (const [k, s] of Object.entries(db.sessions)) if (s.exp < now()) delete db.sessions[k];
  persist();
}, 3600 * 1000).unref();

// ---------- Rate limits and counters ----------
const loginFails = new Map();   // "ip|username" -> { n, until }
const ipAuthHits = new Map();   // ip -> { n, reset }
const connsPerIp = new Map();   // ip -> open sockets
const userLastMsg = new Map();  // username key -> last message time
const userUploads = new Map();  // username key -> [timestamps]

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) {
    return String(req.headers['x-forwarded-for']).split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function ipAllowed(ip) {
  const t = now();
  let e = ipAuthHits.get(ip);
  if (!e || e.reset < t) { e = { n: 0, reset: t + 60000 }; ipAuthHits.set(ip, e); }
  e.n++;
  return e.n <= AUTH_PER_IP_PER_MIN;
}

function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) {
      try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) {}
    }
  });
  return out;
}

function sessionCookie(token, req, maxAge) {
  const secure = req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
  return `ns_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` + (secure ? '; Secure' : '');
}

function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return false;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}

// ---------- Live state ----------
const clients = new Set(); // { ws, ip, user, token, room, alive }

function send(ws, obj) {
  if (ws.readyState === 1) ws.send(JSON.stringify(obj));
}

const notice = (c, text) => send(c.ws, { type: 'notice', room: c.room, text });
const fail = (c, message) => send(c.ws, { type: 'error', message });

function membersOf(room) {
  const names = new Map();
  for (const c of clients) if (c.user && c.room === room) names.set(c.user.key, c.user.name);
  return [...names.values()];
}

// Room list is public (names, topics, counts). Messages and pins are never included.
function roomList() {
  return Object.entries(db.rooms).map(([name, r]) => ({
    name, topic: r.topic, creator: r.creator, count: membersOf(name).length
  }));
}

function toAll(obj) {
  for (const c of clients) if (c.user) send(c.ws, obj);
}

function pushRooms() { toAll({ type: 'rooms', rooms: roomList() }); }

function pushMembers(room) {
  if (!room) return;
  for (const c of clients) if (c.user && c.room === room) send(c.ws, { type: 'members', room, members: membersOf(room) });
}

// Content goes only to people who have joined the channel
function toMembers(room, obj) {
  for (const c of clients) if (c.user && c.room === room) send(c.ws, obj);
}

function event(room, ev) { toMembers(room, Object.assign({ type: 'event', room }, ev)); }

// Everyone else only learns that something happened, with no content
function activity(room) {
  for (const c of clients) if (c.user && c.room !== room) send(c.ws, { type: 'activity', room });
}

function joinRoom(c, room) {
  const prev = c.room;
  const r = db.rooms[room];
  if (!r) return notice(c, 'No such channel.');
  c.room = room;
  send(c.ws, { type: 'room', room, messages: r.messages, pinned: r.pinned });
  if (prev !== room) pushMembers(prev);
  pushMembers(room);
  pushRooms();
}

function addMessage(room, m) {
  const list = db.rooms[room].messages;
  list.push(m);
  if (list.length > MAX_LOG) list.splice(0, list.length - MAX_LOG);
  persist();
  event(room, { op: 'add', message: m });
  activity(room);
}

function totalImageChars() {
  let total = 0;
  for (const r of Object.values(db.rooms)) {
    for (const m of r.messages) if (m.kind === 'image') total += m.src.length;
  }
  return total;
}

const findMsg = (room, id) => {
  const r = room && db.rooms[room];
  return r ? r.messages.find(m => m.id === id) || null : null;
};

const canTopic = (room, u) => !!db.rooms[room] && (u.admin || db.rooms[room].creator === u.key);
const canDeleteMsg = (m, u) => u.admin || m.key === u.key;

function userRateOk(key) {
  const t = now();
  const last = userLastMsg.get(key) || 0;
  if (t - last < MIN_GAP_MS) return false;
  userLastMsg.set(key, t);
  return true;
}

function uploadAllowed(key) {
  const t = now();
  const hits = (userUploads.get(key) || []).filter(x => x > t - 3600 * 1000);
  if (hits.length >= IMAGE_UPLOADS_PER_HOUR) return false;
  hits.push(t);
  userUploads.set(key, hits);
  return true;
}

function normRoom(raw) {
  let r = clean(raw).toLowerCase();
  if (r && !r.startsWith('#')) r = '#' + r;
  return ROOM_RE.test(r) ? r : null;
}

// Pictures must be PNG, JPEG, GIF or WebP, and their first bytes must match the type
function validImage(src) {
  if (typeof src !== 'string' || src.length > MAX_IMAGE_CHARS) return false;
  const m = /^data:image\/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(src);
  if (!m) return false;
  const b = Buffer.from(m[2].slice(0, 24), 'base64');
  if (m[1] === 'png') return b.subarray(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  if (m[1] === 'jpeg') return b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
  if (m[1] === 'gif') return b.subarray(0, 4).toString('latin1') === 'GIF8';
  return b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP';
}

// ---------- Signed-in state ----------
function finishAuth(c, user, token) {
  c.user = { key: user.key, name: user.name, admin: !!user.admin || ADMINS.has(user.key) };
  c.token = token;
  c.room = null;
  send(c.ws, { type: 'authed', me: c.user, rooms: roomList() });
  pushRooms();
}

// ---------- HTTP API: register, log in, log out ----------
function readBody(req, limit = 10000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch (e) { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj, extra = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(obj));
}

async function handleAuthApi(req, res, mode) {
  if (!sameOrigin(req)) return sendJson(res, 403, { ok: false, error: 'Request blocked.' });
  const ip = clientIp(req);
  if (!ipAllowed(ip)) return sendJson(res, 429, { ok: false, error: 'Too many requests. Wait a minute.' });

  let body;
  try { body = await readBody(req); }
  catch (e) { return sendJson(res, 400, { ok: false, error: 'Bad request.' }); }

  const name = clean(body.username).replace(/\s+/g, '');
  const pw = typeof body.password === 'string' ? body.password : '';
  if (!NAME_RE.test(name)) return sendJson(res, 400, { ok: false, error: 'Usernames: letters, numbers, - and _ (max 20).' });
  const key = name.toLowerCase();
  if (RESERVED.includes(key)) return sendJson(res, 400, { ok: false, error: 'That username cannot be used.' });
  if (pw.length < 8 || pw.length > 128) return sendJson(res, 400, { ok: false, error: 'Password must be 8 to 128 characters.' });

  const lockKey = ip + '|' + key;
  const lock = loginFails.get(lockKey);
  if (lock && lock.until > now()) return sendJson(res, 429, { ok: false, error: 'Too many attempts. Wait a minute.' });

  try {
    let user;
    if (mode === 'register') {
      if (Object.keys(db.users).length >= MAX_ACCOUNTS) return sendJson(res, 403, { ok: false, error: 'Account limit reached.' });
      const creds = await withHashSlot(() => hashPassword(pw));
      // Checked again after the slow hash so two simultaneous sign-ups cannot both succeed
      if (db.users[key]) return sendJson(res, 409, { ok: false, error: 'That username cannot be used.' });
      user = { key, name, salt: creds.salt, hash: creds.hash, admin: ADMINS.has(key), banned: false, created: now() };
      db.users[key] = user;
      persist();
    } else {
      const u = db.users[key];
      // Always run the slow check, even for unknown names, so timing does not reveal accounts
      const ok = await withHashSlot(() => checkPassword(pw, u ? u.salt : DUMMY_SALT, u ? u.hash : DUMMY_HASH));
      if (!u || !ok) {
        const a = loginFails.get(lockKey) || { n: 0, until: 0 };
        a.n++;
        if (a.n >= 5) { a.until = now() + LOGIN_LOCK_MS; a.n = 0; }
        loginFails.set(lockKey, a);
        return sendJson(res, 401, { ok: false, error: 'Wrong username or password.' });
      }
      if (u.banned) return sendJson(res, 403, { ok: false, error: 'This account is banned.' });
      loginFails.delete(lockKey);
      user = u;
    }
    const token = createSession(key);
    return sendJson(res, 200, { ok: true, username: user.name },
      { 'Set-Cookie': sessionCookie(token, req, SESSION_S) });
  } catch (e) {
    if (e.code === 'BUSY') return sendJson(res, 503, { ok: false, error: 'Server is busy. Try again.' });
    console.error('auth error:', e);
    return sendJson(res, 500, { ok: false, error: 'Something went wrong.' });
  }
}

function handleLogout(req, res) {
  if (!sameOrigin(req)) return sendJson(res, 403, { ok: false });
  const token = parseCookies(req.headers.cookie).ns_session;
  dropSession(token);
  for (const c of clients) if (c.token && c.token === token) c.ws.close(4002, 'logged out');
  return sendJson(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', req, 0) });
}

// ---------- Commands from signed-in clients ----------
function handleCommand(c, msg) {
  const u = c.user;
  const room = c.room;

  switch (msg.type) {
    case 'join': {
      const r = normRoom(msg.room);
      if (!r || !db.rooms[r]) return notice(c, 'No such channel.');
      return joinRoom(c, r);
    }

    case 'create': {
      const r = normRoom(msg.room);
      if (!r) return notice(c, 'Invalid channel name. Use letters, numbers, - or _ (max 30).');
      if (!db.rooms[r]) {
        if (Object.keys(db.rooms).length >= MAX_ROOMS) return notice(c, 'Channel limit reached.');
        db.rooms[r] = { topic: 'A new channel.', creator: u.key, pinned: null, messages: [] };
        persist();
      }
      return joinRoom(c, r);
    }

    case 'delroom': {
      const r = normRoom(msg.room) || room;
      if (!r || r === '#lobby' || !db.rooms[r]) return notice(c, 'That channel cannot be deleted.');
      if (!canTopic(r, u)) return fail(c, 'Only the creator or an admin can delete this channel.');
      delete db.rooms[r];
      persist();
      if (u.admin) audit(u.key, 'delete-channel', r);
      for (const other of clients) {
        if (other.user && other.room === r) { other.room = null; joinRoom(other, '#lobby'); }
      }
      pushRooms();
      break;
    }

    case 'msg': {
      if (!room) return;
      if (!userRateOk(u.key)) return fail(c, 'Slow down. You are sending messages too fast.');
      const text = clean(msg.text).slice(0, MAX_TEXT);
      if (!text) return;
      const m = { id: newId(), kind: 'msg', key: u.key, name: u.name, text, ts: now() };
      if (msg.replyTo && typeof msg.replyTo.id === 'string') {
        const t = findMsg(room, msg.replyTo.id);
        if (t) m.replyTo = { id: t.id, name: t.name, snippet: (t.kind === 'image' ? '[picture]' : t.text).slice(0, 60) };
      }
      return addMessage(room, m);
    }

    case 'action': {
      if (!room) return;
      if (!userRateOk(u.key)) return fail(c, 'Slow down. You are sending messages too fast.');
      const text = clean(msg.text).slice(0, 400);
      if (!text) return;
      return addMessage(room, { id: newId(), kind: 'action', key: u.key, name: u.name, text, ts: now() });
    }

    case 'image': {
      if (!room) return;
      if (!userRateOk(u.key)) return fail(c, 'Slow down. You are sending messages too fast.');
      if (!validImage(msg.src)) return fail(c, 'That picture could not be verified.');
      if (!uploadAllowed(u.key)) return fail(c, 'Picture upload limit reached. Try again later.');
      if (totalImageChars() + msg.src.length > MAX_TOTAL_IMAGE_CHARS) return fail(c, 'The server has no room for more pictures right now.');
      return addMessage(room, { id: newId(), kind: 'image', key: u.key, name: u.name, src: msg.src, ts: now() });
    }

    case 'edit': {
      const m = findMsg(room, msg.id);
      if (!m || m.key !== u.key || m.kind !== 'msg') return fail(c, 'You can only edit your own messages.');
      const text = clean(msg.text).slice(0, MAX_TEXT);
      if (!text) return;
      m.text = text;
      m.edited = true;
      persist();
      event(room, { op: 'edit', id: m.id, text });
      break;
    }

    case 'delete': {
      const list = room ? db.rooms[room].messages : [];
      const i = list.findIndex(x => x.id === msg.id);
      if (i < 0) return;
      const target = list[i];
      if (!canDeleteMsg(target, u)) return fail(c, 'You can only delete your own messages.');
      list.splice(i, 1);
      if (u.admin && target.key !== u.key) audit(u.key, 'delete-message', room + ' ' + target.id + ' by ' + target.name);
      if (db.rooms[room].pinned && db.rooms[room].pinned.id === target.id) {
        db.rooms[room].pinned = null;
        event(room, { op: 'pin', pinned: null });
      }
      persist();
      event(room, { op: 'delete', id: target.id });
      break;
    }

    case 'react': {
      const m = findMsg(room, msg.id);
      const key = String(msg.key || '');
      if (!m || !REACTIONS.includes(key)) return;
      m.reactions = m.reactions || {};
      const users = m.reactions[key] = m.reactions[key] || [];
      const i = users.indexOf(u.key);
      if (i >= 0) users.splice(i, 1); else users.push(u.key);
      if (!users.length) delete m.reactions[key];
      persist();
      event(room, { op: 'react', id: m.id, reactions: m.reactions });
      break;
    }

    case 'pin': {
      const m = findMsg(room, msg.id);
      if (!m) return;
      if (!canTopic(room, u)) return fail(c, 'Only the creator or an admin can pin.');
      db.rooms[room].pinned = { id: m.id, name: m.name, text: (m.kind === 'image' ? '[picture]' : m.text).slice(0, 140) };
      persist();
      event(room, { op: 'pin', pinned: db.rooms[room].pinned });
      break;
    }

    case 'unpin': {
      if (!room || !canTopic(room, u)) return fail(c, 'Only the creator or an admin can unpin.');
      db.rooms[room].pinned = null;
      persist();
      event(room, { op: 'pin', pinned: null });
      break;
    }

    case 'topic': {
      if (!room || !canTopic(room, u)) return fail(c, 'Only the creator or an admin can change the topic.');
      const t = clean(msg.text).slice(0, MAX_TOPIC);
      if (!t) return;
      db.rooms[room].topic = t;
      persist();
      pushRooms();
      break;
    }

    case 'clearroom': {
      if (!u.admin) return fail(c, 'Admins only.');
      if (!room) return;
      db.rooms[room].messages = [];
      db.rooms[room].pinned = null;
      persist();
      audit(u.key, 'clear-channel', room);
      event(room, { op: 'clear' });
      break;
    }

    case 'clearall': {
      if (!u.admin) return fail(c, 'Admins only.');
      for (const [name, r] of Object.entries(db.rooms)) {
        r.messages = [];
        r.pinned = null;
        event(name, { op: 'clear' });
      }
      persist();
      audit(u.key, 'clear-all', '');
      break;
    }

    case 'ban':
    case 'unban': {
      if (!u.admin) return fail(c, 'Admins only.');
      const key = clean(msg.name).toLowerCase().replace(/^@/, '');
      const target = db.users[key];
      if (!target) return notice(c, 'No account with that name.');
      if (target.admin) return fail(c, 'Admins cannot be banned.');
      if (key === u.key) return fail(c, 'You cannot ban yourself.');
      target.banned = msg.type === 'ban';
      persist();
      audit(u.key, target.banned ? 'ban' : 'unban', target.name);
      if (target.banned) {
        for (const other of clients) if (other.user && other.user.key === key) other.ws.close(4001, 'banned');
      }
      notice(c, target.name + (target.banned ? ' was banned.' : ' was unbanned.'));
      pushRooms();
      break;
    }

    default:
      break;
  }
}

function handleMessage(c, msg) {
  if (!c.user) return; // only signed-in sockets can act; sign-in happens over HTTP
  handleCommand(c, msg);
}

// ---------- Static files ----------
function serveStatic(req, res) {
  let p;
  try { p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname); }
  catch (e) { res.writeHead(400, SECURITY_HEADERS); return res.end(); }
  if (p.includes('\0')) { res.writeHead(400, SECURITY_HEADERS); return res.end(); }
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403, SECURITY_HEADERS); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, SECURITY_HEADERS); return res.end('Not found'); }
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

const server = http.createServer((req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    if (req.method === 'POST' && p === '/api/register') return void handleAuthApi(req, res, 'register');
    if (req.method === 'POST' && p === '/api/login') return void handleAuthApi(req, res, 'login');
    if (req.method === 'POST' && p === '/api/logout') return handleLogout(req, res);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, SECURITY_HEADERS); return res.end(); }
    return serveStatic(req, res);
  } catch (e) {
    console.error('request error:', e);
    if (!res.headersSent) res.writeHead(400, SECURITY_HEADERS);
    res.end();
  }
});
server.requestTimeout = 15000;

// ---------- WebSocket ----------
const wss = new WebSocketServer({ noServer: true, maxPayload: 3 * 1024 * 1024 });

server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws' || !sameOrigin(req)) {
    socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    return socket.destroy();
  }
  const ip = clientIp(req);
  if ((connsPerIp.get(ip) || 0) >= MAX_CONN_PER_IP) {
    socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
});

wss.on('connection', (ws, req) => {
  const ip = clientIp(req);
  connsPerIp.set(ip, (connsPerIp.get(ip) || 0) + 1);
  const c = { ws, ip, user: null, token: null, room: null, alive: true };
  clients.add(c);

  ws.on('pong', () => { c.alive = true; });

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch (e) { return; }
    if (!msg || typeof msg.type !== 'string') return;
    try { handleMessage(c, msg); } catch (err) { console.error('handler error:', err); }
  });

  ws.on('close', () => {
    const room = c.room;
    const wasUser = !!c.user;
    clients.delete(c);
    const left = (connsPerIp.get(ip) || 1) - 1;
    if (left > 0) connsPerIp.set(ip, left); else connsPerIp.delete(ip);
    if (wasUser) { pushMembers(room); pushRooms(); }
  });

  ws.on('error', () => {});

  // The session cookie decides whether this socket is signed in
  const user = userForToken(parseCookies(req.headers.cookie).ns_session);
  if (user && !user.banned) finishAuth(c, user, parseCookies(req.headers.cookie).ns_session);
  else send(ws, { type: 'needlogin' });
});

// Drop connections that stopped answering pings
setInterval(() => {
  for (const c of clients) {
    if (!c.alive) { c.ws.terminate(); continue; }
    c.alive = false;
    c.ws.ping();
  }
}, HEARTBEAT_MS).unref();

// ---------- Start ----------
server.listen(PORT, HOST, () => {
  console.log(`Nightshift is running at http://localhost:${PORT}`);
  if (ADMINS.size) console.log('Admin accounts: ' + [...ADMINS].join(', '));
});

function shutdown() {
  clearTimeout(saveTimer);
  try { writeNow(); } catch (e) {}
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
