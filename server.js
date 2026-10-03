// Daewon Video Queue — litsenziya serveri (bog'liqliksiz, faqat Node 18+).
//
// Endpointlar:
//   POST /activate  { key, deviceId, lmsUserId? }  -> { token, exp, config }
//   POST /refresh   { token, deviceId, lmsUserId? } -> { token, exp, config }
//   GET  /health
//   Admin (sarlavha: x-admin-token):
//     GET  /admin/keys
//     POST /admin/keys           { label, days? }        -> yangi kalit
//     POST /admin/keys/revoke    { key }
//     POST /admin/keys/restore   { key }
//     POST /admin/keys/reset     { key }   (qurilma/LMS bog'lanishini tozalaydi)
//
// Muhit o'zgaruvchilari: ADMIN_TOKEN (majburiy), PORT (3000), DATA_FILE, TOKEN_TTL_SEC (3600)

'use strict';
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3000);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
// Livopsda DATA_DIR (/app/data) doimiy papka; mahalliy ishda server yonida saqlanadi.
const DATA_FILE = process.env.DATA_FILE ||
  path.join(process.env.DATA_DIR || __dirname, 'data.json');
const TOKEN_TTL_SEC = Number(process.env.TOKEN_TTL_SEC || 3600);

if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
  console.error('ADMIN_TOKEN o\'rnatilmagan yoki juda qisqa (kamida 16 belgi).');
  process.exit(1);
}

// ---------------------------------------------------------------- saqlash
function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (_) {
    return { secret: crypto.randomBytes(32).toString('hex'), keys: {} };
  }
}
const db = loadDb();
function saveDb() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
saveDb();

// ---------------------------------------------------------------- JWT (HS256)
const b64u = buf => Buffer.from(buf).toString('base64url');
function sign(payload) {
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', db.secret).update(head + '.' + body).digest('base64url');
  return head + '.' + body + '.' + mac;
}
function verify(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const mac = crypto.createHmac('sha256', db.secret).update(parts[0] + '.' + parts[1]).digest();
  const given = Buffer.from(parts[2], 'base64url');
  if (given.length !== mac.length || !crypto.timingSafeEqual(given, mac)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    return payload.exp > Math.floor(Date.now() / 1000) ? payload : null;
  } catch (_) {
    return null;
  }
}

// ---------------------------------------------------------------- yordamchilar
const safeEq = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

// Sodda tezlik cheklovi: IP bo'yicha daqiqasiga 30 so'rov.
const hits = new Map();
function rateLimited(ip) {
  const minute = Math.floor(Date.now() / 60000);
  const rec = hits.get(ip);
  if (!rec || rec.minute !== minute) { hits.set(ip, { minute, n: 1 }); return false; }
  return ++rec.n > 30;
}

// Skript serverdan oladigan sozlama: chiptasiz skriptda bu qismlar yo'q.
const CLIENT_CONFIG = {
  weekLinkSelector: 'a[href*="selectLessonMain"], a[href*="lessonWeekListForm"]',
  cardSelector: '#lessonWeekList .card'
};

function issue(key, rec, ip) {
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SEC;
  rec.lastSeenAt = new Date().toISOString();
  rec.lastIp = ip;
  rec.ips = Array.from(new Set([...(rec.ips || []), ip])).slice(-20);
  saveDb();
  return { token: sign({ k: key, d: rec.deviceId, u: rec.lmsUserId || null, exp }), exp, config: CLIENT_CONFIG };
}

// Kalitni tekshiradi; muvaffaqiyatda { rec } yoki { error } qaytaradi.
function checkBinding(rec, deviceId, lmsUserId) {
  if (!rec) return { error: 'Kalit topilmadi.' };
  if (rec.revoked) return { error: 'Kalit o\'chirilgan.' };
  if (rec.expiresAt && Date.parse(rec.expiresAt) < Date.now()) return { error: 'Kalit muddati tugagan.' };
  if (!deviceId || typeof deviceId !== 'string' || deviceId.length < 8 || deviceId.length > 128) {
    return { error: 'Qurilma ID noto\'g\'ri.' };
  }
  if (!rec.deviceId) rec.deviceId = deviceId;               // birinchi faollashtirish: bog'lash
  else if (!safeEq(rec.deviceId, deviceId)) return { error: 'Kalit boshqa qurilmaga bog\'langan.' };

  if (lmsUserId) {
    const id = String(lmsUserId).slice(0, 64);
    if (!rec.lmsUserId) rec.lmsUserId = id;
    else if (!safeEq(rec.lmsUserId, id)) return { error: 'Kalit boshqa LMS akkauntiga bog\'langan.' };
  }
  return { rec };
}

// ---------------------------------------------------------------- HTTP
function send(res, status, obj) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type, x-admin-token',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify(obj));
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 16 * 1024) { reject(new Error('big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
const newKey = () => {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part = () => Array.from(crypto.randomBytes(4), b => alphabet[b % alphabet.length]).join('');
  return `DW-${part()}-${part()}-${part()}`;
};

const server = http.createServer(async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const url = new URL(req.url, 'http://x');

  try {
    if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, { ok: true });

    if (url.pathname.startsWith('/admin/')) {
      if (!safeEq(req.headers['x-admin-token'] || '', ADMIN_TOKEN)) return send(res, 401, { error: 'Ruxsat yo\'q.' });
      if (req.method === 'GET' && url.pathname === '/admin/keys') return send(res, 200, db.keys);
      if (req.method !== 'POST') return send(res, 405, { error: 'Method' });
      const body = await readJson(req);
      if (url.pathname === '/admin/keys') {
        const key = newKey();
        db.keys[key] = {
          label: String(body.label || '').slice(0, 80),
          createdAt: new Date().toISOString(),
          expiresAt: body.days ? new Date(Date.now() + Number(body.days) * 864e5).toISOString() : null,
          revoked: false, deviceId: null, lmsUserId: null, ips: []
        };
        saveDb();
        return send(res, 200, { key, ...db.keys[key] });
      }
      const rec = db.keys[body.key];
      if (!rec) return send(res, 404, { error: 'Kalit topilmadi.' });
      if (url.pathname === '/admin/keys/revoke') rec.revoked = true;
      else if (url.pathname === '/admin/keys/restore') rec.revoked = false;
      else if (url.pathname === '/admin/keys/reset') { rec.deviceId = null; rec.lmsUserId = null; }
      else return send(res, 404, { error: 'Topilmadi.' });
      saveDb();
      return send(res, 200, { ok: true, ...rec });
    }

    if (req.method === 'POST' && (url.pathname === '/activate' || url.pathname === '/refresh')) {
      if (rateLimited(ip)) return send(res, 429, { error: 'Juda ko\'p so\'rov. Biroz kuting.' });
      const body = await readJson(req);
      let key;
      if (url.pathname === '/refresh') {
        const claims = verify(body.token);
        if (!claims) return send(res, 401, { error: 'Chipta yaroqsiz yoki eskirgan. Kalitni qayta kiriting.' });
        key = claims.k;
      } else {
        key = String(body.key || '').toUpperCase().trim();
      }
      const checked = checkBinding(db.keys[key], body.deviceId, body.lmsUserId);
      if (checked.error) return send(res, 403, { error: checked.error });
      return send(res, 200, issue(key, checked.rec, ip));
    }

    send(res, 404, { error: 'Topilmadi.' });
  } catch (_) {
    send(res, 400, { error: 'So\'rov noto\'g\'ri.' });
  }
});

server.listen(PORT, () => console.log('Litsenziya serveri: port ' + PORT));
