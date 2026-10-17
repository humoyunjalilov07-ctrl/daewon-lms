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

const PRIVACY_HTML = `<!doctype html><html lang="uz"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Video darslar: maxfiylik siyosati</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:720px;margin:32px auto;padding:0 16px;color:#1b1f23}@media(prefers-color-scheme:dark){body{background:#1c1f24;color:#e8eaed}}</style></head><body>
<h1>Video darslar: maxfiylik siyosati</h1>
<p>Video darslar brauzer kengaytmasi universitet LMS saytlarida video darslarni avtomatik ijro etuvchi skriptlarni yetkazadi.</p>
<h2>Qanday ma'lumotlar yig'iladi</h2>
<ul>
<li><b>Litsenziya kaliti</b> — siz kengaytmaga kiritgan kalit. Uning haqiqiyligini tekshirish uchun serverimizga yuboriladi.</li>
<li><b>Qurilma identifikatori</b> — kengaytma o'zi yaratgan tasodifiy ID. Kalitni bitta qurilmaga bog'lash uchun ishlatiladi.</li>
<li><b>IP manzil va oxirgi faollik vaqti</b> — suiiste'molni aniqlash uchun serverda saqlanadi.</li>
<li><b>LMS akkaunt ID</b> — skript LMS sahifasidan topsa, kalitni shu akkauntga bog'lash uchun yuboriladi.</li>
</ul>
<h2>Nimalar yig'ilmaydi</h2>
<p>Brauzer tarixi, ko'rilgan sahifalar manzili, parollar, sahifa mazmuni va shaxsiy xabarlar yig'ilmaydi va yuborilmaydi. Kengaytma qaysi saytga kirganingizni serverga bildirmaydi.</p>
<h2>Ma'lumotlardan foydalanish</h2>
<p>Ma'lumotlar faqat litsenziyani tekshirish va skriptlarni yetkazish uchun ishlatiladi. Uchinchi tomonlarga sotilmaydi va berilmaydi.</p>
<h2>Saqlash va o'chirish</h2>
<p>Kalit o'chirilganda unga tegishli yozuv serverdan olib tashlanadi. Kengaytmani o'chirsangiz, brauzerdagi barcha saqlangan ma'lumotlar ham o'chadi.</p>
<h2>Aloqa</h2>
<p>Savollar uchun kengaytmani sizga bergan shaxsga murojaat qiling.</p>
</body></html>`;

const ADMIN_HTML =fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');

// ---------------------------------------------------------------- saqlash
function loadDb() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch (_) {
    return { secret: crypto.randomBytes(32).toString('hex'), keys: {} };
  }
}
const db = loadDb();
if (!Array.isArray(db.scripts)) db.scripts = []; // extension foydalanuvchilarga yetkazadigan skriptlar
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
    req.on('data', c => { size += c.length; if (size > 512 * 1024) { reject(new Error('big')); req.destroy(); } else chunks.push(c); });
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

    // Do'konlar (Chrome Web Store, AMO) talab qiladigan maxfiylik siyosati sahifasi.
    if (req.method === 'GET' && url.pathname === '/privacy') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=3600' });
      return res.end(PRIVACY_HTML);
    }

    // Extension skriptlarni shu yerdan oladi: faqat yaroqli kalit chiptasi bilan.
    if (req.method === 'POST' && url.pathname === '/scripts') {
      if (rateLimited(ip)) return send(res, 429, { error: 'Juda ko\'p so\'rov. Biroz kuting.' });
      const body = await readJson(req);
      const claims = verify(body.token);
      if (!claims) return send(res, 401, { error: 'Chipta yaroqsiz yoki eskirgan.' });
      const checked = checkBinding(db.keys[claims.k], body.deviceId, null);
      if (checked.error) return send(res, 403, { error: checked.error });
      return send(res, 200, {
        scripts: db.scripts.filter(x => x.enabled).map(x => ({ id: x.id, name: x.name, version: x.version, matches: x.matches, code: x.code }))
      });
    }

    // Admin sahifa: unda maxfiy narsa yo'q, barcha so'rovlar parol bilan himoyalangan API'ga ketadi.
    if (req.method === 'GET' && (url.pathname === '/admin' || url.pathname === '/admin/')) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-frame-options': 'DENY',
        'referrer-policy': 'no-referrer',
        'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"
      });
      return res.end(ADMIN_HTML);
    }

    if (url.pathname.startsWith('/admin/')) {
      if (!safeEq(req.headers['x-admin-token'] || '', ADMIN_TOKEN)) return send(res, 401, { error: 'Ruxsat yo\'q.' });
      if (req.method === 'GET' && url.pathname === '/admin/keys') return send(res, 200, db.keys);
      if (req.method === 'GET' && url.pathname === '/admin/scripts') return send(res, 200, db.scripts);
      if (req.method !== 'POST') return send(res, 405, { error: 'Method' });
      const body = await readJson(req);
      if (url.pathname === '/admin/scripts') {
        // matches: ["domen.uz", "*.domen.uz"]; kod: userscript matni (sarlavha bo'lsa ham bo'ladi).
        const matches = (Array.isArray(body.matches) ? body.matches : String(body.matches || '').split(/[\s,]+/))
          .map(x => String(x).trim().toLowerCase()).filter(Boolean);
        if (!matches.length || !matches.every(h => /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/.test(h))) {
          return send(res, 400, { error: 'Domenlar noto\'g\'ri (masalan: univer.ac.kr yoki *.univer.ac.kr).' });
        }
        const code = String(body.code || '');
        if (!code.trim() || code.length > 400000) return send(res, 400, { error: 'Skript kodi bo\'sh yoki juda katta.' });
        let rec = body.id && db.scripts.find(x => x.id === body.id);
        if (!rec) { rec = { id: crypto.randomBytes(6).toString('hex'), createdAt: new Date().toISOString(), version: 0 }; db.scripts.push(rec); }
        Object.assign(rec, {
          name: String(body.name || 'Skript').slice(0, 80), matches, code,
          enabled: body.enabled !== false, version: (rec.version || 0) + 1, updatedAt: new Date().toISOString()
        });
        saveDb();
        return send(res, 200, db.scripts);
      }
      if (url.pathname === '/admin/scripts/delete') {
        db.scripts = db.scripts.filter(x => x.id !== body.id);
        saveDb();
        return send(res, 200, db.scripts);
      }
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
      if (url.pathname === '/admin/keys/delete') {
        delete db.keys[body.key]; // butunlay o'chirish: qaytarib bo'lmaydi
        saveDb();
        return send(res, 200, { ok: true });
      }
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
