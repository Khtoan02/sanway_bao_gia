const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = process.env.PORT || 3000;
const IS_VERCEL = Boolean(process.env.VERCEL || process.env.VERCEL_ENV);

// Trên Vercel Serverless, thư mục gốc là read-only nên sử dụng os.tmpdir() (/tmp) khi chưa gắn Cloud DB
const DATA_DIR = IS_VERCEL
  ? path.join(os.tmpdir(), 'sanway_server_data')
  : path.join(__dirname, 'server_data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const CATALOG_SEED_FILE = path.join(__dirname, 'catalog.json');
const SECRET_FILE = path.join(DATA_DIR, '.server_secret');

// Cấu hình Vercel KV / Upstash Redis (Tự động nhận diện khi gắn Storage trên Vercel)
const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const KV_KEY = 'sanway_erp_db_v2';

function getOrCreateServerSecret() {
  if (process.env.SANWAY_SECRET) {
    return process.env.SANWAY_SECRET.trim();
  }
  if (IS_VERCEL) {
    // Đảm bảo các Serverless instance khác nhau trên Vercel dùng chung khóa ký HMAC ổn định
    return crypto
      .createHash('sha256')
      .update(`SANWAY_VERCEL_SECRET_${KV_TOKEN || 'DEFAULT_CLUSTER_2026'}`)
      .digest('hex');
  }
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (fs.existsSync(SECRET_FILE)) {
      return fs.readFileSync(SECRET_FILE, 'utf8').trim();
    }
    const secret = crypto.randomBytes(48).toString('hex');
    fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
    return secret;
  } catch (e) {
    return crypto.createHash('sha256').update('SANWAY_FALLBACK_SECRET_2026').digest('hex');
  }
}

const SERVER_SECRET = getOrCreateServerSecret();

function hashPin(pin, salt = 'SANWAY_PIN_SALT_V2') {
  return crypto.pbkdf2Sync(String(pin), salt, 100000, 32, 'sha256').toString('hex');
}

function getDefaultCatalog() {
  try {
    if (fs.existsSync(CATALOG_SEED_FILE)) {
      return JSON.parse(fs.readFileSync(CATALOG_SEED_FILE, 'utf8'));
    }
  } catch (e) {
    console.error('Không thể đọc catalog.json:', e);
  }
  return [];
}

function createInitialDb() {
  const catalog = getDefaultCatalog();
  const subtotal = catalog.reduce((sum, item) => sum + ((item.default_qty || 1) * (item.default_price || 0)), 0);
  const vatRate = 8;
  const vatAmount = Math.round(subtotal * (vatRate / 100));
  const grandTotal = subtotal + vatAmount;

  return {
    company: {
      fullName: 'CÔNG TY CỔ PHẦN SANWAY',
      hotline: '0936.888.666',
      email: 'contact@sanway.vn',
      address: 'KCN Nomura, Huyện An Dương, TP. Hải Phòng',
      directorName: '',
      signerTitle: 'GIÁM ĐỐC',
      vatRate: 8
    },
    users: [
      { id: 'u_admin', name: 'Quản Trị Viên (Admin)', role: 'admin', pin: '9999', pinHash: hashPin('9999') },
      { id: 'u_leader', name: 'Ban Giám Đốc (Lãnh Đạo)', role: 'leader', pin: '8888', pinHash: hashPin('8888') },
      { id: 'u_sale1', name: 'Nhân Viên Kinh Doanh 01', role: 'sale', pin: '1111', pinHash: hashPin('1111') },
      { id: 'u_sale2', name: 'Nhân Viên Kinh Doanh 02', role: 'sale', pin: '2222', pinHash: hashPin('2222') }
    ],
    catalog,
    quotes: [
      {
        id: 'q_default_001',
        quoteCode: 'BGSW/2026/001',
        customerName: 'CÔNG TY TNHH TÂN HUY HOÀNG',
        projectTitle: 'BẢO DƯỠNG HỆ THỐNG PCCC',
        projectTitleEn: 'FIRE PROTECTION SYSTEM MAINTENANCE QUOTATION',
        quoteDate: 'Hải Phòng, 21/10/2026',
        showStamp: 'yes',
        vatRate,
        selectedCount: catalog.length,
        subtotal,
        vatAmount,
        grandTotal,
        createdBy: 'Quản Trị Viên (Admin)',
        createdByRole: 'admin',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        itemsSnapshot: catalog.map(it => ({
          id: it.id,
          category: it.category,
          name: it.name,
          unit: it.unit,
          quantity: it.default_qty || 1,
          price: it.default_price || 0,
          selected: true
        }))
      }
    ],
    customAssets: {
      stamp: null,
      logo_horizontal: null,
      logo_official: null
    },
    updatedAt: new Date().toISOString()
  };
}

function normalizeDbStructure(db) {
  if (!db || typeof db !== 'object') return createInitialDb();
  if (!db.company) db.company = createInitialDb().company;
  if (!Array.isArray(db.catalog)) db.catalog = getDefaultCatalog();
  if (!Array.isArray(db.quotes)) db.quotes = createInitialDb().quotes;
  if (!db.customAssets) db.customAssets = { stamp: null, logo_horizontal: null, logo_official: null };
  if (Array.isArray(db.users)) {
    db.users = db.users.map(u => {
      const pin = String(u.pin || u.password || '1111');
      return {
        id: u.id,
        name: u.name,
        role: u.role,
        pin,
        pinHash: u.pinHash || hashPin(pin)
      };
    });
  } else {
    db.users = createInitialDb().users;
  }
  return db;
}

// Đọc Database: Ưu tiên Upstash Redis / Vercel KV nếu đã kết nối, ngược lại dùng File DB
async function loadDatabase() {
  if (KV_URL && KV_TOKEN) {
    try {
      const res = await fetch(`${KV_URL.replace(/\/$/, '')}/get/${KV_KEY}`, {
        headers: { Authorization: `Bearer ${KV_TOKEN}` }
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.result) {
          const parsed = typeof data.result === 'string' ? JSON.parse(data.result) : data.result;
          return normalizeDbStructure(parsed);
        }
      }
      const initial = createInitialDb();
      await saveDatabase(initial);
      return initial;
    } catch (e) {
      console.error('Lỗi đọc Vercel KV / Upstash Redis, chuyển sang bộ nhớ cục bộ:', e.message);
    }
  }

  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(DB_FILE)) {
      const initial = createInitialDb();
      fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), { mode: 0o600 });
      return initial;
    }
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return normalizeDbStructure(db);
  } catch (e) {
    const fallback = createInitialDb();
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(fallback, null, 2), { mode: 0o600 });
    } catch (err) {}
    return fallback;
  }
}

async function saveDatabase(db) {
  db.updatedAt = new Date().toISOString();
  if (KV_URL && KV_TOKEN) {
    try {
      await fetch(`${KV_URL.replace(/\/$/, '')}/set/${KV_KEY}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${KV_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(db)
      });
    } catch (e) {
      console.error('Lỗi ghi Vercel KV / Upstash Redis:', e.message);
    }
  }
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), { mode: 0o600 });
  } catch (e) {}
}

// Ký và xác thực Session Token (HMAC-SHA256) trên Backend
function createSessionToken(user) {
  const payload = {
    uid: user.id,
    role: user.role,
    ph: user.pinHash.slice(0, 16),
    exp: Date.now() + 12 * 60 * 60 * 1000 // Hết hạn sau 12 giờ
  };
  const dataB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SERVER_SECRET).update(dataB64).digest('base64url');
  return `${dataB64}.${sig}`;
}

function verifySessionToken(token, db) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [dataB64, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SERVER_SECRET).update(dataB64).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(dataB64, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    const matchedUser = db.users.find(u => u.id === payload.uid && u.pinHash.slice(0, 16) === payload.ph);
    return matchedUser || null;
  } catch (e) {
    return null;
  }
}

function extractTokenFromReq(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7).trim();
  }
  const cookieHeader = req.headers['cookie'] || '';
  const match = cookieHeader.match(/(?:^|;\s*)sanway_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// Chống dò mã PIN 4 số (Brute-force Rate Limiter trên Backend)
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
  if (record.lockUntil > now) {
    const waitSec = Math.ceil((record.lockUntil - now) / 1000);
    return { allowed: false, waitSec };
  }
  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
  record.count += 1;
  if (record.count >= 5) {
    record.lockUntil = now + 60 * 1000;
    record.count = 0;
  }
  loginAttempts.set(ip, record);
}

function clearFailedAttempts(ip) {
  loginAttempts.delete(ip);
}

// Lọc dữ liệu trả về theo đúng phân quyền (Sale tuyệt đối không nhận được danh sách nhân sự/PIN)
function buildClientPayload(user, db) {
  const isManager = user.role === 'admin' || user.role === 'leader';
  return {
    user: {
      id: user.id,
      name: user.name,
      role: user.role
    },
    dbMode: (KV_URL && KV_TOKEN) ? 'vercel-kv' : (IS_VERCEL ? 'vercel-tmp' : 'local-server'),
    company: db.company,
    catalog: db.catalog,
    quotes: Array.isArray(db.quotes) ? db.quotes : [],
    customAssets: db.customAssets || { stamp: null, logo_horizontal: null, logo_official: null },
    users: isManager
      ? db.users.map(u => ({ id: u.id, name: u.name, role: u.role, pin: u.pin }))
      : []
  };
}

function sendJson(res, statusCode, body, extraHeaders = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders
  });
  res.end(JSON.stringify(body));
}

function readJsonBody(req, maxBytes = 15 * 1024 * 1024) {
  if (req.body && typeof req.body === 'object') {
    return Promise.resolve(req.body);
  }
  if (typeof req.body === 'string' && req.body.length > 0) {
    try {
      return Promise.resolve(JSON.parse(req.body));
    } catch (e) {
      return Promise.reject(new Error('Invalid JSON'));
    }
  }
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

const ALLOWED_STATIC_FILES = new Set(['/index.html', '/app_data.js']);

async function requestHandler(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const clientIp = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';

  // ==================== BACKEND REST API ====================
  if (pathname.startsWith('/api/')) {
    const db = await loadDatabase();

    // 1. Đăng nhập bằng mã PIN 4 số
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const rl = checkRateLimit(clientIp);
      if (!rl.allowed) {
        return sendJson(res, 429, {
          ok: false,
          error: `Nhập sai quá nhiều lần. Vui lòng thử lại sau ${rl.waitSec} giây!`
        });
      }

      try {
        const { pin } = await readJsonBody(req);
        const cleanPin = String(pin || '').trim();
        if (!/^\d{4}$/.test(cleanPin)) {
          recordFailedAttempt(clientIp);
          return sendJson(res, 400, { ok: false, error: 'Mã PIN phải gồm đúng 4 chữ số!' });
        }

        const inputHash = hashPin(cleanPin);
        const matchedUser = db.users.find(u => {
          const a = Buffer.from(u.pinHash, 'hex');
          const b = Buffer.from(inputHash, 'hex');
          return a.length === b.length && crypto.timingSafeEqual(a, b);
        });

        if (!matchedUser) {
          recordFailedAttempt(clientIp);
          return sendJson(res, 401, { ok: false, error: 'Mã PIN không chính xác!' });
        }

        clearFailedAttempts(clientIp);
        const token = createSessionToken(matchedUser);
        const cookie = `sanway_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=43200; SameSite=Strict`;

        return sendJson(
          res,
          200,
          {
            ok: true,
            token,
            ...buildClientPayload(matchedUser, db)
          },
          { 'Set-Cookie': cookie }
        );
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Yêu cầu không hợp lệ!' });
      }
    }

    // 2. Kiểm tra phiên đăng nhập hiện hành
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const token = extractTokenFromReq(req);
      const user = verifySessionToken(token, db);
      if (!user) {
        return sendJson(res, 401, { ok: false, error: 'Phiên đăng nhập đã hết hạn!' });
      }
      return sendJson(res, 200, {
        ok: true,
        ...buildClientPayload(user, db)
      });
    }

    // 3. Đăng xuất
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const expiredCookie = 'sanway_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict';
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': expiredCookie });
    }

    // Xác thực người dùng đã đăng nhập (Sale, Leader hoặc Admin)
    const token = extractTokenFromReq(req);
    const currentUser = verifySessionToken(token, db);
    if (!currentUser) {
      return sendJson(res, 401, { ok: false, error: 'Chưa xác thực phiên làm việc!' });
    }

    // 4. Lưu / Tạo mới bản Báo giá (Cả Sale, Lãnh đạo và Admin đều được phép tạo & lưu báo giá)
    if (pathname === '/api/quotes/save' && req.method === 'POST') {
      try {
        const rawBody = await readJsonBody(req);
        const quote = rawBody.quote && typeof rawBody.quote === 'object' ? rawBody.quote : rawBody;
        const quoteCode = String(quote.quoteCode || '').trim();
        const customerName = String(quote.customerName || '').trim();
        if (!quoteCode || !customerName) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập Mã báo giá và Tên khách hàng!' });
        }

        if (!Array.isArray(db.quotes)) db.quotes = [];
        const existingIdx = db.quotes.findIndex(q => q.id === quote.id || q.quoteCode === quoteCode);
        const nowIso = new Date().toISOString();

        const record = {
          id: existingIdx !== -1 ? db.quotes[existingIdx].id : (quote.id || 'q_' + Date.now()),
          quoteCode,
          customerName,
          projectTitle: String(quote.projectTitle || 'BẢO DƯỠNG HỆ THỐNG PCCC').trim(),
          projectTitleEn: String(quote.projectTitleEn || 'FIRE PROTECTION SYSTEM MAINTENANCE QUOTATION').trim(),
          quoteDate: String(quote.quoteDate || '').trim(),
          showStamp: quote.showStamp === 'no' ? 'no' : 'yes',
          vatRate: parseFloat(quote.vatRate) || 0,
          selectedCount: parseInt(quote.selectedCount, 10) || 0,
          subtotal: parseFloat(quote.subtotal) || 0,
          vatAmount: parseFloat(quote.vatAmount) || 0,
          grandTotal: parseFloat(quote.grandTotal) || 0,
          createdBy: existingIdx !== -1 ? db.quotes[existingIdx].createdBy : currentUser.name,
          createdByRole: existingIdx !== -1 ? db.quotes[existingIdx].createdByRole : currentUser.role,
          updatedBy: currentUser.name,
          createdAt: existingIdx !== -1 ? db.quotes[existingIdx].createdAt : nowIso,
          updatedAt: nowIso,
          itemsSnapshot: Array.isArray(quote.itemsSnapshot) ? quote.itemsSnapshot : []
        };

        if (existingIdx !== -1) {
          db.quotes[existingIdx] = record;
        } else {
          db.quotes.unshift(record);
        }

        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, savedQuote: record, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể lưu bản báo giá!' });
      }
    }

    // 5. Xóa một bản Báo giá đã lưu
    if (pathname === '/api/quotes/delete' && req.method === 'DELETE') {
      try {
        const { id } = await readJsonBody(req);
        if (!Array.isArray(db.quotes)) db.quotes = [];
        const target = db.quotes.find(q => q.id === id);
        if (!target) {
          return sendJson(res, 404, { ok: false, error: 'Không tìm thấy bản báo giá!' });
        }
        db.quotes = db.quotes.filter(q => q.id !== id);
        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể xóa bản báo giá!' });
      }
    }

    // Các API bên dưới bắt buộc phải có quyền Admin hoặc Lãnh đạo
    if (currentUser.role !== 'admin' && currentUser.role !== 'leader') {
      return sendJson(res, 403, { ok: false, error: 'Chỉ Admin hoặc Lãnh đạo mới có quyền thực hiện thao tác này!' });
    }

    // 6. Lưu thông tin công ty, bảng giá sản phẩm & con dấu
    if (pathname === '/api/system/save' && req.method === 'POST') {
      try {
        const body = await readJsonBody(req);
        if (body.company && typeof body.company === 'object') {
          db.company = {
            fullName: String(body.company.fullName || '').trim(),
            hotline: String(body.company.hotline || '').trim(),
            email: String(body.company.email || '').trim(),
            address: String(body.company.address || '').trim(),
            directorName: '',
            signerTitle: String(body.company.signerTitle || 'GIÁM ĐỐC').trim(),
            vatRate: parseFloat(body.company.vatRate) || 0
          };
        }
        if (Array.isArray(body.catalog)) {
          db.catalog = body.catalog.map((it, idx) => ({
            id: it.id || (idx + 1),
            category: String(it.category || '').trim(),
            name: String(it.name || '').trim(),
            unit: String(it.unit || '').trim(),
            default_qty: parseFloat(it.default_qty !== undefined ? it.default_qty : it.quantity) || 1,
            default_price: parseFloat(it.default_price !== undefined ? it.default_price : it.price) || 0
          }));
        }
        if (body.customAssets && typeof body.customAssets === 'object') {
          db.customAssets = {
            stamp: body.customAssets.stamp || null,
            logo_horizontal: body.customAssets.logo_horizontal || null,
            logo_official: body.customAssets.logo_official || null
          };
        }
        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Dữ liệu lưu không hợp lệ!' });
      }
    }

    // 7. Cấp mã PIN 4 số mới cho nhân sự
    if (pathname === '/api/users/add' && req.method === 'POST') {
      try {
        const { name, role, pin } = await readJsonBody(req);
        const cleanName = String(name || '').trim();
        const cleanRole = ['admin', 'leader', 'sale'].includes(role) ? role : 'sale';
        const cleanPin = String(pin || '').trim();

        if (!cleanName || !/^\d{4}$/.test(cleanPin)) {
          return sendJson(res, 400, { ok: false, error: 'Vui lòng nhập tên nhân sự và mã PIN đúng 4 chữ số!' });
        }
        const newHash = hashPin(cleanPin);
        if (db.users.some(u => u.pinHash === newHash)) {
          return sendJson(res, 409, { ok: false, error: 'Mã PIN 4 số này đã được cấp cho người khác!' });
        }

        db.users.push({
          id: 'u_' + Date.now(),
          name: cleanName,
          role: cleanRole,
          pin: cleanPin,
          pinHash: newHash
        });
        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể thêm nhân sự!' });
      }
    }

    // 8. Đổi mã PIN 4 số của nhân sự
    if (pathname === '/api/users/update' && req.method === 'PUT') {
      try {
        const { id, pin } = await readJsonBody(req);
        const cleanPin = String(pin || '').trim();
        if (!/^\d{4}$/.test(cleanPin)) {
          return sendJson(res, 400, { ok: false, error: 'Mã PIN phải gồm đúng 4 chữ số (0000 - 9999)!' });
        }
        const targetIdx = db.users.findIndex(u => u.id === id);
        if (targetIdx === -1) {
          return sendJson(res, 404, { ok: false, error: 'Không tìm thấy nhân sự!' });
        }
        const newHash = hashPin(cleanPin);
        if (db.users.some((u, idx) => idx !== targetIdx && u.pinHash === newHash)) {
          return sendJson(res, 409, { ok: false, error: 'Mã PIN 4 số này bị trùng với người khác!' });
        }

        db.users[targetIdx].pin = cleanPin;
        db.users[targetIdx].pinHash = newHash;
        await saveDatabase(db);

        const updatedSelf = db.users[targetIdx].id === currentUser.id ? db.users[targetIdx] : currentUser;
        const newToken = createSessionToken(updatedSelf);
        const cookie = `sanway_session=${encodeURIComponent(newToken)}; HttpOnly; Path=/; Max-Age=43200; SameSite=Strict`;

        return sendJson(
          res,
          200,
          { ok: true, token: newToken, ...buildClientPayload(updatedSelf, db) },
          { 'Set-Cookie': cookie }
        );
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể cập nhật mã PIN!' });
      }
    }

    // 9. Thu hồi / Xóa mã PIN nhân sự
    if (pathname === '/api/users/delete' && req.method === 'DELETE') {
      try {
        const { id } = await readJsonBody(req);
        const target = db.users.find(u => u.id === id);
        if (!target) {
          return sendJson(res, 404, { ok: false, error: 'Không tìm thấy nhân sự!' });
        }
        const managersCount = db.users.filter(u => u.role === 'admin' || u.role === 'leader').length;
        if ((target.role === 'admin' || target.role === 'leader') && managersCount <= 1) {
          return sendJson(res, 400, { ok: false, error: 'Phải giữ lại ít nhất 1 mã PIN Admin hoặc Lãnh đạo!' });
        }
        db.users = db.users.filter(u => u.id !== id);
        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể xóa nhân sự!' });
      }
    }

    // 10. Khôi phục dữ liệu gốc mặc định
    if (pathname === '/api/system/reset' && req.method === 'POST') {
      const freshDb = createInitialDb();
      await saveDatabase(freshDb);
      const adminUser = freshDb.users[0];
      const token = createSessionToken(adminUser);
      const cookie = `sanway_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=43200; SameSite=Strict`;
      return sendJson(
        res,
        200,
        { ok: true, token, ...buildClientPayload(adminUser, freshDb) },
        { 'Set-Cookie': cookie }
      );
    }

    // 11. Nhập cấu hình từ file JSON
    if (pathname === '/api/system/import' && req.method === 'POST') {
      try {
        const imported = await readJsonBody(req);
        if (!imported.company || !Array.isArray(imported.catalog)) {
          return sendJson(res, 400, { ok: false, error: 'File cấu hình không hợp lệ!' });
        }
        db.company = imported.company;
        db.catalog = imported.catalog;
        if (Array.isArray(imported.quotes)) db.quotes = imported.quotes;
        if (imported.customAssets) db.customAssets = imported.customAssets;
        if (Array.isArray(imported.users) && imported.users.length > 0) {
          db.users = imported.users.map(u => {
            const p = String(u.pin || u.password || '1111').trim();
            return {
              id: u.id || ('u_' + Date.now() + Math.random()),
              name: u.name || 'Nhân sự',
              role: u.role || 'sale',
              pin: p,
              pinHash: hashPin(p)
            };
          });
        }
        await saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể nhập file cấu hình!' });
      }
    }

    return sendJson(res, 404, { ok: false, error: 'API không tồn tại!' });
  }

  // ==================== PHỤC VỤ FILE GIAO DIỆN TĨNH (BẢO VỆ MÃ NGUỒN BACKEND) ====================
  const normalizedPath = pathname === '/' ? '/index.html' : pathname;
  if (!ALLOWED_STATIC_FILES.has(normalizedPath)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden - Access Denied by SANWAY Security Policy');
  }

  const filePath = path.join(__dirname, normalizedPath);
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8'
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 Not Found');
    }
    res.writeHead(200, {
      'Content-Type': mimeTypes[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN'
    });
    res.end(content);
  });
}

// Nếu chạy trực tiếp bằng lệnh `node server.js`, khởi chạy HTTP Server
if (require.main === module) {
  const server = http.createServer(requestHandler);
  server.listen(PORT, async () => {
    await loadDatabase();
    console.log(`✅ SANWAY Backend Server đang chạy bảo mật tại: http://localhost:${PORT}`);
  });
}

module.exports = requestHandler;
