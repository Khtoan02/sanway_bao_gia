const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'server_data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const CATALOG_SEED_FILE = path.join(__dirname, 'catalog.json');

// Khóa bí mật chỉ tồn tại trên Backend Server để ký Token phiên đăng nhập (HMAC-SHA256)
const SECRET_FILE = path.join(DATA_DIR, '.server_secret');

function getOrCreateServerSecret() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (fs.existsSync(SECRET_FILE)) {
    return fs.readFileSync(SECRET_FILE, 'utf8').trim();
  }
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
  return secret;
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
    catalog: getDefaultCatalog(),
    customAssets: {
      stamp: null,
      logo_horizontal: null,
      logo_official: null
    },
    updatedAt: new Date().toISOString()
  };
}

function loadDatabase() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initial = createInitialDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), { mode: 0o600 });
    return initial;
  }
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    // Đảm bảo mọi user đều có pinHash chuẩn 4 số
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
    }
    return db;
  } catch (e) {
    const fallback = createInitialDb();
    fs.writeFileSync(DB_FILE, JSON.stringify(fallback, null, 2), { mode: 0o600 });
    return fallback;
  }
}

function saveDatabase(db) {
  db.updatedAt = new Date().toISOString();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), { mode: 0o600 });
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
    record.lockUntil = now + 60 * 1000; // Khóa 60 giây nếu nhập sai 5 lần
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
    company: db.company,
    catalog: db.catalog,
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

// Chỉ cho phép truy cập các file giao diện tĩnh công khai, chặn tuyệt đối file cấu hình/backend
const ALLOWED_STATIC_FILES = new Set(['/index.html', '/app_data.js']);

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;
  const clientIp = req.socket.remoteAddress || 'unknown';

  // ==================== BACKEND REST API ====================
  if (pathname.startsWith('/api/')) {
    const db = loadDatabase();

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
        const matchedUser = db.users.find(u => u.pinHash === inputHash);
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

    // 2. Kiểm tra phiên đăng nhập hiện hành (Khôi phục phiên từ HttpOnly Cookie / Bearer Token)
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

    // Các API bên dưới bắt buộc phải có quyền Admin hoặc Lãnh đạo (Xác thực trên Backend)
    const token = extractTokenFromReq(req);
    const currentUser = verifySessionToken(token, db);
    if (!currentUser) {
      return sendJson(res, 401, { ok: false, error: 'Chưa xác thực phiên làm việc!' });
    }
    if (currentUser.role !== 'admin' && currentUser.role !== 'leader') {
      return sendJson(res, 403, { ok: false, error: 'Chỉ Admin hoặc Lãnh đạo mới có quyền thực hiện thao tác này!' });
    }

    // 4. Lưu thông tin công ty, bảng giá & con dấu
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
        saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Dữ liệu lưu không hợp lệ!' });
      }
    }

    // 5. Cấp mã PIN 4 số mới cho nhân sự
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
        saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể thêm nhân sự!' });
      }
    }

    // 6. Đổi mã PIN 4 số của nhân sự
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
        saveDatabase(db);

        // Nếu người dùng tự đổi mã PIN của chính mình, cấp lại token mới
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

    // 7. Thu hồi / Xóa mã PIN nhân sự
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
        saveDatabase(db);
        return sendJson(res, 200, { ok: true, ...buildClientPayload(currentUser, db) });
      } catch (err) {
        return sendJson(res, 400, { ok: false, error: 'Không thể xóa nhân sự!' });
      }
    }

    // 8. Khôi phục dữ liệu gốc mặc định
    if (pathname === '/api/system/reset' && req.method === 'POST') {
      const freshDb = createInitialDb();
      saveDatabase(freshDb);
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

    // 9. Nhập cấu hình từ file JSON
    if (pathname === '/api/system/import' && req.method === 'POST') {
      try {
        const imported = await readJsonBody(req);
        if (!imported.company || !Array.isArray(imported.catalog)) {
          return sendJson(res, 400, { ok: false, error: 'File cấu hình không hợp lệ!' });
        }
        db.company = imported.company;
        db.catalog = imported.catalog;
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
        saveDatabase(db);
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
});

server.listen(PORT, () => {
  loadDatabase();
  console.log(`✅ SANWAY Backend Server đang chạy bảo mật tại: http://localhost:${PORT}`);
});
