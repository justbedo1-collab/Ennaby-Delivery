require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// تفعيل trust proxy لقراءة الـ IP الحقيقي للعميل بدقة خلف خوادم Vercel
app.set('trust proxy', 1);

// ==========================================
// 1. إعداد الاتصال بـ Supabase و Web Push
// ==========================================
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
// [FIX-01] قراءة مفتاح Supabase العام فقط وحظر أي سقوط احتياطي على المفتاح السري نهائياً
const rawAnonKey = (process.env.APP_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '').trim();
const SUPABASE_ANON_KEY = (rawAnonKey && !rawAnonKey.startsWith('sb_secret_') && rawAnonKey !== SUPABASE_KEY) ? rawAnonKey : '';

// اشتقاق مفتاح التشفير криптоجرافياً من متغيرات البيئة السرية دون كشف أي نص ثابت في الكود ودون تعطيل السيرفر
const JWT_SECRET = (process.env.JWT_SECRET || '').trim() ||
  crypto.createHmac('sha256', String(SUPABASE_KEY || 'ENNABY_FALLBACK_SEED')).update('ENNABY_JWT_SIGNING_KEY_V35').digest('hex');

const CAPTAIN_DOCS_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'captain-docs';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const DEFAULT_VAPID_PUBLIC = 'BOyNefapT_wxw5HHpZFaPsQvyj9OIfV9owv8-9cJd5RMcfdGMK9c0j7D8zv1nNlWBd2K6DB-1v_YhzW2z2xxklc';
const DEFAULT_VAPID_PRIVATE = 'KvjK8OyYPhFEUdIOgmPEBqxgAMw48AU98sI4GfYTeqw';

let VAPID_PRIVATE_KEY = String(process.env.VAPID_PRIVATE_KEY || DEFAULT_VAPID_PRIVATE).trim();
let VAPID_PUBLIC_KEY = String(process.env.VAPID_PUBLIC_KEY || DEFAULT_VAPID_PUBLIC).trim();

// اشتقاق المفتاح العام رياضياً من المفتاح الخاص لضمان التطابق 100% ومنع خطأ 401/403 من جوجل وأبل
try {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(VAPID_PRIVATE_KEY, 'base64url'));
  const derivedPub = ecdh.getPublicKey(null, 'uncompressed').toString('base64url');
  if (derivedPub && derivedPub !== VAPID_PUBLIC_KEY) {
    VAPID_PUBLIC_KEY = derivedPub;
  }
  webpush.setVapidDetails('mailto:support@ennaby.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} catch (err) {
  console.warn('⚠️ WebPush fallback to verified default keys:', err.message);
  VAPID_PUBLIC_KEY = DEFAULT_VAPID_PUBLIC;
  VAPID_PRIVATE_KEY = DEFAULT_VAPID_PRIVATE;
  try {
    webpush.setVapidDetails('mailto:support@ennaby.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
  } catch (e) {}
}

// تغليف المسارات غير المتزامنة لمنع أي Request معلّق أو Unhandled Rejection
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// توليد بصمة مشفرة قصيرة من هاش الباسورد أو الـ PIN لإبطال الجلسات القديمة تلقائياً فور تغيير الباسورد أو الـ PIN
function getPasswordSignature(hashStr) {
  if (!hashStr || typeof hashStr !== 'string') return 'v1';
  return crypto.createHash('sha256').update(hashStr).digest('hex').slice(0, 12);
}

// ==========================================
// 2. إعدادات الحماية القياسية (Security Headers) ودرع مكافحة الإغراق (Rate Limiting)
// ==========================================
const apiRateLimitBuckets = new Map();

function getClientIp(req) {
  return String(req.ip || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'anon')
    .split(',')[0]
    .trim();
}

function createIpRateLimiter(maxRequests, windowMs, errorMessage) {
  return (req, res, next) => {
    try {
      const ip = getClientIp(req);
      const routeScope = `${req.baseUrl || ''}${req.path || ''}` || req.originalUrl || '/';
      const key = `${routeScope}:${ip}`;
      const now = Date.now();
      const record = apiRateLimitBuckets.get(key);

      if (!record || now - record.start > windowMs) {
        apiRateLimitBuckets.set(key, { count: 1, start: now });
        if (apiRateLimitBuckets.size > 3000) {
          for (const [k, v] of apiRateLimitBuckets.entries()) {
            if (now - v.start > windowMs) apiRateLimitBuckets.delete(k);
          }
        }
        return next();
      }

      record.count += 1;
      if (record.count > maxRequests) {
        return res.status(429).json({
          success: false,
          message: errorMessage || 'طلبات كثيرة متتالية في وقت قصير، يرجى الانتظار دقيقة والمحاولة مجدداً ⏳⚠️'
        });
      }
      next();
    } catch (e) {
      next();
    }
  };
}

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(self), microphone=()');
  if (IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net data:; img-src 'self' data: blob: https: http: https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://*.basemaps.cartocdn.com; connect-src 'self' https://nominatim.openstreetmap.org https://*.tile.openstreetmap.org https://tile.openstreetmap.org https://*.basemaps.cartocdn.com https://*.supabase.co wss://*.supabase.co https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'self';"
  );
  next();
});

// حماية المسارات العامة الحساسة ضد التخمين أو الإغراق الآلي (Bots)
app.use('/api/promo-codes/validate', createIpRateLimiter(12, 60 * 1000, 'حاولت تجربة أكواد كثيرة بسرعة يا باشا.. انتظر دقيقة وجرب تاني 🎟️⏳'));
app.use('/api/orders', createIpRateLimiter(15, 60 * 1000, 'تم إرسال طلبات متتالية كثيرة، انتظر لحظات وحاول مجدداً 🛵⏳'));
app.use('/api/captains/register', createIpRateLimiter(6, 10 * 60 * 1000, 'تم إرسال عدة طلبات تسجيل من نفس الجهاز، يرجى الانتظار قليلاً ⏳'));
app.use('/api/auth', createIpRateLimiter(20, 60 * 1000, 'محاولات دخول متتالية كثيرة، انتظر دقيقة وحاول مجدداً 🔒⏳'));

const allowedOriginsList = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (!IS_PRODUCTION && allowedOriginsList.length === 0) return callback(null, true);
    if (allowedOriginsList.includes(origin) || origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true
}));
app.use(express.json({ limit: '25mb' }));
app.use(cookieParser());

// مسارات صريحة لضمان قيام Vercel Node File Tracer بتضمين ملفات مجلد private و public
const EXPLICIT_HTML_PATHS = {
  'index.html': [
    path.join(__dirname, 'index.html'),
    path.join(__dirname, 'public', 'index.html'),
    path.join(process.cwd(), 'index.html'),
    path.join(process.cwd(), 'public', 'index.html')
  ],
  'admin.html': [
    path.join(__dirname, 'private', 'admin.html'),
    path.join(process.cwd(), 'private', 'admin.html'),
    path.join(__dirname, 'admin.html'),
    path.join(__dirname, 'public', 'admin.html'),
    path.join(process.cwd(), 'admin.html'),
    path.join(process.cwd(), 'public', 'admin.html')
  ],
  'install.html': [
    path.join(__dirname, 'install.html'),
    path.join(__dirname, 'public', 'install.html'),
    path.join(__dirname, 'private', 'install.html'),
    path.join(process.cwd(), 'install.html'),
    path.join(process.cwd(), 'public', 'install.html')
  ]
};

function resolveHtmlFilePath(filename) {
  const candidates = EXPLICIT_HTML_PATHS[filename] || [
    path.join(__dirname, filename),
    path.join(__dirname, 'private', filename),
    path.join(__dirname, 'public', filename)
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return candidates[0];
}

// [NEW-SEC-01] تقديم ملفات الواجهة والـ PWA المسموحة فقط مع منع تخزين sw.js في الكاش لضمان عمل الإشعارات فوراً
const ALLOWED_PUBLIC_ASSETS = ['sw.js', 'manifest.json', 'icon-192.png', 'icon-512.png', 'logo-1.png', 'logo-1.jpg'];
ALLOWED_PUBLIC_ASSETS.forEach((assetName) => {
  app.get(`/${assetName}`, (req, res) => {
    if (assetName === 'sw.js') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Service-Worker-Allowed', '/');
    } else if (assetName === 'manifest.json') {
      res.setHeader('Cache-Control', 'no-cache');
    }
    const pubPath = path.join(__dirname, 'public', assetName);
    const rootPath = path.join(__dirname, assetName);
    if (fs.existsSync(pubPath)) return res.sendFile(pubPath);
    if (fs.existsSync(rootPath)) return res.sendFile(rootPath);
    if (assetName === 'logo-1.png') {
      const jpgFallback = fs.existsSync(path.join(__dirname, 'public', 'logo-1.jpg'))
        ? path.join(__dirname, 'public', 'logo-1.jpg')
        : path.join(__dirname, 'logo-1.jpg');
      if (fs.existsSync(jpgFallback)) return res.sendFile(jpgFallback);
    }
    res.status(404).end();
  });
});

app.get('/', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));
app.get('/index.html', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));

app.get(['/admin', '/admins', '/admin.html', '/private/admin.html'], (req, res) => {
  res.sendFile(resolveHtmlFilePath('admin.html'));
});

app.get(['/install', '/install.html'], (req, res) => {
  res.sendFile(resolveHtmlFilePath('install.html'));
});

if (fs.existsSync(path.join(__dirname, 'public'))) {
  app.use(express.static(path.join(__dirname, 'public')));
}

// ==========================================
// 3. دوال مساعدة، تتبع المتواجدين، ومستويات الكباتن
// ==========================================
const DEFAULT_ZONES = ['المنصورة', 'طلخا', 'سندوب', 'جديلة'];
const DEFAULT_PACKAGE_TYPES = [
  'طرد خفيف (أقل من 3 كجم) - شنطة أو ورق',
  'طرد متوسط (3 إلى 8 كجم) - كرتونة',
  'أكل أو حلويات (حاجة حساسة ع الميزان)'
];
const DEFAULT_PRICING = {
  'المنصورة|المنصورة': 40, 'طلخا|طلخا': 35, 'سندوب|سندوب': 35, 'جديلة|جديلة': 35,
  'المنصورة|طلخا': 50, 'طلخا|المنصورة': 50, 'المنصورة|سندوب': 50, 'سندوب|المنصورة': 50,
  'المنصورة|جديلة': 50, 'جديلة|المنصورة': 50, 'طلخا|سندوب': 70, 'سندوب|طلخا': 70,
  'طلخا|جديلة': 70, 'جديلة|طلخا': 70, 'سندوب|جديلة': 70, 'جديلة|سندوب': 70
};

const ACTIVE_COURIER_ORDER_STATUSES = [
  'تم قبول الطلب',
  'الكابتن وصل للاستلام',
  'استلم الطرد وفي السكة',
  'الكابتن وصل للتسليم'
];

const ALLOWED_ADVANCE_STATUSES = [
  'الكابتن وصل للاستلام',
  'استلم الطرد وفي السكة',
  'الكابتن وصل للتسليم'
];

// [NEW-LOGIC-01] خريطة التسلسل الإجباري لحالات خط سير الطلب
const REQUIRED_PREV_STATUS_FOR_ADVANCE = {
  'الكابتن وصل للاستلام': 'تم قبول الطلب',
  'استلم الطرد وفي السكة': 'الكابتن وصل للاستلام',
  'الكابتن وصل للتسليم': 'استلم الطرد وفي السكة'
};

// خريطة تتبع العملاء المتواجدين حالياً على المنصة (Presence Heartbeat)
const customerPresenceMap = new Map();
const PRESENCE_TTL_MS = 45000; // 45 ثانية

// أقفال تزامن لمنع تجاوز الحد الأقصى لاستخدام الكوبون بالطلبات المتزامنة، ومنع تكرار إشعارات Push اللحظية
const promoRedeemLocks = new Set();
const recentAdminPushDedupeMap = new Map();

function touchCustomerPresence(req, explicitClientId = null) {
  try {
    if (isRequestFromAdminView(req)) return;
    const roleParam = String((req.query && req.query.role) || (req.body && req.body.role) || '').toLowerCase();
    if (roleParam === 'courier' || roleParam === 'admin') return;

    let key = explicitClientId || (req.query && req.query.clientId) || (req.body && req.body.clientId) || '';
    if (!key && req.cookies && req.cookies.customer_session) {
      try {
        const dec = jwt.verify(req.cookies.customer_session, JWT_SECRET);
        if (dec && dec.phone) key = `cust_${dec.phone}`;
      } catch (e) {}
    }
    if (!key) {
      const ip = getClientIp(req);
      const ua = String(req.headers['user-agent'] || '').slice(0, 48);
      key = `anon_${ip}_${ua}`;
    }
    customerPresenceMap.set(String(key), Date.now());
  } catch (e) {}
}

function getOnlineCustomersCount() {
  const now = Date.now();
  let count = 0;
  for (const [k, ts] of customerPresenceMap.entries()) {
    if (now - ts <= PRESENCE_TTL_MS) {
      count++;
    } else {
      customerPresenceMap.delete(k);
    }
  }
  return count;
}

function roundMoney(val) {
  if (val === null || val === undefined || val === '') return 0;
  const cleanStr = String(val)
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
    .trim();
  const num = Number(cleanStr);
  if (!Number.isFinite(num)) return 0;
  return Math.round((num + Number.EPSILON) * 100) / 100;
}

function normalizePhoneServer(raw) {
  if (raw === null || raw === undefined) return '';
  let s = String(raw)
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
    .replace(/[\s\-()]/g, '');
  if (s.startsWith('+20')) s = '0' + s.slice(3);
  else if (s.startsWith('0020')) s = '0' + s.slice(4);
  else if (s.startsWith('20') && s.length === 12) s = '0' + s.slice(2);
  return s;
}

function isValidEgyptianPhoneServer(phone) {
  return /^01[0125][0-9]{8}$/.test(normalizePhoneServer(phone));
}

function formatArabicTripsText(count) {
  const n = Math.max(1, Number(count) || 2);
  if (n === 1) return 'مشوار واحد';
  if (n === 2) return 'مشوارين';
  if (n >= 3 && n <= 10) return `${n} مشاوير`;
  return `${n} مشوار`;
}

function formatCairoTime(dateInput = Date.now()) {
  try {
    return new Date(dateInput).toLocaleString('ar-EG', {
      timeZone: 'Africa/Cairo',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (e) {
    return new Date(dateInput).toLocaleTimeString('ar-EG');
  }
}

// استخراج تاريخ اليوم بتوقيت القاهرة بصيغة YYYY-MM-DD لتخزين مؤشرات الأداء السنوية (365 يوماً)
function getCairoDateKey(dateInput = Date.now()) {
  try {
    const d = new Date(dateInput);
    if (isNaN(d.getTime())) return new Date().toISOString().slice(0, 10);
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Africa/Cairo',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }).formatToParts(d);
    const y = parts.find(p => p.type === 'year')?.value;
    const m = parts.find(p => p.type === 'month')?.value;
    const day = parts.find(p => p.type === 'day')?.value;
    if (y && m && day) return `${y}-${m}-${day}`;
  } catch (e) {}
  return new Date().toISOString().slice(0, 10);
}

// دوال مساعدة لحساب عدد مرات استخدام الكوبون لكل عميل بدقة وتوافق مع السجل القديم
function getPromoMaxUsesForPhone(promo) {
  if (!promo) return 1;
  const isCustomTarget = Boolean(promo.targetPhone && promo.targetPhone !== 'all');
  if (isCustomTarget) {
    return Math.max(1, parseInt(promo.maxUses, 10) || 1);
  }
  return Math.max(1, parseInt(promo.maxUses, 10) || 1);
}

function getPromoPhoneUsedCount(promo, phone) {
  const cleanPh = normalizePhoneServer(phone);
  if (!promo || !cleanPh) return 0;
  if (promo.usageCounts && typeof promo.usageCounts === 'object' && promo.usageCounts[cleanPh] !== undefined) {
    return Math.max(0, parseInt(promo.usageCounts[cleanPh], 10) || 0);
  }
  const usedBy = Array.isArray(promo.usedBy) ? promo.usedBy : [];
  return usedBy.filter(p => normalizePhoneServer(p) === cleanPh).length;
}

function normalizePromoCodeObject(promo) {
  if (!promo || typeof promo !== 'object') return null;
  const cleanTarget = (!promo.targetPhone || promo.targetPhone === 'all') ? 'all' : normalizePhoneServer(promo.targetPhone);
  const maxUses = cleanTarget === 'all' ? 1 : Math.max(1, parseInt(promo.maxUses, 10) || 1);
  const rawCounts = (promo.usageCounts && typeof promo.usageCounts === 'object') ? { ...promo.usageCounts } : {};
  const rawUsedBy = Array.isArray(promo.usedBy) ? promo.usedBy : [];

  rawUsedBy.forEach(ph => {
    const cPh = normalizePhoneServer(ph);
    if (cPh && rawCounts[cPh] === undefined) {
      rawCounts[cPh] = 1;
    }
  });

  const normalizedCounts = {};
  Object.entries(rawCounts).forEach(([ph, cnt]) => {
    const cPh = normalizePhoneServer(ph);
    const nCnt = Math.max(0, parseInt(cnt, 10) || 0);
    if (cPh && nCnt > 0) normalizedCounts[cPh] = nCnt;
  });

  const syncedUsedBy = Object.keys(normalizedCounts).filter(ph => normalizedCounts[ph] >= maxUses);

  return {
    ...promo,
    code: String(promo.code || '').trim().toUpperCase(),
    discountAmount: roundMoney(promo.discountAmount || 0),
    targetPhone: cleanTarget,
    maxUses,
    usageCounts: normalizedCounts,
    usedBy: syncedUsedBy
  };
}

// تنظيف وتجميع بيانات مؤشرات الأداء لمدة 400 يوم (شاملاً الطلبات المؤكدة، التحميلات، العملاء، والكباتن)
function sanitizeAnalyticsHistory(rawHistory = {}, rawCustomersRows = [], rawCaptainsRows = [], rawOrdersRows = []) {
  const cutoffMs = Date.now() - 400 * 24 * 60 * 60 * 1000;
  const cutoffKey = getCairoDateKey(cutoffMs);

  const cleanBucket = (bucket) => {
    const out = {};
    if (bucket && typeof bucket === 'object') {
      for (const [k, v] of Object.entries(bucket)) {
        if (/^\d{4}-\d{2}-\d{2}$/.test(k) && k >= cutoffKey) {
          const num = Math.max(0, Number(v) || 0);
          if (num > 0) out[k] = num;
        }
      }
    }
    return out;
  };

  const installs = cleanBucket(rawHistory.installs);
  const customers = cleanBucket(rawHistory.customers);
  const captains = cleanBucket(rawHistory.captains);
  const completedOrders = cleanBucket(rawHistory.completedOrders);

  const dbCustCounts = {};
  (rawCustomersRows || []).forEach(r => {
    if (r && r.created_at) {
      const k = getCairoDateKey(r.created_at);
      if (k >= cutoffKey) dbCustCounts[k] = (dbCustCounts[k] || 0) + 1;
    }
  });
  for (const [k, cnt] of Object.entries(dbCustCounts)) {
    customers[k] = Math.max(customers[k] || 0, cnt);
  }

  const dbCapCounts = {};
  (rawCaptainsRows || []).forEach(r => {
    if (r && r.created_at) {
      const k = getCairoDateKey(r.created_at);
      if (k >= cutoffKey) dbCapCounts[k] = (dbCapCounts[k] || 0) + 1;
    }
  });
  for (const [k, cnt] of Object.entries(dbCapCounts)) {
    captains[k] = Math.max(captains[k] || 0, cnt);
  }

  const dbOrdCounts = {};
  (rawOrdersRows || []).forEach(r => {
    if (r && r.status === 'مكتمل') {
      const ts = r.created_at || r.createdAt;
      if (ts) {
        const k = getCairoDateKey(ts);
        if (k >= cutoffKey) dbOrdCounts[k] = (dbOrdCounts[k] || 0) + 1;
      }
    }
  });
  for (const [k, cnt] of Object.entries(dbOrdCounts)) {
    completedOrders[k] = Math.max(completedOrders[k] || 0, cnt);
  }

  return { installs, customers, captains, completedOrders };
}

// تسجيل حدث إحصائي جديد (installs | customers | captains | completedOrders) في سجل الـ 365 يوماً
async function recordAnalyticsMetricEvent(metricType, incrementBy = 1, extraPartialIncentives = {}) {
  try {
    const rawState = await fetchRawDatabaseState(true);
    const prevSettings = rawState.settings || {};
    const todayKey = getCairoDateKey();
    const rawSavedHistory = (rawState.storedIncentives && rawState.storedIncentives.analyticsHistory) || {};
    const hadSavedToday = Boolean(rawSavedHistory[metricType] && rawSavedHistory[metricType][todayKey] !== undefined);
    const prevSavedVal = Number(rawSavedHistory[metricType]?.[todayKey]) || 0;

    const history = sanitizeAnalyticsHistory(
      prevSettings.analyticsHistory || {},
      rawState.rawCustomersRows || [],
      rawState.rawCaptains || [],
      rawState.rawOrdersRows || rawState.orders || []
    );
    const inc = Math.max(1, Number(incrementBy) || 1);

    if (!history[metricType]) history[metricType] = {};
    const dbSyncedVal = Number(history[metricType][todayKey]) || 0;
    history[metricType][todayKey] = hadSavedToday
      ? Math.max(prevSavedVal + inc, dbSyncedVal)
      : (dbSyncedVal > 0 ? dbSyncedVal : inc);

    const partial = { ...extraPartialIncentives, analyticsHistory: history };
    if (metricType === 'installs') {
      const sumInstalls = Object.values(history.installs).reduce((a, b) => a + (Number(b) || 0), 0);
      partial.appInstallsCount = Math.max((Number(prevSettings.appInstallsCount) || 0) + inc, sumInstalls);
    }

    await saveIncentivesToDatabase(rawState, partial);
    invalidateStateCache();
    return partial.appInstallsCount || prevSettings.appInstallsCount || 0;
  } catch (e) {
    console.warn('Analytics record warning:', e.message);
    return 0;
  }
}

// دوال ترميز وفك ترميز إحداثيات الخريطة والكوبون وعروض التفاوض داخل ملاحظات الطلب بأمان تام
function stripMetaAndBrokenBrackets(text) {
  let s = String(text || '');
  const metaIdx = s.indexOf('[META:{');
  if (metaIdx !== -1) {
    s = s.slice(0, metaIdx);
  }
  return s
    .replace(/\s*\[META:\{[\s\S]*\}\]/g, '')
    .replace(/(?:\s*[\]}]){2,}\s*$/g, '')
    .replace(/^[\]}\s]+$/g, '')
    .trim();
}

function encodeOrderMetaIntoNotes(rawNotes, meta = {}) {
  const cleanNotes = stripMetaAndBrokenBrackets(rawNotes);
  const payload = {};
  if (Number.isFinite(Number(meta.pickupLat)) && Number.isFinite(Number(meta.pickupLng))) {
    payload.plat = Number(Number(meta.pickupLat).toFixed(6));
    payload.plng = Number(Number(meta.pickupLng).toFixed(6));
  }
  if (Number.isFinite(Number(meta.dropoffLat)) && Number.isFinite(Number(meta.dropoffLng))) {
    payload.dlat = Number(Number(meta.dropoffLat).toFixed(6));
    payload.dlng = Number(Number(meta.dropoffLng).toFixed(6));
  }
  if (meta.promoCode) payload.c = String(meta.promoCode).trim().toUpperCase();
  if (meta.promoDiscount > 0) payload.cd = roundMoney(meta.promoDiscount);
  if (meta.walletDiscount > 0) payload.wd = roundMoney(meta.walletDiscount);
  if (meta.surgePercent > 0) payload.sp = Number(meta.surgePercent);
  if (meta.routeDefaultFare > 0) payload.rf = roundMoney(meta.routeDefaultFare);
  if (meta.customerProposedFare > 0) payload.cf = roundMoney(meta.customerProposedFare);
  if (meta.purchaseBudget) payload.bg = String(meta.purchaseBudget).trim();
  if (Number.isFinite(Number(meta.arrivedAt)) && Number(meta.arrivedAt) > 0) payload.at = Number(meta.arrivedAt);
  if (Number.isFinite(Number(meta.lastBuzzAt)) && Number(meta.lastBuzzAt) > 0) payload.bz = Number(meta.lastBuzzAt);
  if (Array.isArray(meta.captainOffers) && meta.captainOffers.length > 0) {
    payload.of = meta.captainOffers.slice(0, 15);
  }

  if (Object.keys(payload).length === 0) return cleanNotes;
  return `${cleanNotes} [META:${JSON.stringify(payload)}]`.trim();
}

function decodeOrderMetaFromNotes(storedNotes) {
  const raw = String(storedNotes || '');
  let meta = {};
  const metaStartIdx = raw.lastIndexOf('[META:{');
  if (metaStartIdx !== -1) {
    const metaSub = raw.slice(metaStartIdx);
    const closeIdx = metaSub.lastIndexOf('}]');
    if (closeIdx !== -1) {
      const jsonCandidate = metaSub.slice(6, closeIdx + 1);
      try {
        meta = JSON.parse(jsonCandidate);
      } catch (e) {
        const greedyMatch = metaSub.match(/\[META:(\{[\s\S]*\})\]/);
        if (greedyMatch && greedyMatch[1]) {
          try { meta = JSON.parse(greedyMatch[1]); } catch (err) {}
        }
      }
    }
  }
  const cleanNotes = stripMetaAndBrokenBrackets(raw);
  const pLat = meta.plat !== undefined ? Number(meta.plat) : (Array.isArray(meta.p) ? Number(meta.p[0]) : null);
  const pLng = meta.plng !== undefined ? Number(meta.plng) : (Array.isArray(meta.p) ? Number(meta.p[1]) : null);
  const dLat = meta.dlat !== undefined ? Number(meta.dlat) : (Array.isArray(meta.d) ? Number(meta.d[0]) : null);
  const dLng = meta.dlng !== undefined ? Number(meta.dlng) : (Array.isArray(meta.d) ? Number(meta.d[1]) : null);
  return {
    cleanNotes,
    pickupLat: Number.isFinite(pLat) ? pLat : null,
    pickupLng: Number.isFinite(pLng) ? pLng : null,
    dropoffLat: Number.isFinite(dLat) ? dLat : null,
    dropoffLng: Number.isFinite(dLng) ? dLng : null,
    promoCode: meta.c || null,
    promoDiscount: roundMoney(meta.cd || 0),
    walletDiscount: roundMoney(meta.wd || 0),
    surgePercent: Number(meta.sp || 0),
    routeDefaultFare: meta.rf !== undefined ? roundMoney(meta.rf) : null,
    customerProposedFare: meta.cf !== undefined ? roundMoney(meta.cf) : null,
    purchaseBudget: meta.bg || null,
    arrivedAt: meta.at ? Number(meta.at) : null,
    lastBuzzAt: meta.bz ? Number(meta.bz) : null,
    captainOffers: Array.isArray(meta.of) ? meta.of : []
  };
}

// فحص حالة وقت الذروة (Surge Pricing)
function getActiveSurgeInfo(settings) {
  const now = Date.now();
  const endTime = Number(settings?.surgeEndTime || 0);
  const percent = Math.max(0, Number(settings?.surgePercent || 0));
  const isActive = Boolean(endTime > now && percent > 0);
  return {
    isActive,
    surgePercent: isActive ? percent : 0,
    surgeEndTime: isActive ? endTime : 0,
    remainingMinutes: isActive ? Math.max(1, Math.ceil((endTime - now) / 60000)) : 0
  };
}

// حساب العمولة الافتراضية للمنصة على الطلب (عند إنشائه أو عند إعادته للرادار)
function computeDefaultOrderPlatformFee(originalFare, settings) {
  const s = settings || {};
  const fare = Math.max(0, roundMoney(originalFare));
  const surgeInfo = getActiveSurgeInfo(s);
  if (s.commissionMode === 'percentage') {
    const basePctRate = Math.min(100, Math.max(0, roundMoney(s.platformFeePercent ?? 13)));
    return Math.max(0, roundMoney((fare * basePctRate) / 100));
  }
  const basePlatformFee = Math.max(0, roundMoney(s.platformFee ?? 7));
  return surgeInfo.isActive
    ? roundMoney(basePlatformFee * (1 + surgeInfo.surgePercent / 100))
    : basePlatformFee;
}

// حساب مستوى الكابتن (برونزي 🥉 / بلاتيني 🥈 / ماسي 💎) والعمولة (نسبة مئوية % أو مبلغ ثابت ج) مع الهبوط التدريجي الآمن
function computeCaptainTierAndFee(captainRow, mappedOrders, settings, orderFare = null) {
  const s = settings || {};
  const commissionMode = s.commissionMode === 'percentage' ? 'percentage' : 'fixed';
  const weeklyTarget = Math.max(1, Number(s.tierWeeklyOrdersTarget ?? 25));
  const tierDaysWindow = Math.max(1, Number(s.tierDaysWindow ?? 7));
  const tierConsecutiveDaysForDiamond = Math.max(
    tierDaysWindow,
    Number(s.tierConsecutiveDaysForDiamond ?? (Number(s.tierWeeksForDiamond ?? 4) * tierDaysWindow))
  );
  const diamondWeeksTarget = Math.max(1, Math.ceil(tierConsecutiveDaysForDiamond / tierDaysWindow));

  const platDiscount = Math.max(0, roundMoney(s.tierPlatinumDiscount ?? 1));
  const diaDiscount = Math.max(0, roundMoney(s.tierDiamondDiscount ?? 2));

  const bronzePercent = Math.min(100, Math.max(0, roundMoney(s.platformFeePercent ?? 13)));
  const platPercent = Math.min(100, Math.max(0, roundMoney(s.tierPlatinumPercent ?? 12.5)));
  const diaPercent = Math.min(100, Math.max(0, roundMoney(s.tierDiamondPercent ?? 12)));

  const now = Date.now();
  const windowMs = tierDaysWindow * 24 * 60 * 60 * 1000;

  const capCompletedOrders = (mappedOrders || []).filter(
    o => o.assignedCourierPhone === captainRow.phone && (o.status === 'مكتمل' || o.status === 'قيد مراجعة الاعتراض' || o.status === 'تمت التسوية الإدارية')
  );

  const totalWindowsToCheck = Math.max(diamondWeeksTarget + 2, 8);
  const weeklyCounts = [];
  for (let w = 0; w < totalWindowsToCheck; w++) {
    const startWindow = now - (w + 1) * windowMs;
    const endWindow = now - w * windowMs;
    const cnt = capCompletedOrders.filter(o => o.createdAt >= startWindow && o.createdAt <= endWindow).length;
    weeklyCounts.push(cnt);
  }

  const currentWeekOrders = weeklyCounts[0] || 0;

  let pastConsecutiveWeeks = 0;
  for (let w = 1; w < weeklyCounts.length; w++) {
    if (weeklyCounts[w] >= weeklyTarget) {
      pastConsecutiveWeeks++;
    } else {
      break;
    }
  }

  let consecutiveQualifiedWeeks = 0;
  let autoTier = 'bronze';
  let gracefulDemotion = false;

  let wasRecentlyDiamond = pastConsecutiveWeeks >= diamondWeeksTarget;
  if (!wasRecentlyDiamond && diamondWeeksTarget >= 2 && pastConsecutiveWeeks >= (diamondWeeksTarget - 1)) {
    const twoWindowsMs = 2 * windowMs;
    const recentTwoWeeksCount = capCompletedOrders.filter(o => o.createdAt >= (now - twoWindowsMs) && o.createdAt <= now).length;
    if (recentTwoWeeksCount >= (weeklyTarget * 2)) {
      wasRecentlyDiamond = true;
    }
  }

  if (currentWeekOrders >= weeklyTarget) {
    consecutiveQualifiedWeeks = 1 + pastConsecutiveWeeks;
    if (consecutiveQualifiedWeeks >= diamondWeeksTarget) {
      autoTier = 'diamond';
    } else {
      autoTier = 'platinum';
    }
  } else {
    if (wasRecentlyDiamond) {
      autoTier = 'platinum';
      gracefulDemotion = true;
      consecutiveQualifiedWeeks = Math.max(pastConsecutiveWeeks, diamondWeeksTarget - 1);
    } else {
      autoTier = 'bronze';
      consecutiveQualifiedWeeks = 0;
    }
  }

  const manualOverrides = (s.tierManualOverrides && typeof s.tierManualOverrides === 'object') ? s.tierManualOverrides : {};
  const manualTier = manualOverrides[captainRow.phone];
  const finalTier = ['bronze', 'platinum', 'diamond'].includes(manualTier) ? manualTier : autoTier;

  const tierMetaMap = {
    bronze: {
      key: 'bronze',
      name: 'كابتن برونزي',
      emoji: '🥉',
      badgeText: 'كابتن برونزي 🥉',
      discount: 0,
      percentRate: bronzePercent,
      percentDiscount: 0,
      color: '#CD7F32'
    },
    platinum: {
      key: 'platinum',
      name: 'كابتن بلاتيني',
      emoji: '🥈',
      badgeText: 'كابتن بلاتيني 🥈',
      discount: platDiscount,
      percentRate: platPercent,
      percentDiscount: Math.max(0, roundMoney(bronzePercent - platPercent)),
      color: '#37474F'
    },
    diamond: {
      key: 'diamond',
      name: 'كابتن ماسي',
      emoji: '💎',
      badgeText: 'كابتن ماسي 💎',
      discount: diaDiscount,
      percentRate: diaPercent,
      percentDiscount: Math.max(0, roundMoney(bronzePercent - diaPercent)),
      color: '#0288D1'
    }
  };

  const tierInfo = tierMetaMap[finalTier] || tierMetaMap.bronze;

  const surgeInfo = getActiveSurgeInfo(s);
  const basePlatformFee = Math.max(0, roundMoney(s.platformFee ?? 7));
  const surgedPlatformFee = surgeInfo.isActive
    ? roundMoney(basePlatformFee * (1 + surgeInfo.surgePercent / 100))
    : basePlatformFee;

  const hasCustomFee = captainRow.custom_fee !== null && captainRow.custom_fee !== undefined;
  let effectiveFeePercent = tierInfo.percentRate;
  if (hasCustomFee && commissionMode === 'percentage') {
    effectiveFeePercent = Math.min(100, Math.max(0, roundMoney(captainRow.custom_fee)));
  }

  let fixedEffectiveFee = Math.max(0, roundMoney(surgedPlatformFee - tierInfo.discount));
  if (hasCustomFee && commissionMode === 'fixed') {
    const baseCustom = Math.max(0, roundMoney(captainRow.custom_fee));
    fixedEffectiveFee = surgeInfo.isActive
      ? roundMoney(baseCustom * (1 + surgeInfo.surgePercent / 100))
      : baseCustom;
  }

  const refFare = (orderFare !== null && orderFare !== undefined && Number.isFinite(Number(orderFare)))
    ? Math.max(0, roundMoney(orderFare))
    : null;

  let effectiveFee = fixedEffectiveFee;
  if (commissionMode === 'percentage') {
    if (refFare !== null) {
      effectiveFee = Math.max(0, roundMoney((refFare * effectiveFeePercent) / 100));
    } else {
      effectiveFee = Math.max(0, roundMoney((40 * effectiveFeePercent) / 100));
    }
  }

  const tierProgressPct = Math.min(100, Math.round((currentWeekOrders / weeklyTarget) * 100));
  const consecutiveQualifiedDays = consecutiveQualifiedWeeks * tierDaysWindow;

  return {
    tier: finalTier,
    autoTier,
    isManualTier: ['bronze', 'platinum', 'diamond'].includes(manualTier),
    gracefulDemotion,
    tierName: tierInfo.name,
    tierEmoji: tierInfo.emoji,
    tierBadgeText: tierInfo.badgeText,
    tierDiscount: tierInfo.discount,
    tierPercentRate: tierInfo.percentRate,
    tierPercentDiscount: tierInfo.percentDiscount,
    commissionMode,
    effectiveFeePercent,
    tierColor: tierInfo.color,
    weeklyCompletedOrders: currentWeekOrders,
    consecutiveQualifiedWeeks,
    consecutiveQualifiedDays,
    weeklyTarget,
    tierDaysWindow,
    tierConsecutiveDaysForDiamond,
    diamondWeeksTarget,
    tierProgressPct,
    effectiveFee,
    fixedEffectiveFee,
    surgedPlatformFee
  };
}

function resolveCaptainPhotoUrl(rawVal) {
  if (!rawVal || typeof rawVal !== 'string') return null;
  const s = rawVal.trim();
  if (!s) return null;
  if (s.startsWith('data:image/') || s.startsWith('https://') || s.startsWith('http://') || s.startsWith('/uploads/')) {
    return s;
  }
  const cleanBase = String(SUPABASE_URL || '').replace(/\/+$/, '');
  if (!cleanBase) return s;

  let cleanPath = s.replace(/^\/+/, '');
  if (cleanPath.startsWith(`storage/v1/object/public/`)) {
    return `${cleanBase}/${cleanPath}`;
  }
  if (cleanPath.startsWith(`${CAPTAIN_DOCS_BUCKET}/`)) {
    cleanPath = cleanPath.slice(CAPTAIN_DOCS_BUCKET.length + 1);
  }
  if (!cleanPath.includes('/')) {
    cleanPath = `captains/${cleanPath}`;
  }
  return `${cleanBase}/storage/v1/object/public/${CAPTAIN_DOCS_BUCKET}/${cleanPath}`;
}

async function uploadCaptainDocToStorage(phone, docKey, dataUrl) {
  if (!dataUrl || typeof dataUrl !== 'string') return null;
  if (!dataUrl.startsWith('data:image/')) {
    return resolveCaptainPhotoUrl(dataUrl);
  }
  try {
    const matches = dataUrl.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
    if (!matches) return dataUrl;
    const mimeType = matches[1];
    const base64Data = matches[2];
    const ext = mimeType.includes('png') ? 'png' : 'jpg';
    const filePath = `captains/${phone}_${docKey}_${Date.now()}.${ext}`;
    const buffer = Buffer.from(base64Data, 'base64');

    const { error } = await supabase.storage
      .from(CAPTAIN_DOCS_BUCKET)
      .upload(filePath, buffer, { contentType: mimeType, upsert: true });

    if (error) {
      console.warn(`Storage upload fallback (${docKey}):`, error.message);
      return dataUrl;
    }
    invalidateStorageCache();
    return resolveCaptainPhotoUrl(filePath);
  } catch (err) {
    return dataUrl;
  }
}

// ==========================================
// 4. إدارة الكاش الذكي وبناء حالة العميل والكابتن والأدمن
// ==========================================
let stateCache = {
  raw: null,
  lastFetched: 0,
  ttlMs: 3000
};

// كاش مستقل لملفات صور الكباتن لمدة 5 دقائق لتسريع الاستجابة وتوفير استهلاك Supabase Storage
let storageCache = {
  map: {},
  lastFetched: 0,
  ttlMs: 300000
};

let lastLazyCleanupRun = 0;

function invalidateStateCache() {
  stateCache.raw = null;
  stateCache.lastFetched = 0;
}

function invalidateStorageCache() {
  storageCache.lastFetched = 0;
}

// [FIX-03] إنشاء حساب الأدمن الرئيسي عند عدم وجوده فقط دون الكتابة فوق بياناته عند إعادة تشغيل السيرفر
async function ensureMasterAdminSeeded() {
  try {
    const { data: existing } = await supabase.from('admins').select('username').eq('is_master', true).maybeSingle();
    if (!existing) {
      const initUser = (process.env.INITIAL_ADMIN_USER || 'ennaby1').trim();
      const initPass = (process.env.INITIAL_ADMIN_PASS || '01023024988').trim();
      const hashed = await bcrypt.hash(String(initPass), 10);
      await supabase.from('admins').insert([{
        username: initUser,
        name: 'الأدمن الرئيسي',
        password_hash: hashed,
        is_master: true,
        status: 'نشط',
        permissions: {}
      }]);
      console.log('✅ تم إنشاء حساب الأدمن الرئيسي لأول مرة بنجاح.');
    }
  } catch (err) {
    console.warn('Admin seed warning:', err.message);
  }
}
ensureMasterAdminSeeded();

async function logAdminAudit(actionType, target, details, actor = 'الأدمن الرئيسي') {
  try {
    await supabase.from('audit_logs').insert([{
      action_type: actionType,
      target: String(target || ''),
      details: String(details || ''),
      actor: String(actor || 'الإدارة'),
      time: formatCairoTime()
    }]);
  } catch (e) {}
}

// فحص صارم لما إذا كان الطلب قادماً من لوحة الإدارة دون تداخل مع واجهة العميل أو الكابتن على نفس المتصفح
function isRequestFromAdminView(req) {
  const explicitRole = String((req.query && req.query.role) || (req.body && req.body.role) || '').toLowerCase();
  if (explicitRole === 'admin') return true;
  if (explicitRole === 'customer' || explicitRole === 'courier') return false;
  if (req.path && req.path.startsWith('/api/admin')) return true;
  return false;
}

function getAuthenticatedAdminFromCookie(req, rawAdminsRows = null) {
  try {
    const token = req.cookies && req.cookies.admin_session;
    if (!token) return null;
    const dec = jwt.verify(token, JWT_SECRET);
    if (!dec || !dec.username) return null;

    if (Array.isArray(rawAdminsRows)) {
      const admRow = rawAdminsRows.find(
        a => a && String(a.username || '').toLowerCase() === String(dec.username).toLowerCase()
      );
      if (!admRow || admRow.status === 'معطل') return null;
      if (dec.pwdSig && getPasswordSignature(admRow.password_hash) !== dec.pwdSig) {
        return null;
      }
    }
    return dec;
  } catch (e) {
    return null;
  }
}

function getAuthenticatedCustomerFromCookie(req, rawCustomersRows = null) {
  try {
    const token = req.cookies && req.cookies.customer_session;
    if (!token) return null;
    const dec = jwt.verify(token, JWT_SECRET);
    const phone = dec && dec.phone ? normalizePhoneServer(dec.phone) : null;
    if (!phone) return null;

    if (Array.isArray(rawCustomersRows)) {
      const custRow = rawCustomersRows.find(c => normalizePhoneServer(c.phone) === phone);
      if (!custRow) return null;
      if (dec.pwdSig && getPasswordSignature(custRow.pin_hash) !== dec.pwdSig) {
        return null;
      }
    }
    return phone;
  } catch (e) {
    return null;
  }
}

function getAuthenticatedCaptainFromCookie(req, rawCaptainsList = null) {
  try {
    const token = req.cookies && req.cookies.captain_session;
    if (!token) return null;
    const dec = jwt.verify(token, JWT_SECRET);
    const phone = dec && dec.phone ? normalizePhoneServer(dec.phone) : null;
    if (!phone) return null;
    if (Array.isArray(rawCaptainsList)) {
      const capRow = rawCaptainsList.find(c => normalizePhoneServer(c.phone) === phone);
      if (!capRow || capRow.status === 'مرفوض') return null;
      if (capRow.session_version && dec.session_version && Number(capRow.session_version) !== Number(dec.session_version)) {
        return null;
      }
      if (dec.pwdSig && getPasswordSignature(capRow.password_hash) !== dec.pwdSig) {
        return null;
      }
    }
    return phone;
  } catch (e) {
    return null;
  }
}

// [FIX-06 & NEW-SEC-03] التحقق الصارم من ملكية العميل للطلب عبر كوكي الجلسة الموثق فقط
function verifyCustomerOrderOwnership(req, orderRow, rawCustomersRows = null) {
  if (!orderRow) return false;
  const orderOwnerPhone = normalizePhoneServer(orderRow.customer_phone || orderRow.client_phone);
  if (!orderOwnerPhone) return false;
  const cookiePhone = getAuthenticatedCustomerFromCookie(req, rawCustomersRows);
  return Boolean(cookiePhone && cookiePhone === orderOwnerPhone);
}

function mapCaptainRow(c, includePhotos = false, storageMap = {}, mappedOrders = [], settings = {}) {
  const phoneFiles = storageMap[c.phone] || {};
  const frontPhoto = resolveCaptainPhotoUrl(c.id_front_photo || c.id_front_url || c.doc_id_front_path) || phoneFiles.idFront || null;
  const backPhoto = resolveCaptainPhotoUrl(c.id_back_photo || c.id_back_url || c.doc_id_back_path) || phoneFiles.idBack || null;
  const vehPhoto = resolveCaptainPhotoUrl(c.vehicle_photo || c.vehicle_photo_url || c.vehicle_url || c.doc_vehicle_path) || phoneFiles.vehicle || null;

  const tierData = computeCaptainTierAndFee(c, mappedOrders, settings);

  return {
    phone: c.phone,
    fullName: c.full_name || '',
    nationalId: c.national_id || '',
    primaryZone: c.primary_zone || 'المنصورة',
    vehicleType: c.vehicle_type || 'موتوسيكل',
    plateNumber: c.plate_number || 'بدون لوحة',
    idFrontPhoto: includePhotos ? frontPhoto : null,
    idBackPhoto: includePhotos ? backPhoto : null,
    vehiclePhoto: includePhotos ? vehPhoto : null,
    status: c.status || 'قيد المراجعة',
    suspendReason: c.suspend_reason || c.reject_reason || null,
    isAvailable: Boolean(c.is_available),
    walletBalance: roundMoney(c.wallet_balance ?? 0),
    points: Number(c.points || 0),
    customFee: c.custom_fee !== null && c.custom_fee !== undefined ? roundMoney(c.custom_fee) : null,
    customFeeReason: c.custom_fee_reason || null,
    referredByPhone: c.referred_by_phone || null,
    referralsCount: Number(c.referrals_count || 0),
    lifetimeCompleted: Number(c.lifetime_completed || 0),
    lifetimeCancelled: Number(c.lifetime_cancelled || 0),
    lifetimeNetEarnings: roundMoney(c.lifetime_net_earnings || 0),
    walletTransactions: Array.isArray(c.wallet_transactions) ? c.wallet_transactions.slice(0, 40) : [],
    adminNotices: Array.isArray(c.admin_notices) ? c.admin_notices : (Array.isArray(c.admin_notices_json) ? c.admin_notices_json : []),
    createdAt: c.created_at ? new Date(c.created_at).getTime() : null,
    tier: tierData.tier,
    autoTier: tierData.autoTier,
    isManualTier: tierData.isManualTier,
    gracefulDemotion: tierData.gracefulDemotion,
    tierName: tierData.tierName,
    tierEmoji: tierInfoSafeEmoji(tierData),
    tierBadgeText: tierData.tierBadgeText,
    tierDiscount: tierData.tierDiscount,
    tierPercentRate: tierData.tierPercentRate,
    tierPercentDiscount: tierData.tierPercentDiscount,
    commissionMode: tierData.commissionMode,
    effectiveFeePercent: tierData.effectiveFeePercent,
    tierColor: tierData.tierColor,
    weeklyCompletedOrders: tierData.weeklyCompletedOrders,
    consecutiveQualifiedWeeks: tierData.consecutiveQualifiedWeeks,
    consecutiveQualifiedDays: tierData.consecutiveQualifiedDays,
    tierDaysWindow: tierData.tierDaysWindow,
    tierConsecutiveDaysForDiamond: tierData.tierConsecutiveDaysForDiamond,
    tierProgressPct: tierData.tierProgressPct,
    effectiveFee: tierData.effectiveFee,
    fixedEffectiveFee: tierData.fixedEffectiveFee
  };
}

function tierInfoSafeEmoji(tierData) {
  return (tierData && tierData.tierEmoji) ? tierData.tierEmoji : '🥉';
}

function mapOrderRow(o) {
  const createdMs = o.created_at ? new Date(o.created_at).getTime() : Date.now();
  const parsedMeta = decodeOrderMetaFromNotes(o.customer_notes || '');
  const origFare = roundMoney(o.original_fare ?? o.fare ?? 0);
  return {
    id: o.id,
    customerPhone: o.customer_phone || o.client_phone || '',
    clientPhone: o.client_phone || o.customer_phone || '',
    tripType: o.trip_type || 'send',
    pickupZone: o.pickup_zone || 'المنصورة',
    pickupAddress: o.pickup_address || '',
    dropoffZone: o.dropoff_zone || 'المنصورة',
    dropoffAddress: o.dropoff_address || '',
    customerNotes: parsedMeta.cleanNotes,
    pickupLat: parsedMeta.pickupLat,
    pickupLng: parsedMeta.pickupLng,
    dropoffLat: parsedMeta.dropoffLat,
    dropoffLng: parsedMeta.dropoffLng,
    promoCode: parsedMeta.promoCode,
    promoDiscount: parsedMeta.promoDiscount,
    walletDiscount: parsedMeta.walletDiscount > 0
      ? parsedMeta.walletDiscount
      : Math.max(0, roundMoney(roundMoney(o.discount_applied ?? 0) - parsedMeta.promoDiscount)),
    surgePercent: parsedMeta.surgePercent,
    routeDefaultFare: parsedMeta.routeDefaultFare || origFare,
    customerProposedFare: parsedMeta.customerProposedFare || null,
    purchaseBudget: parsedMeta.purchaseBudget || null,
    arrivedAt: parsedMeta.arrivedAt || null,
    lastBuzzAt: parsedMeta.lastBuzzAt || null,
    captainOffers: Array.isArray(parsedMeta.captainOffers) ? parsedMeta.captainOffers : [],
    packageType: o.package_type || DEFAULT_PACKAGE_TYPES[0],
    payer: o.payer || 'الراسل',
    senderPhone: o.sender_phone || '',
    recipientPhone: o.recipient_phone || '',
    originalFare: origFare,
    discountApplied: roundMoney(o.discount_applied ?? 0),
    fare: roundMoney(o.fare ?? 0),
    platformFee: roundMoney(o.platform_fee ?? 7),
    courierNet: roundMoney(o.courier_net ?? 0),
    status: o.status || 'في انتظار كابتن',
    assignedCourierPhone: o.assigned_courier_phone || null,
    feeDeducted: Boolean(o.fee_deducted),
    feeRefunded: Boolean(o.fee_refunded),
    rating: o.rating !== null && o.rating !== undefined ? Number(o.rating) : null,
    disputeReason: o.dispute_reason || null,
    adminResolutionNote: o.admin_resolution_note || null,
    createdAt: createdMs
  };
}

// استرجاع استخدام واحد من الكوبون عند إلغاء الطلب
async function releasePromoCodeUsageForCancelledOrder(promoCode, customerPhone) {
  const cleanCode = String(promoCode || '').trim().toUpperCase();
  const cleanPhone = normalizePhoneServer(customerPhone);
  if (!cleanCode || !cleanPhone) return;
  try {
    const rawState = await fetchRawDatabaseState(true);
    const promoList = Array.isArray(rawState.settings.promoCodes)
      ? rawState.settings.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
      : [];
    const pIdx = promoList.findIndex(p => p.code === cleanCode);
    if (pIdx === -1) return;

    const promoObj = promoList[pIdx];
    const currentUsed = getPromoPhoneUsedCount(promoObj, cleanPhone);
    const nextUsed = Math.max(0, currentUsed - 1);
    const counts = { ...(promoObj.usageCounts || {}) };
    if (nextUsed > 0) {
      counts[cleanPhone] = nextUsed;
    } else {
      delete counts[cleanPhone];
    }
    const maxUses = getPromoMaxUsesForPhone(promoObj);
    promoList[pIdx] = {
      ...promoObj,
      usageCounts: counts,
      usedBy: Object.keys(counts).filter(ph => counts[ph] >= maxUses)
    };
    await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
  } catch (e) {}
}

// [FIX-08] تنظيف تلقائي متزامن للطلبات التي تجاوزت المهلة لضمان اكتمال التنفيذ على Vercel Serverless
async function runLazyExpiredOrdersCleanup(timeoutMinutes = 30) {
  const now = Date.now();
  if (now - lastLazyCleanupRun < 120000) return 0;
  lastLazyCleanupRun = now;

  try {
    const mins = Number(timeoutMinutes || process.env.WAITING_TIMEOUT_MINUTES || 30);
    if (mins <= 0) return 0;

    const cutoff = new Date(now - mins * 60000).toISOString();
    const { data: expired } = await supabase.from('orders')
      .update({ status: 'ملغي (تجاوز مهلة الانتظار)', fee_refunded: true })
      .eq('status', 'في انتظار كابتن')
      .lt('created_at', cutoff)
      .select();

    if (expired && expired.length > 0) {
      for (const order of expired) {
        const custPhone = order.customer_phone || order.client_phone;
        const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
        const refundWalletAmt = meta.walletDiscount > 0
          ? meta.walletDiscount
          : Math.max(0, roundMoney((order.discount_applied || 0) - (meta.promoDiscount || 0)));

        if (refundWalletAmt > 0 && custPhone) {
          await safeAdjustCustomerWallet(
            custPhone,
            roundMoney(refundWalletAmt),
            `رد المبلغ التعويضي لمحفظتك لعدم اكتمال طلب ${order.id}`
          );
        }
        if (meta.promoCode && custPhone) {
          await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
        }
        if (custPhone && (refundWalletAmt > 0 || meta.promoCode)) {
          sendPushNotificationToPhone(custPhone, {
            title: `خصمك لسه معاك يا باشا! 🎁✅`,
            body: `عشان الطلب (${order.id}) مكتملش وعدى وقت الانتظار، رجّعنالك خصمك (${roundMoney(order.discount_applied)} ج) لمحفظتك/كودك تاني تقدر تستخدمه في أي وقت 😎🛵`
          });
        }
        notifyAdminsPush('platform', {
          title: `⏳ إلغاء تلقائي لطلب (${order.id})`,
          body: `تجاوز الطلب مهلة الانتظار (${mins} دقيقة) دون قبول وتم إلغاؤه تلقائياً ورد خصم العميل.`
        });
      }
      invalidateStateCache();
      return expired.length;
    }
  } catch (e) {}
  return 0;
}

async function fetchCaptainStorageFilesMap() {
  const now = Date.now();
  if (storageCache.lastFetched > 0 && (now - storageCache.lastFetched < storageCache.ttlMs)) {
    return storageCache.map;
  }
  const storageMap = {};
  try {
    const { data: files } = await supabase.storage
      .from(CAPTAIN_DOCS_BUCKET)
      .list('captains', { limit: 1000, sortBy: { column: 'name', order: 'desc' } });

    if (Array.isArray(files)) {
      for (const f of files) {
        if (!f || !f.name) continue;
        const match = f.name.match(/^(01[0-9]{9})_(idFront|idBack|vehicle)/i);
        if (match) {
          const phone = match[1];
          const rawType = match[2].toLowerCase();
          if (!storageMap[phone]) storageMap[phone] = {};
          const fullUrl = resolveCaptainPhotoUrl(`captains/${f.name}`);
          if (rawType === 'idfront' && !storageMap[phone].idFront) storageMap[phone].idFront = fullUrl;
          else if (rawType === 'idback' && !storageMap[phone].idBack) storageMap[phone].idBack = fullUrl;
          else if (rawType === 'vehicle' && !storageMap[phone].vehicle) storageMap[phone].vehicle = fullUrl;
        }
      }
    }
    storageCache.map = storageMap;
    storageCache.lastFetched = now;
  } catch (e) {}
  return storageCache.map || storageMap;
}

async function fetchRawDatabaseState(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && stateCache.raw && (now - stateCache.lastFetched < stateCache.ttlMs)) {
    return stateCache.raw;
  }

  const cachedTimeoutMins = stateCache.raw?.settings?.waitingTimeoutMinutes ?? Number(process.env.WAITING_TIMEOUT_MINUTES || 30);
  await runLazyExpiredOrdersCleanup(cachedTimeoutMins);

  const [settingsRes, customersRes, captainsRes, ordersRes, adminsRes, logsRes, storageFilesMap] = await Promise.all([
    supabase.from('settings').select('*').eq('id', 1).maybeSingle(),
    supabase.from('customers').select('*'),
    supabase.from('captains').select('*').order('created_at', { ascending: false }),
    supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(500),
    supabase.from('admins').select('*').order('created_at', { ascending: true }),
    supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(50),
    fetchCaptainStorageFilesMap()
  ]);

  const sRow = settingsRes.data || {};
  const rawPricingObj = (sRow.pricing && typeof sRow.pricing === 'object') ? { ...sRow.pricing } : { ...DEFAULT_PRICING };
  const storedIncentives = (rawPricingObj.__incentives && typeof rawPricingObj.__incentives === 'object') ? rawPricingObj.__incentives : {};
  delete rawPricingObj.__incentives;

  const welcomeBonusActive = storedIncentives.welcomeBonusActive !== undefined
    ? Boolean(storedIncentives.welcomeBonusActive)
    : (sRow.welcome_bonus_active !== undefined ? Boolean(sRow.welcome_bonus_active) : true);

  const welcomeBonusAmount = storedIncentives.welcomeBonusAmount !== undefined && storedIncentives.welcomeBonusAmount !== null
    ? Math.max(0, roundMoney(storedIncentives.welcomeBonusAmount))
    : (sRow.welcome_bonus_amount !== undefined && sRow.welcome_bonus_amount !== null ? Math.max(0, roundMoney(sRow.welcome_bonus_amount)) : 7);

  const referralRewardActive = storedIncentives.referralRewardActive !== undefined
    ? Boolean(storedIncentives.referralRewardActive)
    : (sRow.referral_reward_active !== undefined ? Boolean(sRow.referral_reward_active) : true);

  const referralRewardAmount = storedIncentives.referralRewardAmount !== undefined && storedIncentives.referralRewardAmount !== null
    ? Math.max(0, roundMoney(storedIncentives.referralRewardAmount))
    : (sRow.referral_reward_amount !== undefined && sRow.referral_reward_amount !== null ? Math.max(0, roundMoney(sRow.referral_reward_amount)) : 50);

  const referralRequiredOrders = Math.max(1, Number(storedIncentives.referralRequiredOrders ?? 2));
  const maxConcurrentOrdersPerCaptain = Math.max(1, Number(storedIncentives.maxConcurrentOrdersPerCaptain ?? 3));
  const broadcastTarget = sRow.broadcast_target || storedIncentives.broadcastTarget || 'all';

  const commissionMode = storedIncentives.commissionMode === 'percentage' ? 'percentage' : 'fixed';
  const platformFeePercent = Math.min(100, Math.max(0, roundMoney(storedIncentives.platformFeePercent ?? 13)));
  const tierPlatinumPercent = Math.min(100, Math.max(0, roundMoney(storedIncentives.tierPlatinumPercent ?? 12.5)));
  const tierDiamondPercent = Math.min(100, Math.max(0, roundMoney(storedIncentives.tierDiamondPercent ?? 12)));

  const tierWeeklyOrdersTarget = Math.max(1, Number(storedIncentives.tierWeeklyOrdersTarget ?? 25));
  const tierDaysWindow = Math.max(1, Number(storedIncentives.tierDaysWindow ?? 7));
  const tierConsecutiveDaysForDiamond = Math.max(
    tierDaysWindow,
    Number(storedIncentives.tierConsecutiveDaysForDiamond ?? (Number(storedIncentives.tierWeeksForDiamond ?? 4) * tierDaysWindow))
  );
  const tierWeeksForDiamond = Math.max(1, Math.ceil(tierConsecutiveDaysForDiamond / tierDaysWindow));
  const tierPlatinumDiscount = Math.max(0, roundMoney(storedIncentives.tierPlatinumDiscount ?? 1));
  const tierDiamondDiscount = Math.max(0, roundMoney(storedIncentives.tierDiamondDiscount ?? 2));
  const tierManualOverrides = (storedIncentives.tierManualOverrides && typeof storedIncentives.tierManualOverrides === 'object')
    ? storedIncentives.tierManualOverrides
    : {};

  const surgePercent = Math.max(0, Number(storedIncentives.surgePercent ?? 0));
  const surgeEndTime = Math.max(0, Number(storedIncentives.surgeEndTime ?? 0));
  const surgeDurationMinutes = Math.max(1, Number(storedIncentives.surgeDurationMinutes ?? 30));
  const autoSurgeEnabled = Boolean(storedIncentives.autoSurgeEnabled);
  const pendingTopupRequests = Array.isArray(storedIncentives.pendingTopupRequests)
    ? storedIncentives.pendingTopupRequests.slice(0, 50)
    : [];

  const promoCodes = Array.isArray(storedIncentives.promoCodes)
    ? storedIncentives.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
    : [];

  const adminPushMasterEnabled = storedIncentives.adminPushMasterEnabled !== false;
  const adminPushCustomersEnabled = storedIncentives.adminPushCustomersEnabled !== false;
  const adminPushCaptainsEnabled = storedIncentives.adminPushCaptainsEnabled !== false;
  const priceHumorMessage = storedIncentives.priceHumorMessage !== undefined
    ? String(storedIncentives.priceHumorMessage)
    : 'صديقي العزيز اللذيذ 😂 السعر ممكن يزيد لو المشوار بتاعك بره نطاق الاختيارات، وساعتها الكابتن هيبعتلك عرض بالسعر في التطبيق توافق عليه أو تتفاوض معاه براحتك 🛵🤝';

  const rawCustomersRows = customersRes.data || [];
  const rawCaptainsRows = captainsRes.data || [];
  const rawOrdersRows = ordersRes.data || [];
  const rawAdminsRows = adminsRes.data || [];

  const analyticsHistory = sanitizeAnalyticsHistory(
    storedIncentives.analyticsHistory || {},
    rawCustomersRows,
    rawCaptainsRows,
    rawOrdersRows
  );
  const sumHistoryInstalls = Object.values(analyticsHistory.installs || {}).reduce((a, b) => a + (Number(b) || 0), 0);
  const appInstallsCount = Math.max(Number(storedIncentives.appInstallsCount || 0), sumHistoryInstalls);
  const installedClientIds = Array.isArray(storedIncentives.installedClientIds) ? storedIncentives.installedClientIds.slice(-2000) : [];

  const settings = {
    platformFee: Math.max(0, roundMoney(sRow.platform_fee ?? 7)),
    commissionMode,
    platformFeePercent,
    tierPlatinumPercent,
    tierDiamondPercent,
    customerPointsPerOrder: Math.max(1, Number(sRow.customer_points_per_order ?? 5)),
    customerRewardThreshold: Math.max(5, Number(sRow.customer_reward_threshold ?? 100)),
    customerRewardCash: Math.max(1, roundMoney(sRow.customer_reward_cash ?? 10)),
    courierPointsPerOrder: Math.max(1, Number(sRow.courier_points_per_order ?? 5)),
    courierRewardThreshold: Math.max(5, Number(sRow.courier_reward_threshold ?? 100)),
    courierRewardCash: Math.max(1, roundMoney(sRow.courier_reward_cash ?? 10)),
    welcomeBonusActive,
    welcomeBonusAmount,
    referralRewardActive,
    referralRewardAmount,
    referralRequiredOrders,
    maxConcurrentOrdersPerCaptain,
    tierWeeklyOrdersTarget,
    tierDaysWindow,
    tierConsecutiveDaysForDiamond,
    tierWeeksForDiamond,
    tierPlatinumDiscount,
    tierDiamondDiscount,
    tierManualOverrides,
    surgePercent,
    surgeEndTime,
    surgeDurationMinutes,
    autoSurgeEnabled,
    pendingTopupRequests,
    promoCodes,
    adminPushMasterEnabled,
    adminPushCustomersEnabled,
    adminPushCaptainsEnabled,
    appInstallsCount,
    installedClientIds,
    analyticsHistory,
    supportWhatsapp: sRow.support_whatsapp || '201507800875',
    broadcastMessage: sRow.broadcast_message || '',
    broadcastTarget,
    priceHumorMessage,
    waitingTimeoutMinutes: Math.max(0, Number(sRow.waiting_timeout_minutes ?? 30)),
    maintenanceMode: Boolean(sRow.maintenance_mode),
    allowCaptainRegistration: sRow.allow_captain_registration !== false,
    packageTypes: Array.isArray(sRow.package_types) && sRow.package_types.length > 0 ? sRow.package_types : DEFAULT_PACKAGE_TYPES
  };

  const surgeInfo = getActiveSurgeInfo(settings);
  settings.surgeActive = surgeInfo.isActive;
  settings.surgeRemainingMinutes = surgeInfo.remainingMinutes;
  settings.effectivePlatformFee = surgeInfo.isActive
    ? roundMoney(settings.platformFee * (1 + surgeInfo.surgePercent / 100))
    : settings.platformFee;

  const zones = Array.isArray(sRow.zones) && sRow.zones.length > 0 ? sRow.zones : DEFAULT_ZONES;
  const pricing = Object.keys(rawPricingObj).length > 0 ? rawPricingObj : { ...DEFAULT_PRICING };

  const customersMap = {};
  rawCustomersRows.forEach(c => {
    customersMap[c.phone] = {
      walletBalance: roundMoney(c.wallet_balance ?? 0),
      points: Number(c.points ?? 0),
      createdAt: c.created_at ? new Date(c.created_at).getTime() : null,
      walletTransactions: Array.isArray(c.wallet_transactions) ? c.wallet_transactions.slice(0, 30) : []
    };
  });

  const mappedOrders = rawOrdersRows.map(mapOrderRow);

  const rawData = {
    settings,
    storedIncentives,
    zones,
    pricing,
    customers: customersMap,
    rawCustomersRows,
    rawCaptains: rawCaptainsRows,
    rawOrdersRows,
    rawAdminsRows,
    storageFilesMap: storageFilesMap || {},
    orders: mappedOrders,
    adminAccounts: rawAdminsRows.map(a => ({
      username: a.username,
      name: a.name,
      isMaster: Boolean(a.is_master),
      status: a.status || 'نشط',
      permissions: a.permissions || {}
    })),
    auditLogs: (logsRes.data || []).map(l => ({
      actionType: l.action_type || '',
      target: l.target || '',
      details: l.details || '',
      actor: l.actor || '',
      time: l.time || formatCairoTime(l.created_at)
    }))
  };

  stateCache.raw = rawData;
  stateCache.lastFetched = now;
  return rawData;
}

async function saveIncentivesToDatabase(rawState, partialIncentives = {}, extraSettingsColumns = {}, customBasePricing = null) {
  const prevSettings = rawState.settings || {};
  const mergedIncentives = {
    commissionMode: prevSettings.commissionMode === 'percentage' ? 'percentage' : 'fixed',
    platformFeePercent: Math.min(100, Math.max(0, roundMoney(prevSettings.platformFeePercent ?? 13))),
    tierPlatinumPercent: Math.min(100, Math.max(0, roundMoney(prevSettings.tierPlatinumPercent ?? 12.5))),
    tierDiamondPercent: Math.min(100, Math.max(0, roundMoney(prevSettings.tierDiamondPercent ?? 12))),
    welcomeBonusActive: prevSettings.welcomeBonusActive !== false,
    welcomeBonusAmount: roundMoney(prevSettings.welcomeBonusAmount ?? 7),
    referralRewardActive: prevSettings.referralRewardActive !== false,
    referralRewardAmount: roundMoney(prevSettings.referralRewardAmount ?? 50),
    referralRequiredOrders: Math.max(1, Number(prevSettings.referralRequiredOrders ?? 2)),
    maxConcurrentOrdersPerCaptain: Math.max(1, Number(prevSettings.maxConcurrentOrdersPerCaptain ?? 3)),
    broadcastTarget: prevSettings.broadcastTarget || 'all',
    priceHumorMessage: prevSettings.priceHumorMessage !== undefined
      ? String(prevSettings.priceHumorMessage)
      : 'صديقي العزيز اللذيذ 😂 السعر ممكن يزيد لو المشوار بتاعك بره نطاق الاختيارات، وساعتها الكابتن هيبعتلك عرض بالسعر في التطبيق توافق عليه أو تتفاوض معاه براحتك 🛵🤝',
    tierWeeklyOrdersTarget: Math.max(1, Number(prevSettings.tierWeeklyOrdersTarget ?? 25)),
    tierDaysWindow: Math.max(1, Number(prevSettings.tierDaysWindow ?? 7)),
    tierConsecutiveDaysForDiamond: Math.max(1, Number(prevSettings.tierConsecutiveDaysForDiamond ?? 28)),
    tierWeeksForDiamond: Math.max(1, Number(prevSettings.tierWeeksForDiamond ?? 4)),
    tierPlatinumDiscount: Math.max(0, roundMoney(prevSettings.tierPlatinumDiscount ?? 1)),
    tierDiamondDiscount: Math.max(0, roundMoney(prevSettings.tierDiamondDiscount ?? 2)),
    tierManualOverrides: prevSettings.tierManualOverrides || {},
    surgePercent: Math.max(0, Number(prevSettings.surgePercent ?? 0)),
    surgeEndTime: Math.max(0, Number(prevSettings.surgeEndTime ?? 0)),
    surgeDurationMinutes: Math.max(1, Number(prevSettings.surgeDurationMinutes ?? 30)),
    autoSurgeEnabled: Boolean(prevSettings.autoSurgeEnabled),
    pendingTopupRequests: Array.isArray(prevSettings.pendingTopupRequests) ? prevSettings.pendingTopupRequests.slice(0, 50) : [],
    promoCodes: Array.isArray(prevSettings.promoCodes) ? prevSettings.promoCodes : [],
    adminPushMasterEnabled: prevSettings.adminPushMasterEnabled !== false,
    adminPushCustomersEnabled: prevSettings.adminPushCustomersEnabled !== false,
    adminPushCaptainsEnabled: prevSettings.adminPushCaptainsEnabled !== false,
    appInstallsCount: Math.max(0, Number(prevSettings.appInstallsCount ?? 0)),
    installedClientIds: Array.isArray(prevSettings.installedClientIds) ? prevSettings.installedClientIds.slice(-2000) : [],
    analyticsHistory: prevSettings.analyticsHistory || { installs: {}, customers: {}, captains: {}, completedOrders: {} },
    ...partialIncentives
  };

  const basePricing = customBasePricing ? { ...customBasePricing } : { ...(rawState.pricing || DEFAULT_PRICING) };
  basePricing.__incentives = mergedIncentives;

  await supabase.from('settings').upsert({
    id: 1,
    ...extraSettingsColumns,
    pricing: basePricing
  });

  return mergedIncentives;
}

// [FIX-02 & NEW-SEC-02] تنقية استجابة /api/bootstrap بالكامل وعزل بيانات العملاء والكباتن والطلبات حسب الجلسة الموثقة
async function buildClientState(req, forceRefresh = false) {
  touchCustomerPresence(req);
  const raw = await fetchRawDatabaseState(forceRefresh);
  const isAdminView = isRequestFromAdminView(req);
  const adminToken = getAuthenticatedAdminFromCookie(req, raw.rawAdminsRows);
  const authenticatedCustomerPhone = getAuthenticatedCustomerFromCookie(req, raw.rawCustomersRows);
  const authenticatedCaptainPhone = getAuthenticatedCaptainFromCookie(req, raw.rawCaptains);

  let verifiedAdminAccount = null;
  if (adminToken && adminToken.username) {
    verifiedAdminAccount = (raw.adminAccounts || []).find(
      a => a.username.toLowerCase() === String(adminToken.username).toLowerCase() && a.status !== 'معطل'
    ) || null;
  }
  const isAuthenticatedAdmin = Boolean(isAdminView && verifiedAdminAccount);
  const admPerms = (verifiedAdminAccount && verifiedAdminAccount.permissions) || {};
  const isMasterAdm = Boolean(isAuthenticatedAdmin && verifiedAdminAccount && verifiedAdminAccount.isMaster);

  const canAdmViewCaptains = Boolean(isMasterAdm || admPerms.viewCaptains || admPerms.manageCaptains || admPerms.manageWallets || admPerms.manageCommissions || admPerms.viewDashboard || admPerms.viewAnalytics);
  const canAdmViewCapIdentity = Boolean(isMasterAdm || admPerms.viewCaptains || admPerms.manageCaptains);
  const canAdmViewWallets = Boolean(isMasterAdm || admPerms.manageWallets);
  const canAdmViewOrders = Boolean(isMasterAdm || admPerms.viewOrders || admPerms.manageOrders || admPerms.viewDashboard || admPerms.viewAnalytics);
  const canAdmViewCustomers = Boolean(isMasterAdm || admPerms.manageWallets || admPerms.manageSettings || admPerms.viewDashboard || admPerms.viewAnalytics);

  const surgeInfo = getActiveSurgeInfo(raw.settings);
  const clientSettings = {
    ...raw.settings,
    surgeActive: surgeInfo.isActive,
    surgeRemainingMinutes: surgeInfo.remainingMinutes,
    effectivePlatformFee: surgeInfo.isActive
      ? roundMoney(raw.settings.platformFee * (1 + surgeInfo.surgePercent / 100))
      : raw.settings.platformFee
  };

  delete clientSettings.installedClientIds;

  if (!isAuthenticatedAdmin) {
    delete clientSettings.analyticsHistory;
    if (authenticatedCaptainPhone && Array.isArray(clientSettings.pendingTopupRequests)) {
      clientSettings.myPendingTopupRequests = clientSettings.pendingTopupRequests.filter(
        r => r && normalizePhoneServer(r.phone) === authenticatedCaptainPhone
      );
    }
    delete clientSettings.pendingTopupRequests;

    // عدم تسريب الأكواد المخصصة لغير صاحب الجلسة الموثقة بالكوكي نهائياً
    const promoCustPhone = authenticatedCustomerPhone || '';
    const nowTs = Date.now();
    const allPromos = Array.isArray(raw.settings.promoCodes) ? raw.settings.promoCodes : [];

    clientSettings.availablePromoCodes = allPromos.filter(p => {
      if (!p || p.active === false) return false;
      if (p.expiresAt && nowTs > Number(p.expiresAt)) return false;
      const isTargetAll = !p.targetPhone || p.targetPhone === 'all';
      const isTargetCustom = Boolean(promoCustPhone && normalizePhoneServer(p.targetPhone) === promoCustPhone);
      if (!isTargetAll && !isTargetCustom) return false;

      const maxUses = getPromoMaxUsesForPhone(p);
      const usedCount = promoCustPhone ? getPromoPhoneUsedCount(p, promoCustPhone) : 0;
      return usedCount < maxUses;
    }).map(p => {
      const maxUses = getPromoMaxUsesForPhone(p);
      const usedCount = promoCustPhone ? getPromoPhoneUsedCount(p, promoCustPhone) : 0;
      return {
        code: p.code,
        discountAmount: roundMoney(p.discountAmount),
        targetPhone: (!p.targetPhone || p.targetPhone === 'all') ? 'all' : normalizePhoneServer(p.targetPhone),
        maxUses,
        usedCount,
        remainingUses: Math.max(0, maxUses - usedCount),
        expiresAt: p.expiresAt || null
      };
    });

    delete clientSettings.promoCodes;
  } else {
    if (!isMasterAdm && !admPerms.viewAnalytics && !admPerms.viewDashboard) {
      delete clientSettings.analyticsHistory;
    }
    if (!isMasterAdm && !admPerms.manageWallets && !admPerms.manageSettings) {
      delete clientSettings.promoCodes;
    }
  }

  const allMappedCaptains = raw.rawCaptains.map(c => {
    const row = mapCaptainRow(c, canAdmViewCapIdentity, raw.storageFilesMap, raw.orders, clientSettings);
    if (isAuthenticatedAdmin) {
      if (!canAdmViewCapIdentity) row.nationalId = '';
      if (!canAdmViewWallets) row.walletTransactions = [];
    }
    return row;
  });
  const availableCaptainsCount = allMappedCaptains.filter(c => c.status === 'معتمد' && c.isAvailable).length;
  const onlineCustomersCount = getOnlineCustomersCount();

  const authenticatedCaptainObj = authenticatedCaptainPhone
    ? allMappedCaptains.find(c => normalizePhoneServer(c.phone) === authenticatedCaptainPhone) || null
    : null;
  const isApprovedCaptain = Boolean(authenticatedCaptainObj && authenticatedCaptainObj.status === 'معتمد');

  const filteredCaptains = isAuthenticatedAdmin
    ? (canAdmViewCaptains ? allMappedCaptains : [])
    : (authenticatedCaptainObj ? [authenticatedCaptainObj] : []);

  let filteredCustomers = {};
  if (isAuthenticatedAdmin) {
    if (canAdmViewCustomers) {
      if (canAdmViewWallets) {
        filteredCustomers = raw.customers;
      } else {
        Object.entries(raw.customers).forEach(([ph, rec]) => {
          filteredCustomers[ph] = { ...rec, walletTransactions: [] };
        });
      }
    }
  } else if (authenticatedCustomerPhone && raw.customers[authenticatedCustomerPhone]) {
    filteredCustomers = { [authenticatedCustomerPhone]: raw.customers[authenticatedCustomerPhone] };
  }

  const captainInfoByPhone = new Map();
  allMappedCaptains.forEach(c => {
    captainInfoByPhone.set(normalizePhoneServer(c.phone), {
      fullName: c.fullName || 'كابتن العنابي',
      vehicleType: c.vehicleType || 'موتوسيكل',
      plateNumber: c.plateNumber || '',
      tier: c.tier || 'bronze',
      tierBadgeText: c.tierBadgeText || 'كابتن برونزي 🥉'
    });
  });

  const captainActiveOrderCounts = new Map();
  raw.orders.forEach(o => {
    if (o && o.assignedCourierPhone && ACTIVE_COURIER_ORDER_STATUSES.includes(o.status)) {
      const cPh = normalizePhoneServer(o.assignedCourierPhone);
      if (cPh) captainActiveOrderCounts.set(cPh, (captainActiveOrderCounts.get(cPh) || 0) + 1);
    }
  });

  const enrichOrderWithCaptainMeta = (ord) => {
    const capPh = normalizePhoneServer(ord.assignedCourierPhone);
    const meta = capPh ? captainInfoByPhone.get(capPh) : null;
    const isOrdActive = ACTIVE_COURIER_ORDER_STATUSES.includes(ord.status);
    const activeCount = (isOrdActive && capPh) ? (captainActiveOrderCounts.get(capPh) || 1) : 0;
    const enrichedOffers = (Array.isArray(ord.captainOffers) ? ord.captainOffers : []).map(ofItem => {
      const ofCapPh = normalizePhoneServer(ofItem.captainPhone);
      const ofCapMeta = ofCapPh ? captainInfoByPhone.get(ofCapPh) : null;
      return {
        ...ofItem,
        captainName: ofCapMeta ? ofCapMeta.fullName : (ofItem.captainName || 'كابتن العنابي'),
        vehicleType: ofCapMeta ? ofCapMeta.vehicleType : (ofItem.vehicleType || 'موتوسيكل'),
        tier: ofCapMeta ? ofCapMeta.tier : (ofItem.tier || 'bronze'),
        tierBadgeText: ofCapMeta ? ofCapMeta.tierBadgeText : (ofItem.tierBadgeText || 'كابتن برونزي 🥉')
      };
    });

    return {
      ...ord,
      captainOffers: enrichedOffers,
      assignedCourierName: meta ? meta.fullName : '',
      assignedCourierVehicle: meta ? meta.vehicleType : '',
      assignedCourierPlate: meta ? meta.plateNumber : '',
      assignedCourierTier: meta ? meta.tier : 'bronze',
      assignedCourierTierBadge: meta ? meta.tierBadgeText : '',
      assignedCourierActiveCount: activeCount,
      isCourierStacked: Boolean(isOrdActive && activeCount > 1)
    };
  };

  let filteredOrders = [];
  if (isAuthenticatedAdmin) {
    filteredOrders = canAdmViewOrders ? raw.orders.map(enrichOrderWithCaptainMeta) : [];
  } else {
    const seenIds = new Set();
    raw.orders.forEach(rawOrd => {
      const o = enrichOrderWithCaptainMeta(rawOrd);
      const ownerPh = normalizePhoneServer(o.clientPhone || o.customerPhone);
      const isCustOwner = Boolean(authenticatedCustomerPhone && ownerPh === authenticatedCustomerPhone);
      const isAssignedCap = Boolean(authenticatedCaptainPhone && normalizePhoneServer(o.assignedCourierPhone) === authenticatedCaptainPhone);
      // حصر رؤية طلبات الرادار المنتظرة على الكباتن المعتمدين فقط (status === 'معتمد')
      const isWaitingRadar = Boolean(isApprovedCaptain && o.status === 'في انتظار كابتن');
      const isFinished = o.status === 'مكتمل' || o.status === 'قيد مراجعة الاعتراض' || o.status === 'تمت التسوية الإدارية' || String(o.status || '').includes('ملغي');

      if (isCustOwner) {
        if (!seenIds.has(o.id)) {
          seenIds.add(o.id);
          filteredOrders.push((isFinished && !isAssignedCap) ? {
            ...o,
            assignedCourierPhone: ''
          } : o);
        }
      } else if (isAssignedCap || isWaitingRadar) {
        if (!seenIds.has(o.id)) {
          seenIds.add(o.id);
          const hidePhonesForCap = isWaitingRadar || isFinished;
          const myOnlyOffers = authenticatedCaptainPhone
            ? (o.captainOffers || []).filter(ofItem => normalizePhoneServer(ofItem.captainPhone) === authenticatedCaptainPhone)
            : [];
          filteredOrders.push(hidePhonesForCap ? {
            ...o,
            customerPhone: '',
            clientPhone: '',
            senderPhone: '',
            recipientPhone: '',
            captainOffers: myOnlyOffers
          } : {
            ...o,
            captainOffers: myOnlyOffers
          });
        }
      }
    });
  }

  const canViewAuditAndAdmins = Boolean(isMasterAdm);

  return {
    settings: clientSettings,
    zones: raw.zones,
    pricing: raw.pricing,
    customers: filteredCustomers,
    captains: filteredCaptains,
    orders: filteredOrders,
    availableCaptainsCount,
    onlineCustomersCount,
    authenticatedCustomerPhone,
    realtimeConfig: {
      supabaseUrl: SUPABASE_URL || '',
      supabaseAnonKey: SUPABASE_ANON_KEY || '',
      vapidPublicKey: VAPID_PUBLIC_KEY || ''
    },
    adminAccounts: canViewAuditAndAdmins ? raw.adminAccounts : (isAuthenticatedAdmin && verifiedAdminAccount ? [verifiedAdminAccount] : []),
    auditLogs: canViewAuditAndAdmins ? raw.auditLogs : [],
    authenticatedAdminUsername: verifiedAdminAccount ? verifiedAdminAccount.username : null
  };
}

// ==========================================
// 5. محرك إشعارات الموبايل (Web Push Notifications) + رادار الأدمن اللحظي
// ==========================================
const WEB_PUSH_OPTIONS = {
  TTL: 86400,
  urgency: 'high'
};

// طابور تتبع ذكي يضمن اكتمال إرسال جميع إشعارات الـ Push قبل إغلاق استجابة Vercel Serverless
const pendingPushPromises = new Set();

function trackPushTask(promise) {
  if (!promise || typeof promise.then !== 'function') return promise;
  pendingPushPromises.add(promise);
  promise.finally(() => pendingPushPromises.delete(promise)).catch(() => {});
  return promise;
}

async function flushPendingPushTasks(timeoutMs = 4500) {
  if (pendingPushPromises.size === 0) return;
  const tasks = Array.from(pendingPushPromises);
  await Promise.race([
    Promise.allSettled(tasks),
    new Promise(resolve => setTimeout(resolve, timeoutMs))
  ]);
}

app.use((req, res, next) => {
  const origJson = res.json.bind(res);
  res.json = function(body) {
    if (pendingPushPromises.size > 0) {
      flushPendingPushTasks(4500).finally(() => {
        origJson(body);
      });
      return res;
    }
    return origJson(body);
  };
  next();
});

async function sendWebPushWithHighPriority(rawSubscription, payloadObj = {}) {
  let subscription = rawSubscription;
  if (typeof subscription === 'string') {
    try { subscription = JSON.parse(subscription); } catch (e) { subscription = null; }
  }
  if (!subscription || typeof subscription !== 'object' || !subscription.endpoint) {
    return { ok: false, expired: true, errorMsg: 'Invalid subscription object' };
  }
  const payloadStr = JSON.stringify({
    title: payloadObj.title || 'الرجل العنابي 🛵',
    body: payloadObj.body || 'تحديث جديد في طلبك!',
    url: payloadObj.url || '/',
    tag: payloadObj.tag || ('ennaby-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6))
  });
  try {
    await webpush.sendNotification(subscription, payloadStr, WEB_PUSH_OPTIONS);
    return { ok: true };
  } catch (err) {
    const code = Number(err && err.statusCode) || 0;
    // إذا كان الاشتراك مسجلاً بالمفتاح الافتراضي بينما تم تغيير مفتاح البيئة في Vercel، نعيد المحاولة تلقائياً بالمفتاح الافتراضي
    if ((code === 401 || code === 403) && (VAPID_PUBLIC_KEY !== DEFAULT_VAPID_PUBLIC || VAPID_PRIVATE_KEY !== DEFAULT_VAPID_PRIVATE)) {
      try {
        await webpush.sendNotification(subscription, payloadStr, {
          ...WEB_PUSH_OPTIONS,
          vapidDetails: {
            subject: 'mailto:support@ennaby.com',
            publicKey: DEFAULT_VAPID_PUBLIC,
            privateKey: DEFAULT_VAPID_PRIVATE
          }
        });
        return { ok: true };
      } catch (retryErr) {
        const retryCode = Number(retryErr && retryErr.statusCode) || code;
        const retryExpired = (retryCode === 404 || retryCode === 410);
        return { ok: false, expired: retryExpired, statusCode: retryCode };
      }
    }
    const errBody = String((err && err.body) || (err && err.message) || '');
    console.warn(`⚠️ WebPush error [HTTP ${code}]:`, errBody);
    // لا نحذف الاشتراك من القاعدة إلا إذا كان منتهياً فعلياً (404 أو 410)
    const expired = (code === 404 || code === 410);
    return { ok: false, expired, statusCode: code, errorMsg: errBody };
  }
}

function sendPushNotificationToPhone(phone, payloadObj = {}) {
  return trackPushTask((async () => {
    const cleanPh = normalizePhoneServer(phone);
    if (!cleanPh) return;
    try {
      const { data: subRows } = await supabase
        .from('push_subscriptions')
        .select('phone, subscription')
        .ilike('phone', `${cleanPh}%`);

      const matchedRows = (subRows || []).filter(r => {
        const k = String(r && r.phone ? r.phone : '');
        return k === cleanPh || k.startsWith(`${cleanPh}:`);
      });

      if (matchedRows.length === 0) return;

      const expiredKeys = [];
      const seenEndpoints = new Set();

      await Promise.allSettled(
        matchedRows.map(async (row) => {
          const subObj = typeof row.subscription === 'string' ? JSON.parse(row.subscription) : row.subscription;
          if (!subObj || !subObj.endpoint) return;
          if (seenEndpoints.has(subObj.endpoint)) return;
          seenEndpoints.add(subObj.endpoint);

          const res = await sendWebPushWithHighPriority(subObj, payloadObj);
          if (res.expired) expiredKeys.push(row.phone);
        })
      );

      if (expiredKeys.length > 0) {
        await supabase.from('push_subscriptions').delete().in('phone', expiredKeys);
      }
    } catch (err) {}
  })());
}

function notifyAdminsPush(category = 'platform', payloadObj = {}) {
  return trackPushTask((async () => {
    try {
      const rawState = await fetchRawDatabaseState(false);
      const s = rawState.settings || {};

      if (s.adminPushMasterEnabled === false) return;
      if (category === 'customer' && s.adminPushCustomersEnabled === false) return;
      if (category === 'captain' && s.adminPushCaptainsEnabled === false) return;

      const dedupeKey = `${category}|${payloadObj.title || ''}|${payloadObj.body || ''}`;
      const nowTs = Date.now();
      const lastSentTs = recentAdminPushDedupeMap.get(dedupeKey) || 0;
      if (nowTs - lastSentTs < 3000) return;
      recentAdminPushDedupeMap.set(dedupeKey, nowTs);
      if (recentAdminPushDedupeMap.size > 200) {
        for (const [k, ts] of recentAdminPushDedupeMap.entries()) {
          if (nowTs - ts > 10000) recentAdminPushDedupeMap.delete(k);
        }
      }

      const allowedAdminUsers = new Set();
      const envMasterUser = String(process.env.INITIAL_ADMIN_USER || 'ennaby1').trim().toLowerCase();
      allowedAdminUsers.add(envMasterUser);

      (rawState.adminAccounts || []).forEach(a => {
        if (!a || a.status === 'معطل') return;
        if (a.isMaster || (a.permissions && a.permissions.receiveAdminPush)) {
          allowedAdminUsers.add(String(a.username || '').trim().toLowerCase());
        }
      });

      const { data: adminSubs } = await supabase
        .from('push_subscriptions')
        .select('phone, subscription')
        .ilike('phone', 'admin:%');

      if (!adminSubs || adminSubs.length === 0) return;

      const targetSubs = adminSubs.filter(sub => {
        const rawPhoneKey = String(sub.phone || '');
        const parts = rawPhoneKey.split(':');
        const uname = String(parts[1] || '').trim().toLowerCase();
        return uname && allowedAdminUsers.has(uname);
      });

      if (targetSubs.length === 0) return;

      const expiredKeys = [];
      const seenEndpoints = new Set();

      await Promise.allSettled(
        targetSubs.map(async (subRow) => {
          const subObj = typeof subRow.subscription === 'string' ? JSON.parse(subRow.subscription) : subRow.subscription;
          if (!subObj || !subObj.endpoint) return;
          if (seenEndpoints.has(subObj.endpoint)) return;
          seenEndpoints.add(subObj.endpoint);

          const res = await sendWebPushWithHighPriority(subObj, {
            title: payloadObj.title || '🔔 رادار غرفة العمليات 🛡️',
            body: payloadObj.body || 'حركة جديدة على منصة الرجل العنابي',
            url: payloadObj.url || '/admin'
          });
          if (res.expired) expiredKeys.push(subRow.phone);
        })
      );

      if (expiredKeys.length > 0) {
        await supabase.from('push_subscriptions').delete().in('phone', expiredKeys);
      }
    } catch (e) {
      console.warn('Admin push notify warning:', e.message);
    }
  })());
}

function broadcastPushToAvailableCaptains(payloadObj = {}) {
  return trackPushTask((async () => {
    try {
      const { data: availCaptains } = await supabase
        .from('captains')
        .select('phone')
        .eq('status', 'معتمد')
        .eq('is_available', true);

      if (!availCaptains || availCaptains.length === 0) return;
      const availSet = new Set(availCaptains.map(c => normalizePhoneServer(c.phone)).filter(Boolean));

      const { data: allSubs } = await supabase.from('push_subscriptions').select('phone, subscription');
      if (!allSubs || allSubs.length === 0) return;

      const matchedSubs = allSubs.filter(s => {
        const rawPh = String(s.phone || '');
        if (rawPh.startsWith('admin:') || rawPh.startsWith('guest:')) return false;
        const basePh = normalizePhoneServer(rawPh.split(':')[0]);
        return availSet.has(basePh);
      });

      if (matchedSubs.length === 0) return;

      const expiredKeys = [];
      const seenEndpoints = new Set();

      await Promise.allSettled(
        matchedSubs.map(async (s) => {
          const subObj = typeof s.subscription === 'string' ? JSON.parse(s.subscription) : s.subscription;
          if (!subObj || !subObj.endpoint) return;
          if (seenEndpoints.has(subObj.endpoint)) return;
          seenEndpoints.add(subObj.endpoint);

          const res = await sendWebPushWithHighPriority(subObj, {
            title: payloadObj.title || 'الرجل العنابي 🛵',
            body: payloadObj.body || 'أوردر جديد متاح على الرادار الآن!',
            url: payloadObj.url || '/'
          });
          if (res.expired) expiredKeys.push(s.phone);
        })
      );

      if (expiredKeys.length > 0) {
        await supabase.from('push_subscriptions').delete().in('phone', expiredKeys);
      }
    } catch (e) {}
  })());
}

function broadcastPushByTargetGroup(target = 'all', payloadObj = {}) {
  return trackPushTask((async () => {
    try {
      const { data: allSubs } = await supabase.from('push_subscriptions').select('phone, subscription');
      if (!allSubs || allSubs.length === 0) return 0;

      const { data: captainsRows } = await supabase.from('captains').select('phone');
      const captainPhones = new Set((captainsRows || []).map(c => normalizePhoneServer(c.phone)).filter(Boolean));

      const publicSubs = allSubs.filter(s => !String(s.phone || '').startsWith('admin:'));
      const registeredEndpoints = new Set();
      publicSubs.forEach(s => {
        const ph = String(s.phone || '').trim();
        const subObj = typeof s.subscription === 'string' ? JSON.parse(s.subscription) : s.subscription;
        if (!ph.startsWith('guest:') && subObj && subObj.endpoint) {
          registeredEndpoints.add(subObj.endpoint);
        }
      });

      let filteredSubs = target === 'all' ? allSubs : publicSubs;
      if (target === 'captains') {
        filteredSubs = publicSubs.filter(s => {
          const basePh = normalizePhoneServer(String(s.phone || '').split(':')[0]);
          return captainPhones.has(basePh);
        });
      } else if (target === 'customers') {
        filteredSubs = publicSubs.filter(s => {
          const rawPh = String(s.phone || '').trim();
          if (rawPh.startsWith('guest:')) return false;
          const basePh = normalizePhoneServer(rawPh.split(':')[0]);
          return Boolean(basePh && !captainPhones.has(basePh));
        });
      } else if (target === 'unregistered') {
        filteredSubs = publicSubs.filter(s => {
          const ph = String(s.phone || '').trim();
          const subObj = typeof s.subscription === 'string' ? JSON.parse(s.subscription) : s.subscription;
          const ep = subObj && subObj.endpoint;
          return ph.startsWith('guest:') && (!ep || !registeredEndpoints.has(ep));
        });
      }

      const seenEndpoints = new Set();
      const targetSubs = [];
      filteredSubs.forEach(s => {
        let subObj = s && s.subscription;
        if (typeof subObj === 'string') {
          try { subObj = JSON.parse(subObj); } catch (e) { subObj = null; }
        }
        if (!subObj || !subObj.endpoint) return;
        if (seenEndpoints.has(subObj.endpoint)) return;
        seenEndpoints.add(subObj.endpoint);
        targetSubs.push({ phone: s.phone, subscription: subObj });
      });

      let sent = 0;
      const expiredKeys = [];

      await Promise.allSettled(
        targetSubs.map(async s => {
          const res = await sendWebPushWithHighPriority(s.subscription, payloadObj);
          if (res.ok) sent++;
          else if (res.expired) expiredKeys.push(s.phone);
        })
      );

      if (expiredKeys.length > 0) {
        await supabase.from('push_subscriptions').delete().in('phone', expiredKeys);
      }
      return sent;
    } catch (e) {
      return 0;
    }
  })());
}

app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ success: true, vapidPublicKey: VAPID_PUBLIC_KEY });
});

// حفظ ومزامنة اشتراك Web Push لجميع الأدوار النشطة على الهاتف (أدمن، كباتن، عملاء، وزوار)
app.post('/api/push/subscribe', asyncHandler(async (req, res) => {
  try {
    const { phone, courierPhone, customerPhone, clientId, subscription } = req.body || {};
    if (!subscription || typeof subscription !== 'object' || !subscription.endpoint) {
      return res.status(400).json({ success: false, message: 'بيانات الاشتراك غير صالحة ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
    const rawPhoneStr = phone ? String(phone).trim() : '';
    const cleanClientId = String(clientId || '').trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80);
    const nowIso = new Date().toISOString();

    const custCookiePhone = getAuthenticatedCustomerFromCookie(req, rawState.rawCustomersRows);
    const capCookiePhone = getAuthenticatedCaptainFromCookie(req, rawState.rawCaptains);

    const keysToUpsert = new Set();

    if (rawPhoneStr.startsWith('admin:')) {
      const adminToken = getAuthenticatedAdminFromCookie(req, rawState.rawAdminsRows);
      if (!adminToken || !adminToken.username) {
        return res.status(401).json({ success: false, message: 'يرجى تسجيل دخول المسؤول أولاً 🔒' });
      }
      const { data: adminRow } = await supabase
        .from('admins')
        .select('*')
        .ilike('username', adminToken.username)
        .maybeSingle();

      if (!adminRow || adminRow.status === 'معطل') {
        return res.status(403).json({ success: false, message: 'حساب المسؤول غير نشط ⛔' });
      }
      if (!adminRow.is_master && !(adminRow.permissions && adminRow.permissions.receiveAdminPush)) {
        return res.status(403).json({ success: false, message: 'ليس لديك صلاحية استقبال إشعارات الرادار ⛔' });
      }
      const parts = rawPhoneStr.split(':');
      const deviceSuffix = parts[2] ? String(parts[2]).trim().replace(/[^a-zA-Z0-9_-]/g, '') : 'default';
      keysToUpsert.add(`admin:${String(adminRow.username).trim().toLowerCase()}:${deviceSuffix}`);
    }

    [rawPhoneStr, courierPhone, customerPhone, capCookiePhone, custCookiePhone].forEach(phCandidate => {
      if (!phCandidate || String(phCandidate).startsWith('admin:') || String(phCandidate).startsWith('guest:')) return;
      const norm = normalizePhoneServer(phCandidate);
      if (isValidEgyptianPhoneServer(norm)) {
        keysToUpsert.add(norm);
        if (cleanClientId) {
          keysToUpsert.add(`${norm}:${cleanClientId}`);
        }
      }
    });

    if (keysToUpsert.size === 0) {
      const guestId = cleanClientId || rawPhoneStr.replace(/^guest:/, '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 80) || ('g_' + Date.now());
      keysToUpsert.add(`guest:${guestId}`);
    } else if (cleanClientId) {
      await supabase.from('push_subscriptions').delete().eq('phone', `guest:${cleanClientId}`);
    }

    const upsertRows = Array.from(keysToUpsert).map(k => ({
      phone: k,
      subscription,
      updated_at: nowIso
    }));

    await supabase.from('push_subscriptions').upsert(upsertRows);
    res.json({ success: true, keys: Array.from(keysToUpsert), vapidPublicKey: VAPID_PUBLIC_KEY });
  } catch (e) {
    res.status(500).json({ success: false });
  }
}));

app.post('/api/analytics/install', asyncHandler(async (req, res) => {
  try {
    const rawClientId = String((req.body && req.body.clientId) || (req.query && req.query.clientId) || '').trim();
    const rawState = await fetchRawDatabaseState(true);
    const prevInstalledIds = Array.isArray(rawState.settings?.installedClientIds)
      ? rawState.settings.installedClientIds
      : [];

    if (rawClientId && prevInstalledIds.includes(rawClientId)) {
      const state = await buildClientState(req, false);
      return res.json({
        success: true,
        alreadyCounted: true,
        appInstallsCount: rawState.settings?.appInstallsCount || 0,
        state
      });
    }

    const updatedIds = rawClientId ? [...prevInstalledIds.slice(-1999), rawClientId] : prevInstalledIds;
    const newTotal = await recordAnalyticsMetricEvent('installs', 1, { installedClientIds: updatedIds });

    notifyAdminsPush('customer', {
      title: '📲 تثبيت فعلي جديد للتطبيق!',
      body: `قام مستخدم بتثبيت تطبيق الرجل العنابي على هاتفه الآن (إجمالي التثبيتات الفعلية: ${newTotal}) 🚀`
    });
    const state = await buildClientState(req, true);
    res.json({ success: true, appInstallsCount: newTotal, state });
  } catch (err) {
    res.status(500).json({ success: false });
  }
}));

app.post('/api/presence/ping', (req, res) => {
  touchCustomerPresence(req, req.body && req.body.clientId);
  res.json({ success: true, onlineCustomersCount: getOnlineCustomersCount() });
});

// ==========================================
// 5-ب. مسار المزامنة الرئيسي (Bootstrap) والتحقق من الكوبونات
// ==========================================
app.get('/api/bootstrap', asyncHandler(async (req, res) => {
  try {
    const state = await buildClientState(req, false);
    res.json({ success: true, state });
  } catch (err) {
    console.error('Bootstrap error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر جلب البيانات' });
  }
}));

app.post('/api/promo-codes/validate', asyncHandler(async (req, res) => {
  try {
    const { code, clientPhone } = req.body || {};
    const cleanCode = String(code || '').trim().toUpperCase();
    const rawState = await fetchRawDatabaseState(false);
    const sessionPhone = getAuthenticatedCustomerFromCookie(req, rawState.rawCustomersRows);
    const cleanPhone = sessionPhone || normalizePhoneServer(clientPhone);

    if (!cleanCode) {
      return res.status(400).json({ success: false, message: 'اكتب كود الخصم الأول يا باشا! 🎟️⚠️' });
    }

    const promoCodes = Array.isArray(rawState.settings.promoCodes) ? rawState.settings.promoCodes : [];
    const promo = promoCodes.find(p => p && String(p.code).toUpperCase() === cleanCode && p.active !== false);

    if (!promo) {
      return res.status(404).json({ success: false, message: 'كود الخصم ده غير صحيح أو انتهى يا نجم 🧐⚠️' });
    }

    if (promo.expiresAt && Date.now() > Number(promo.expiresAt)) {
      return res.status(400).json({ success: false, message: 'يا خسارة! فترة سماح الكود ده خلصت خلاص ⏳❌' });
    }

    const isCustomTarget = Boolean(promo.targetPhone && promo.targetPhone !== 'all');
    const maxUses = getPromoMaxUsesForPhone(promo);

    if (isCustomTarget) {
      if (!cleanPhone) {
        return res.status(400).json({ success: false, message: 'اكتب رقم تليفونك في خانة الراسل الأول عشان نتحقق من الكود 📱⚠️' });
      }
      if (normalizePhoneServer(promo.targetPhone) !== cleanPhone) {
        return res.status(403).json({ success: false, message: 'الكود ده مخصوص لعميل تاني بالاسم يا باشا 😅🔒' });
      }
    }

    const usedCount = cleanPhone ? getPromoPhoneUsedCount(promo, cleanPhone) : 0;
    const remainingUses = Math.max(0, maxUses - usedCount);

    if (cleanPhone && usedCount >= maxUses) {
      const limitMsg = maxUses > 1
        ? `استهلكت الحد الأقصى المسموح به لهذا الكود (${maxUses} مرات استخدام) يا باشا 😎✅`
        : 'أنت استخدمت الكود ده قبل كده في مشوار سابق يا باشا 😎✅';
      return res.status(400).json({ success: false, message: limitMsg });
    }

    const usageHint = (isCustomTarget && maxUses > 1)
      ? ` (متاح ليك استخدامه ${remainingUses} من ${maxUses} مرات)`
      : '';

    res.json({
      success: true,
      promo: {
        code: promo.code,
        discountAmount: roundMoney(promo.discountAmount),
        targetPhone: promo.targetPhone || 'all',
        maxUses,
        usedCount,
        remainingUses,
        expiresAt: promo.expiresAt || null
      },
      message: `مبروك يا باشا! 🎉 الكود (${promo.code}) شغال وهيديك خصم ${promo.discountAmount} جنيه${usageHint} وتقدر تحتفظ بيه لحد انتهاء فترة السماح 🛵💸`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر التحقق من الكود حالياً ⚠️' });
  }
}));
// ==========================================
// 6. حماية التخمين، دوال المحافظ الذرية الآمنة، والمصادقة والصلاحيات
// ==========================================
async function checkRateLimit(phone) {
  const { data: attempt } = await supabase.from('login_attempts').select('*').eq('phone', phone).maybeSingle();
  if (attempt && attempt.locked_until && new Date(attempt.locked_until) > new Date()) {
    return { locked: true, message: 'حسابك مقفول مؤقتاً بسبب محاولات متكررة خاطئة. جرب كمان 15 دقيقة 🔒' };
  }
  return { locked: false, attemptData: attempt };
}

async function recordFailedAttempt(phone, attemptData) {
  const attempts = (attemptData?.attempts || 0) + 1;
  const updates = {
    attempts,
    locked_until: attempts >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null,
    updated_at: new Date().toISOString()
  };
  await supabase.from('login_attempts').upsert({ phone, ...updates });
}

async function clearFailedAttempts(phone) {
  await supabase.from('login_attempts').delete().eq('phone', phone);
}

// دوال محفظة ذرية تفحص أخطاء RPC وتتوافق مع الدوال المحدثة في قاعدة البيانات
async function safeAdjustCaptainWallet(phone, amount, reason) {
  const cleanPhone = normalizePhoneServer(phone);
  const cleanAmt = roundMoney(amount);
  if (!cleanPhone || cleanAmt === 0) return { ok: true };

  const { error } = await supabase.rpc('adjust_captain_wallet_atomic', {
    p_phone: cleanPhone,
    p_amount: cleanAmt,
    p_reason: String(reason || 'حركة مالية')
  });

  if (error) {
    const isInsufficient = String(error.message || '').includes('INSUFFICIENT_CAPTAIN_WALLET_BALANCE');
    console.error(`❌ RPC adjust_captain_wallet_atomic error (${cleanPhone}, ${cleanAmt}):`, error.message);
    return { ok: false, insufficientBalance: isInsufficient, error };
  }
  return { ok: true };
}

async function safeAdjustCustomerWallet(phone, amount, reason) {
  const cleanPhone = normalizePhoneServer(phone);
  const cleanAmt = roundMoney(amount);
  if (!cleanPhone || cleanAmt === 0) return { ok: true };

  const { error } = await supabase.rpc('adjust_customer_wallet_atomic', {
    p_phone: cleanPhone,
    p_amount: cleanAmt,
    p_reason: String(reason || 'حركة مالية')
  });

  if (error) {
    console.error(`❌ RPC adjust_customer_wallet_atomic error (${cleanPhone}, ${cleanAmt}):`, error.message);
    return { ok: false, error };
  }
  return { ok: true };
}

async function authenticateCaptain(req, res, next) {
  const token = req.cookies && req.cookies.captain_session;
  if (!token) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: captain } = await supabase.from('captains').select('*').eq('phone', normalizePhoneServer(decoded.phone)).maybeSingle();
    if (
      !captain ||
      (captain.session_version && decoded.session_version && Number(captain.session_version) !== Number(decoded.session_version)) ||
      (decoded.pwdSig && getPasswordSignature(captain.password_hash) !== decoded.pwdSig)
    ) {
      res.clearCookie('captain_session');
      return res.status(401).json({ success: false, message: 'تم إنهاء جلستك أمنياً، يرجى الدخول مجدداً ⛔' });
    }
    if (captain.status === 'موقوف' || captain.status === 'مرفوض') {
      return res.status(403).json({ success: false, message: `حسابك ${captain.status}.. راجع الإدارة ⛔` });
    }
    req.user = captain;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'جلسة الكابتن غير صالحة' });
  }
}

async function authenticateAdmin(req, res, next) {
  try {
    const token = req.cookies && req.cookies.admin_session;
    if (!token) {
      return res.status(401).json({ success: false, message: 'يرجى تسجيل دخول المسؤول أولاً 🔒' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.username) {
      return res.status(401).json({ success: false, message: 'جلسة المسؤول غير صالحة 🔒' });
    }

    const { data: admin } = await supabase
      .from('admins')
      .select('*')
      .ilike('username', String(decoded.username).trim())
      .maybeSingle();

    if (!admin) {
      res.clearCookie('admin_session');
      return res.status(401).json({ success: false, message: 'حساب المسؤول غير موجود 🔒' });
    }

    if (admin.status === 'معطل') {
      res.clearCookie('admin_session');
      return res.status(403).json({ success: false, message: 'تم تعطيل حساب المسؤول من الإدارة ⛔' });
    }

    if (decoded.pwdSig && getPasswordSignature(admin.password_hash) !== decoded.pwdSig) {
      res.clearCookie('admin_session');
      return res.status(401).json({ success: false, message: 'تم تغيير كلمة المرور، يرجى تسجيل الدخول مجدداً 🔒' });
    }

    req.admin = admin;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'انتهت جلسة المسؤول، يرجى تسجيل الدخول مجدداً 🔒' });
  }
}

function requireAdminPerm(req, res, permKeys = []) {
  const adm = req.admin;
  if (!adm || adm.status === 'معطل') {
    res.status(403).json({ success: false, message: 'حساب المسؤول غير مصرح له ⛔' });
    return false;
  }
  if (adm.is_master || adm.isMaster) return true;
  const keys = Array.isArray(permKeys) ? permKeys : [permKeys];
  const perms = adm.permissions || {};
  const hasAny = keys.some(k => Boolean(perms[k]));
  if (!hasAny) {
    res.status(403).json({ success: false, message: 'عفواً، ليس لديك صلاحية لتنفيذ هذا الإجراء في غرفة العمليات ⛔' });
    return false;
  }
  return true;
}

// ==========================================
// 7. مسارات المصادقة وتسجيل الدخول والكباتن الجدد
// ==========================================
app.post('/api/auth/admin/login', asyncHandler(async (req, res) => {
  try {
    const rawUser = String((req.body && req.body.username) || '').trim();
    const rawPass = String((req.body && req.body.password) || '').trim();

    if (!rawUser || !rawPass) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال اسم المستخدم وكلمة المرور ⚠️' });
    }

    const rateKey = `admin_${rawUser.toLowerCase()}`;
    const rateLimit = await checkRateLimit(rateKey);
    if (rateLimit.locked) {
      return res.status(429).json({ success: false, message: rateLimit.message });
    }

    const { data: admin } = await supabase
      .from('admins')
      .select('*')
      .ilike('username', rawUser)
      .maybeSingle();

    if (!admin) {
      await recordFailedAttempt(rateKey, rateLimit.attemptData);
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    }

    if (admin.status === 'معطل') {
      return res.status(403).json({ success: false, message: 'هذا الحساب معطل حالياً من الإدارة الرئيسية ⛔' });
    }

    const isMatch = await bcrypt.compare(rawPass, admin.password_hash);
    if (!isMatch) {
      await recordFailedAttempt(rateKey, rateLimit.attemptData);
      return res.status(401).json({ success: false, message: 'كلمة المرور غير صحيحة! ⚠️' });
    }

    await clearFailedAttempts(rateKey);

    const token = jwt.sign(
      {
        username: admin.username,
        isMaster: Boolean(admin.is_master),
        pwdSig: getPasswordSignature(admin.password_hash)
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const isSecureCookie = IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('admin_session', token, {
      httpOnly: true,
      secure: isSecureCookie,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    req.cookies = { ...(req.cookies || {}), admin_session: token };
    req.query = { ...(req.query || {}), role: 'admin' };
    const state = await buildClientState(req, true);

    res.json({
      success: true,
      message: `مرحباً بك يا ${admin.name} في غرفة العمليات 🛡️✅`,
      admin: {
        username: admin.username,
        name: admin.name,
        isMaster: Boolean(admin.is_master),
        permissions: admin.permissions || {}
      },
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول' });
  }
}));

app.post('/api/auth/admin/logout', (req, res) => {
  res.clearCookie('admin_session');
  res.json({ success: true });
});

app.post('/api/auth/customer/login', asyncHandler(async (req, res) => {
  try {
    const cleanPhone = normalizePhoneServer(req.body && req.body.phone);
    const cleanPin = String((req.body && req.body.pin) || '')
      .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
      .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
      .trim();

    if (!isValidEgyptianPhoneServer(cleanPhone) || !/^[0-9]{4}$/.test(cleanPin)) {
      return res.status(400).json({ success: false, message: 'تأكد من كتابة رقم الموبايل ورمز الـ PIN (4 أرقام) بشكل صحيح 📱⚠️' });
    }

    const rateLimit = await checkRateLimit(cleanPhone);
    if (rateLimit.locked) {
      return res.status(429).json({ success: false, message: rateLimit.message });
    }

    const { data: customer } = await supabase.from('customers').select('*').eq('phone', cleanPhone).maybeSingle();
    if (!customer) {
      await recordFailedAttempt(cleanPhone, rateLimit.attemptData);
      return res.status(404).json({ success: false, message: 'الرقم ده ملوش حساب مسجل عندنا لسه.. اطلب أول مشوار وهيتسجل فوراً! 🛵' });
    }

    const isMatch = await bcrypt.compare(cleanPin, customer.pin_hash);
    if (!isMatch) {
      await recordFailedAttempt(cleanPhone, rateLimit.attemptData);
      return res.status(401).json({ success: false, message: 'رمز الـ PIN غير صحيح يا باشا! 🔒⚠️' });
    }

    await clearFailedAttempts(cleanPhone);

    const token = jwt.sign(
      { phone: cleanPhone, role: 'customer', pwdSig: getPasswordSignature(customer.pin_hash) },
      JWT_SECRET,
      { expiresIn: '90d' }
    );
    const isSecureCookie = IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('customer_session', token, {
      httpOnly: true,
      secure: isSecureCookie,
      sameSite: 'lax',
      maxAge: 90 * 24 * 60 * 60 * 1000
    });

    req.cookies = { ...(req.cookies || {}), customer_session: token };
    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: 'فتحنا حسابك ورجّعنا نقطك ومحفظتك بنجاح يا باشا 🛵👑',
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر فتح الحساب حالياً ⚠️' });
  }
}));

app.post('/api/auth/captain/login', asyncHandler(async (req, res) => {
  try {
    const cleanPhone = normalizePhoneServer(req.body && req.body.phone);
    const rawPass = String((req.body && req.body.password) || '').trim();

    if (!isValidEgyptianPhoneServer(cleanPhone) || !rawPass) {
      return res.status(400).json({ success: false, message: 'اكتب رقم الموبايل والباسورد صح يا بطل ⚠️' });
    }

    const rateLimit = await checkRateLimit(cleanPhone);
    if (rateLimit.locked) {
      return res.status(429).json({ success: false, message: rateLimit.message });
    }

    const { data: captain } = await supabase.from('captains').select('*').eq('phone', cleanPhone).maybeSingle();
    if (!captain) {
      await recordFailedAttempt(cleanPhone, rateLimit.attemptData);
      return res.status(401).json({ success: false, message: 'رقم الموبايل ده مش مسجل في كباتن العنابي ⚠️' });
    }

    const isMatch = await bcrypt.compare(rawPass, captain.password_hash);
    if (!isMatch) {
      await recordFailedAttempt(cleanPhone, rateLimit.attemptData);
      return res.status(401).json({ success: false, message: 'كلمة السر غير صحيحة يا كابتن! ⚠️' });
    }

    await clearFailedAttempts(cleanPhone);

    if (captain.status === 'مرفوض') {
      return res.status(403).json({
        success: false,
        status: 'مرفوض',
        rejectReason: captain.reject_reason || captain.suspend_reason || 'يرجى إعادة رفع صور البطاقة والمركبة بوضوح',
        captainProfile: {
          phone: captain.phone,
          fullName: captain.full_name,
          nationalId: captain.national_id,
          primaryZone: captain.primary_zone,
          vehicleType: captain.vehicle_type,
          plateNumber: captain.plate_number
        },
        message: 'تم رفض المستندات السابقة، يرجى إعادة رفع صور واضحة 📄⚠️'
      });
    }

    if (captain.status === 'موقوف') {
      return res.status(403).json({
        success: false,
        status: 'موقوف',
        message: `حسابك موقوف حالياً: ${captain.suspend_reason || 'يرجى التواصل مع الإدارة'} ⛔`
      });
    }

    const sessionVer = Number(captain.session_version || 1);
    const token = jwt.sign(
      {
        phone: cleanPhone,
        role: 'courier',
        session_version: sessionVer,
        pwdSig: getPasswordSignature(captain.password_hash)
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    const isSecureCookie = IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('captain_session', token, {
      httpOnly: true,
      secure: isSecureCookie,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });

    req.cookies = { ...(req.cookies || {}), captain_session: token };
    req.query = { ...(req.query || {}), role: 'courier' };
    const state = await buildClientState(req, true);

    res.json({
      success: true,
      message: `منور الميدان يا كابتن ${captain.full_name}! 🛵💪`,
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر تسجيل الدخول حالياً ⚠️' });
  }
}));

app.post('/api/auth/captain/logout', (req, res) => {
  res.clearCookie('captain_session');
  res.json({ success: true });
});

app.post('/api/captains/register', asyncHandler(async (req, res) => {
  try {
    const rawState = await fetchRawDatabaseState(true);
    const body = req.body || {};
    const cleanPhone = normalizePhoneServer(body.phone);
    const fullName = String(body.fullName || '').trim();
    const nationalId = String(body.nationalId || '').replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632)).trim();
    const password = String(body.password || '').trim();
    const primaryZone = String(body.primaryZone || 'المنصورة').trim();
    const vehicleType = String(body.vehicleType || 'موتوسيكل').trim();
    const plateNumber = vehicleType === 'دراجة' ? 'دراجة معفية' : String(body.plateNumber || '').trim();
    const referredByRaw = body.referredByPhone ? normalizePhoneServer(body.referredByPhone) : null;
    const referredByPhone = (referredByRaw && isValidEgyptianPhoneServer(referredByRaw) && referredByRaw !== cleanPhone) ? referredByRaw : null;

    if (!isValidEgyptianPhoneServer(cleanPhone)) {
      return res.status(400).json({ success: false, message: 'رقم الموبايل غير صحيح ⚠️' });
    }
    if (!fullName || fullName.split(/\s+/).length < 3) {
      return res.status(400).json({ success: false, message: 'يرجى كتابة الاسم ثلاثياً كما في البطاقة ⚠️' });
    }
    if (!/^[0-9]{14}$/.test(nationalId)) {
      return res.status(400).json({ success: false, message: 'الرقم القومي يجب أن يكون 14 رقماً ⚠️' });
    }
    if (!password || password.length < 4) {
      return res.status(400).json({ success: false, message: 'كلمة المرور يجب ألا تقل عن 4 أحرف أو أرقام ⚠️' });
    }
    if (!body.idFrontPhoto || !body.idBackPhoto) {
      return res.status(400).json({ success: false, message: 'لازم ترفع صورة وش وضهر البطاقة واضحة ⚠️' });
    }
    if (vehicleType !== 'دراجة' && (!plateNumber || !body.vehiclePhoto)) {
      return res.status(400).json({ success: false, message: 'يرجى إدخال رقم اللوحة وصورة المركبة ⚠️' });
    }

    const { data: existingCap } = await supabase.from('captains').select('*').eq('phone', cleanPhone).maybeSingle();
    if (existingCap && existingCap.status !== 'مرفوض') {
      return res.status(400).json({ success: false, message: 'رقم الهاتف هذا مسجل بالفعل في كباتن العنابي! سجل دخولك مباشرة 🛵' });
    }
    if (!existingCap && rawState.settings.allowCaptainRegistration === false) {
      return res.status(403).json({ success: false, message: 'باب تسجيل الكباتن الجدد مغلق حالياً لاكتمال العدد 🛵' });
    }

    const [frontUrl, backUrl, vehUrl] = await Promise.all([
      uploadCaptainDocToStorage(cleanPhone, 'idFront', body.idFrontPhoto),
      uploadCaptainDocToStorage(cleanPhone, 'idBack', body.idBackPhoto),
      vehicleType === 'دراجة' ? Promise.resolve(null) : uploadCaptainDocToStorage(cleanPhone, 'vehicle', body.vehiclePhoto)
    ]);

    const hashedPass = await bcrypt.hash(password, 10);

    if (existingCap && existingCap.status === 'مرفوض') {
      const nextSessionVer = Number(existingCap.session_version || 1) + 1;
      const { error: updErr } = await supabase.from('captains').update({
        password_hash: hashedPass,
        full_name: fullName,
        national_id: nationalId,
        primary_zone: primaryZone,
        vehicle_type: vehicleType,
        plate_number: plateNumber,
        id_front_photo: frontUrl,
        id_back_photo: backUrl,
        vehicle_photo: vehUrl,
        status: 'قيد المراجعة',
        reject_reason: null,
        suspend_reason: null,
        session_version: nextSessionVer
      }).eq('phone', cleanPhone);

      if (updErr) {
        return res.status(500).json({ success: false, message: 'تعذر تحديث بيانات التسجيل حالياً ⚠️' });
      }
    } else {
      const { error: insErr } = await supabase.from('captains').insert([{
        phone: cleanPhone,
        password_hash: hashedPass,
        full_name: fullName,
        national_id: nationalId,
        primary_zone: primaryZone,
        vehicle_type: vehicleType,
        plate_number: plateNumber,
        id_front_photo: frontUrl,
        id_back_photo: backUrl,
        vehicle_photo: vehUrl,
        status: 'قيد المراجعة',
        is_available: false,
        wallet_balance: 0,
        points: 0,
        referred_by_phone: referredByPhone
      }]);

      if (insErr) {
        return res.status(500).json({ success: false, message: 'تعذر حفظ طلب التسجيل حالياً ⚠️' });
      }
      await recordAnalyticsMetricEvent('captains', 1);
    }

    invalidateStateCache();
    notifyAdminsPush('captain', {
      title: `🛵 طلب انضمام كابتن جديد: ${fullName}`,
      body: `الهاتف: ${cleanPhone} | المنطقة: ${primaryZone} | المركبة: ${vehicleType} — بانتظار المراجعة والاعتماد.`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: 'تم إرسال أوراقك للإدارة بنجاح وفي انتظار التفعيل 🛵🎉',
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء رفع المستندات ⚠️' });
  }
}));

// ==========================================
// 8. دورة حياة الطلبات والتفاوض والرادار (الجزء الأول)
// ==========================================
app.post('/api/orders', asyncHandler(async (req, res) => {
  const body = req.body || {};
  const clientPhone = normalizePhoneServer(body.clientPhone);
  const lockKey = `order_create_${clientPhone || 'anon'}`;

  if (promoRedeemLocks.has(lockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تأكيد طلبك بالفعل، انتظر لحظة يا باشا ⏳' });
  }
  promoRedeemLocks.add(lockKey);

  try {
    const rawState = await fetchRawDatabaseState(true);
    const settings = rawState.settings || {};

    if (settings.maintenanceMode) {
      return res.status(503).json({ success: false, message: 'المنصة في وضع الصيانة السريعة حالياً، راجعين في ثواني 🛠️' });
    }

    const tripType = body.tripType === 'fetch' ? 'fetch' : 'send';
    const pickupZone = String(body.pickupZone || rawState.zones[0] || 'المنصورة').trim();
    const pickupAddress = stripMetaAndBrokenBrackets(body.pickupAddress || '');
    const dropoffZone = String(body.dropoffZone || rawState.zones[0] || 'المنصورة').trim();
    const dropoffAddress = stripMetaAndBrokenBrackets(body.dropoffAddress || '');
    const customerNotes = stripMetaAndBrokenBrackets(body.customerNotes || '');
    const packageType = String(body.packageType || DEFAULT_PACKAGE_TYPES[0]).trim();
    const payer = String(body.payer || 'الراسل').trim();
    const senderPhone = normalizePhoneServer(body.senderPhone);
    const recipientPhone = normalizePhoneServer(body.recipientPhone);

    if (!pickupAddress || !dropoffAddress) {
      return res.status(400).json({ success: false, message: 'يرجى كتابة عنوان الاستلام والتسليم بالتفصيل 📍⚠️' });
    }
    if (!isValidEgyptianPhoneServer(clientPhone) || !isValidEgyptianPhoneServer(senderPhone) || !isValidEgyptianPhoneServer(recipientPhone)) {
      return res.status(400).json({ success: false, message: 'تأكد من صحة أرقام الهواتف المدخلة (11 رقم يبدأ بـ 01) 📱⚠️' });
    }

    const cookieCustomerPhone = getAuthenticatedCustomerFromCookie(req, rawState.rawCustomersRows);
    const isCookieVerifiedForPhone = Boolean(cookieCustomerPhone && cookieCustomerPhone === clientPhone);
    const cleanPin = String(body.pin || '')
      .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
      .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
      .trim();

    const { data: existingCust } = await supabase.from('customers').select('*').eq('phone', clientPhone).maybeSingle();
    let activePinHash = existingCust ? existingCust.pin_hash : '';

    if (existingCust) {
      if (!isCookieVerifiedForPhone) {
        if (!/^[0-9]{4}$/.test(cleanPin)) {
          return res.status(401).json({
            success: false,
            needPin: true,
            message: 'اكتب رمز الـ PIN السري بتاعك (4 أرقام) عشان نأكد طلبك يا باشا 🔒'
          });
        }
        // حماية الـ PIN في إنشاء الطلب من التخمين عبر فحص وتسجيل المحاولات الفاشلة
        const rateLimit = await checkRateLimit(clientPhone);
        if (rateLimit.locked) {
          return res.status(429).json({ success: false, message: rateLimit.message });
        }
        const pinOk = await bcrypt.compare(cleanPin, existingCust.pin_hash);
        if (!pinOk) {
          await recordFailedAttempt(clientPhone, rateLimit.attemptData);
          return res.status(401).json({
            success: false,
            needPin: true,
            message: 'رمز الـ PIN غير صحيح لهذا الرقم يا باشا! 🔒⚠️'
          });
        }
        await clearFailedAttempts(clientPhone);
      }
    } else {
      if (!/^[0-9]{4}$/.test(cleanPin)) {
        return res.status(400).json({
          success: false,
          needPin: true,
          message: 'اختار رمز PIN سري من 4 أرقام عشان نحفظ بيه حسابك ونقطك يا باشا 🔒'
        });
      }
      activePinHash = await bcrypt.hash(cleanPin, 10);
      const { error: custInsErr } = await supabase.from('customers').insert([{
        phone: clientPhone,
        pin_hash: activePinHash,
        wallet_balance: 0,
        points: 0,
        wallet_transactions: []
      }]);
      if (custInsErr) {
        return res.status(500).json({ success: false, message: 'تعذر تسجيل حساب العميل حالياً ⚠️' });
      }
      await recordAnalyticsMetricEvent('customers', 1);
    }

    const custToken = jwt.sign(
      { phone: clientPhone, role: 'customer', pwdSig: getPasswordSignature(activePinHash) },
      JWT_SECRET,
      { expiresIn: '90d' }
    );
    const isSecureCookie = IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https';
    res.cookie('customer_session', custToken, {
      httpOnly: true,
      secure: isSecureCookie,
      sameSite: 'lax',
      maxAge: 90 * 24 * 60 * 60 * 1000
    });
    req.cookies = { ...(req.cookies || {}), customer_session: custToken };

    const routeKey = `${pickupZone}|${dropoffZone}`;
    const baseRoutePrice = roundMoney(rawState.pricing[routeKey] ?? DEFAULT_PRICING[routeKey] ?? 40);
    const surgeInfo = getActiveSurgeInfo(settings);
    const routeDefaultFare = surgeInfo.isActive
      ? roundMoney(baseRoutePrice * (1 + surgeInfo.surgePercent / 100))
      : baseRoutePrice;
    const minAllowedFare = Math.max(15, Math.floor(routeDefaultFare * 0.7));

    let originalFare = routeDefaultFare;
    let customerProposedFare = null;
    if (body.proposedFare !== undefined && body.proposedFare !== null && body.proposedFare !== '') {
      const propNum = roundMoney(body.proposedFare);
      if (!Number.isFinite(propNum) || propNum < minAllowedFare) {
        return res.status(400).json({
          success: false,
          message: `الحد الأدنى للأجرة العادلة لهذا المسار هو (${minAllowedFare} جنيه) يا باشا 🛵⚠️`
        });
      }
      originalFare = propNum;
      if (propNum !== routeDefaultFare) {
        customerProposedFare = propNum;
      }
    }

    const { data: freshCust } = await supabase.from('customers').select('*').eq('phone', clientPhone).maybeSingle();
    const availableWallet = Math.max(0, roundMoney(freshCust?.wallet_balance ?? 0));
    const walletDiscount = availableWallet > 0 ? roundMoney(Math.min(availableWallet, originalFare)) : 0;

    let promoDiscount = 0;
    let appliedPromoCode = null;
    const requestedPromo = body.promoCode ? String(body.promoCode).trim().toUpperCase() : '';
    const promoList = Array.isArray(settings.promoCodes)
      ? settings.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
      : [];

    if (requestedPromo) {
      const pIdx = promoList.findIndex(p => p.code === requestedPromo && p.active !== false);
      if (pIdx !== -1) {
        const promoObj = promoList[pIdx];
        const notExpired = !promoObj.expiresAt || Date.now() <= Number(promoObj.expiresAt);
        const matchesTarget = !promoObj.targetPhone || promoObj.targetPhone === 'all' || normalizePhoneServer(promoObj.targetPhone) === clientPhone;
        const maxUses = getPromoMaxUsesForPhone(promoObj);
        const usedCount = getPromoPhoneUsedCount(promoObj, clientPhone);

        if (notExpired && matchesTarget && usedCount < maxUses) {
          const remAfterWallet = Math.max(0, roundMoney(originalFare - walletDiscount));
          promoDiscount = roundMoney(Math.min(roundMoney(promoObj.discountAmount || 0), remAfterWallet));
          if (promoDiscount > 0) {
            appliedPromoCode = promoObj.code;
            const nextUsed = usedCount + 1;
            const counts = { ...(promoObj.usageCounts || {}), [clientPhone]: nextUsed };
            promoList[pIdx] = {
              ...promoObj,
              usageCounts: counts,
              usedBy: Object.keys(counts).filter(ph => counts[ph] >= maxUses)
            };
            await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
          }
        }
      }
    }

    const discountApplied = roundMoney(walletDiscount + promoDiscount);
    const finalCashFare = Math.max(0, roundMoney(originalFare - discountApplied));
    const platformFee = computeDefaultOrderPlatformFee(originalFare, settings);
    const courierNet = Math.max(0, roundMoney(originalFare - platformFee));

    const orderId = `#ORD-${Math.floor(1000 + Math.random() * 9000)}`;
    const encodedNotes = encodeOrderMetaIntoNotes(customerNotes, {
      pickupLat: body.pickupLat,
      pickupLng: body.pickupLng,
      dropoffLat: body.dropoffLat,
      dropoffLng: body.dropoffLng,
      promoCode: appliedPromoCode,
      promoDiscount,
      walletDiscount,
      surgePercent: surgeInfo.isActive ? surgeInfo.surgePercent : 0,
      routeDefaultFare,
      customerProposedFare,
      purchaseBudget: tripType === 'fetch' ? (body.purchaseBudget || 'أقل من 200 ج') : null
    });

    if (walletDiscount > 0) {
      const walRes = await safeAdjustCustomerWallet(
        clientPhone,
        -walletDiscount,
        `خصم تلقائي لطلب مشوار ${orderId}`
      );
      if (!walRes.ok) {
        if (appliedPromoCode) await releasePromoCodeUsageForCancelledOrder(appliedPromoCode, clientPhone);
        return res.status(500).json({ success: false, message: 'تعذر خصم رصيد المحفظة، يرجى المحاولة مرة أخرى ⚠️' });
      }
    }

    const { error: ordErr } = await supabase.from('orders').insert([{
      id: orderId,
      customer_phone: clientPhone,
      client_phone: clientPhone,
      trip_type: tripType,
      pickup_zone: pickupZone,
      pickup_address: pickupAddress,
      dropoff_zone: dropoffZone,
      dropoff_address: dropoffAddress,
      customer_notes: encodedNotes,
      package_type: packageType,
      payer,
      sender_phone: senderPhone,
      recipient_phone: recipientPhone,
      original_fare: originalFare,
      discount_applied: discountApplied,
      fare: finalCashFare,
      platform_fee: platformFee,
      courier_net: courierNet,
      status: 'في انتظار كابتن',
      fee_deducted: false,
      fee_refunded: false
    }]);

    if (ordErr) {
      if (walletDiscount > 0) {
        await safeAdjustCustomerWallet(clientPhone, walletDiscount, `استرداد تلقائي لعدم اكتمال إنشاء طلب ${orderId}`);
      }
      if (appliedPromoCode) {
        await releasePromoCodeUsageForCancelledOrder(appliedPromoCode, clientPhone);
      }
      return res.status(500).json({ success: false, message: 'تعذر إنشاء الطلب حالياً، حاول مرة أخرى ⚠️' });
    }

    // تفعيل الذروة التلقائية الذكية (Auto-Surge) إذا كانت مفعلة وتراكمت 3 طلبات منتظرة مع قلة الكباتن
    if (settings.autoSurgeEnabled && !surgeInfo.isActive) {
      const waitingCnt = (rawState.orders || []).filter(o => o.status === 'في انتظار كابتن').length + 1;
      const availCapCnt = (rawState.rawCaptains || []).filter(c => c.status === 'معتمد' && c.is_available).length;
      if (waitingCnt >= 3 && waitingCnt > availCapCnt) {
        const autoEnd = Date.now() + 20 * 60000;
        await saveIncentivesToDatabase(rawState, {
          surgePercent: 15,
          surgeDurationMinutes: 20,
          surgeEndTime: autoEnd
        });
      }
    }

    invalidateStateCache();

    broadcastPushToAvailableCaptains({
      title: `🔔 أوردر جديد ع الرادار (${orderId}) 🛵`,
      body: `من: ${pickupZone} (${pickupAddress}) ⬅️ إلى: ${dropoffZone} | الأجرة: ${originalFare} ج`
    });

    notifyAdminsPush('customer', {
      title: `📦 طلب جديد (${orderId}) — ${originalFare} ج`,
      body: `العميل: ${clientPhone} | من (${pickupZone}) إلى (${dropoffZone}) | الدفع كاش: ${finalCashFare} ج`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `طلبك (${orderId}) طار ع الرادار للكباتن بنجاح يا باشا! 🚀🛵`,
      orderId,
      state
    });
  } catch (err) {
    console.error('Create order error:', err.message);
    res.status(500).json({ success: false, message: 'حدث خطأ غير متوقع أثناء تأكيد الطلب ⚠️' });
  } finally {
    promoRedeemLocks.delete(lockKey);
  }
}));

// مسار تقديم الكابتن لعرض سعر أو رفض السعر المقابل من العميل
app.post('/api/orders/:id/offer', authenticateCaptain, asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const lockKey = `order_lock_${orderId}`;
  if (promoRedeemLocks.has(lockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تحديث بيانات الطلب، حاول بعد لحظة ⏳' });
  }
  promoRedeemLocks.add(lockKey);

  try {
    const captain = req.user;
    if (captain.status !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك غير معتمد حالياً لتقديم عروض ⛔' });
    }

    const { action, offeredFare } = req.body || {};
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.status !== 'في انتظار كابتن') {
      return res.status(400).json({ success: false, message: 'هذا الطلب لم يعد متاحاً على الرادار 🏃‍♂️' });
    }

    const rawState = await fetchRawDatabaseState(false);
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
    const offers = Array.isArray(meta.captainOffers) ? [...meta.captainOffers] : [];
    const capPhone = normalizePhoneServer(captain.phone);
    const existingIdx = offers.findIndex(o => normalizePhoneServer(o.captainPhone) === capPhone);

    if (action === 'reject_counter') {
      if (existingIdx !== -1) {
        offers[existingIdx] = {
          ...offers[existingIdx],
          status: 'rejected_by_captain',
          updatedAt: Date.now()
        };
      }
      const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, { ...meta, captainOffers: offers });
      await supabase.from('orders').update({ customer_notes: updatedNotes }).eq('id', orderId).eq('status', 'في انتظار كابتن');
      invalidateStateCache();

      const custPhone = order.customer_phone || order.client_phone;
      if (custPhone) {
        sendPushNotificationToPhone(custPhone, {
          title: `اعتذار عن السعر المقترح (${orderId}) 🛵`,
          body: `اعتذر الكابتن ${captain.full_name} عن السعر المقترح، وطلبك ما زال متاحاً للكباتن ع الرادار.`
        });
      }
      const state = await buildClientState(req, true);
      return res.json({ success: true, message: 'تم رفض السعر المقترح من العميل ✅', state });
    }

    const cleanOfferedFare = roundMoney(offeredFare);
    const baseRef = roundMoney(meta.routeDefaultFare || order.original_fare || 35);
    const minOffer = Math.max(15, Math.floor(baseRef * 0.7));
    if (!Number.isFinite(cleanOfferedFare) || cleanOfferedFare < minOffer) {
      return res.status(400).json({ success: false, message: `يرجى إدخال سعر منطقي لا يقل عن (${minOffer} ج) ⚠️` });
    }

    const tierInfo = computeCaptainTierAndFee(captain, rawState.orders, rawState.settings, cleanOfferedFare);
    if (roundMoney(captain.wallet_balance || 0) < tierInfo.effectiveFee) {
      return res.status(400).json({
        success: false,
        message: `رصيد محفظتك الحالي (${roundMoney(captain.wallet_balance)} ج) لا يكفي عمولة المنصة (${tierInfo.effectiveFee} ج). اشحن محفظتك أولاً 🛵💸`
      });
    }

    const newOfferObj = {
      captainPhone: capPhone,
      captainName: captain.full_name || 'كابتن العنابي',
      vehicleType: captain.vehicle_type || 'موتوسيكل',
      tier: tierInfo.tier,
      tierBadgeText: tierInfo.tierBadgeText,
      offeredFare: cleanOfferedFare,
      status: 'pending',
      at: Date.now()
    };

    if (existingIdx !== -1) {
      offers[existingIdx] = newOfferObj;
    } else {
      offers.unshift(newOfferObj);
    }

    const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, { ...meta, captainOffers: offers });
    await supabase.from('orders').update({ customer_notes: updatedNotes }).eq('id', orderId).eq('status', 'في انتظار كابتن');
    invalidateStateCache();

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      sendPushNotificationToPhone(custPhone, {
        title: `💵 عرض سعر جديد لطلبك (${orderId}) 🛵`,
        body: `الكابتن ${captain.full_name} (${tierInfo.tierBadgeText}) يقترح توصيل مشوارك بـ ${cleanOfferedFare} جنيه. افتح التطبيق للقبول أو التفاوض!`
      });
    }
    notifyAdminsPush('captain', {
      title: `🤝 عرض كابتن على طلب (${orderId})`,
      body: `الكابتن ${captain.full_name} اقترح ${cleanOfferedFare} ج (بدلاً من ${order.original_fare} ج).`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `تم إرسال عرضك (${cleanOfferedFare} ج) للعميل بنجاح! 🚀`,
      state
    });
  } catch (err) {
    console.error('Order offer error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر إرسال العرض حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(lockKey);
  }
}));

// مسار تفاوض العميل على الطلب (قبول عرض كابتن، رفض عرض، عرض مقابل، أو تحديث السعر)
app.post('/api/orders/:id/negotiate', asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const lockKey = `order_lock_${orderId}`;
  if (promoRedeemLocks.has(lockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ العملية على الطلب، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(lockKey);

  try {
    const rawState = await fetchRawDatabaseState(true);
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.status !== 'في انتظار كابتن') {
      return res.status(400).json({ success: false, message: 'الطلب لم يعد في حالة انتظار كابتن ⚠️' });
    }

    if (!verifyCustomerOrderOwnership(req, order, rawState.rawCustomersRows)) {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بتعديل هذا الطلب 🔒' });
    }

    const { action, captainPhone, newFare } = req.body || {};
    const cleanCapPhone = captainPhone ? normalizePhoneServer(captainPhone) : '';
    const custPhone = normalizePhoneServer(order.customer_phone || order.client_phone);
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
    const offers = Array.isArray(meta.captainOffers) ? [...meta.captainOffers] : [];
    const offerIdx = cleanCapPhone ? offers.findIndex(o => normalizePhoneServer(o.captainPhone) === cleanCapPhone) : -1;

    if (action === 'reject_offer') {
      if (offerIdx === -1) {
        return res.status(404).json({ success: false, message: 'العرض غير موجود ⚠️' });
      }
      offers[offerIdx] = { ...offers[offerIdx], status: 'rejected', updatedAt: Date.now() };
      const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, { ...meta, captainOffers: offers });
      await supabase.from('orders').update({ customer_notes: updatedNotes }).eq('id', orderId).eq('status', 'في انتظار كابتن');
      invalidateStateCache();

      sendPushNotificationToPhone(cleanCapPhone, {
        title: `رفض العرض على الطلب (${orderId}) ❌`,
        body: `رفض العميل السعر المقترح (${offers[offerIdx].offeredFare} ج)؛ يمكنك قبول السعر الحالي أو تقديم عرض آخر.`
      });

      const state = await buildClientState(req, true);
      return res.json({ success: true, message: 'تم رفض عرض الكابتن، وطلبك ما زال متاحاً على الرادار 📡', state });
    }

    if (action === 'accept_offer') {
      if (offerIdx === -1) {
        return res.status(404).json({ success: false, message: 'عرض الكابتن غير موجود ⚠️' });
      }
      const targetOffer = offers[offerIdx];
      const agreedFare = roundMoney(targetOffer.offeredFare || order.original_fare);

      const { data: capRow } = await supabase.from('captains').select('*').eq('phone', cleanCapPhone).maybeSingle();
      if (!capRow || capRow.status !== 'معتمد') {
        return res.status(400).json({ success: false, message: 'الكابتن لم يعد متاحاً حالياً ⚠️' });
      }

      const activeCapOrders = (rawState.orders || []).filter(
        o => normalizePhoneServer(o.assignedCourierPhone) === cleanCapPhone && ACTIVE_COURIER_ORDER_STATUSES.includes(o.status)
      );
      const maxConcurrent = Math.max(1, Number(rawState.settings.maxConcurrentOrdersPerCaptain ?? 3));
      if (activeCapOrders.length >= maxConcurrent) {
        return res.status(400).json({ success: false, message: 'الكابتن انشغل بالحد الأقصى من المشاوير حالياً، اختر عرضاً آخر 🛵' });
      }

      const tierInfo = computeCaptainTierAndFee(capRow, rawState.orders, rawState.settings, agreedFare);
      const effectiveFee = tierInfo.effectiveFee;
      if (roundMoney(capRow.wallet_balance || 0) < effectiveFee) {
        return res.status(400).json({ success: false, message: 'رصيد محفظة الكابتن لم يعد كافياً لقبول هذا المشوار ⚠️' });
      }

      // تسوية فرق خصم محفظة العميل إذا زاد السعر وكان العميل يملك رصيداً إضافياً في محفظته
      const { data: custRow } = await supabase.from('customers').select('*').eq('phone', custPhone).maybeSingle();
      let walletDiscount = roundMoney(meta.walletDiscount || 0);
      const promoDiscount = roundMoney(meta.promoDiscount || 0);
      const availCustWallet = Math.max(0, roundMoney(custRow?.wallet_balance || 0));
      const maxNeedFromWallet = Math.max(0, roundMoney(agreedFare - promoDiscount - walletDiscount));
      const extraWalletDeduct = availCustWallet > 0 ? roundMoney(Math.min(availCustWallet, maxNeedFromWallet)) : 0;

      if (extraWalletDeduct > 0) {
        const custWalRes = await safeAdjustCustomerWallet(custPhone, -extraWalletDeduct, `خصم إضافي تلقائي بعد قبول عرض طلب ${orderId}`);
        if (custWalRes.ok) {
          walletDiscount = roundMoney(walletDiscount + extraWalletDeduct);
        }
      }

      const totalDiscount = roundMoney(Math.min(agreedFare, walletDiscount + promoDiscount));
      const finalCashFare = Math.max(0, roundMoney(agreedFare - totalDiscount));
      const courierNet = Math.max(0, roundMoney(agreedFare - effectiveFee));

      const updatedOffers = offers.map((ofItem, idx) => ({
        ...ofItem,
        status: idx === offerIdx ? 'accepted' : (ofItem.status === 'pending' ? 'rejected' : ofItem.status),
        updatedAt: Date.now()
      }));

      const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, {
        ...meta,
        walletDiscount,
        promoDiscount,
        customerProposedFare: agreedFare,
        captainOffers: updatedOffers
      });

      const { data: updatedOrd, error: updErr } = await supabase
        .from('orders')
        .update({
          original_fare: agreedFare,
          discount_applied: totalDiscount,
          fare: finalCashFare,
          platform_fee: effectiveFee,
          courier_net: courierNet,
          status: 'تم قبول الطلب',
          assigned_courier_phone: cleanCapPhone,
          fee_deducted: true,
          fee_refunded: false,
          customer_notes: updatedNotes
        })
        .eq('id', orderId)
        .eq('status', 'في انتظار كابتن')
        .select()
        .maybeSingle();

      if (updErr || !updatedOrd) {
        if (extraWalletDeduct > 0) {
          await safeAdjustCustomerWallet(custPhone, extraWalletDeduct, `رد فرق الخصم لعدم اكتمال قبول العرض في طلب ${orderId}`);
        }
        return res.status(400).json({ success: false, message: 'تم قبول الطلب بالفعل أو تغيرت حالته ⚠️' });
      }

      // خصم العمولة ذرياً مع التراجع الفوري (Rollback) إذا فشل الخصم أو نقص رصيد الكابتن
      const feeRes = await safeAdjustCaptainWallet(cleanCapPhone, -effectiveFee, `عمولة منصة للطلب ${orderId}`);
      if (!feeRes.ok) {
        const rollbackNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, meta);
        await supabase.from('orders').update({
          original_fare: order.original_fare,
          discount_applied: order.discount_applied,
          fare: order.fare,
          platform_fee: order.platform_fee,
          courier_net: order.courier_net,
          status: 'في انتظار كابتن',
          assigned_courier_phone: null,
          fee_deducted: false,
          customer_notes: rollbackNotes
        }).eq('id', orderId);

        if (extraWalletDeduct > 0) {
          await safeAdjustCustomerWallet(custPhone, extraWalletDeduct, `رد فرق الخصم لعدم كفاية رصيد الكابتن في طلب ${orderId}`);
        }
        invalidateStateCache();
        return res.status(400).json({ success: false, message: 'رصيد الكابتن لم يعد كافياً لإتمام القبول، جرب عرضاً آخر ⚠️' });
      }

      if (totalDiscount > 0) {
        await safeAdjustCaptainWallet(cleanCapPhone, totalDiscount, `تعويض خصم العميل للطلب ${orderId}`);
      }

      invalidateStateCache();

      sendPushNotificationToPhone(cleanCapPhone, {
        title: `🎉 وافق العميل على سعرك (${agreedFare} ج) للطلب ${orderId}!`,
        body: `الطلب اتسند ليك رسمياً! هتقبض كاش (${finalCashFare} ج) وصافيك (${courierNet} ج). انطلق للاستلام الآن 🛵🚀`
      });

      notifyAdminsPush('customer', {
        title: `✅ اتفاق تفاوض وقبول طلب (${orderId})`,
        body: `وافق العميل (${custPhone}) على عرض الكابتن ${capRow.full_name} بسعر ${agreedFare} ج.`
      });

      const state = await buildClientState(req, true);
      return res.json({
        success: true,
        message: `تم قبول عرض الكابتن ${capRow.full_name} (${agreedFare} ج) وهو في طريقه إليك الآن! 🛵🚀`,
        state
      });
    }

    // حالتا counter_offer أو update_fare لتعديل سعر الطلب وهو في انتظار كابتن
    const cleanNewFare = roundMoney(newFare);
    const baseRef = roundMoney(meta.routeDefaultFare || order.original_fare || 35);
    const minAllowed = Math.max(15, Math.floor(baseRef * 0.7));
    if (!Number.isFinite(cleanNewFare) || cleanNewFare < minAllowed) {
      return res.status(400).json({ success: false, message: `أقل سعر مسموح به لهذا المسار هو (${minAllowed} جنيه) ⚠️` });
    }

    const { data: custRow } = await supabase.from('customers').select('*').eq('phone', custPhone).maybeSingle();
    const prevWalletDiscount = roundMoney(meta.walletDiscount || 0);
    const prevPromoDiscount = roundMoney(meta.promoDiscount || 0);
    const availCustWallet = Math.max(0, roundMoney(custRow?.wallet_balance || 0));
    const totalAvailableCustCredit = roundMoney(prevWalletDiscount + availCustWallet);

    const newWalletDiscount = roundMoney(Math.min(totalAvailableCustCredit, cleanNewFare));
    const walletDiff = roundMoney(newWalletDiscount - prevWalletDiscount);

    if (walletDiff > 0) {
      await safeAdjustCustomerWallet(custPhone, -walletDiff, `خصم إضافي لتحديث أجرة الطلب ${orderId}`);
    } else if (walletDiff < 0) {
      await safeAdjustCustomerWallet(custPhone, Math.abs(walletDiff), `رد فرق خصم المحفظة لتخفيض أجرة الطلب ${orderId}`);
    }

    const remAfterWallet = Math.max(0, roundMoney(cleanNewFare - newWalletDiscount));
    let newPromoDiscount = prevPromoDiscount;
    if (meta.promoCode) {
      const promoObj = (rawState.settings.promoCodes || []).find(p => p && p.code === meta.promoCode);
      const maxPromoVal = promoObj ? roundMoney(promoObj.discountAmount || prevPromoDiscount) : prevPromoDiscount;
      newPromoDiscount = roundMoney(Math.min(maxPromoVal, remAfterWallet));
    }

    const newTotalDiscount = roundMoney(newWalletDiscount + newPromoDiscount);
    const newFinalCash = Math.max(0, roundMoney(cleanNewFare - newTotalDiscount));
    const newPlatformFee = computeDefaultOrderPlatformFee(cleanNewFare, rawState.settings);
    const newCourierNet = Math.max(0, roundMoney(cleanNewFare - newPlatformFee));

    if (action === 'counter_offer' && offerIdx !== -1) {
      offers[offerIdx] = {
        ...offers[offerIdx],
        status: 'countered',
        customerCounterFare: cleanNewFare,
        updatedAt: Date.now()
      };
    }

    const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, {
      ...meta,
      walletDiscount: newWalletDiscount,
      promoDiscount: newPromoDiscount,
      customerProposedFare: cleanNewFare,
      captainOffers: offers
    });

    await supabase.from('orders').update({
      original_fare: cleanNewFare,
      discount_applied: newTotalDiscount,
      fare: newFinalCash,
      platform_fee: newPlatformFee,
      courier_net: newCourierNet,
      customer_notes: updatedNotes
    }).eq('id', orderId).eq('status', 'في انتظار كابتن');

    invalidateStateCache();

    if (action === 'counter_offer' && cleanCapPhone) {
      sendPushNotificationToPhone(cleanCapPhone, {
        title: `🤝 عرض مقابل من العميل في الطلب (${orderId})`,
        body: `اقترح العميل أجرة (${cleanNewFare} ج) للمشوار. افتح الرادار لقبول السعر الجديد فوراً 🛵`
      });
    } else {
      broadcastPushToAvailableCaptains({
        title: `💰 تحديث أجرة الطلب (${orderId}) إلى ${cleanNewFare} ج!`,
        body: `من: ${order.pickup_zone} إلى: ${order.dropoff_zone} — الأجرة الجديدة: ${cleanNewFare} ج 🛵`
      });
    }

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `تم تحديث أجرة المشوار إلى (${cleanNewFare} ج) وإبلاغ الكباتن فوراً! 🚀`,
      state
    });
  } catch (err) {
    console.error('Negotiate order error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر تحديث السعر حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(lockKey);
  }
}));

// مسار قبول الكابتن للطلب مباشرة من الرادار (مع الحماية الذرية والتراجع التلقائي عند نقص الرصيد)
app.post('/api/orders/:id/accept', authenticateCaptain, asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const lockKey = `order_lock_${orderId}`;
  if (promoRedeemLocks.has(lockKey)) {
    return res.status(429).json({ success: false, message: 'كابتن آخر يقبل هذا الطلب في نفس اللحظة، انتظر ثانية ⏳' });
  }
  promoRedeemLocks.add(lockKey);

  try {
    const captain = req.user;
    if (captain.status !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك غير معتمد لقبول الطلبات حالياً ⛔' });
    }

    const rawState = await fetchRawDatabaseState(true);
    const activeCapOrders = (rawState.orders || []).filter(
      o => normalizePhoneServer(o.assignedCourierPhone) === normalizePhoneServer(captain.phone) &&
           ACTIVE_COURIER_ORDER_STATUSES.includes(o.status)
    );
    const maxConcurrent = Math.max(1, Number(rawState.settings.maxConcurrentOrdersPerCaptain ?? 3));
    if (activeCapOrders.length >= maxConcurrent) {
      return res.status(400).json({
        success: false,
        message: `معاك ${activeCapOrders.length} مشاوير شغالة دلوقتي (الحد الأقصى ${maxConcurrent}).. خلّص مشوار الأول يا بطل 🛵`
      });
    }

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.status !== 'في انتظار كابتن') {
      return res.status(400).json({ success: false, message: 'يا خسارة! كابتن تاني سبقك ولقط الأوردر ده 🏃‍♂️' });
    }

    const origFare = roundMoney(order.original_fare ?? order.fare ?? 40);
    const tierInfo = computeCaptainTierAndFee(captain, rawState.orders, rawState.settings, origFare);
    const effectiveFee = tierInfo.effectiveFee;
    const courierNet = Math.max(0, roundMoney(origFare - effectiveFee));

    if (roundMoney(captain.wallet_balance || 0) < effectiveFee) {
      return res.status(400).json({
        success: false,
        message: `رصيد محفظتك الحالي (${roundMoney(captain.wallet_balance)} ج) لا يكفي عمولة المنصة (${effectiveFee} ج). اشحن محفظتك أولاً 🛵💸`
      });
    }

    const { data: updatedOrder, error: updErr } = await supabase
      .from('orders')
      .update({
        status: 'تم قبول الطلب',
        assigned_courier_phone: captain.phone,
        platform_fee: effectiveFee,
        courier_net: courierNet,
        fee_deducted: true,
        fee_refunded: false
      })
      .eq('id', orderId)
      .eq('status', 'في انتظار كابتن')
      .select()
      .maybeSingle();

    if (updErr || !updatedOrder) {
      return res.status(400).json({ success: false, message: 'كابتن آخر سبقك بجزء من الثانية ولقط الطلب! 🏃‍♂️' });
    }

    // خصم العمولة ذرياً مع التراجع الفوري إذا فشل الخصم في قاعدة البيانات
    const feeRes = await safeAdjustCaptainWallet(captain.phone, -effectiveFee, `عمولة منصة للطلب ${orderId}`);
    if (!feeRes.ok) {
      await supabase.from('orders').update({
        status: 'في انتظار كابتن',
        assigned_courier_phone: null,
        platform_fee: order.platform_fee,
        courier_net: order.courier_net,
        fee_deducted: false
      }).eq('id', orderId);
      invalidateStateCache();
      return res.status(400).json({
        success: false,
        message: 'رصيد محفظتك الحالي لا يكفي عمولة المنصة لإتمام قبول الطلب. اشحن محفظتك أولاً 🛵💸'
      });
    }

    const discountApplied = roundMoney(order.discount_applied || 0);
    if (discountApplied > 0) {
      await safeAdjustCaptainWallet(captain.phone, discountApplied, `تعويض خصم العميل للطلب ${orderId}`);
    }

    invalidateStateCache();

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      sendPushNotificationToPhone(custPhone, {
        title: `🛵 الكابتن ${captain.full_name} قبل طلبك (${orderId})!`,
        body: `الكابتن في طريقه ليك دلوقتي (${captain.vehicle_type} - ${tierInfo.tierBadgeText}) 🚀`
      });
    }

    notifyAdminsPush('captain', {
      title: `✅ قبول طلب (${orderId}) — كابتن ${captain.full_name}`,
      body: `المسار: ${order.pickup_zone} ⬅️ ${order.dropoff_zone} | الأجرة: ${origFare} ج | العمولة: ${effectiveFee} ج`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `عاش يا بطل! لقطت الأوردر (${orderId}).. توكل على الله 🚀🛵`,
      state
    });
  } catch (err) {
    console.error('Accept order error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر قبول الطلب حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(lockKey);
  }
}));

// مسار تقدم الكابتن في خط سير الطلب (وصل للاستلام -> استلم وفي السكة -> وصل للتسليم)
app.post('/api/orders/:id/advance', authenticateCaptain, asyncHandler(async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const { nextStatus } = req.body || {};
    const captain = req.user;

    if (!ALLOWED_ADVANCE_STATUSES.includes(nextStatus)) {
      return res.status(400).json({ success: false, message: 'الحالة المطلوبة غير صالحة ⚠️' });
    }

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || normalizePhoneServer(order.assigned_courier_phone) !== normalizePhoneServer(captain.phone)) {
      return res.status(403).json({ success: false, message: 'هذا الطلب غير مسند إليك ⚠️' });
    }

    const requiredPrev = REQUIRED_PREV_STATUS_FOR_ADVANCE[nextStatus];
    if (order.status !== requiredPrev) {
      return res.status(400).json({
        success: false,
        message: `لا يمكن الانتقال إلى (${nextStatus}) قبل إتمام خطوة (${requiredPrev}) بالترتيب 🛵⚠️`
      });
    }

    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
    if (nextStatus === 'الكابتن وصل للاستلام' || nextStatus === 'الكابتن وصل للتسليم') {
      meta.arrivedAt = Date.now();
    } else {
      meta.arrivedAt = null;
    }
    const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, meta);

    const { data: updated, error } = await supabase
      .from('orders')
      .update({ status: nextStatus, customer_notes: updatedNotes })
      .eq('id', orderId)
      .eq('status', requiredPrev)
      .select()
      .maybeSingle();

    if (error || !updated) {
      return res.status(400).json({ success: false, message: 'تعذر تحديث حالة الطلب حالياً ⚠️' });
    }

    invalidateStateCache();

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      sendPushNotificationToPhone(custPhone, {
        title: `تحديث في طلبك (${orderId}) 🛵`,
        body: `${nextStatus} — الكابتن: ${captain.full_name}`
      });
    }

    notifyAdminsPush('captain', {
      title: `📍 تحديث خط سير (${orderId})`,
      body: `الكابتن ${captain.full_name}: ${nextStatus}`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `تمام يا بطل! حدّثنا حالة المشوار: ${nextStatus} 🛵✅`,
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر تحديث حالة المشوار ⚠️' });
  }
}));

// مسار رنّة استعجال العميل (الكابتن تحت الباب 🔔)
app.post('/api/orders/:id/buzz', authenticateCaptain, asyncHandler(async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const captain = req.user;

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || normalizePhoneServer(order.assigned_courier_phone) !== normalizePhoneServer(captain.phone)) {
      return res.status(403).json({ success: false, message: 'هذا الطلب غير مسند إليك ⚠️' });
    }
    if (!['الكابتن وصل للاستلام', 'الكابتن وصل للتسليم'].includes(order.status)) {
      return res.status(400).json({ success: false, message: 'تقدر تبعت رنّة للعميل لما توصل لمكان الاستلام أو التسليم فقط 📍' });
    }

    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
    const now = Date.now();
    if (meta.lastBuzzAt && now - Number(meta.lastBuzzAt) < 45000) {
      const waitSec = Math.ceil((45000 - (now - Number(meta.lastBuzzAt))) / 1000);
      return res.status(429).json({ success: false, message: `بعتنا رنّة للعميل لسه حالا.. انتظر ${waitSec} ثانية لو حبيت ترن تاني 🔔` });
    }

    meta.lastBuzzAt = now;
    const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, meta);
    await supabase.from('orders').update({ customer_notes: updatedNotes }).eq('id', orderId);
    invalidateStateCache();

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      sendPushNotificationToPhone(custPhone, {
        title: `🔔 الكابتن ${captain.full_name} مستنيك تحت الباب! (${orderId})`,
        body: `الكابتن وصل في (${order.status === 'الكابتن وصل للاستلام' ? order.pickup_zone : order.dropoff_zone}) ومستنيك حالاً 🛵🏃‍♂️`
      });
    }

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: 'بعتنا رنّة وتنبيه فوري للعميل إنك مستنيه تحت الباب! 🔔✅',
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر إرسال الرنّة حالياً ⚠️' });
  }
}));

// مسار اعتذار الكابتن عن الطلب وإعادته للرادار قبل استلام الطرد
app.post('/api/orders/:id/release', authenticateCaptain, asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const lockKey = `order_lock_${orderId}`;
  if (promoRedeemLocks.has(lockKey)) {
    return res.status(429).json({ success: false, message: 'جاري معالجة الطلب، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(lockKey);

  try {
    const captain = req.user;
    const reason = String((req.body && req.body.reason) || '').trim() || 'ظرف طارئ للكابتن';

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || normalizePhoneServer(order.assigned_courier_phone) !== normalizePhoneServer(captain.phone)) {
      return res.status(403).json({ success: false, message: 'هذا الطلب غير مسند إليك ⚠️' });
    }

    if (!['تم قبول الطلب', 'الكابتن وصل للاستلام'].includes(order.status)) {
      return res.status(400).json({
        success: false,
        message: 'لا يمكن الاعتذار عن الطلب بعد استلام الطرد فعلياً! تواصل مع الدعم الفني فوراً 🛡️⚠️'
      });
    }

    const rawState = await fetchRawDatabaseState(true);
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');
    meta.arrivedAt = null;
    meta.lastBuzzAt = null;
    const updatedNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, meta);

    const origFare = roundMoney(order.original_fare ?? order.fare ?? 40);
    const defaultPlatformFee = computeDefaultOrderPlatformFee(origFare, rawState.settings);
    const defaultCourierNet = Math.max(0, roundMoney(origFare - defaultPlatformFee));

    const { data: releasedOrd, error: relErr } = await supabase
      .from('orders')
      .update({
        status: 'في انتظار كابتن',
        assigned_courier_phone: null,
        platform_fee: defaultPlatformFee,
        courier_net: defaultCourierNet,
        fee_deducted: false,
        fee_refunded: false,
        admin_resolution_note: `اعتذر الكابتن السابق (${captain.full_name}): ${reason}`,
        customer_notes: updatedNotes
      })
      .eq('id', orderId)
      .in('status', ['تم قبول الطلب', 'الكابتن وصل للاستلام'])
      .select()
      .maybeSingle();

    if (relErr || !releasedOrd) {
      return res.status(400).json({ success: false, message: 'تعذر إعادة الطلب للرادار حالياً ⚠️' });
    }

    if (order.fee_deducted && !order.fee_refunded) {
      const feeAmt = roundMoney(order.platform_fee || 0);
      if (feeAmt > 0) {
        await safeAdjustCaptainWallet(captain.phone, feeAmt, `استرداد عمولة اعتذار عن طلب ${orderId}`);
      }
      const discAmt = roundMoney(order.discount_applied || 0);
      if (discAmt > 0) {
        await safeAdjustCaptainWallet(captain.phone, -discAmt, `خصم التعويض المضاف مسبقاً لعدم إتمام طلب ${orderId}`);
      }
    }

    invalidateStateCache();

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      sendPushNotificationToPhone(custPhone, {
        title: `🔄 جاري إسناد طلبك (${orderId}) لكابتن آخر فوراً`,
        body: `حصل ظرف طارئ للكابتن، ورجّعنا طلبك لأولوية الرادار عشان يوصلك أسرع كابتن متاح 🛵`
      });
    }

    broadcastPushToAvailableCaptains({
      title: `🔔 أوردر عاجل عاد للرادار (${orderId}) 🛵`,
      body: `من: ${order.pickup_zone} إلى: ${order.dropoff_zone} | الأجرة: ${origFare} ج`
    });

    notifyAdminsPush('captain', {
      title: `🔄 اعتذار كابتن عن طلب (${orderId})`,
      body: `اعتذر الكابتن ${captain.full_name} عن الطلب — السبب: ${reason}`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: 'رجّعنا الأوردر للرادار وردينا العمولة لمحفظتك بنجاح 🔄✅',
      state
    });
  } catch (err) {
    console.error('Release order error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر تنفيذ الاعتذار حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(lockKey);
  }
}));
// تسجيل طلب شحن محفظة معلق ليظهر في طابور الإدارة بضغطة واحدة
app.post('/api/captain/topup-request', authenticateCaptain, asyncHandler(async (req, res) => {
  try {
    const amount = roundMoney(req.body?.amount || 100);
    if (!Number.isFinite(amount) || amount <= 0 || amount > 10000) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال مبلغ شحن صحيح ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(true);
    const list = Array.isArray(rawState.settings.pendingTopupRequests)
      ? [...rawState.settings.pendingTopupRequests]
      : [];

    const reqObj = {
      id: 'topreq_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
      phone: req.user.phone,
      fullName: req.user.full_name || 'كابتن العنابي',
      amount,
      createdAt: Date.now(),
      time: formatCairoTime()
    };

    // إذا كان لنفس الكابتن طلب معلق سابق نحدثه بالمبلغ الجديد بدلاً من التكرار
    const existingIdx = list.findIndex(r => r && normalizePhoneServer(r.phone) === normalizePhoneServer(req.user.phone));
    if (existingIdx !== -1) {
      list[existingIdx] = reqObj;
    } else {
      list.unshift(reqObj);
    }

    await saveIncentivesToDatabase(rawState, { pendingTopupRequests: list.slice(0, 50) });

    notifyAdminsPush('captain', {
      title: `⚡ طلب شحن محفظة جديد (${amount} ج)`,
      body: `الكابتن ${req.user.full_name} (${req.user.phone}) طلب شحن محفظته بمبلغ ${amount} ج — يمكنك اعتماده بضغطة واحدة من غرفة العمليات!`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, message: `تم تسجيل طلب شحن (${amount} ج) في غرفة العمليات وجاري تحويلك للواتساب 💬⚡`, state });
  } catch (e) {
    res.status(500).json({ success: false, message: 'تعذر تسجيل طلب الشحن ⚠️' });
  }
}));

// [FIX-05 & NEW-LOGIC-01] التأكد من وصول الكابتن لمرحلة «الكابتن وصل للتسليم» قبل إتمام الطلب مع حماية ذرية للمكافآت
app.post('/api/orders/:id/complete', authenticateCaptain, asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const completeLockKey = `order_complete_lock:${orderId}`;
  if (promoRedeemLocks.has(completeLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري إتمام تسليم الطلب بالفعل، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(completeLockKey);

  try {
    const cap = req.user;
    const rawBefore = await fetchRawDatabaseState(false);
    const oldTierData = computeCaptainTierAndFee(cap, rawBefore.orders, rawBefore.settings);

    const { data, error } = await supabase.from('orders')
      .update({ status: 'مكتمل' })
      .eq('id', orderId)
      .eq('assigned_courier_phone', cap.phone)
      .eq('status', 'الكابتن وصل للتسليم')
      .select();

    if (error || !data || !data.length) {
      return res.status(400).json({ success: false, message: 'تعذر إنهاء الطلب (يجب الوصول لمكان التسليم أولاً أو التأكد من أن الطلب نشط) ⚠️' });
    }

    const order = data[0];
    const rawState = await fetchRawDatabaseState(true);
    const s = rawState.settings;

    const custPhone = order.customer_phone || order.client_phone;
    if (custPhone) {
      const { data: cust } = await supabase.from('customers').select('*').eq('phone', custPhone).maybeSingle();
      if (cust) {
        let newCustPts = Number(cust.points || 0) + Math.max(1, Number(s.customerPointsPerOrder || 5));
        const custTarget = Math.max(5, Number(s.customerRewardThreshold || 100));
        const custCash = Math.max(1, roundMoney(s.customerRewardCash || 10));
        if (newCustPts >= custTarget) {
          newCustPts -= custTarget;
          await safeAdjustCustomerWallet(
            custPhone,
            custCash,
            'مكافأة نقاط عنابي بوينتس 🍇🎁'
          );
          sendPushNotificationToPhone(custPhone, {
            title: 'مبروك يا باشا مصر! 🍇💸',
            body: `جمعت نقاط عنابي ونزلك ${custCash} جنيه كاش هدية في محفظتك تتخصم أوتوماتيك من مشوارك الجاي! 😍🎉`
          });
        }
        await supabase.from('customers').update({ points: newCustPts }).eq('phone', custPhone);
      }
    }

    const { data: freshCap } = await supabase.from('captains').select('*').eq('phone', cap.phone).maybeSingle();
    if (freshCap) {
      let newCapPts = Number(freshCap.points || 0) + Math.max(1, Number(s.courierPointsPerOrder || 5));
      const capTarget = Math.max(5, Number(s.courierRewardThreshold || 100));
      const capCash = Math.max(1, roundMoney(s.courierRewardCash || 10));
      if (newCapPts >= capTarget) {
        newCapPts -= capTarget;
        await safeAdjustCaptainWallet(
          cap.phone,
          capCash,
          'مكافأة نقاط عنابي بوينتس للكباتن 🍇🛵'
        );
        sendPushNotificationToPhone(cap.phone, {
          title: 'عاش يا وحش الميدان! 🍇💸',
          body: `قفلت تارجت نقاط عنابي بوينتس ونزلك ${capCash} جنيه كاش فوري في محفظتك هدية! 🛵🔥`
        });
      }

      const newTierData = computeCaptainTierAndFee(freshCap, rawState.orders, s);
      const capNotices = Array.isArray(freshCap.admin_notices) ? [...freshCap.admin_notices] : [];

      if (newTierData.tier !== oldTierData.tier && (newTierData.tier === 'platinum' || newTierData.tier === 'diamond')) {
        const isPct = newTierData.commissionMode === 'percentage';
        const upgradeMsg = newTierData.tier === 'diamond'
          ? (isPct
              ? `💎 وسّع للكابتن الماسي! مبروك يا بطل، حافظت على مستواك ووصلت لـ (${newTierData.tierBadgeText}) وعمولتك نزلت لنسبة ${newTierData.effectiveFeePercent}% بس من قيمة المشوار! 🚀🔥`
              : `💎 وسّع للكابتن الماسي! مبروك يا بطل، حافظت على مستواك ووصلت لـ (${newTierData.tierBadgeText}) وعمولتك نزلت بخصم ${newTierData.tierDiscount} جنيه على كل أوردر! 🚀🔥`)
          : (isPct
              ? `🥈 عاش يا نجم الطيارين! كملت تارجت الـ ${newTierData.weeklyTarget} طلب في ${newTierData.tierDaysWindow} أيام واترقيت لـ (${newTierData.tierBadgeText}) وعمولتك بقت مخفضة لنسبة ${newTierData.effectiveFeePercent}% بس! حافظ على مستواك عشان توصل للماسي 💎🛵`
              : `🥈 عاش يا نجم الطيارين! كملت تارجت الـ ${newTierData.weeklyTarget} طلب في ${newTierData.tierDaysWindow} أيام واترقيت لـ (${newTierData.tierBadgeText}) وعمولتك بقت مخفضة بـ ${newTierData.tierDiscount} جنيه! حافظ على مستواك عشان توصل للماسي 💎🛵`);

        capNotices.unshift({
          id: 'tier-up-' + Date.now(),
          text: upgradeMsg,
          type: 'reward',
          at: Date.now()
        });

        sendPushNotificationToPhone(cap.phone, {
          title: `ترقية جديدة: ${newTierData.tierBadgeText} 🎉`,
          body: upgradeMsg
        });
      }

      await supabase.from('captains').update({
        points: newCapPts,
        admin_notices: capNotices.slice(0, 10)
      }).eq('phone', cap.phone);

      const referralActive = s.referralRewardActive !== false;
      const referralRewardAmt = Math.max(0, roundMoney(s.referralRewardAmount ?? 50));
      const requiredReferralTrips = Math.max(1, Number(s.referralRequiredOrders ?? 2));
      const tripsTextAr = formatArabicTripsText(requiredReferralTrips);

      if (referralActive && referralRewardAmt > 0 && freshCap.referred_by_phone && !freshCap.referral_reward_claimed) {
        const { count } = await supabase.from('orders')
          .select('id', { count: 'exact', head: true })
          .eq('assigned_courier_phone', cap.phone)
          .eq('status', 'مكتمل');

        if ((count || 0) >= requiredReferralTrips) {
          // قفل ذري في قاعدة البيانات يضمن استحالة صرف مكافأة الإحالة مرتين
          const { data: claimedRows } = await supabase.from('captains')
            .update({ referral_reward_claimed: true })
            .eq('phone', cap.phone)
            .eq('referral_reward_claimed', false)
            .select('phone');

          if (claimedRows && claimedRows.length > 0) {
            const { data: refCaptain } = await supabase.from('captains').select('*').eq('phone', freshCap.referred_by_phone).maybeSingle();
            if (refCaptain) {
              await safeAdjustCaptainWallet(
                refCaptain.phone,
                referralRewardAmt,
                `هدية دعوة الكابتن ${freshCap.full_name} بعد إتمام ${tripsTextAr} 🎁`
              );

              const refNotices = Array.isArray(refCaptain.admin_notices) ? [...refCaptain.admin_notices] : [];
              refNotices.unshift({
                id: 'ref-reward-' + Date.now(),
                text: `🎁 مبروك يا بطل! نزل في محفظتك ${referralRewardAmt} جنيه هدية دعوة الكابتن (${freshCap.full_name}) بعد إتمامه ${tripsTextAr} بنجاح 🛵💸`,
                type: 'reward',
                at: Date.now()
              });

              await supabase.from('captains').update({
                referrals_count: Number(refCaptain.referrals_count || 0) + 1,
                admin_notices: refNotices.slice(0, 10)
              }).eq('phone', refCaptain.phone);

              sendPushNotificationToPhone(refCaptain.phone, {
                title: 'مكافأة دعوة صديق نزلتلك! 🎁💸',
                body: `مبروك يا بطل! صاحبك الكابتن ${freshCap.full_name} كمل ${tripsTextAr} ونزل في محفظتك ${referralRewardAmt} جنيه هدية حلال عليك 😎🛵`
              });
            }
          }
        }
      }
    }

    invalidateStateCache();
    sendPushNotificationToPhone(custPhone, {
      title: 'تم تسليم طلبك بنجاح 🎉',
      body: `عدينا على تماسيح وأسود في الطريق 😵 بس الحمد لله الأوردر (${order.id}) اتسلم يا باشا! متنساش تقيم الكابتن الجدع ⭐🛵`
    });

    notifyAdminsPush('captain', {
      title: `🎉 اكتمال توصيل الطلب (${order.id})`,
      body: `سلّم الكابتن ${cap.full_name} (${cap.phone}) الطلب بنجاح للعميل (${custPhone}) — صافي الكابتن: ${order.courier_net} ج`
    });
    await recordAnalyticsMetricEvent('completedOrders', 1);
    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تسلم إيدك يا بطل! تم التسليم 🛵💨', state });
  } catch (err) {
    console.error('Complete order error:', err.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إتمام تسليم الطلب ⚠️' });
  } finally {
    promoRedeemLocks.delete(completeLockKey);
  }
}));

app.post('/api/captain/availability', authenticateCaptain, asyncHandler(async (req, res) => {
  if (req.user.status === 'قيد المراجعة') {
    return res.status(403).json({
      success: false,
      message: 'حسابك لسة بيتراجع يانجم الطيارين 😎'
    });
  }
  if (req.user.status !== 'معتمد') {
    return res.status(403).json({
      success: false,
      message: 'حسابك غير معتمد حالياً لتفعيل الاستعداد ⚠️'
    });
  }
  const isAvail = Boolean(req.body.isAvailable);
  await supabase.from('captains').update({ is_available: isAvail }).eq('phone', req.user.phone);
  notifyAdminsPush('captain', {
    title: '📡 تغيير حالة استعداد كابتن',
    body: `الكابتن ${req.user.full_name} (${req.user.phone}) أصبح الآن: ${isAvail ? 'متاح على الرادار 🟢' : 'في استراحة 🔴'}`
  });
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تحديث حالة الاستعداد 📡✅', state });
}));

app.post('/api/captain/notices/:noticeId/dismiss', authenticateCaptain, asyncHandler(async (req, res) => {
  const notices = Array.isArray(req.user.admin_notices) ? req.user.admin_notices : [];
  const filtered = notices.filter(n => String(n.id) !== String(req.params.noticeId));
  await supabase.from('captains').update({ admin_notices: filtered }).eq('phone', req.user.phone);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

// [FIX-06 & NEW-SEC-03] التحقق الصارم من ملكية العميل للطلب عبر كوكي الجلسة قبل الإلغاء ورد الخصم والكوبون كاملاً
app.post('/api/orders/:id/cancel', asyncHandler(async (req, res) => {
  const orderId = String(req.params.id || '').trim();
  const cancelLockKey = `order_cancel_lock:${orderId}`;
  if (promoRedeemLocks.has(cancelLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري إلغاء الطلب حالياً يا باشا، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(cancelLockKey);

  try {
    const rawState = await fetchRawDatabaseState(false);
    const { data: existing } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!existing || !['في انتظار كابتن', 'تم قبول الطلب'].includes(existing.status)) {
      return res.status(400).json({ success: false, message: 'لا يمكن الإلغاء.. الطلب قيد التنفيذ ⚠️' });
    }

    if (!verifyCustomerOrderOwnership(req, existing, rawState.rawCustomersRows)) {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بإلغاء هذا الطلب 🔒⚠️' });
    }

    const hadFeeDeducted = Boolean(existing.fee_deducted && !existing.fee_refunded);
    const feeToRefund = roundMoney(existing.platform_fee || 0);
    const prevAssignedCaptain = existing.assigned_courier_phone;

    const { data: updated, error } = await supabase.from('orders')
      .update({ status: 'ملغي من العميل', fee_refunded: true })
      .eq('id', orderId)
      .in('status', ['في انتظار كابتن', 'تم قبول الطلب'])
      .select();

    if (error || !updated || !updated.length) {
      return res.status(400).json({ success: false, message: 'لا يمكن الإلغاء.. الطلب قيد التنفيذ ⚠️' });
    }

    const order = updated[0];
    const custPhone = order.customer_phone || order.client_phone;
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');

    const refundWalletAmt = meta.walletDiscount > 0
      ? meta.walletDiscount
      : Math.max(0, roundMoney((order.discount_applied || 0) - (meta.promoDiscount || 0)));

    if (refundWalletAmt > 0 && custPhone) {
      await safeAdjustCustomerWallet(
        custPhone,
        roundMoney(refundWalletAmt),
        `رد المبلغ التعويضي لمحفظتك لإلغاء طلب ${order.id}`
      );
    }

    if (meta.promoCode && custPhone) {
      await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
    }

    if (prevAssignedCaptain) {
      if (hadFeeDeducted && feeToRefund > 0) {
        await safeAdjustCaptainWallet(
          prevAssignedCaptain,
          feeToRefund,
          `رد عمولة لطلب ملغي من العميل ${order.id}`
        );
      }
      if (order.discount_applied > 0) {
        await safeAdjustCaptainWallet(
          prevAssignedCaptain,
          -Math.abs(roundMoney(order.discount_applied)),
          `خصم تعويض خصم العميل لإلغاء وعدم اكتمال طلب ${order.id}`
        );
      }
      sendPushNotificationToPhone(prevAssignedCaptain, {
        title: `تم إلغاء الطلب ${order.id} ❌`,
        body: 'قام العميل بإلغاء الطلب وتم رد العمولة لمحفظتك وتسوية تعويض الخصم فوراً ولا يهمك يا بطل 🛵💪'
      });
    }

    const totalDisc = roundMoney(order.discount_applied || 0);
    if (custPhone && (totalDisc > 0 || meta.promoCode)) {
      sendPushNotificationToPhone(custPhone, {
        title: `خصمك لسه معاك يا باشا! 🎁✅`,
        body: `لأن الطلب (${order.id}) مكتملش، رجّعنالك خصمك (${totalDisc} ج) لمحفظتك/كودك تاني وجاهز معاك لأي مشوار جاي 😎🛵`
      });
    }

    notifyAdminsPush('customer', {
      title: `❌ إلغاء طلب من العميل (${order.id})`,
      body: `ألغى العميل (${custPhone}) الطلب من ${order.pickup_zone} إلى ${order.dropoff_zone}`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({
      success: true,
      restoredPromoCode: meta.promoCode || null,
      message: (totalDisc > 0 || meta.promoCode)
        ? `لغينا الطلب يا باشا، وخصمك (${totalDisc} ج) لسه معاك ورجع لمحفظتك/كودك تاني لأن الطلب مكتملش 🎁✅`
        : 'خلاص لغينا طلبك يا باشا ✅',
      state
    });
  } catch (err) {
    console.error('Cancel order error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر إلغاء الطلب حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(cancelLockKey);
  }
}));

// [FIX-06 & NEW-SEC-03] التحقق من ملكية العميل للطلب واكتماله قبل التقييم
app.post('/api/orders/:id/rate', asyncHandler(async (req, res) => {
  const rawState = await fetchRawDatabaseState(false);
  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing) {
    return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });
  }
  if (!verifyCustomerOrderOwnership(req, existing, rawState.rawCustomersRows)) {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بتقييم هذا الطلب 🔒⚠️' });
  }
  if (existing.status !== 'مكتمل') {
    return res.status(400).json({ success: false, message: 'لا يمكن تقييم الطلب قبل اكتمال التسليم ⚠️' });
  }
  if (existing.rating !== null && existing.rating !== undefined) {
    return res.status(400).json({ success: false, message: 'تم تقييم هذا المشوار مسبقاً يا باشا ⭐' });
  }

  const rating = Math.min(5, Math.max(1, Number(req.body.rating) || 5));
  await supabase.from('orders').update({ rating }).eq('id', req.params.id).is('rating', null);
  notifyAdminsPush('customer', {
    title: `⭐ تقييم جديد للطلب (${req.params.id})`,
    body: `قام العميل بتقييم الكابتن بـ ${rating} نجوم.`
  });
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

// [FIX-06 & NEW-SEC-03] التحقق من ملكية العميل للطلب واكتماله قبل تقديم اعتراض
app.post('/api/orders/:id/dispute', asyncHandler(async (req, res) => {
  const reason = String(req.body.reason || '').trim();
  if (!reason) return res.status(400).json({ success: false, message: 'اكتب سبب الاعتراض ⚠️' });

  const rawState = await fetchRawDatabaseState(false);
  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing) {
    return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });
  }
  if (!verifyCustomerOrderOwnership(req, existing, rawState.rawCustomersRows)) {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بتقديم اعتراض على هذا الطلب 🔒⚠️' });
  }
  if (existing.status !== 'مكتمل') {
    return res.status(400).json({ success: false, message: 'الاعتراض متاح فقط بعد تسليم الطلب ⚠️' });
  }
  if (existing.rating !== null && existing.rating !== undefined) {
    return res.status(400).json({
      success: false,
      message: 'لقد قمت بتأكيد استلام الطلب وتقييم الكابتن بالفعل، ولا يجوز تقديم شكوى بعد إتمام التقييم ⭐✅'
    });
  }
  if (existing.dispute_reason) {
    return res.status(400).json({ success: false, message: 'تم تسجيل اعتراض على هذا الطلب مسبقاً ولا يجوز تكرار الشكوى ⚠️' });
  }

  await supabase.from('orders').update({
    dispute_reason: reason,
    status: 'قيد مراجعة الاعتراض'
  }).eq('id', req.params.id).eq('status', 'مكتمل');

  notifyAdminsPush('customer', {
    title: `⚠️ اعتراض وشكوى على طلب (${req.params.id})`,
    body: `سجّل العميل اعتراضاً: "${reason}" — يرجى المراجعة من غرفة العمليات.`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

// ==========================================
// 9. مسارات غرفة العمليات المركزية (Admin) مع التحقق الصارم من الصلاحيات
// ==========================================
app.post('/api/admin/settings', authenticateAdmin, asyncHandler(async (req, res) => {
  const body = req.body || {};

  const isChangingPushSwitches =
    body.adminPushMasterEnabled !== undefined ||
    body.adminPushCustomersEnabled !== undefined ||
    body.adminPushCaptainsEnabled !== undefined;

  if (isChangingPushSwitches && !req.admin.is_master) {
    return res.status(403).json({
      success: false,
      message: 'عفواً، التحكم في مفاتيح إشعارات Push الرئيسية متاح للأدمن الرئيسي فقط 👑⛔'
    });
  }

  if (
    (body.platformFee !== undefined ||
      body.commissionMode !== undefined ||
      body.platformFeePercent !== undefined) &&
    !requireAdminPerm(req, res, ['manageCommissions'])
  ) {
    return;
  }

  if (
    body.tierManualOverride !== undefined &&
    !requireAdminPerm(req, res, ['manageCaptains'])
  ) {
    return;
  }

  if (
    (body.tierWeeklyOrdersTarget !== undefined ||
      body.tierDaysWindow !== undefined ||
      body.tierConsecutiveDaysForDiamond !== undefined ||
      body.tierWeeksForDiamond !== undefined ||
      body.tierPlatinumDiscount !== undefined ||
      body.tierDiamondDiscount !== undefined ||
      body.tierPlatinumPercent !== undefined ||
      body.tierDiamondPercent !== undefined) &&
    !requireAdminPerm(req, res, ['manageCaptains', 'manageCommissions'])
  ) {
    return;
  }

  if (
    (Array.isArray(body.zones) || body.pricing !== undefined) &&
    !requireAdminPerm(req, res, ['managePricing'])
  ) {
    return;
  }

  if (
    (Array.isArray(body.packageTypes) || body.surgeAction !== undefined || body.autoSurgeEnabled !== undefined) &&
    !requireAdminPerm(req, res, ['managePricing', 'manageSettings'])
  ) {
    return;
  }

  // قصر إعدادات المنصة العامة والطارئة (مثل وضع الصيانة ورقم الدعم) على صلاحية manageSettings حصرياً
  if (
    (body.broadcastMessage !== undefined ||
      body.broadcastTarget !== undefined ||
      body.priceHumorMessage !== undefined ||
      body.supportWhatsapp !== undefined ||
      body.waitingTimeoutMinutes !== undefined ||
      body.maxConcurrentOrdersPerCaptain !== undefined ||
      body.maintenanceMode !== undefined ||
      body.allowCaptainRegistration !== undefined) &&
    !requireAdminPerm(req, res, ['manageSettings'])
  ) {
    return;
  }

  if (
    (body.welcomeBonusActive !== undefined ||
      body.welcomeBonusAmount !== undefined ||
      body.referralRewardActive !== undefined ||
      body.referralRewardAmount !== undefined ||
      body.referralRequiredOrders !== undefined ||
      body.loyaltyField !== undefined) &&
    !requireAdminPerm(req, res, ['manageSettings', 'manageWallets'])
  ) {
    return;
  }

  const rawState = await fetchRawDatabaseState(true);
  const prevSettings = rawState.settings || {};
  const updates = {};

  if (body.platformFee !== undefined) updates.platform_fee = Math.max(0, roundMoney(body.platformFee));
  if (body.broadcastMessage !== undefined) updates.broadcast_message = String(body.broadcastMessage);
  if (body.supportWhatsapp !== undefined) updates.support_whatsapp = String(body.supportWhatsapp).trim();
  if (body.waitingTimeoutMinutes !== undefined) updates.waiting_timeout_minutes = Math.max(0, Number(body.waitingTimeoutMinutes) || 0);
  if (body.maintenanceMode !== undefined) updates.maintenance_mode = Boolean(body.maintenanceMode);
  if (body.allowCaptainRegistration !== undefined) updates.allow_captain_registration = Boolean(body.allowCaptainRegistration);
  if (Array.isArray(body.zones)) updates.zones = body.zones;
  if (Array.isArray(body.packageTypes)) updates.package_types = body.packageTypes;

  if (body.loyaltyField && body.loyaltyField.key) {
    const keyMap = {
      customerPointsPerOrder: 'customer_points_per_order',
      customerRewardThreshold: 'customer_reward_threshold',
      customerRewardCash: 'customer_reward_cash',
      courierPointsPerOrder: 'courier_points_per_order',
      courierRewardThreshold: 'courier_reward_threshold',
      courierRewardCash: 'courier_reward_cash'
    };
    const dbCol = keyMap[body.loyaltyField.key];
    if (dbCol) {
      const isThreshold = body.loyaltyField.key.includes('Threshold');
      const minVal = isThreshold ? 5 : 1;
      updates[dbCol] = Math.max(minVal, Number(body.loyaltyField.value) || minVal);
    }
  }

  const partialIncentives = {};
  if (body.commissionMode !== undefined) {
    partialIncentives.commissionMode = body.commissionMode === 'percentage' ? 'percentage' : 'fixed';
  }
  if (body.platformFeePercent !== undefined) {
    partialIncentives.platformFeePercent = Math.min(100, Math.max(0, roundMoney(body.platformFeePercent)));
  }
  if (body.tierPlatinumPercent !== undefined) {
    partialIncentives.tierPlatinumPercent = Math.min(100, Math.max(0, roundMoney(body.tierPlatinumPercent)));
  }
  if (body.tierDiamondPercent !== undefined) {
    partialIncentives.tierDiamondPercent = Math.min(100, Math.max(0, roundMoney(body.tierDiamondPercent)));
  }

  if (body.welcomeBonusActive !== undefined) partialIncentives.welcomeBonusActive = Boolean(body.welcomeBonusActive);
  if (body.welcomeBonusAmount !== undefined) partialIncentives.welcomeBonusAmount = Math.max(0, roundMoney(body.welcomeBonusAmount));
  if (body.referralRewardActive !== undefined) partialIncentives.referralRewardActive = Boolean(body.referralRewardActive);
  if (body.referralRewardAmount !== undefined) partialIncentives.referralRewardAmount = Math.max(0, roundMoney(body.referralRewardAmount));
  if (body.referralRequiredOrders !== undefined) partialIncentives.referralRequiredOrders = Math.max(1, Number(body.referralRequiredOrders) || 1);
  if (body.maxConcurrentOrdersPerCaptain !== undefined) partialIncentives.maxConcurrentOrdersPerCaptain = Math.min(20, Math.max(1, Number(body.maxConcurrentOrdersPerCaptain) || 3));
  if (body.broadcastTarget !== undefined) partialIncentives.broadcastTarget = String(body.broadcastTarget).trim();
  if (body.priceHumorMessage !== undefined) partialIncentives.priceHumorMessage = String(body.priceHumorMessage).trim();

  if (body.adminPushMasterEnabled !== undefined) partialIncentives.adminPushMasterEnabled = Boolean(body.adminPushMasterEnabled);
  if (body.adminPushCustomersEnabled !== undefined) partialIncentives.adminPushCustomersEnabled = Boolean(body.adminPushCustomersEnabled);
  if (body.adminPushCaptainsEnabled !== undefined) partialIncentives.adminPushCaptainsEnabled = Boolean(body.adminPushCaptainsEnabled);

  if (body.tierWeeklyOrdersTarget !== undefined) {
    partialIncentives.tierWeeklyOrdersTarget = Math.max(1, Number(body.tierWeeklyOrdersTarget) || 25);
  }
  const effDaysWin = body.tierDaysWindow !== undefined
    ? Math.max(1, Number(body.tierDaysWindow) || 7)
    : Math.max(1, Number(prevSettings.tierDaysWindow ?? 7));

  if (body.tierDaysWindow !== undefined) {
    partialIncentives.tierDaysWindow = effDaysWin;
  }
  if (body.tierConsecutiveDaysForDiamond !== undefined) {
    const consDays = Math.max(effDaysWin, Number(body.tierConsecutiveDaysForDiamond) || 28);
    partialIncentives.tierConsecutiveDaysForDiamond = consDays;
    partialIncentives.tierWeeksForDiamond = Math.max(1, Math.ceil(consDays / effDaysWin));
  } else if (body.tierWeeksForDiamond !== undefined) {
    const wks = Math.max(1, Number(body.tierWeeksForDiamond) || 4);
    partialIncentives.tierWeeksForDiamond = wks;
    partialIncentives.tierConsecutiveDaysForDiamond = wks * effDaysWin;
  }
  if (body.tierPlatinumDiscount !== undefined) partialIncentives.tierPlatinumDiscount = Math.max(0, roundMoney(body.tierPlatinumDiscount));
  if (body.tierDiamondDiscount !== undefined) partialIncentives.tierDiamondDiscount = Math.max(0, roundMoney(body.tierDiamondDiscount));
  if (body.tierManualOverride && body.tierManualOverride.phone) {
    const curOverrides = { ...(prevSettings.tierManualOverrides || {}) };
    const tVal = body.tierManualOverride.tier;
    if (!tVal || tVal === 'auto') {
      delete curOverrides[body.tierManualOverride.phone];
    } else if (['bronze', 'platinum', 'diamond'].includes(tVal)) {
      curOverrides[body.tierManualOverride.phone] = tVal;
    }
    partialIncentives.tierManualOverrides = curOverrides;
  }

  if (body.surgeAction === 'start') {
    const pct = Math.min(200, Math.max(1, Number(body.surgePercent ?? 20)));
    const mins = Math.max(1, Number(body.surgeDurationMinutes ?? 30));
    partialIncentives.surgePercent = pct;
    partialIncentives.surgeDurationMinutes = mins;
    partialIncentives.surgeEndTime = Date.now() + mins * 60000;

    broadcastPushByTargetGroup('captains', {
      title: 'وقت الذروة اشتغل يارجالة! ⚡🔥',
      body: `الأوردرات دلوقتي عليها زيادة ذروة +${pct}% لمدة ${mins} دقيقة.. افتح الرادار واكسب أكتر! 🛵💸`
    });
  } else if (body.surgeAction === 'stop') {
    partialIncentives.surgeEndTime = 0;
  }
  if (body.autoSurgeEnabled !== undefined) {
    partialIncentives.autoSurgeEnabled = Boolean(body.autoSurgeEnabled);
  }

  const customBasePricing = (body.pricing && typeof body.pricing === 'object') ? body.pricing : null;
  const updatedIncentives = await saveIncentivesToDatabase(rawState, partialIncentives, updates, customBasePricing);

  let auditDetails = 'تعديل في إعدادات التشغيل أو التسعير';
  if (body.commissionMode !== undefined || body.platformFeePercent !== undefined || body.platformFee !== undefined) {
    const modeTitle = updatedIncentives.commissionMode === 'percentage'
      ? `نظام النسبة المئوية (${updatedIncentives.platformFeePercent}% برونزي | ${updatedIncentives.tierPlatinumPercent}% بلاتيني | ${updatedIncentives.tierDiamondPercent}% ماسي)`
      : `نظام المبلغ الثابت (${updates.platform_fee ?? prevSettings.platformFee ?? 7} ج)`;
    auditDetails = `تحديث نظام عمولة المنصة إلى: ${modeTitle}`;
  } else if (body.maxConcurrentOrdersPerCaptain !== undefined) {
    auditDetails = `تحديد أقصى عدد مشاوير يأخذها الكابتن في سكته معاً بـ (${updatedIncentives.maxConcurrentOrdersPerCaptain} مشاوير)`;
  } else if (body.surgeAction === 'start') {
    auditDetails = `تفعيل وقت الذروة (+${partialIncentives.surgePercent}%) لمدة ${partialIncentives.surgeDurationMinutes} دقيقة`;
  } else if (body.surgeAction === 'stop') {
    auditDetails = 'إيقاف وقت الذروة والعودة للتسعير الطبيعي';
  } else if (isChangingPushSwitches) {
    auditDetails = `تحديث مفاتيح إشعارات Push الأدمن (العام: ${updatedIncentives.adminPushMasterEnabled ? 'مفعل' : 'متوقف'} | العملاء: ${updatedIncentives.adminPushCustomersEnabled ? 'مفعل' : 'متوقف'} | الكباتن: ${updatedIncentives.adminPushCaptainsEnabled ? 'مفعل' : 'متوقف'})`;
  } else if (
    body.tierWeeklyOrdersTarget !== undefined ||
    body.tierPlatinumDiscount !== undefined ||
    body.tierPlatinumPercent !== undefined ||
    body.tierDaysWindow !== undefined
  ) {
    auditDetails = updatedIncentives.commissionMode === 'percentage'
      ? `تحديث مستويات الكباتن (${updatedIncentives.tierWeeklyOrdersTarget} طلب خلال ${updatedIncentives.tierDaysWindow} يوم — برونزي ${updatedIncentives.platformFeePercent}% | بلاتيني ${updatedIncentives.tierPlatinumPercent}% | ماسي ${updatedIncentives.tierDiamondPercent}%)`
      : `تحديث مستويات الكباتن (${updatedIncentives.tierWeeklyOrdersTarget} طلب خلال ${updatedIncentives.tierDaysWindow} يوم - الماسي ${updatedIncentives.tierConsecutiveDaysForDiamond} يوم - خصم بلاتيني ${updatedIncentives.tierPlatinumDiscount}ج - ماسي ${updatedIncentives.tierDiamondDiscount}ج)`;
  } else if (body.broadcastMessage !== undefined || body.broadcastTarget !== undefined) {
    const targetNames = { all: 'الجميع', customers: 'العملاء فقط', captains: 'الكباتن فقط', admins: 'المسؤولين فقط', public: 'العملاء والكباتن' };
    const msgTxt = body.broadcastMessage !== undefined ? body.broadcastMessage : (prevSettings.broadcastMessage || '');
    auditDetails = `تحديث الإعلان العام (${targetNames[updatedIncentives.broadcastTarget] || 'الجميع'}): ${msgTxt || 'إخفاء الإعلان'}`;
  } else if (body.welcomeBonusAmount !== undefined || body.referralRewardAmount !== undefined || body.referralRequiredOrders !== undefined) {
    auditDetails = `تحديث الحوافز — الترحيب: ${updatedIncentives.welcomeBonusActive ? updatedIncentives.welcomeBonusAmount + ' ج' : 'متوقف'} | الإحالة: ${updatedIncentives.referralRewardActive ? updatedIncentives.referralRewardAmount + ' ج بعد ' + updatedIncentives.referralRequiredOrders + ' مشاوير' : 'متوقف'}`;
  }
  await logAdminAudit('تحديث إعدادات', 'المنصة', auditDetails, req.admin.name);

  if (!isChangingPushSwitches) {
    notifyAdminsPush('platform', {
      title: `⚙️ تحديث إعدادات المنصة`,
      body: `${auditDetails} (بواسطة: ${req.admin.name})`
    });
  }

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

app.post('/api/admin/promo-codes', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets', 'manageSettings'])) return;
  try {
    const { code, discountAmount, targetPhone = 'all', validHours = 48, maxUses = 1 } = req.body || {};
    const cleanCode = String(code || '').trim().toUpperCase().replace(/\s+/g, '');
    const amt = roundMoney(discountAmount);
    const hours = Math.max(1, Number(validHours) || 48);
    const cleanTarget = (!targetPhone || targetPhone === 'all') ? 'all' : normalizePhoneServer(targetPhone);
    const allowedUses = cleanTarget === 'all' ? 1 : Math.max(1, parseInt(maxUses, 10) || 1);

    if (!cleanCode || amt <= 0) {
      return res.status(400).json({ success: false, message: 'اكتب اسم الكود وقيمة الخصم بشكل صحيح يا باشا ⚠️' });
    }
    if (cleanTarget !== 'all' && !isValidEgyptianPhoneServer(cleanTarget)) {
      return res.status(400).json({ success: false, message: 'رقم هاتف العميل المخصص غير صحيح ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(true);
    const promoList = Array.isArray(rawState.settings.promoCodes)
      ? rawState.settings.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
      : [];
    const existingIdx = promoList.findIndex(p => p && p.code === cleanCode);

    const expiresAt = Date.now() + hours * 3600000;
    const prevObj = existingIdx !== -1 ? promoList[existingIdx] : null;
    const preservedCounts = (prevObj && prevObj.targetPhone === cleanTarget && prevObj.usageCounts)
      ? { ...prevObj.usageCounts }
      : {};
    const syncedUsedBy = Object.keys(preservedCounts).filter(ph => preservedCounts[ph] >= allowedUses);

    const newPromoObj = {
      code: cleanCode,
      discountAmount: amt,
      targetPhone: cleanTarget,
      maxUses: allowedUses,
      usageCounts: preservedCounts,
      validHours: hours,
      expiresAt,
      usedBy: syncedUsedBy,
      active: true,
      createdAt: prevObj?.createdAt || Date.now()
    };

    if (existingIdx !== -1) {
      promoList[existingIdx] = newPromoObj;
    } else {
      promoList.unshift(newPromoObj);
    }

    await saveIncentivesToDatabase(rawState, { promoCodes: promoList.slice(0, 50) });

    if (cleanTarget === 'all') {
      broadcastPushByTargetGroup('customers', {
        title: 'كود خصم عنابي جديد لكل البشوات! 🎟️😍',
        body: `استخدم كود (${cleanCode}) واكسب خصم فوري ${amt} جنيه على مشوارك! الكود شغال معاك لمدة ${hours} ساعة 🛵💨`
      });
    } else {
      const usesNote = allowedUses > 1 ? ` (متاح ليك استخدامه ${allowedUses} مرات)` : '';
      sendPushNotificationToPhone(cleanTarget, {
        title: 'هدية خاصة ليك يا باشا مصر! 🎟️👑',
        body: `إدارة الرجل العنابي عملتلك كود خصم مخصوص (${cleanCode}) بقيمة ${amt} جنيه${usesNote}! تقدر تستخدمه خلال ${hours} ساعة 😎🛵`
      });
    }

    const targetDesc = cleanTarget === 'all' ? 'جميع العملاء' : `${cleanTarget} (${allowedUses} مرات استخدام)`;
    const detailsTxt = `خصم ${amt} ج — المستهدف: ${targetDesc} (صالح لـ ${hours} ساعة)`;
    await logAdminAudit('إصدار كود خصم', cleanCode, detailsTxt, req.admin.name);
    notifyAdminsPush('platform', {
      title: `🎟️ إصدار كود خصم (${cleanCode})`,
      body: `${detailsTxt} (بواسطة: ${req.admin.name})`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: `تم تفعيل كود الخصم (${cleanCode}) وإرسال الإشعارات بنجاح 🎟️✅`,
      state
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر حفظ كود الخصم ⚠️' });
  }
}));

app.post('/api/admin/promo-codes/delete', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets', 'manageSettings'])) return;
  const { code } = req.body || {};
  const cleanCode = String(code || '').trim().toUpperCase();
  const rawState = await fetchRawDatabaseState(true);
  const promoList = (rawState.settings.promoCodes || []).filter(p => p && String(p.code).toUpperCase() !== cleanCode);

  await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
  await logAdminAudit('حذف كود خصم', cleanCode, 'إلغاء وحذف كود الخصم', req.admin.name);
  notifyAdminsPush('platform', {
    title: `🗑️ حذف كود خصم (${cleanCode})`,
    body: `تم إلغاء وحذف الكود بواسطة: ${req.admin.name}`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم حذف كود الخصم بنجاح 🗑️✅', state });
}));

app.post('/api/admin/wallets/captain-topup', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!phone || amt <= 0) return res.status(400).json({ success: false, message: 'بيانات الشحن غير صحيحة ⚠️' });

  const topupLockKey = `admin_topup:${phone}`;
  if (promoRedeemLocks.has(topupLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ شحن لهذا الكابتن حالياً، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(topupLockKey);

  try {
    const walRes = await safeAdjustCaptainWallet(phone, amt, 'شحن رصيد من الإدارة ⚡');
    if (!walRes.ok) {
      return res.status(500).json({ success: false, message: 'تعذر شحن المحفظة حالياً ⚠️' });
    }

    const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', phone).maybeSingle();
    if (cap) {
      const notices = Array.isArray(cap.admin_notices) ? [...cap.admin_notices] : [];
      notices.unshift({
        id: 'topup-' + Date.now(),
        text: `⚡ تم شحن محفظتك بمبلغ ${amt} جنيه من الإدارة بنجاح.. طير في الميدان يا بطل! 🛵`,
        type: 'reward',
        at: Date.now()
      });
      await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);
    }

    // إزالة أي طلب شحن معلق لنفس الكابتن تلقائياً بعد الشحن
    const rawState = await fetchRawDatabaseState(true);
    const pendList = Array.isArray(rawState.settings.pendingTopupRequests) ? rawState.settings.pendingTopupRequests : [];
    const filteredPend = pendList.filter(r => r && normalizePhoneServer(r.phone) !== phone);
    if (filteredPend.length !== pendList.length) {
      await saveIncentivesToDatabase(rawState, { pendingTopupRequests: filteredPend });
    }

    await logAdminAudit('شحن محفظة كابتن', phone, `شحن مبلغ ${amt} ج`, req.admin.name);
    sendPushNotificationToPhone(phone, {
      title: 'تم شحن محفظتك يانجم! 💰✅',
      body: `نزل في محفظتك ${amt} جنيه من إدارة الرجل العنابي.. ربنا يرزقك يا بطل 🛵💪`
    });

    notifyAdminsPush('platform', {
      title: `💰 شحن محفظة كابتن (${amt} ج)`,
      body: `تم شحن ${amt} ج للكابتن ${cap?.full_name || ''} (${phone}) بواسطة: ${req.admin.name}`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, state });
  } finally {
    promoRedeemLocks.delete(topupLockKey);
  }
}));

// اعتماد أو تجاهل طلب شحن معلق من طابور الشحن بضغطة واحدة (مع قفل منع الشحن المزدوج)
app.post('/api/admin/wallets/topup-requests/:reqId/resolve', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const reqId = String(req.params.reqId || '').trim();
  const action = String(req.body?.action || 'approve').trim();

  const resolveLockKey = `topup_req_resolve:${reqId}`;
  if (promoRedeemLocks.has(resolveLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري معالجة طلب الشحن هذا بالفعل ⏳' });
  }
  promoRedeemLocks.add(resolveLockKey);

  try {
    const rawState = await fetchRawDatabaseState(true);
    const pendList = Array.isArray(rawState.settings.pendingTopupRequests)
      ? [...rawState.settings.pendingTopupRequests]
      : [];
    const targetIdx = pendList.findIndex(r => r && r.id === reqId);
    if (targetIdx === -1) {
      return res.status(404).json({ success: false, message: 'طلب الشحن غير موجود أو تم اعتماده مسبقاً ⚠️' });
    }

    const targetReq = pendList[targetIdx];
    pendList.splice(targetIdx, 1);
    await saveIncentivesToDatabase(rawState, { pendingTopupRequests: pendList });

    const phone = normalizePhoneServer(targetReq.phone);
    const amt = roundMoney(targetReq.amount);

    if (action === 'approve' && phone && amt > 0) {
      const walRes = await safeAdjustCaptainWallet(phone, amt, 'شحن رصيد فوري من الإدارة ⚡');
      if (!walRes.ok) {
        return res.status(500).json({ success: false, message: 'تعذر شحن المحفظة حالياً ⚠️' });
      }

      const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', phone).maybeSingle();
      if (cap) {
        const notices = Array.isArray(cap.admin_notices) ? [...cap.admin_notices] : [];
        notices.unshift({
          id: 'topup-' + Date.now(),
          text: `⚡ تم اعتماد طلبك وشحن محفظتك بمبلغ ${amt} جنيه فوراً.. ربنا يوسع رزقك يا بطل! 🛵💸`,
          type: 'reward',
          at: Date.now()
        });
        await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);
      }

      await logAdminAudit('اعتماد شحن فوري', phone, `اعتماد طلب شحن مبلغ ${amt} ج بضغطة واحدة`, req.admin.name);
      sendPushNotificationToPhone(phone, {
        title: 'تم اعتماد شحن محفظتك فوراً! ⚡💰',
        body: `نزل في محفظتك ${amt} جنيه من إدارة الرجل العنابي.. انطلق على الرادار يا وحش 🛵💪`
      });
    } else {
      await logAdminAudit('تجاهل طلب شحن', phone, `رفض/تجاهل طلب شحن بقيمة ${amt} ج`, req.admin.name);
    }

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: action === 'approve' ? `تم شحن (${amt} ج) للكابتن ${targetReq.fullName} بنجاح ⚡✅` : 'تم إزالة طلب الشحن من الطابور 🗑️',
      state
    });
  } finally {
    promoRedeemLocks.delete(resolveLockKey);
  }
}));

// إرسال تنبيه استعجال فوري للكابتن من رادار الإنذار المبكر (SLA Watchdog)
app.post('/api/admin/orders/:id/remind-captain', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageOrders', 'viewOrders'])) return;
  const { data: order } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!order || !order.assigned_courier_phone) {
    return res.status(404).json({ success: false, message: 'الطلب غير مسند لكابتن حالياً ⚠️' });
  }

  const capPhone = normalizePhoneServer(order.assigned_courier_phone);
  const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', capPhone).maybeSingle();
  if (cap) {
    const notices = Array.isArray(cap.admin_notices) ? [...cap.admin_notices] : [];
    notices.unshift({
      id: 'sla-' + Date.now(),
      text: `🚨 تنبيه من غرفة العمليات بخصوص الطلب (${order.id}): يرجى التحرك وتحديث حالة المشوار فوراً لعدم تأخير العميل! 🛵⚡`,
      type: 'deduct',
      at: Date.now()
    });
    await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', capPhone);
  }

  sendPushNotificationToPhone(capPhone, {
    title: `🚨 استعجال من غرفة العمليات (${order.id})!`,
    body: `يا كابتن ${cap?.full_name || ''}، الطلب (${order.id}) متأخر في حالة (${order.status}).. حدّث خط السير أو تواصل مع العميل فوراً 🛵⚡`
  });

  await logAdminAudit('تنبيه تأخير كابتن', order.id, `إرسال تنبيه استعجال للكابتن ${capPhone}`, req.admin.name);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم إرسال تنبيه استعجال فوري للكابتن 🔔✅', state });
}));

app.post('/api/admin/wallets/captain-deduct', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount, reason } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!phone || amt <= 0 || !reason) return res.status(400).json({ success: false, message: 'أكمل البيانات والسبب ⚠️' });

  const deductLockKey = `admin_deduct:${phone}`;
  if (promoRedeemLocks.has(deductLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ خصم لهذا الكابتن حالياً، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(deductLockKey);

  try {
    const walRes = await safeAdjustCaptainWallet(phone, -Math.abs(amt), `خصم إداري: ${reason}`);
    if (!walRes.ok) {
      return res.status(500).json({ success: false, message: 'تعذر تنفيذ الخصم حالياً ⚠️' });
    }

    const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', phone).maybeSingle();
    if (cap) {
      const notices = Array.isArray(cap.admin_notices) ? [...cap.admin_notices] : [];
      notices.unshift({
        id: 'deduct-' + Date.now(),
        text: `⚠️ تم خصم ${amt} ج من محفظتك — السبب: ${reason}`,
        type: 'deduct',
        at: Date.now()
      });
      await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);
    }

    sendPushNotificationToPhone(phone, {
      title: 'تنبيه خصم من المحفظة ⚠️',
      body: `تم خصم ${amt} ج من محفظتك — السبب: ${reason}`
    });

    await logAdminAudit('خصم من كابتن', phone, `خصم ${amt} ج - السبب: ${reason}`, req.admin.name);
    notifyAdminsPush('platform', {
      title: `⛔ خصم إداري من كابتن (${amt} ج)`,
      body: `خصم ${amt} ج من الكابتن ${cap?.full_name || ''} (${phone}) — السبب: ${reason} (بواسطة: ${req.admin.name})`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, state });
  } finally {
    promoRedeemLocks.delete(deductLockKey);
  }
}));

app.post('/api/admin/wallets/customer-compensate', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount, reason } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!isValidEgyptianPhoneServer(phone) || amt <= 0) return res.status(400).json({ success: false, message: 'بيانات العميل أو المبلغ غير صحيحة ⚠️' });

  const compLockKey = `admin_cust_comp:${phone}`;
  if (promoRedeemLocks.has(compLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري إضافة رصيد لهذا العميل حالياً، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(compLockKey);

  try {
    const { data: existing } = await supabase.from('customers').select('phone').eq('phone', phone).maybeSingle();
    if (!existing) {
      const defaultPinHash = await bcrypt.hash('1234', 10);
      await supabase.from('customers').insert([{
        phone,
        pin_hash: defaultPinHash,
        wallet_balance: 0,
        points: 0,
        wallet_transactions: []
      }]);
      await recordAnalyticsMetricEvent('customers', 1);
    }

    const walRes = await safeAdjustCustomerWallet(
      phone,
      amt,
      reason ? `هدية وتعويض: ${reason}` : 'رصيد هدية من إدارة العنابي 🎁'
    );
    if (!walRes.ok) {
      return res.status(500).json({ success: false, message: 'تعذر إضافة الرصيد للعميل حالياً ⚠️' });
    }

    await logAdminAudit('تعويض عميل', phone, `إضافة ${amt} ج - ${reason || 'هدية'}`, req.admin.name);
    sendPushNotificationToPhone(phone, {
      title: 'هدية في محفظتك يا باشا! 🎁👑',
      body: `نزل في محفظتك ${amt} جنيه رصيد هدية من الرجل العنابي هيتخصم أوتوماتيك في طلبك الجاي فوراً! 😍🛵`
    });

    notifyAdminsPush('platform', {
      title: `🎁 إضافة رصيد لعميل (${amt} ج)`,
      body: `تم إضافة ${amt} ج لمحفظة العميل (${phone}) — ${reason || 'هدية'} (بواسطة: ${req.admin.name})`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, state });
  } finally {
    promoRedeemLocks.delete(compLockKey);
  }
}));

app.post('/api/admin/captains/custom-fee', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageCommissions'])) return;
  const { phone: rawPhone, customFee, reason, reset } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const rawState = await fetchRawDatabaseState(false);
  const isPct = rawState.settings?.commissionMode === 'percentage';
  const unitLbl = isPct ? '%' : ' ج';
  const cleanFeeVal = isPct ? Math.min(100, Math.max(0, roundMoney(customFee))) : Math.max(0, roundMoney(customFee));

  const updates = reset
    ? { custom_fee: null, custom_fee_reason: null }
    : { custom_fee: cleanFeeVal, custom_fee_reason: reason || 'تخصيص من الإدارة' };

  await supabase.from('captains').update(updates).eq('phone', phone);
  await logAdminAudit('عمولة خاصة', phone, reset ? 'إرجاع للعمولة العامة/المستويات' : `تحديد عمولة ${cleanFeeVal}${unitLbl}`, req.admin.name);

  if (!reset) {
    sendPushNotificationToPhone(phone, {
      title: 'تحديث عمولتك الخاصة 🎯🛵',
      body: `الإدارة خصصت لك عمولة (${cleanFeeVal}${unitLbl}) — السبب: ${reason || 'تقديراً لمجهودك يا بطل!'}`
    });
  }

  notifyAdminsPush('platform', {
    title: `🎯 تحديث عمولة كابتن (${phone})`,
    body: `${reset ? 'إرجاع الكابتن للعمولة العامة/المستويات' : `تخصيص عمولة ${cleanFeeVal}${unitLbl} — ${reason || ''}`} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

app.post('/api/admin/captains/:phone/status', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageCaptains'])) return;
  const { status, reason } = req.body || {};
  const phone = normalizePhoneServer(req.params.phone);

  const { data: currentCap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
  if (!currentCap) {
    return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });
  }

  await supabase.from('captains').update({
    status,
    suspend_reason: reason || null,
    reject_reason: status === 'مرفوض' ? (reason || null) : null,
    is_available: status === 'معتمد' ? true : false
  }).eq('phone', phone);

  const rawState = await fetchRawDatabaseState(false);

  if (status === 'معتمد') {
    const s = rawState.settings || {};
    const welcomeActive = s.welcomeBonusActive !== false;
    const welcomeBonus = Math.max(0, roundMoney(s.welcomeBonusAmount ?? 7));

    const txList = Array.isArray(currentCap.wallet_transactions) ? currentCap.wallet_transactions : [];
    const notices = Array.isArray(currentCap.admin_notices) ? [...currentCap.admin_notices] : [];

    if (welcomeActive && welcomeBonus > 0) {
      const alreadyReceivedWelcome = txList.some(t => t && String(t.title || '').includes('هدية التسجيل'));

      if (!alreadyReceivedWelcome) {
        await safeAdjustCaptainWallet(
          phone,
          welcomeBonus,
          `هدية التسجيل الترحيبية (${welcomeBonus} ج) 🎁`
        );
      }

      const dynamicWelcomeText = `🎁 مبروك يا بطل! نزل في محفظتك ${welcomeBonus} جنيه هدية تسجيل ترحيبية عشان تبدأ مشاويرك بقوة مع الرجل العنابي 🛵💪`;
      const existingWelcomeIdx = notices.findIndex(n => n && String(n.id || '').startsWith('welcome-'));

      if (existingWelcomeIdx === -1) {
        notices.unshift({
          id: 'welcome-' + Date.now(),
          text: dynamicWelcomeText,
          type: 'reward',
          at: Date.now()
        });
      } else {
        notices[existingWelcomeIdx].text = dynamicWelcomeText;
      }
      await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);

      sendPushNotificationToPhone(phone, {
        title: 'تم اعتماد حسابك يا بطل! 🛵🎉',
        body: dynamicWelcomeText
      });
    } else {
      sendPushNotificationToPhone(phone, {
        title: 'تم اعتماد حسابك يا بطل! 🛵🎉',
        body: 'مبروك يا نجم! تم اعتماد وتفعيل حسابك في منصة الرجل العنابي.. افتح الرادار وانطلق الآن 🛵💪'
      });
    }
  } else if (status === 'مرفوض') {
    sendPushNotificationToPhone(phone, {
      title: 'يرجى تحديث مستنداتك 📄⚠️',
      body: `سبب الملاحظة: ${reason || 'يرجى رفع صور واضحة للمستندات'}`
    });
  } else if (status === 'موقوف') {
    sendPushNotificationToPhone(phone, {
      title: 'تنبيه إيقاف الحساب مؤقتاً ⛔',
      body: `السبب: ${reason || 'يرجى مراجعة إدارة الرجل العنابي'}`
    });
  }

  // إذا تم إيقاف أو رفض الكابتن وكان لديه طلبات لم يستلمها بعد، نعيدها تلقائياً للرادار ونرد عمولتها
  if (status === 'موقوف' || status === 'مرفوض') {
    const { data: prePickupOrders } = await supabase.from('orders')
      .select('*')
      .eq('assigned_courier_phone', phone)
      .in('status', ['تم قبول الطلب', 'الكابتن وصل للاستلام']);

    if (Array.isArray(prePickupOrders) && prePickupOrders.length > 0) {
      for (const ord of prePickupOrders) {
        const ordMeta = decodeOrderMetaFromNotes(ord.customer_notes || '');
        const cleanedNotes = encodeOrderMetaIntoNotes(ordMeta.cleanNotes, {
          ...ordMeta,
          arrivedAt: null,
          lastBuzzAt: null
        });
        const origFare = roundMoney(ord.original_fare ?? ord.fare ?? 40);
        const defFee = computeDefaultOrderPlatformFee(origFare, rawState.settings);
        const defNet = Math.max(0, roundMoney(origFare - defFee));

        const { data: revertedRows } = await supabase.from('orders').update({
          status: 'في انتظار كابتن',
          assigned_courier_phone: null,
          platform_fee: defFee,
          courier_net: defNet,
          fee_deducted: false,
          fee_refunded: false,
          customer_notes: cleanedNotes,
          admin_resolution_note: 'اعتذار الكابتن: تم إعادة توجيه الطلب للرادار لاختيار كابتن آخر فوراً'
        }).eq('id', ord.id).in('status', ['تم قبول الطلب', 'الكابتن وصل للاستلام']).select();

        if (revertedRows && revertedRows.length > 0) {
          if (ord.fee_deducted && !ord.fee_refunded && ord.platform_fee > 0) {
            await safeAdjustCaptainWallet(
              phone,
              roundMoney(ord.platform_fee),
              `رد عمولة لإعادة طلب ${ord.id} للرادار لإيقاف الحساب`
            );
          }
          if (ord.discount_applied > 0 && !ord.fee_refunded) {
            await safeAdjustCaptainWallet(
              phone,
              -Math.abs(roundMoney(ord.discount_applied)),
              `استرداد تعويض خصم لإعادة طلب ${ord.id} للرادار`
            );
          }
          const cPh = ord.customer_phone || ord.client_phone;
          if (cPh) {
            sendPushNotificationToPhone(cPh, {
              title: `تحديث بخصوص طلبك (${ord.id}) 🔄`,
              body: 'تمت إعادة توجيه طلبك على الرادار لاختيار كابتن آخر متاح فوراً يا باشا 🛵'
            });
          }
        }
      }
      broadcastPushToAvailableCaptains({
        title: 'أوردر عاد للرادار الآن! 📡🛵',
        body: 'يوجد طلب متاح الآن على الرادار.. الحق اقبله فوراً! 🚀'
      });
    }
  }

  await logAdminAudit('حالة كابتن', phone, `تغيير الحالة إلى ${status}${reason ? ' - السبب: ' + reason : ''}`, req.admin.name);
  notifyAdminsPush('platform', {
    title: `🛵 تحديث حالة كابتن (${status})`,
    body: `الكابتن ${currentCap.full_name} (${phone}) أصبح: ${status}${reason ? ' — السبب: ' + reason : ''} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

app.post('/api/admin/captains/reset-password', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageCaptains'])) return;
  const { phone: rawPhone, newPass } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  if (!phone || !newPass || String(newPass).trim().length < 4) {
    return res.status(400).json({ success: false, message: 'كلمة المرور قصيرة جداً ⚠️' });
  }
  const { data: cap } = await supabase.from('captains').select('full_name, session_version').eq('phone', phone).maybeSingle();
  if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

  const hashed = await bcrypt.hash(String(newPass).trim(), 10);
  await supabase.from('captains').update({
    password_hash: hashed,
    session_version: Number(cap.session_version || 1) + 1
  }).eq('phone', phone);

  await clearFailedAttempts(phone);
  await logAdminAudit('تصفير باسورد كابتن', phone, 'تعيين كلمة مرور جديدة للكابتن', req.admin.name);
  notifyAdminsPush('platform', {
    title: `🔑 تغيير باسورد كابتن (${phone})`,
    body: `تم تعيين كلمة مرور جديدة للكابتن ${cap.full_name || ''} بواسطة: ${req.admin.name}`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تحديث كلمة مرور الكابتن 🔑✅', state });
}));

app.post('/api/admin/customers/reset-pin', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets', 'manageSettings'])) return;
  const { phone: rawPhone, newPin } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const cleanPin = String(newPin || '')
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
    .trim();

  if (!isValidEgyptianPhoneServer(phone) || !/^[0-9]{4}$/.test(cleanPin)) {
    return res.status(400).json({ success: false, message: 'رقم الهاتف أو رمز الـ PIN (4 أرقام) غير صالح ⚠️' });
  }
  const hashedPin = await bcrypt.hash(cleanPin, 10);
  const { data: existing } = await supabase.from('customers').select('phone').eq('phone', phone).maybeSingle();

  if (existing) {
    await supabase.from('customers').update({ pin_hash: hashedPin }).eq('phone', phone);
  } else {
    await supabase.from('customers').insert([{
      phone,
      pin_hash: hashedPin,
      wallet_balance: 0,
      points: 0,
      wallet_transactions: []
    }]);
    await recordAnalyticsMetricEvent('customers', 1);
  }

  await clearFailedAttempts(phone);
  await logAdminAudit('تصفير PIN عميل', phone, 'تعيين رمز PIN جديد للعميل', req.admin.name);
  notifyAdminsPush('platform', {
    title: `🔒 تصفير PIN عميل (${phone})`,
    body: `تم تعيين رمز PIN جديد للعميل (${phone}) بواسطة: ${req.admin.name}`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تعيين رمز الـ PIN للعميل بنجاح 🔒✅', state });
}));

// [FIX-04] منع تكرار عداد الطلبات المكتملة ومعالجة الاسترداد المالي الإداري بذرية تامة
app.post('/api/admin/orders/:id/manage', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageOrders'])) return;
  const { action, reason } = req.body || {};
  const orderId = String(req.params.id || '').trim();
  const manageLockKey = `admin_order_manage:${orderId}`;
  if (promoRedeemLocks.has(manageLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ إجراء إداري على هذا الطلب حالياً ⏳' });
  }
  promoRedeemLocks.add(manageLockKey);

  try {
    const rawState = await fetchRawDatabaseState(true);
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود' });

    const isAlreadyCancelled = String(order.status || '').includes('ملغي') || order.status === 'تمت التسوية الإدارية';
    if ((action === 'cancel' || action === 'resolve_cancel' || action === 'radar') && isAlreadyCancelled) {
      return res.status(400).json({ success: false, message: 'الطلب ملغي أو تمت تسويته بالفعل مسبقاً ⚠️' });
    }
    if (action === 'radar' && !ACTIVE_COURIER_ORDER_STATUSES.includes(order.status)) {
      return res.status(400).json({ success: false, message: 'لا يمكن إعادة الطلب للرادار إلا إذا كان جارياً حالياً مع كابتن ⚠️' });
    }

    const custPhone = order.customer_phone || order.client_phone;
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');

    if (action === 'radar') {
      const prevCapPhone = order.assigned_courier_phone;
      const cleanedOffers = (Array.isArray(meta.captainOffers) ? meta.captainOffers : []).map(ofItem =>
        prevCapPhone && normalizePhoneServer(ofItem.captainPhone) === normalizePhoneServer(prevCapPhone) && ofItem.status === 'accepted'
          ? { ...ofItem, status: 'rejected_by_captain', updatedAt: Date.now() }
          : ofItem
      );
      const cleanedRadarNotes = encodeOrderMetaIntoNotes(meta.cleanNotes, {
        ...meta,
        arrivedAt: null,
        lastBuzzAt: null,
        captainOffers: cleanedOffers
      });
      const origFare = roundMoney(order.original_fare ?? order.fare ?? 40);
      const defaultPlatformFee = computeDefaultOrderPlatformFee(origFare, rawState.settings);
      const defaultCourierNet = Math.max(0, roundMoney(origFare - defaultPlatformFee));

      // تحديث مشروط بالحالة الحالية أولاً لمنع أي صرف مزدوج
      const { data: updatedRadarOrd, error: radarUpdErr } = await supabase.from('orders')
        .update({
          status: 'في انتظار كابتن',
          assigned_courier_phone: null,
          platform_fee: defaultPlatformFee,
          courier_net: defaultCourierNet,
          fee_deducted: false,
          fee_refunded: false,
          customer_notes: cleanedRadarNotes,
          admin_resolution_note: reason ? `إعادة للرادار: ${reason}` : null
        })
        .eq('id', orderId)
        .eq('status', order.status)
        .select()
        .maybeSingle();

      if (radarUpdErr || !updatedRadarOrd) {
        return res.status(400).json({ success: false, message: 'تغيرت حالة الطلب بالفعل، يرجى التحديث ⚠️' });
      }

      if (prevCapPhone) {
        if (order.fee_deducted && !order.fee_refunded && order.platform_fee > 0) {
          await safeAdjustCaptainWallet(
            prevCapPhone,
            roundMoney(order.platform_fee),
            `رد عمولة لإعادة طلب ${order.id} للرادار إدارياً`
          );
        }
        if (order.discount_applied > 0 && !order.fee_refunded) {
          await safeAdjustCaptainWallet(
            prevCapPhone,
            -Math.abs(roundMoney(order.discount_applied)),
            `استرداد تعويض خصم لإعادة طلب ${order.id} للرادار`
          );
        }
        sendPushNotificationToPhone(prevCapPhone, {
          title: `🔄 إعادة الطلب (${order.id}) للرادار`,
          body: `قامت غرفة العمليات بإعادة الطلب (${order.id}) للرادار ورد العمولة لمحفظتك${reason ? ' — السبب: ' + reason : ''}`
        });
      }

      if (custPhone) {
        sendPushNotificationToPhone(custPhone, {
          title: `تحديث في طلبك (${order.id}) 🔄🛵`,
          body: `قامت غرفة العمليات بإعادة توجيه طلبك على الرادار لكابتن آخر لضمان سرعة خدمتك يا باشا!`
        });
      }
      broadcastPushToAvailableCaptains({
        title: 'أوردر عاد للرادار الآن! 📡🛵',
        body: `طلب (${order.id}) من ${order.pickup_zone} إلى ${order.dropoff_zone} متاح الآن على الرادار.. الحق اقبله! 🚀`
      });
    } else if (action === 'resolve_cancel' || (action === 'cancel' && order.status === 'قيد مراجعة الاعتراض')) {
      const resolutionMsg = reason || 'شكوتك تمت مراجعتها من قبل الإدارة وجاري التحقيق مع الطرف الآخر "سيتم تعويضك بالشكل المناسب"';
      const { data: resolvedOrd } = await supabase.from('orders')
        .update({
          status: 'تمت التسوية الإدارية',
          fee_refunded: false,
          admin_resolution_note: resolutionMsg
        })
        .eq('id', orderId)
        .eq('status', order.status)
        .select()
        .maybeSingle();

      if (!resolvedOrd) {
        return res.status(400).json({ success: false, message: 'تغيرت حالة الطلب بالفعل ⚠️' });
      }

      if (custPhone) {
        sendPushNotificationToPhone(custPhone, {
          title: `تمت مراجعة شكوتك لطلب (${order.id}) ⚖️✅`,
          body: resolutionMsg
        });
      }
    } else if (action === 'cancel') {
      // تحديث حالة الطلب إلى ملغي إدارياً بشرط حالته السابقة أولاً قبل رد الأموال للمحافظ
      const { data: cancelledOrd, error: cancErr } = await supabase.from('orders')
        .update({
          status: 'ملغي إدارياً',
          fee_refunded: true,
          admin_resolution_note: reason || 'تم إلغاء الطلب بواسطة الإدارة'
        })
        .eq('id', orderId)
        .eq('status', order.status)
        .select()
        .maybeSingle();

      if (cancErr || !cancelledOrd) {
        return res.status(400).json({ success: false, message: 'تغيرت حالة الطلب بالفعل ⚠️' });
      }

      const refundWalletAmt = meta.walletDiscount > 0
        ? meta.walletDiscount
        : Math.max(0, roundMoney((order.discount_applied || 0) - (meta.promoDiscount || 0)));

      if (refundWalletAmt > 0 && custPhone) {
        await safeAdjustCustomerWallet(
          custPhone,
          roundMoney(refundWalletAmt),
          `رد خصم لطلب ملغي إدارياً ${order.id}`
        );
      }
      if (meta.promoCode && custPhone && !isAlreadyCancelled) {
        await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
      }
      if (order.assigned_courier_phone && !order.fee_refunded) {
        if (order.fee_deducted && order.platform_fee > 0) {
          await safeAdjustCaptainWallet(
            order.assigned_courier_phone,
            roundMoney(order.platform_fee),
            `رد عمولة لطلب ملغي إدارياً قبل التسليم ${order.id}`
          );
        }
        if (order.discount_applied > 0) {
          await safeAdjustCaptainWallet(
            order.assigned_courier_phone,
            -Math.abs(roundMoney(order.discount_applied)),
            `إلغاء تعويض خصم لطلب ملغي إدارياً ${order.id}`
          );
        }
        sendPushNotificationToPhone(order.assigned_courier_phone, {
          title: `تم إلغاء الطلب (${order.id}) إدارياً ❌`,
          body: `قامت غرفة العمليات بإلغاء الطلب ورد العمولة لمحفظتك${reason ? ' — السبب: ' + reason : ''}`
        });
      }

      if (custPhone) {
        sendPushNotificationToPhone(custPhone, {
          title: (refundWalletAmt > 0 || meta.promoCode) ? `إلغاء الطلب (${order.id}) وخصمك رجعلك! 🎁✅` : `تم إلغاء الطلب (${order.id}) إدارياً ❌`,
          body: (refundWalletAmt > 0 || meta.promoCode)
            ? `تم إلغاء الطلب (${order.id}) ورجّعنالك خصمك (${roundMoney(order.discount_applied)} ج) لمحفظتك/كودك تاني تقدر تستخدمه في أي وقت 😎🛵`
            : `تم إلغاء الطلب (${order.id}) بواسطة الإدارة: ${reason || ''}`
        });
      }
    } else if (action === 'resolve_complete') {
      const wasAlreadyCompletedBeforeDispute = (order.status === 'مكتمل' || order.status === 'قيد مراجعة الاعتراض');
      const resolutionMsg = reason || 'تمت المراجعة واعتماد اكتمال الطلب بواسطة الإدارة ✅';
      const { data: compOrd } = await supabase.from('orders')
        .update({
          status: 'مكتمل',
          admin_resolution_note: resolutionMsg
        })
        .eq('id', orderId)
        .eq('status', order.status)
        .select()
        .maybeSingle();

      if (!compOrd) {
        return res.status(400).json({ success: false, message: 'تغيرت حالة الطلب بالفعل ⚠️' });
      }
      if (!wasAlreadyCompletedBeforeDispute) {
        await recordAnalyticsMetricEvent('completedOrders', 1);
      }
      if (custPhone) {
        sendPushNotificationToPhone(custPhone, {
          title: `قرار الإدارة بخصوص طلبك (${order.id}) ✅`,
          body: resolutionMsg
        });
      }
    } else {
      return res.status(400).json({ success: false, message: 'إجراء إداري غير معروف ⚠️' });
    }

    await logAdminAudit('تدخل في طلب', orderId, `الإجراء: ${action} ${reason ? '- ' + reason : ''}`, req.admin.name);
    notifyAdminsPush('platform', {
      title: `⚖️ تدخل إداري في طلب (${orderId})`,
      body: `الإجراء: ${action}${reason ? ' — السبب: ' + reason : ''} (بواسطة: ${req.admin.name})`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, state });
  } catch (err) {
    console.error('Admin manage order error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر تنفيذ الإجراء الإداري حالياً ⚠️' });
  } finally {
    promoRedeemLocks.delete(manageLockKey);
  }
}));

// [FIX-03] إلزام التحقق من كلمة المرور الحالية عند تحديث بيانات الأدمن الرئيسي وفحص نجاح التحديث قبل إصدار التوكن
app.post('/api/admin/accounts/master', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'هذا الإجراء مخصص للأدمن الرئيسي فقط 👑⛔' });
  }
  const { name, username, currentPassword, newPassword } = req.body || {};
  if (!currentPassword) {
    return res.status(400).json({ success: false, message: 'برجاء إدخال كلمة المرور الحالية للتأكيد ⚠️' });
  }

  const cleanNewPass = newPassword ? String(newPassword).trim() : '';
  if (cleanNewPass && cleanNewPass.length < 4) {
    return res.status(400).json({ success: false, message: 'كلمة المرور الجديدة يجب ألا تقل عن 4 أحرف أو أرقام ⚠️' });
  }

  const { data: master } = await supabase.from('admins').select('*').eq('is_master', true).limit(1).maybeSingle();

  if (master) {
    const valid = await bcrypt.compare(String(currentPassword), master.password_hash || '');
    if (!valid) {
      return res.status(401).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة ⚠️' });
    }
  }

  const cleanName = String(name || (master ? master.name : 'الأدمن الرئيسي')).trim();
  const cleanUser = String(username || (master ? master.username : 'ennaby1')).trim();

  if (!cleanName || !cleanUser) {
    return res.status(400).json({ success: false, message: 'الاسم واسم المستخدم مطلوبان ⚠️' });
  }

  if (master && cleanUser.toLowerCase() !== String(master.username).toLowerCase()) {
    const { data: conflictSub } = await supabase.from('admins').select('username').ilike('username', cleanUser).maybeSingle();
    if (conflictSub) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم هذا مستخدم بالفعل لمسؤول آخر ⚠️' });
    }
  }

  const updates = {
    name: cleanName,
    username: cleanUser
  };
  let finalPasswordHash = master ? master.password_hash : '';
  if (cleanNewPass) {
    finalPasswordHash = await bcrypt.hash(cleanNewPass, 10);
    updates.password_hash = finalPasswordHash;
  }

  if (master) {
    const { error: updErr } = await supabase.from('admins').update(updates).eq('username', master.username);
    if (updErr) {
      return res.status(400).json({ success: false, message: 'تعذر تحديث بيانات الحساب، تأكد من عدم تكرار اسم المستخدم ⚠️' });
    }
  } else {
    finalPasswordHash = updates.password_hash || await bcrypt.hash(String(currentPassword), 10);
    updates.password_hash = finalPasswordHash;
    updates.is_master = true;
    updates.status = 'نشط';
    const { error: insErr } = await supabase.from('admins').insert([updates]);
    if (insErr) {
      return res.status(400).json({ success: false, message: 'تعذر حفظ بيانات الأدمن الرئيسي ⚠️' });
    }
  }

  const newToken = jwt.sign(
    {
      username: updates.username,
      role: 'admin',
      isMaster: true,
      pwdSig: getPasswordSignature(finalPasswordHash)
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  const isSecureCookie = IS_PRODUCTION || req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie('admin_session', newToken, {
    httpOnly: true,
    secure: isSecureCookie,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  });
  req.cookies = { ...req.cookies, admin_session: newToken };

  await logAdminAudit('تحديث حساب الماستر', updates.username, 'تحديث بيانات/كلمة مرور الأدمن الرئيسي', cleanName);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم حفظ وتحديث بيانات الأدمن الرئيسي ✅', state });
}));

app.post('/api/admin/accounts/sub', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'إدارة حسابات وصلاحيات المسؤولين متاحة للأدمن الرئيسي فقط 👑⛔' });
  }
  const { origUsername, name, username, password, permissions } = req.body || {};
  const cleanName = String(name || '').trim();
  const cleanUser = String(username || '').trim();
  const cleanOrig = origUsername ? String(origUsername).trim() : '';
  const cleanPass = password ? String(password).trim() : '';

  if (!cleanName || !cleanUser) {
    return res.status(400).json({ success: false, message: 'الاسم واسم المستخدم مطلوبان ⚠️' });
  }
  if (cleanPass && cleanPass.length < 4) {
    return res.status(400).json({ success: false, message: 'كلمة المرور يجب ألا تقل عن 4 أحرف أو أرقام ⚠️' });
  }

  const { data: masterRow } = await supabase.from('admins').select('username').eq('is_master', true).maybeSingle();
  if (
    masterRow &&
    (masterRow.username.toLowerCase() === cleanUser.toLowerCase() ||
      (cleanOrig && masterRow.username.toLowerCase() === cleanOrig.toLowerCase()))
  ) {
    return res.status(400).json({
      success: false,
      message: 'لا يمكن استخدام أو تعديل اسم مستخدم الأدمن الرئيسي كمسؤول فرعي 👑⛔'
    });
  }

  const updates = {
    name: cleanName,
    username: cleanUser,
    is_master: false,
    status: 'نشط',
    permissions: permissions || {}
  };
  if (cleanPass) {
    updates.password_hash = await bcrypt.hash(cleanPass, 10);
  }

  if (cleanOrig) {
    const { error: updErr } = await supabase.from('admins').update(updates).ilike('username', cleanOrig).eq('is_master', false);
    if (updErr) {
      return res.status(400).json({ success: false, message: 'تعذر تعديل المسؤول (تأكد من عدم تكرار اسم المستخدم) ⚠️' });
    }
  } else {
    if (!cleanPass) return res.status(400).json({ success: false, message: 'كلمة المرور مطلوبة للمسؤول الجديد ⚠️' });
    const { data: existingSub } = await supabase.from('admins').select('username').ilike('username', cleanUser).maybeSingle();
    if (existingSub) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم مسجل لمسؤول آخر بالفعل ⚠️' });
    }
    const { error: insErr } = await supabase.from('admins').insert([updates]);
    if (insErr) {
      return res.status(400).json({ success: false, message: 'تعذر إضافة المسؤول الجديد ⚠️' });
    }
  }

  await logAdminAudit('إدارة مسؤولين', cleanUser, cleanOrig ? 'تعديل صلاحيات مسؤول' : 'إضافة مسؤول جديد', req.admin.name);
  notifyAdminsPush('platform', {
    title: `🛡️ ${cleanOrig ? 'تعديل صلاحيات مسؤول' : 'إضافة مسؤول فرعي جديد'}`,
    body: `المسؤول: ${cleanName} (@${cleanUser}) — بواسطة: ${req.admin.name}`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

app.post('/api/admin/accounts/:username/toggle', authenticateAdmin, asyncHandler(async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'تغيير حالة المسؤولين متاح للأدمن الرئيسي فقط 👑⛔' });
  }
  const targetUser = String(req.params.username || '').trim();
  const { data: acc } = await supabase.from('admins').select('username, status, is_master').ilike('username', targetUser).maybeSingle();
  if (!acc || acc.is_master) return res.status(404).json({ success: false, message: 'المسؤول غير موجود ⚠️' });

  const newStatus = acc.status === 'نشط' ? 'معطل' : 'نشط';
  await supabase.from('admins').update({ status: newStatus }).eq('username', acc.username);
  await logAdminAudit('حالة مسؤول', acc.username, `تغيير الحالة إلى ${newStatus}`, req.admin.name);
  notifyAdminsPush('platform', {
    title: `🛡️ تغيير حالة مسؤول (@${acc.username})`,
    body: `تم تغيير حالة المسؤول إلى: ${newStatus} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
}));

app.post('/api/admin/push-broadcast', authenticateAdmin, asyncHandler(async (req, res) => {
  try {
    if (!req.admin || !req.admin.is_master) {
      return res.status(403).json({
        success: false,
        message: 'عفواً، إرسال الإشعارات العامة للهواتف متاح للأدمن الرئيسي فقط 👑⛔'
      });
    }

    const { target = 'all', title = 'الرجل العنابي 🛵', body = '' } = req.body || {};
    const cleanTitle = String(title || 'الرجل العنابي 🛵').trim();
    const cleanBody = String(body || '').trim();

    if (!cleanBody) {
      return res.status(400).json({ success: false, message: 'برجاء كتابة نص الإشعار أولاً ⚠️' });
    }

    const { data: allSubs } = await supabase.from('push_subscriptions').select('phone, subscription');
    if (!allSubs || allSubs.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'لا توجد هواتف مشتركة في الإشعارات حالياً (اضغط على تفعيل واستقبال إشعارات الرادار أعلى الصفحة أولاً) 📲⚠️'
      });
    }

    const sentCount = await broadcastPushByTargetGroup(target, {
      title: cleanTitle,
      body: cleanBody,
      url: '/'
    });

    if (sentCount === 0) {
      return res.status(400).json({
        success: false,
        message: 'لم يتم العثور على هواتف نشطة في هذه الفئة أو انتهت صلاحية الاشتراكات القديمة؛ اضغط على «تفعيل واستقبال إشعارات الرادار على هذا الجهاز» وجرب مجدداً 🔄📲'
      });
    }

    const targetLabels = {
      all: 'جميع الهواتف المحملة للتطبيق',
      unregistered: 'الزوار غير المسجلين',
      customers: 'العملاء المسجلين',
      captains: 'الكباتن المسجلين'
    };
    await logAdminAudit(
      'إشعار موبايل عام',
      targetLabels[target] || 'الجميع',
      `العنوان: ${cleanTitle} | النص: ${cleanBody} (وصل إلى ${sentCount} جهاز)`,
      req.admin.name
    );

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({
      success: true,
      sentCount,
      message: `تم إرسال الإشعار الفوري بنجاح إلى ${sentCount} هاتف محمول 📲✅`,
      state
    });
  } catch (err) {
    console.error('Push broadcast error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إرسال الإشعارات ⚠️' });
  }
}));

// ==========================================
// 10. المهام المجدولة (Vercel Cron) ومعالج الأخطاء المركزي
// ==========================================
app.get('/api/cron/cleanup-orders', asyncHandler(async (req, res) => {
  const cronSecret = (process.env.CRON_SECRET || '').trim();
  const authHeader = String(req.headers.authorization || '').trim();
  const isAuthorizedBySecret = Boolean(cronSecret && authHeader === `Bearer ${cronSecret}`);
  const isVercelCronHeader = req.headers['x-vercel-cron'] === '1';

  if (IS_PRODUCTION && cronSecret && !isAuthorizedBySecret) {
    return res.status(401).json({ success: false });
  }
  if (IS_PRODUCTION && !cronSecret && !isVercelCronHeader) {
    return res.status(401).json({ success: false });
  }

  lastLazyCleanupRun = 0;
  const rawState = await fetchRawDatabaseState(false);
  const canceledCount = await runLazyExpiredOrdersCleanup(rawState.settings.waitingTimeoutMinutes);
  res.json({ success: true, canceled: canceledCount });
}));

// معالج الأخطاء المركزي (Global Error Middleware) لمنع أي Request معلّق
app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err && err.message ? err.message : err);
  if (res.headersSent) {
    return next(err);
  }
  res.status(500).json({
    success: false,
    message: 'حدث خطأ غير متوقع في السيرفر، يرجى المحاولة مرة أخرى ⚠️'
  });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running securely on http://localhost:${PORT}`));
}
module.exports = app;