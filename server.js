require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ==========================================
// 1. إعداد الاتصال بـ Supabase و Web Push
// ==========================================
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
// [FIX-01] قراءة مفتاح Supabase العام فقط وحظر أي سقوط احتياطي على المفتاح السري نهائياً
const rawAnonKey = (process.env.APP_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY || '').trim();
const SUPABASE_ANON_KEY = (rawAnonKey && !rawAnonKey.startsWith('sb_secret_') && rawAnonKey !== SUPABASE_KEY) ? rawAnonKey : '';
const JWT_SECRET = process.env.JWT_SECRET || 'ENNABY_SUPER_SECRET_KEY_V31_2026';
const CAPTAIN_DOCS_BUCKET = process.env.SUPABASE_STORAGE_BUCKET || 'captain-docs';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || 'BOyNefapT_wxw5HHpZFaPsQvyj9OIfV9owv8-9cJd5RMcfdGMK9c0j7D8zv1nNlWBd2K6DB-1v_YhzW2z2xxklc';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || 'KvjK8OyYPhFEUdIOgmPEBqxgAMw48AU98sI4GfYTeqw';

try {
  webpush.setVapidDetails('mailto:support@ennaby.com', VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} catch (err) {
  console.warn('⚠️ WebPush setup warning:', err.message);
}

// ==========================================
// 2. إعدادات الحماية والـ Middleware
// ==========================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

app.use(cors({
  origin: process.env.NODE_ENV === 'production' && process.env.ALLOWED_ORIGIN ? process.env.ALLOWED_ORIGIN : true,
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

// [NEW-SEC-01] تقديم ملفات الواجهة والـ PWA المسموحة فقط وحظر كشف ملفات الجذر مثل server.js و .env
const ALLOWED_PUBLIC_ASSETS = ['sw.js', 'manifest.json', 'icon-192.png', 'icon-512.png', 'logo-1.png', 'logo-1.jpg'];
ALLOWED_PUBLIC_ASSETS.forEach((assetName) => {
  app.get(`/${assetName}`, (req, res) => {
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
      const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'anon').split(',')[0].trim();
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
  const num = Number(val);
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

  // دمج التواريخ الفعلية المسجلة في الجداول لضمان دقة الرسم البياني التاريخي
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

// دوال ترميز وفك ترميز إحداثيات الخريطة والكوبون داخل ملاحظات الطلب بأمان تام وبدون تعارض مع الأقواس
function encodeOrderMetaIntoNotes(rawNotes, meta = {}) {
  const cleanNotes = String(rawNotes || '').replace(/\s*\[META:\{[\s\S]*?\}\]/g, '').trim();
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

  if (Object.keys(payload).length === 0) return cleanNotes;
  return `${cleanNotes} [META:${JSON.stringify(payload)}]`.trim();
}

function decodeOrderMetaFromNotes(storedNotes) {
  const raw = String(storedNotes || '');
  const match = raw.match(/\[META:(\{[\s\S]*?\})\]/);
  let meta = {};
  if (match && match[1]) {
    try { meta = JSON.parse(match[1]); } catch (e) {}
  }
  const cleanNotes = raw.replace(/\s*\[META:\{[\s\S]*?\}\]/g, '').trim();
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
    surgePercent: Number(meta.sp || 0)
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

// حساب مستوى الكابتن (برونزي 🥉 / بلاتيني 🥈 / ماسي 💎) مع مبدأ الهبوط التدريجي الآمن (Graceful Demotion)
function computeCaptainTierAndFee(captainRow, mappedOrders, settings) {
  const s = settings || {};
  const weeklyTarget = Math.max(1, Number(s.tierWeeklyOrdersTarget ?? 25));
  const tierDaysWindow = Math.max(1, Number(s.tierDaysWindow ?? 7));
  const tierConsecutiveDaysForDiamond = Math.max(
    tierDaysWindow,
    Number(s.tierConsecutiveDaysForDiamond ?? (Number(s.tierWeeksForDiamond ?? 4) * tierDaysWindow))
  );
  const diamondWeeksTarget = Math.max(1, Math.ceil(tierConsecutiveDaysForDiamond / tierDaysWindow));
  const platDiscount = Math.max(0, roundMoney(s.tierPlatinumDiscount ?? 1));
  const diaDiscount = Math.max(0, roundMoney(s.tierDiamondDiscount ?? 2));

  const now = Date.now();
  const windowMs = tierDaysWindow * 24 * 60 * 60 * 1000;

  const capCompletedOrders = (mappedOrders || []).filter(
    o => o.assignedCourierPhone === captainRow.phone && (o.status === 'مكتمل' || o.status === 'قيد مراجعة الاعتراض')
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

  if (currentWeekOrders >= weeklyTarget) {
    consecutiveQualifiedWeeks = 1 + pastConsecutiveWeeks;
    if (consecutiveQualifiedWeeks >= diamondWeeksTarget) {
      autoTier = 'diamond';
    } else {
      autoTier = 'platinum';
    }
  } else {
    if (pastConsecutiveWeeks >= diamondWeeksTarget) {
      autoTier = 'platinum';
      gracefulDemotion = true;
      consecutiveQualifiedWeeks = pastConsecutiveWeeks;
    } else {
      autoTier = 'bronze';
      consecutiveQualifiedWeeks = 0;
    }
  }

  const manualOverrides = (s.tierManualOverrides && typeof s.tierManualOverrides === 'object') ? s.tierManualOverrides : {};
  const manualTier = manualOverrides[captainRow.phone];
  const finalTier = ['bronze', 'platinum', 'diamond'].includes(manualTier) ? manualTier : autoTier;

  const tierMetaMap = {
    bronze: { key: 'bronze', name: 'كابتن برونزي', emoji: '🥉', badgeText: 'كابتن برونزي 🥉', discount: 0, color: '#CD7F32' },
    platinum: { key: 'platinum', name: 'كابتن بلاتيني', emoji: '🥈', badgeText: 'كابتن بلاتيني 🥈', discount: platDiscount, color: '#37474F' },
    diamond: { key: 'diamond', name: 'كابتن ماسي', emoji: '💎', badgeText: 'كابتن ماسي 💎', discount: diaDiscount, color: '#0288D1' }
  };

  const tierInfo = tierMetaMap[finalTier] || tierMetaMap.bronze;

  const surgeInfo = getActiveSurgeInfo(s);
  const basePlatformFee = roundMoney(s.platformFee ?? 7);
  const surgedPlatformFee = surgeInfo.isActive
    ? roundMoney(basePlatformFee * (1 + surgeInfo.surgePercent / 100))
    : basePlatformFee;

  let effectiveFee = Math.max(0, roundMoney(surgedPlatformFee - tierInfo.discount));
  if (captainRow.custom_fee !== null && captainRow.custom_fee !== undefined) {
    const baseCustom = roundMoney(captainRow.custom_fee);
    effectiveFee = surgeInfo.isActive
      ? roundMoney(baseCustom * (1 + surgeInfo.surgePercent / 100))
      : baseCustom;
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
    return resolveCaptainPhotoUrl(filePath);
  } catch (err) {
    return dataUrl;
  }
}

let stateCache = {
  raw: null,
  lastFetched: 0,
  ttlMs: 3000
};

let lastLazyCleanupRun = 0;

function invalidateStateCache() {
  stateCache.raw = null;
  stateCache.lastFetched = 0;
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

function isRequestFromAdminView(req) {
  if (req.query && req.query.role === 'admin') return true;
  if (req.cookies && req.cookies.admin_session) return true;
  const ref = String(req.headers.referer || '');
  return ref.includes('/admin');
}

function getAuthenticatedAdminFromCookie(req) {
  try {
    const token = req.cookies && req.cookies.admin_session;
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

function getAuthenticatedCustomerFromCookie(req) {
  try {
    const token = req.cookies && req.cookies.customer_session;
    if (!token) return null;
    const dec = jwt.verify(token, JWT_SECRET);
    return dec && dec.phone ? normalizePhoneServer(dec.phone) : null;
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
    }
    return phone;
  } catch (e) {
    return null;
  }
}

// [FIX-06 & NEW-SEC-03] التحقق الصارم من ملكية العميل للطلب عبر كوكي الجلسة الموثق فقط
function verifyCustomerOrderOwnership(req, orderRow) {
  if (!orderRow) return false;
  const orderOwnerPhone = normalizePhoneServer(orderRow.customer_phone || orderRow.client_phone);
  if (!orderOwnerPhone) return false;
  const cookiePhone = getAuthenticatedCustomerFromCookie(req);
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
    tierColor: tierData.tierColor,
    weeklyCompletedOrders: tierData.weeklyCompletedOrders,
    consecutiveQualifiedWeeks: tierData.consecutiveQualifiedWeeks,
    consecutiveQualifiedDays: tierData.consecutiveQualifiedDays,
    tierDaysWindow: tierData.tierDaysWindow,
    tierConsecutiveDaysForDiamond: tierData.tierConsecutiveDaysForDiamond,
    tierProgressPct: tierData.tierProgressPct,
    effectiveFee: tierData.effectiveFee
  };
}

function tierInfoSafeEmoji(tierData) {
  return (tierData && tierData.tierEmoji) ? tierData.tierEmoji : '🥉';
}

function mapOrderRow(o) {
  const createdMs = o.created_at ? new Date(o.created_at).getTime() : Date.now();
  const parsedMeta = decodeOrderMetaFromNotes(o.customer_notes || '');
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
    walletDiscount: parsedMeta.walletDiscount || roundMoney(o.discount_applied ?? 0),
    surgePercent: parsedMeta.surgePercent,
    packageType: o.package_type || DEFAULT_PACKAGE_TYPES[0],
    payer: o.payer || 'الراسل',
    senderPhone: o.sender_phone || '',
    recipientPhone: o.recipient_phone || '',
    originalFare: roundMoney(o.original_fare ?? o.fare ?? 0),
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
          await supabase.rpc('adjust_customer_wallet_atomic', {
            p_phone: custPhone,
            p_amount: roundMoney(refundWalletAmt),
            p_reason: `رد تعويض مهلة طلب ${order.id}`
          });
        }
        if (meta.promoCode && custPhone) {
          await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
        }
        notifyAdminsPush('platform', {
          title: `⏳ إلغاء تلقائي لطلب (${order.id})`,
          body: `تجاوز الطلب مهلة الانتظار (${mins} دقيقة) دون قبول وتم إلغاؤه تلقائياً.`
        });
      }
      invalidateStateCache();
      return expired.length;
    }
  } catch (e) {}
  return 0;
}

async function fetchCaptainStorageFilesMap() {
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
  } catch (e) {}
  return storageMap;
}

async function fetchRawDatabaseState(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && stateCache.raw && (now - stateCache.lastFetched < stateCache.ttlMs)) {
    return stateCache.raw;
  }

  // [FIX-08] تنفيذ وانتظار تنظيف الطلبات المنتهية بـ await قبل قراءة جدول الطلبات لضمان اكتمال العملية على Vercel
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

  const welcomeBonusActive = sRow.welcome_bonus_active !== undefined
    ? Boolean(sRow.welcome_bonus_active)
    : (storedIncentives.welcomeBonusActive !== undefined ? Boolean(storedIncentives.welcomeBonusActive) : true);

  const welcomeBonusAmount = sRow.welcome_bonus_amount !== undefined && sRow.welcome_bonus_amount !== null
    ? Math.max(0, roundMoney(sRow.welcome_bonus_amount))
    : (storedIncentives.welcomeBonusAmount !== undefined ? Math.max(0, roundMoney(storedIncentives.welcomeBonusAmount)) : 7);

  const referralRewardActive = sRow.referral_reward_active !== undefined
    ? Boolean(sRow.referral_reward_active)
    : (storedIncentives.referralRewardActive !== undefined ? Boolean(storedIncentives.referralRewardActive) : true);

  const referralRewardAmount = sRow.referral_reward_amount !== undefined && sRow.referral_reward_amount !== null
    ? Math.max(0, roundMoney(sRow.referral_reward_amount))
    : (storedIncentives.referralRewardAmount !== undefined ? Math.max(0, roundMoney(storedIncentives.referralRewardAmount)) : 50);

  const referralRequiredOrders = Math.max(1, Number(storedIncentives.referralRequiredOrders ?? 2));
  const broadcastTarget = sRow.broadcast_target || storedIncentives.broadcastTarget || 'all';

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

  const promoCodes = Array.isArray(storedIncentives.promoCodes)
    ? storedIncentives.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
    : [];

  const adminPushMasterEnabled = storedIncentives.adminPushMasterEnabled !== false;
  const adminPushCustomersEnabled = storedIncentives.adminPushCustomersEnabled !== false;
  const adminPushCaptainsEnabled = storedIncentives.adminPushCaptainsEnabled !== false;

  const rawCustomersRows = customersRes.data || [];
  const rawCaptainsRows = captainsRes.data || [];
  const rawOrdersRows = ordersRes.data || [];
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
    platformFee: roundMoney(sRow.platform_fee ?? 7),
    customerPointsPerOrder: Number(sRow.customer_points_per_order ?? 5),
    customerRewardThreshold: Number(sRow.customer_reward_threshold ?? 100),
    customerRewardCash: roundMoney(sRow.customer_reward_cash ?? 10),
    courierPointsPerOrder: Number(sRow.courier_points_per_order ?? 5),
    courierRewardThreshold: Number(sRow.courier_reward_threshold ?? 100),
    courierRewardCash: roundMoney(sRow.courier_reward_cash ?? 10),
    welcomeBonusActive,
    welcomeBonusAmount,
    referralRewardActive,
    referralRewardAmount,
    referralRequiredOrders,
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
    waitingTimeoutMinutes: Number(sRow.waiting_timeout_minutes ?? 30),
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
    storageFilesMap: storageFilesMap || {},
    orders: mappedOrders,
    adminAccounts: (adminsRes.data || []).map(a => ({
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
    welcomeBonusActive: prevSettings.welcomeBonusActive !== false,
    welcomeBonusAmount: roundMoney(prevSettings.welcomeBonusAmount ?? 7),
    referralRewardActive: prevSettings.referralRewardActive !== false,
    referralRewardAmount: roundMoney(prevSettings.referralRewardAmount ?? 50),
    referralRequiredOrders: Math.max(1, Number(prevSettings.referralRequiredOrders ?? 2)),
    broadcastTarget: prevSettings.broadcastTarget || 'all',
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
  const adminToken = getAuthenticatedAdminFromCookie(req);
  const authenticatedCustomerPhone = getAuthenticatedCustomerFromCookie(req);
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

    // استخراج رقم العميل من كوكي الجلسة أو معرف المزامنة لإرسال الأكواد العامة أو المخصصة له فقط
    const queryCustPhone = (req.query && String(req.query.clientId || '').startsWith('cust_'))
      ? normalizePhoneServer(String(req.query.clientId).slice(5))
      : '';
    const promoCustPhone = authenticatedCustomerPhone || (isValidEgyptianPhoneServer(queryCustPhone) ? queryCustPhone : '');
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

  const filteredCaptains = isAuthenticatedAdmin
    ? (canAdmViewCaptains ? allMappedCaptains : [])
    : (authenticatedCaptainPhone
        ? allMappedCaptains.filter(c => normalizePhoneServer(c.phone) === authenticatedCaptainPhone)
        : []);

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

  let filteredOrders = [];
  if (isAuthenticatedAdmin) {
    filteredOrders = canAdmViewOrders ? raw.orders : [];
  } else {
    const seenIds = new Set();
    raw.orders.forEach(o => {
      const ownerPh = normalizePhoneServer(o.clientPhone || o.customerPhone);
      const isCustOwner = Boolean(authenticatedCustomerPhone && ownerPh === authenticatedCustomerPhone);
      const isAssignedCap = Boolean(authenticatedCaptainPhone && normalizePhoneServer(o.assignedCourierPhone) === authenticatedCaptainPhone);
      const isWaitingRadar = Boolean(authenticatedCaptainPhone && o.status === 'في انتظار كابتن');

      if (isCustOwner) {
        if (!seenIds.has(o.id)) {
          seenIds.add(o.id);
          filteredOrders.push(o);
        }
      } else if (isAssignedCap || isWaitingRadar) {
        if (!seenIds.has(o.id)) {
          seenIds.add(o.id);
          const isFinished = o.status === 'مكتمل' || o.status === 'قيد مراجعة الاعتراض' || String(o.status || '').includes('ملغي');
          const hidePhonesForCap = isWaitingRadar || isFinished;
          filteredOrders.push(hidePhonesForCap ? {
            ...o,
            customerPhone: '',
            clientPhone: '',
            senderPhone: '',
            recipientPhone: ''
          } : o);
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
      supabaseAnonKey: SUPABASE_ANON_KEY || ''
    },
    adminAccounts: canViewAuditAndAdmins ? raw.adminAccounts : (isAuthenticatedAdmin && verifiedAdminAccount ? [verifiedAdminAccount] : []),
    auditLogs: canViewAuditAndAdmins ? raw.auditLogs : [],
    authenticatedAdminUsername: verifiedAdminAccount ? verifiedAdminAccount.username : null
  };
}

// ==========================================
// 4. محرك إشعارات الموبايل (Web Push Notifications) + رادار الأدمن اللحظي
// ==========================================
async function sendPushNotificationToPhone(phone, payloadObj) {
  if (!phone) return;
  try {
    const { data: subRow } = await supabase.from('push_subscriptions').select('subscription').eq('phone', phone).maybeSingle();
    if (!subRow || !subRow.subscription) return;
    await webpush.sendNotification(subRow.subscription, JSON.stringify({
      title: payloadObj.title || 'الرجل العنابي 🛵',
      body: payloadObj.body || 'تحديث جديد في طلبك!',
      url: payloadObj.url || '/'
    }));
  } catch (err) {
    if (err.statusCode === 410 || err.statusCode === 404) {
      await supabase.from('push_subscriptions').delete().eq('phone', phone);
    }
  }
}

async function notifyAdminsPush(category = 'platform', payloadObj = {}) {
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
      .like('phone', 'admin:%');

    if (!adminSubs || adminSubs.length === 0) return;

    const targetSubs = adminSubs.filter(sub => {
      const rawPhoneKey = String(sub.phone || '');
      const parts = rawPhoneKey.split(':');
      const uname = String(parts[1] || '').trim().toLowerCase();
      return uname && allowedAdminUsers.has(uname);
    });

    if (targetSubs.length === 0) return;

    const payloadStr = JSON.stringify({
      title: payloadObj.title || '🔔 رادار غرفة العمليات 🛡️',
      body: payloadObj.body || 'حركة جديدة على منصة الرجل العنابي',
      url: payloadObj.url || '/admin'
    });

    const expiredKeys = [];
    await Promise.allSettled(
      targetSubs.map(async (subRow) => {
        if (!subRow || !subRow.subscription) return;
        try {
          await webpush.sendNotification(subRow.subscription, payloadStr);
        } catch (err) {
          if (err.statusCode === 410 || err.statusCode === 404) {
            expiredKeys.push(subRow.phone);
          }
        }
      })
    );

    if (expiredKeys.length > 0) {
      await supabase.from('push_subscriptions').delete().in('phone', expiredKeys);
    }
  } catch (e) {
    console.warn('Admin push notify warning:', e.message);
  }
}

async function broadcastPushToAvailableCaptains(payloadObj) {
  try {
    const { data: availCaptains } = await supabase
      .from('captains')
      .select('phone')
      .eq('status', 'معتمد')
      .eq('is_available', true);

    if (!availCaptains || availCaptains.length === 0) return;
    const phones = availCaptains.map(c => c.phone);
    const { data: subs } = await supabase.from('push_subscriptions').select('phone, subscription').in('phone', phones);
    if (!subs || subs.length === 0) return;

    const payloadStr = JSON.stringify({
      title: payloadObj.title || 'الرجل العنابي 🛵',
      body: payloadObj.body || 'أوردر جديد متاح على الرادار الآن!',
      url: '/'
    });

    await Promise.allSettled(subs.map(s => webpush.sendNotification(s.subscription, payloadStr)));
  } catch (e) {}
}

async function broadcastPushByTargetGroup(target = 'all', payloadObj = {}) {
  try {
    const { data: allSubs } = await supabase.from('push_subscriptions').select('phone, subscription');
    if (!allSubs || allSubs.length === 0) return 0;

    const publicSubs = allSubs.filter(s => !String(s.phone || '').startsWith('admin:'));

    let targetSubs = publicSubs;
    if (target === 'captains' || target === 'customers') {
      const { data: captainsRows } = await supabase.from('captains').select('phone');
      const captainPhones = new Set((captainsRows || []).map(c => String(c.phone).trim()));
      if (target === 'captains') {
        targetSubs = publicSubs.filter(s => captainPhones.has(String(s.phone).trim()));
      } else if (target === 'customers') {
        targetSubs = publicSubs.filter(s => !captainPhones.has(String(s.phone).trim()));
      }
    }

    const payloadStr = JSON.stringify({
      title: payloadObj.title || 'الرجل العنابي 🛵',
      body: payloadObj.body || '',
      url: payloadObj.url || '/'
    });

    let sent = 0;
    await Promise.allSettled(
      targetSubs.map(async s => {
        if (!s || !s.subscription) return;
        await webpush.sendNotification(s.subscription, payloadStr);
        sent++;
      })
    );
    return sent;
  } catch (e) {
    return 0;
  }
}

// [NEW-SEC-04] التحقق من ملكية الرقم أو جلسة الأدمن قبل ربط إشعارات Web Push
app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { phone, subscription } = req.body || {};
    if (!phone || !subscription) {
      return res.status(400).json({ success: false });
    }
    let cleanKey = String(phone).trim();

    if (cleanKey.startsWith('admin:')) {
      const adminToken = getAuthenticatedAdminFromCookie(req);
      if (!adminToken || !adminToken.username) {
        return res.status(401).json({ success: false, message: 'يرجى تسجيل دخول المسؤول أولاً 🔒' });
      }
      const { data: adminRow } = await supabase
        .from('admins')
        .select('*')
        .eq('username', adminToken.username)
        .maybeSingle();

      if (!adminRow || adminRow.status === 'معطل') {
        return res.status(403).json({ success: false, message: 'حساب المسؤول غير نشط ⛔' });
      }
      if (!adminRow.is_master && !(adminRow.permissions && adminRow.permissions.receiveAdminPush)) {
        return res.status(403).json({ success: false, message: 'ليس لديك صلاحية استقبال إشعارات الرادار ⛔' });
      }
      const parts = cleanKey.split(':');
      const deviceSuffix = parts[2] ? String(parts[2]).trim() : 'default';
      cleanKey = `admin:${String(adminRow.username).trim().toLowerCase()}:${deviceSuffix}`;
    } else {
      cleanKey = normalizePhoneServer(cleanKey);
      if (!isValidEgyptianPhoneServer(cleanKey)) {
        return res.status(400).json({ success: false, message: 'رقم الهاتف غير صالح ⚠️' });
      }
      const custPhone = getAuthenticatedCustomerFromCookie(req);
      const capPhone = getAuthenticatedCaptainFromCookie(req);
      if (cleanKey !== custPhone && cleanKey !== capPhone) {
        const { data: pendingCap } = await supabase.from('captains').select('status').eq('phone', cleanKey).maybeSingle();
        if (!pendingCap || pendingCap.status !== 'قيد المراجعة') {
          return res.status(403).json({ success: false, message: 'غير مصرح بربط الإشعارات لهذا الرقم 🔒' });
        }
      }
    }

    await supabase.from('push_subscriptions').upsert([{
      phone: cleanKey,
      subscription,
      updated_at: new Date().toISOString()
    }]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false });
  }
});

app.post('/api/analytics/install', async (req, res) => {
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
});

app.post('/api/presence/ping', (req, res) => {
  touchCustomerPresence(req, req.body && req.body.clientId);
  res.json({ success: true, onlineCustomersCount: getOnlineCustomersCount() });
});

// ==========================================
// 5. مسار المزامنة الرئيسي (Bootstrap) والتحقق من الكوبونات
// ==========================================
app.get('/api/bootstrap', async (req, res) => {
  try {
    const state = await buildClientState(req, false);
    res.json({ success: true, state });
  } catch (err) {
    console.error('Bootstrap error:', err.message);
    res.status(500).json({ success: false, message: 'تعذر جلب البيانات' });
  }
});

app.post('/api/promo-codes/validate', async (req, res) => {
  try {
    const { code, clientPhone } = req.body || {};
    const cleanCode = String(code || '').trim().toUpperCase();
    const cleanPhone = normalizePhoneServer(clientPhone);

    if (!cleanCode) {
      return res.status(400).json({ success: false, message: 'اكتب كود الخصم الأول يا باشا! 🎟️⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
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
});

// ==========================================
// 6. حماية التخمين (Rate Limiter) والمصادقة والصلاحيات
// ==========================================
async function checkRateLimit(phone) {
  const { data: attempt } = await supabase.from('login_attempts').select('*').eq('phone', phone).maybeSingle();
  if (attempt && attempt.locked_until && new Date(attempt.locked_until) > new Date()) {
    return { locked: true, message: 'حسابك مقفول مؤقتاً بسبب محاولات متكررة. جرب كمان 15 دقيقة 🔒' };
  }
  return { locked: false, attemptData: attempt };
}

async function recordFailedAttempt(phone, attemptData) {
  const attempts = (attemptData?.attempts || 0) + 1;
  const updates = {
    attempts,
    locked_until: attempts >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null
  };
  await supabase.from('login_attempts').upsert({ phone, ...updates });
}

async function clearFailedAttempts(phone) {
  await supabase.from('login_attempts').delete().eq('phone', phone);
}

async function authenticateCaptain(req, res, next) {
  const token = req.cookies.captain_session;
  if (!token) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { data: captain } = await supabase.from('captains').select('*').eq('phone', decoded.phone).maybeSingle();
    if (!captain || (captain.session_version && decoded.session_version && captain.session_version !== decoded.session_version)) {
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
      .eq('username', decoded.username)
      .maybeSingle();

    if (!admin) {
      res.clearCookie('admin_session');
      return res.status(401).json({ success: false, message: 'حساب المسؤول غير موجود 🔒' });
    }

    if (admin.status === 'معطل') {
      res.clearCookie('admin_session');
      return res.status(403).json({ success: false, message: 'تم تعطيل حساب المسؤول من الإدارة ⛔' });
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
// 7. مسارات مصادقة وتسجيل العملاء والكباتن والأدمن
// ==========================================

app.post('/api/auth/admin/login', async (req, res) => {
  try {
    const rawUser = req.body.username || req.body.user || req.body.phone || '';
    const rawPass = req.body.password || req.body.pass || '';
    const username = String(rawUser).trim();
    const password = String(rawPass).trim();

    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال اسم المستخدم وكلمة المرور ⚠️' });
    }

    let { data: admin } = await supabase.from('admins').select('*').eq('username', username).maybeSingle();

    if (!admin) {
      // [FIX-03] لا يتم الإنشاء من .env إلا إذا لم يكن هناك أي حساب أدمن رئيسي مسجل في القاعدة إطلاقاً
      const { data: existingMaster } = await supabase.from('admins').select('*').eq('is_master', true).maybeSingle();
      const envUser = (process.env.INITIAL_ADMIN_USER || 'ennaby1').trim();
      const envPass = (process.env.INITIAL_ADMIN_PASS || '01023024988').trim();

      if (!existingMaster && username.toLowerCase() === envUser.toLowerCase() && password === envPass) {
        const hashed = await bcrypt.hash(String(envPass), 10);
        const { data: createdMaster } = await supabase.from('admins').insert([{
          username: envUser,
          name: 'الأدمن الرئيسي',
          password_hash: hashed,
          is_master: true,
          status: 'نشط',
          permissions: {}
        }]).select().maybeSingle();
        admin = createdMaster;
      } else {
        return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
      }
    } else {
      if (admin.status === 'معطل') {
        return res.status(403).json({ success: false, message: 'حساب المسؤول معطل من الإدارة ⛔' });
      }
      const valid = await bcrypt.compare(String(password), admin.password_hash || '');
      if (!valid) {
        return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
      }
    }

    const token = jwt.sign({ username: admin.username, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('admin_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    req.cookies = { ...req.cookies, admin_session: token };

    req.query = { ...req.query, role: 'admin' };
    invalidateStateCache();
    const state = await buildClientState(req, true);
    state.authenticatedAdminUsername = admin.username;

    res.json({
      success: true,
      message: `أهلاً بك يا ${admin.name || 'باشا'} في غرفة العمليات المركزية 🛡️`,
      admin: {
        username: admin.username,
        name: admin.name || 'الأدمن الرئيسي',
        isMaster: Boolean(admin.is_master),
        status: admin.status || 'نشط',
        permissions: admin.permissions || {}
      },
      state
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ في السيرفر أثناء تسجيل الدخول ⚠️' });
  }
});

app.post('/api/auth/customer/login', async (req, res) => {
  try {
    const { phone: rawPhone, pin } = req.body || {};
    const phone = normalizePhoneServer(rawPhone);
    const cleanPin = String(pin || '')
      .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
      .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
      .trim();

    if (!isValidEgyptianPhoneServer(phone) || !/^[0-9]{4}$/.test(cleanPin)) {
      return res.status(400).json({ success: false, message: 'بيانات الهاتف أو رمز الـ PIN غير صحيحة ⚠️' });
    }

    const rateLimit = await checkRateLimit(phone);
    if (rateLimit.locked) return res.status(403).json({ success: false, message: rateLimit.message });

    let { data: user } = await supabase.from('customers').select('*').eq('phone', phone).maybeSingle();

    if (!user) {
      const hashedPin = await bcrypt.hash(cleanPin, 10);
      const { data: createdUser, error: insErr } = await supabase.from('customers').upsert([{
        phone,
        pin_hash: hashedPin,
        wallet_balance: 0,
        points: 0,
        wallet_transactions: []
      }], { onConflict: 'phone' }).select().single();

      if (insErr || !createdUser) {
        return res.status(400).json({ success: false, message: 'تعذر فتح الحساب حالياً، حاول مرة أخرى ⚠️' });
      }
      user = createdUser;
      await recordAnalyticsMetricEvent('customers', 1);
    } else {
      const valid = await bcrypt.compare(cleanPin, String(user.pin_hash || ''));
      if (!valid) {
        await recordFailedAttempt(phone, rateLimit.attemptData);
        return res.status(401).json({ success: false, message: 'رمز الـ PIN السري غير صحيح! تأكد من الـ 4 أرقام يا باشا 🔒⚠️' });
      }
    }

    await clearFailedAttempts(phone);
    touchCustomerPresence(req, `cust_${phone}`);
    invalidateStateCache();
    const token = jwt.sign({ phone: user.phone, role: 'customer' }, JWT_SECRET, { expiresIn: '90d' });
    res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 90 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
    req.cookies = { ...req.cookies, customer_session: token };
    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تم استرجاع حسابك وتفعيل جلستك الدائمة بنجاح يا باشا 👑', state });
  } catch (err) {
    console.error('Customer login error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول، جرب مرة أخرى ⚠️' });
  }
});

app.post('/api/captains/register', async (req, res) => {
  try {
    const {
      phone: rawPhone, password, fullName: rawFullName, nationalId: rawNationalId, primaryZone,
      vehicleType, plateNumber: rawPlateNumber, idFrontPhoto, idBackPhoto,
      vehiclePhoto, referredByPhone
    } = req.body || {};

    const phone = normalizePhoneServer(rawPhone);
    const fullName = String(rawFullName || '').trim();
    const nationalId = String(rawNationalId || '')
      .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
      .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776))
      .trim();
    const plateNumber = String(rawPlateNumber || '').trim();

    if (!isValidEgyptianPhoneServer(phone) || !password || String(password).trim().length < 4 || !fullName || !nationalId || !vehicleType) {
      return res.status(400).json({ success: false, message: 'برجاء استكمال جميع البيانات الإجبارية وكلمة مرور صالحة ⚠️' });
    }
    if (fullName.split(/\s+/).length < 3) {
      return res.status(400).json({ success: false, message: 'برجاء كتابة الاسم ثلاثي كاملاً كما في البطاقة ⚠️' });
    }
    if (!/^[0-9]{14}$/.test(nationalId)) {
      return res.status(400).json({ success: false, message: 'الرقم القومي يجب أن يتكون من 14 رقماً بالضبط ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
    const { data: existing } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();

    if (!existing && rawState.settings.allowCaptainRegistration === false) {
      return res.status(403).json({ success: false, message: 'باب تسجيل الكباتن الجدد مغلق حالياً لاكتمال العدد 🛵' });
    }
    if (!existing && (!idFrontPhoto || !idBackPhoto)) {
      return res.status(400).json({ success: false, message: 'لازم ترفع صورة وش وضهر البطاقة الشخصية يا بطل ⚠️' });
    }
    if (vehicleType !== 'دراجة' && (!plateNumber || (!existing && !vehiclePhoto))) {
      return res.status(400).json({ success: false, message: 'لازم تكتب نمرة المركبة وترفع صورتها واضحة ⚠️' });
    }

    const hashedPassword = await bcrypt.hash(String(password), 10);

    const [uploadedFrontUrl, uploadedBackUrl, uploadedVehicleUrl] = await Promise.all([
      idFrontPhoto ? uploadCaptainDocToStorage(phone, 'idFront', idFrontPhoto) : Promise.resolve(null),
      idBackPhoto ? uploadCaptainDocToStorage(phone, 'idBack', idBackPhoto) : Promise.resolve(null),
      vehiclePhoto ? uploadCaptainDocToStorage(phone, 'vehicle', vehiclePhoto) : Promise.resolve(null)
    ]);

    if (existing) {
      if (existing.status !== 'مرفوض') {
        return res.status(400).json({ success: false, message: 'رقم الهاتف مسجل مسبقاً ⚠️' });
      }
      const { error: updErr } = await supabase.from('captains').update({
        password_hash: hashedPassword,
        full_name: fullName,
        national_id: nationalId,
        primary_zone: primaryZone || 'المنصورة',
        vehicle_type: vehicleType,
        plate_number: plateNumber || 'بدون لوحة',
        id_front_photo: uploadedFrontUrl || existing.id_front_photo,
        id_back_photo: uploadedBackUrl || existing.id_back_photo,
        vehicle_photo: uploadedVehicleUrl || existing.vehicle_photo,
        status: 'قيد المراجعة',
        suspend_reason: null,
        reject_reason: null,
        is_available: false
      }).eq('phone', phone);

      if (updErr) {
        return res.status(400).json({ success: false, message: 'تعذر تحديث المستندات، حاول مرة أخرى ⚠️' });
      }
      notifyAdminsPush('captain', {
        title: '📄 إعادة رفع مستندات كابتن',
        body: `قام الكابتن ${fullName} (${phone}) بتحديث مستنداته وينتظر المراجعة الآن.`
      });
      invalidateStateCache();
      const state = await buildClientState(req, true);
      return res.json({ success: true, message: 'تم إعادة إرسال مستنداتك للمراجعة بنجاح ⏳', state });
    }

    let validReferrer = null;
    const cleanRefPhone = normalizePhoneServer(referredByPhone);
    if (rawState.settings.referralRewardActive !== false && cleanRefPhone && cleanRefPhone !== phone) {
      const { data: refCap } = await supabase.from('captains').select('phone').eq('phone', cleanRefPhone).maybeSingle();
      if (refCap) validReferrer = refCap.phone;
    }

    const { error } = await supabase.from('captains').insert([{
      phone,
      password_hash: hashedPassword,
      full_name: fullName,
      national_id: nationalId,
      primary_zone: primaryZone || 'المنصورة',
      vehicle_type: vehicleType,
      plate_number: plateNumber || 'بدون لوحة',
      id_front_photo: uploadedFrontUrl || null,
      id_back_photo: uploadedBackUrl || null,
      vehicle_photo: uploadedVehicleUrl || null,
      status: 'قيد المراجعة',
      is_available: false,
      wallet_balance: 0.00,
      points: 0,
      referred_by_phone: validReferrer,
      referral_reward_claimed: false,
      referrals_count: 0,
      wallet_transactions: [],
      admin_notices: [],
      session_version: 1
    }]);

    if (error) {
      console.error('Captain Registration Error:', error.message);
      return res.status(400).json({ success: false, message: 'فشل إتمام التسجيل.. تأكد من صحة البيانات المدخلة' });
    }

    await recordAnalyticsMetricEvent('captains', 1);
    notifyAdminsPush('captain', {
      title: '🛵 تسجيل كابتن جديد للمراجعة!',
      body: `الكابتن: ${fullName} (${phone}) — المركبة: ${vehicleType} — المنطقة: ${primaryZone || 'المنصورة'}`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تم إرسال طلبك بنجاح وسيتم مراجعته من الإدارة قريباً ⏳', state });
  } catch (err) {
    console.error('Registration exception:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ في السيرفر أثناء التسجيل ⚠️' });
  }
});

app.post('/api/auth/captain/login', async (req, res) => {
  const { phone: rawPhone, password } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const rateLimit = await checkRateLimit(phone);
  if (rateLimit.locked) return res.status(403).json({ success: false, message: rateLimit.message });

  const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
  if (!cap) return res.status(401).json({ success: false, message: 'رقم الهاتف غير مسجل كابتن ⚠️' });

  const valid = await bcrypt.compare(String(password || ''), cap.password_hash);
  if (!valid) {
    await recordFailedAttempt(phone, rateLimit.attemptData);
    return res.status(401).json({ success: false, message: 'كلمة المرور غير صحيحة ⚠️' });
  }

  await clearFailedAttempts(phone);

  if (cap.status === 'مرفوض') {
    const raw = await fetchRawDatabaseState(false);
    return res.status(403).json({
      success: false,
      status: 'مرفوض',
      rejectReason: cap.suspend_reason || cap.reject_reason || 'يرجى رفع صور واضحة للمستندات',
      captainProfile: mapCaptainRow(cap, false, {}, raw.orders, raw.settings),
      message: 'تم رفض المستندات، يمكنك إعادة رفع صور واضحة الآن 📄⚠️'
    });
  }

  const token = jwt.sign({ phone: cap.phone, role: 'captain', session_version: cap.session_version || 1 }, JWT_SECRET, { expiresIn: '14d' });
  res.cookie('captain_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 14 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  req.cookies = { ...req.cookies, captain_session: token };
  const state = await buildClientState(req, false);
  res.json({ success: true, message: 'منور الميدان يا بطل 🛵', state });
});

app.post('/api/auth/captain/logout', (req, res) => {
  res.clearCookie('captain_session');
  res.json({ success: true });
});

app.post('/api/auth/admin/logout', (req, res) => {
  res.clearCookie('admin_session');
  res.json({ success: true });
});

// ==========================================
// 8. مسارات إنشاء وإدارة الطلبات (العميل والكابتن)
// ==========================================
app.post('/api/orders', async (req, res) => {
  let activeLockKey = null;
  let clientOrderLockKey = null;
  try {
    const {
      clientPhone: rawClientPhone, pin, tripType, pickupZone, pickupAddress,
      dropoffZone, dropoffAddress, customerNotes, packageType,
      payer, senderPhone: rawSenderPhone, recipientPhone: rawRecipientPhone,
      pickupLat, pickupLng, dropoffLat, dropoffLng, promoCode
    } = req.body || {};

    const clientPhone = normalizePhoneServer(rawClientPhone);
    const senderPhone = normalizePhoneServer(rawSenderPhone || clientPhone);
    const recipientPhone = normalizePhoneServer(rawRecipientPhone || '');

    if (!isValidEgyptianPhoneServer(clientPhone) || !pickupAddress || !dropoffAddress) {
      return res.status(400).json({ success: false, message: 'برجاء استكمال كافة بيانات وعناوين الطلب ورقم الهاتف بشكل صحيح ⚠️' });
    }
    if (!isValidEgyptianPhoneServer(senderPhone) || !isValidEgyptianPhoneServer(recipientPhone)) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال أرقام هواتف مصرية صحيحة للراسل والمستلم 📱⚠️' });
    }

    clientOrderLockKey = `client_order_lock:${clientPhone}`;
    if (promoRedeemLocks.has(clientOrderLockKey)) {
      return res.status(429).json({ success: false, message: 'جاري تسجيل طلبك الحالي يا باشا، انتظر لحظة واحدة ⏳' });
    }
    promoRedeemLocks.add(clientOrderLockKey);

    const rawState = await fetchRawDatabaseState(true);
    if (rawState.settings.maintenanceMode) {
      return res.status(403).json({ success: false, message: 'المنصة في وضع الصيانة الطارئة حالياً 🛠️' });
    }

    const sessionCustPhone = normalizePhoneServer(getAuthenticatedCustomerFromCookie(req));
    const isSessionTrustedForPhone = Boolean(sessionCustPhone && sessionCustPhone === clientPhone);
    const cleanPin = String(pin || '').trim();

    let { data: cust } = await supabase.from('customers').select('*').eq('phone', clientPhone).maybeSingle();
    if (!cust) {
      if (!/^[0-9]{4}$/.test(cleanPin)) {
        return res.status(400).json({
          success: false,
          needPin: true,
          message: 'برجاء كتابة رمز PIN سري (4 أرقام) لمرة واحدة فقط لتأمين حسابك في أول طلب 🔒⚠️'
        });
      }
      const hashedPin = await bcrypt.hash(cleanPin, 10);
      const { data: createdCust } = await supabase.from('customers').insert([{
        phone: clientPhone,
        pin_hash: hashedPin,
        wallet_balance: 0,
        points: 0,
        wallet_transactions: []
      }]).select().single();
      cust = createdCust;

      await recordAnalyticsMetricEvent('customers', 1);
      notifyAdminsPush('customer', {
        title: '👑 تسجيل عميل جديد!',
        body: `عميل جديد انضم للمنصة مع أول طلب برقم: ${clientPhone}`
      });
    } else if (!isSessionTrustedForPhone) {
      if (!/^[0-9]{4}$/.test(cleanPin)) {
        return res.status(401).json({
          success: false,
          needPin: true,
          message: 'يرجى إدخال رمز الـ PIN السري (4 أرقام) لمرة واحدة لتفعيل جلستك على هذا الجهاز 🔒⚠️'
        });
      }
      const pinOk = await bcrypt.compare(cleanPin, cust.pin_hash);
      if (!pinOk) {
        return res.status(401).json({
          success: false,
          needPin: true,
          message: 'رمز الـ PIN غير مطابق لحسابك المسجل! (يمكنك استرجاعه من تبويب حسابي) 🔒⚠️'
        });
      }
    }

    touchCustomerPresence(req, `cust_${clientPhone}`);
    const custToken = jwt.sign({ phone: clientPhone, role: 'customer' }, JWT_SECRET, { expiresIn: '90d' });
    res.cookie('customer_session', custToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 90 * 24 * 60 * 60 * 1000,
      sameSite: 'lax'
    });
    req.cookies = { ...req.cookies, customer_session: custToken };

    const routeKey = `${pickupZone}|${dropoffZone}`;
    if (rawState.pricing[routeKey] === undefined) {
      return res.status(400).json({ success: false, message: 'مسار المناطق المحدد غير مدعوم حالياً في التسعير ⚠️' });
    }
    const baseRouteFare = roundMoney(rawState.pricing[routeKey]);

    const surgeInfo = getActiveSurgeInfo(rawState.settings);
    const originalFare = surgeInfo.isActive
      ? roundMoney(baseRouteFare * (1 + surgeInfo.surgePercent / 100))
      : baseRouteFare;

    const basePlatformFee = roundMoney(rawState.settings.platformFee ?? 7);
    const platformFee = surgeInfo.isActive
      ? roundMoney(basePlatformFee * (1 + surgeInfo.surgePercent / 100))
      : basePlatformFee;

    const availableWallet = Math.max(0, roundMoney(cust.wallet_balance || 0));
    const walletDiscount = availableWallet > 0 ? roundMoney(Math.min(availableWallet, originalFare)) : 0;

    let promoDiscount = 0;
    let appliedPromoCode = null;
    let updatedPromoListToSave = null;
    const cleanPromo = String(promoCode || '').trim().toUpperCase();

    if (cleanPromo) {
      activeLockKey = `${cleanPromo}:${clientPhone}`;
      if (promoRedeemLocks.has(activeLockKey)) {
        return res.status(429).json({ success: false, message: 'جاري معالجة طلبك بالكود حالياً، انتظر لحظة يا باشا ⏳' });
      }
      promoRedeemLocks.add(activeLockKey);

      const freshRawState = await fetchRawDatabaseState(true);
      const promoList = Array.isArray(freshRawState.settings.promoCodes)
        ? freshRawState.settings.promoCodes.map(normalizePromoCodeObject).filter(Boolean)
        : [];
      const promoIdx = promoList.findIndex(p => p && p.code === cleanPromo && p.active !== false);

      // [FIX-07] إرجاع رسالة خطأ صريحة عند إرسال كود خصم غير صحيح بدلاً من تجاهله بصمت
      if (promoIdx === -1) {
        promoRedeemLocks.delete(activeLockKey);
        activeLockKey = null;
        return res.status(400).json({ success: false, message: 'كود الخصم المدخل غير صحيح أو انتهت صلاحيته يا باشا 🎟️⚠️' });
      }

      const promoObj = promoList[promoIdx];
      const notExpired = !promoObj.expiresAt || Date.now() <= Number(promoObj.expiresAt);
      const matchesTarget = !promoObj.targetPhone || promoObj.targetPhone === 'all' || normalizePhoneServer(promoObj.targetPhone) === clientPhone;
      const maxUses = getPromoMaxUsesForPhone(promoObj);
      const currentUses = getPromoPhoneUsedCount(promoObj, clientPhone);

      if (!notExpired) {
        promoRedeemLocks.delete(activeLockKey);
        activeLockKey = null;
        return res.status(400).json({ success: false, message: 'انتهت صلاحية كود الخصم المحدد ⏳⚠️' });
      }
      if (!matchesTarget) {
        promoRedeemLocks.delete(activeLockKey);
        activeLockKey = null;
        return res.status(403).json({ success: false, message: 'كود الخصم هذا مخصص لرقم عميل آخر 🔒⚠️' });
      }
      if (currentUses >= maxUses) {
        promoRedeemLocks.delete(activeLockKey);
        activeLockKey = null;
        return res.status(400).json({
          success: false,
          message: maxUses > 1
            ? `لقد استهلكت جميع مرات الاستخدام المسموح بها لهذا الكود (${maxUses} مرات) ⚠️`
            : 'لقد استخدمت كود الخصم هذا من قبل ⚠️'
        });
      }

      const remainingFareAfterWallet = Math.max(0, roundMoney(originalFare - walletDiscount));
      promoDiscount = roundMoney(Math.min(roundMoney(promoObj.discountAmount || 0), remainingFareAfterWallet));
      if (promoDiscount > 0) {
        appliedPromoCode = promoObj.code;
        const nextUses = currentUses + 1;
        const nextUsageCounts = { ...(promoObj.usageCounts || {}), [clientPhone]: nextUses };
        const nextUsedBy = Object.keys(nextUsageCounts).filter(ph => nextUsageCounts[ph] >= maxUses);
        promoList[promoIdx] = {
          ...promoObj,
          usageCounts: nextUsageCounts,
          usedBy: nextUsedBy
        };
        updatedPromoListToSave = { rawState: freshRawState, promoList };
      }
    }

    const discountApplied = roundMoney(walletDiscount + promoDiscount);
    const finalFare = Math.max(0, roundMoney(originalFare - discountApplied));
    const courierNet = Math.max(0, roundMoney(originalFare - platformFee));

    const existingIds = new Set((rawState.orders || []).map(o => o.id));
    let orderId = `#ORD-${Math.floor(1000 + Math.random() * 9000)}`;
    while (existingIds.has(orderId)) {
      orderId = `#ORD-${Math.floor(10000 + Math.random() * 90000)}`;
    }

    const storedNotesWithMeta = encodeOrderMetaIntoNotes(customerNotes || '', {
      pickupLat,
      pickupLng,
      dropoffLat,
      dropoffLng,
      promoCode: appliedPromoCode,
      promoDiscount,
      walletDiscount,
      surgePercent: surgeInfo.surgePercent
    });

    const { error: ordErr } = await supabase.from('orders').insert([{
      id: orderId,
      customer_phone: clientPhone,
      client_phone: clientPhone,
      trip_type: tripType === 'fetch' ? 'fetch' : 'send',
      pickup_zone: pickupZone,
      pickup_address: pickupAddress,
      dropoff_zone: dropoffZone,
      dropoff_address: dropoffAddress,
      customer_notes: storedNotesWithMeta,
      package_type: packageType || DEFAULT_PACKAGE_TYPES[0],
      payer: payer || 'الراسل',
      sender_phone: senderPhone,
      recipient_phone: recipientPhone,
      original_fare: originalFare,
      discount_applied: discountApplied,
      fare: finalFare,
      platform_fee: platformFee,
      courier_net: courierNet,
      status: 'في انتظار كابتن',
      fee_deducted: false,
      fee_refunded: false
    }]);

    if (ordErr) {
      if (activeLockKey) {
        promoRedeemLocks.delete(activeLockKey);
        activeLockKey = null;
      }
      return res.status(400).json({ success: false, message: 'تعذر تسجيل الطلب، حاول مرة أخرى ⚠️' });
    }

    if (walletDiscount > 0) {
      await supabase.rpc('adjust_customer_wallet_atomic', {
        p_phone: clientPhone,
        p_amount: -Math.abs(walletDiscount),
        p_reason: `خصم رصيد محفظة على طلب ${orderId}`
      });
    }

    if (updatedPromoListToSave) {
      await saveIncentivesToDatabase(updatedPromoListToSave.rawState, {
        promoCodes: updatedPromoListToSave.promoList
      });
    }

    if (activeLockKey) {
      promoRedeemLocks.delete(activeLockKey);
      activeLockKey = null;
    }

    invalidateStateCache();
    broadcastPushToAvailableCaptains({
      title: 'أوردر جديد على الرادار يانجم! 📡🛵',
      body: `طلب (${orderId}) من ${pickupZone} إلى ${dropoffZone} - الأجرة: ${originalFare} ج.. الحق اقبله قبل ما يطير! 🚀`
    });

    notifyAdminsPush('customer', {
      title: `🚀 طلب جديد على الرادار (${orderId})`,
      body: `العميل (${clientPhone}) طلب (${tripType === 'fetch' ? 'هاتلي' : 'طرد'}) من ${pickupZone} (${pickupAddress}) إلى ${dropoffZone} (${dropoffAddress}) — الكاش: ${finalFare} ج`
    });

    const state = await buildClientState(req, true);
    res.json({
      success: true,
      message: appliedPromoCode
        ? `تم إرسال طلبك بنجاح وتطبيق كود الخصم (${appliedPromoCode}) يا باشا! 🚀🎁`
        : 'تم إرسال طلبك بنجاح 🚀',
      state
    });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تأكيد الطلب ⚠️' });
  } finally {
    if (activeLockKey) promoRedeemLocks.delete(activeLockKey);
    if (clientOrderLockKey) promoRedeemLocks.delete(clientOrderLockKey);
  }
});

app.post('/api/orders/:id/accept', authenticateCaptain, async (req, res) => {
  const cap = req.user;
  const acceptLockKey = `cap_accept_lock:${cap.phone}`;
  if (promoRedeemLocks.has(acceptLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ طلب القبول حالياً يا بطل، انتظر لحظة ⏳' });
  }
  promoRedeemLocks.add(acceptLockKey);

  try {
    const { data: freshCap } = await supabase.from('captains').select('*').eq('phone', cap.phone).maybeSingle();
    if (!freshCap || !freshCap.is_available || freshCap.status !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك غير مصرح له بقبول الطلبات حالياً ⛔' });
    }

    const { data: activeOrders } = await supabase.from('orders')
      .select('id')
      .eq('assigned_courier_phone', freshCap.phone)
      .in('status', ACTIVE_COURIER_ORDER_STATUSES);

    if (activeOrders && activeOrders.length > 0) {
      return res.status(400).json({ success: false, message: 'معاك مشوار جاري بالفعل يا بطل، خلصه الأول 🛵⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
    const tierData = computeCaptainTierAndFee(freshCap, rawState.orders, rawState.settings);
    const fee = tierData.effectiveFee;

    if (roundMoney(freshCap.wallet_balance || 0) < fee) {
      return res.status(400).json({
        success: false,
        message: `رصيد محفظتك (${roundMoney(freshCap.wallet_balance)} ج) أقل من عمولة الطلب (${fee} ج). اشحن محفظتك أولاً 💸⚠️`
      });
    }

    const { data: targetOrder } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
    if (!targetOrder || targetOrder.status !== 'في انتظار كابتن') {
      return res.status(400).json({ success: false, message: 'عفواً.. الأوردر راح لكابتن تاني قبلك 🏃‍♂️' });
    }

    const courierNet = Math.max(0, roundMoney(Number(targetOrder.original_fare || targetOrder.fare) - fee));

    const { data: accepted, error } = await supabase.from('orders')
      .update({
        status: 'تم قبول الطلب',
        assigned_courier_phone: freshCap.phone,
        platform_fee: fee,
        courier_net: courierNet,
        fee_deducted: fee > 0,
        fee_refunded: false
      })
      .eq('id', req.params.id)
      .eq('status', 'في انتظار كابتن')
      .select();

    if (error || !accepted || !accepted.length) {
      return res.status(400).json({ success: false, message: 'عفواً.. الأوردر راح لكابتن تاني قبلك 🏃‍♂️' });
    }

    if (fee > 0) {
      await supabase.rpc('adjust_captain_wallet_atomic', {
        p_phone: freshCap.phone,
        p_amount: -Math.abs(fee),
        p_reason: `عمولة منصة (${tierData.tierBadgeText}) لطلب ${req.params.id}`
      });
    }

    const discount = roundMoney(targetOrder.discount_applied || 0);
    if (discount > 0) {
      await supabase.rpc('adjust_captain_wallet_atomic', {
        p_phone: freshCap.phone,
        p_amount: discount,
        p_reason: `تعويض خصم/كوبون عميل لطلب ${req.params.id}`
      });
    }

    invalidateStateCache();
    sendPushNotificationToPhone(targetOrder.customer_phone || targetOrder.client_phone, {
      title: 'تم قبول طلبك يا باشا! 🛵✅',
      body: `الكابتن ${freshCap.full_name} (${tierData.tierBadgeText}) لقط الأوردر (${req.params.id}) وطاير عليك فوراً! 🚀`
    });

    notifyAdminsPush('captain', {
      title: `✅ قبول طلب (${req.params.id})`,
      body: `الكابتن ${freshCap.full_name} (${freshCap.phone}) قبل الطلب من ${targetOrder.pickup_zone} إلى ${targetOrder.dropoff_zone} (العمولة: ${fee} ج)`
    });

    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تم قبول الطلب.. توكل على الله 🛵', state });
  } finally {
    promoRedeemLocks.delete(acceptLockKey);
  }
});

// [FIX-05 & NEW-LOGIC-01] فرض التسلسل الصارم لحالات خط سير الطلب والتأكد من أنه نشط وغير ملغي
app.post('/api/orders/:id/advance', authenticateCaptain, async (req, res) => {
  const { nextStatus } = req.body || {};
  const requiredPrevStatus = REQUIRED_PREV_STATUS_FOR_ADVANCE[nextStatus];
  if (!requiredPrevStatus) {
    return res.status(400).json({ success: false, message: 'حالة التحديث غير صالحة ⚠️' });
  }

  const { data, error } = await supabase.from('orders')
    .update({ status: nextStatus })
    .eq('id', req.params.id)
    .eq('assigned_courier_phone', req.user.phone)
    .eq('status', requiredPrevStatus)
    .select();

  if (error || !data || !data.length) {
    return res.status(400).json({ success: false, message: 'تعذر تحديث الحالة (يرجى الالتزام بتسلسل خط السير أو التأكد من أن الطلب نشط) ⚠️' });
  }

  invalidateStateCache();
  const order = data[0];
  let funnyBody = nextStatus;
  if (nextStatus === 'الكابتن وصل للاستلام') funnyBody = 'الكابتن وصل مكان الاستلام وبيستلم المصلحة أهو! 🛵📍';
  else if (nextStatus === 'استلم الطرد وفي السكة') funnyBody = 'الكابتن استلم الأوردر يانجم العالم وطاير بيه في السكة ليك! 🚀💨';
  else if (nextStatus === 'الكابتن وصل للتسليم') funnyBody = 'الكابتن وصل بالسلامة تحت الباب وجاهز للتسليم.. افتح يا باشا! 🔔😎';

  sendPushNotificationToPhone(order.customer_phone || order.client_phone, {
    title: `تحديث في طلبك ${order.id} 🛵`,
    body: funnyBody
  });

  notifyAdminsPush('captain', {
    title: `📍 تحديث خط سير (${order.id})`,
    body: `الكابتن ${req.user.full_name} (${req.user.phone}) حدّث الحالة إلى: ${nextStatus}`
  });

  const state = await buildClientState(req, true);
  res.json({ success: true, message: `تم التحديث: ${nextStatus} 🛵✅`, state });
});

// [FIX-05 & NEW-LOGIC-01] التأكد من وصول الكابتن لمرحلة «الكابتن وصل للتسليم» قبل إتمام الطلب
app.post('/api/orders/:id/complete', authenticateCaptain, async (req, res) => {
  const cap = req.user;
  const rawBefore = await fetchRawDatabaseState(false);
  const oldTierData = computeCaptainTierAndFee(cap, rawBefore.orders, rawBefore.settings);

  const { data, error } = await supabase.from('orders')
    .update({ status: 'مكتمل' })
    .eq('id', req.params.id)
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
      let newCustPts = Number(cust.points || 0) + Number(s.customerPointsPerOrder || 5);
      const custTarget = Number(s.customerRewardThreshold || 100);
      const custCash = roundMoney(s.customerRewardCash || 10);
      if (newCustPts >= custTarget) {
        newCustPts -= custTarget;
        await supabase.rpc('adjust_customer_wallet_atomic', {
          p_phone: custPhone,
          p_amount: custCash,
          p_reason: 'مكافأة نقاط عنابي بوينتس 🍇🎁'
        });
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
    let newCapPts = Number(freshCap.points || 0) + Number(s.courierPointsPerOrder || 5);
    const capTarget = Number(s.courierRewardThreshold || 100);
    const capCash = roundMoney(s.courierRewardCash || 10);
    if (newCapPts >= capTarget) {
      newCapPts -= capTarget;
      await supabase.rpc('adjust_captain_wallet_atomic', {
        p_phone: cap.phone,
        p_amount: capCash,
        p_reason: 'مكافأة نقاط عنابي بوينتس للكباتن 🍇🛵'
      });
      sendPushNotificationToPhone(cap.phone, {
        title: 'عاش يا وحش الميدان! 🍇💸',
        body: `قفلت تارجت نقاط عنابي بوينتس ونزلك ${capCash} جنيه كاش فوري في محفظتك هدية! 🛵🔥`
      });
    }

    const newTierData = computeCaptainTierAndFee(freshCap, rawState.orders, s);
    const capNotices = Array.isArray(freshCap.admin_notices) ? freshCap.admin_notices : [];

    if (newTierData.tier !== oldTierData.tier && (newTierData.tier === 'platinum' || newTierData.tier === 'diamond')) {
      const upgradeMsg = newTierData.tier === 'diamond'
        ? `💎 وسّع للكابتن الماسي! مبروك يا بطل، حافظت على مستواك ووصلت لـ (${newTierData.tierBadgeText}) وعمولتك نزلت بخصم ${newTierData.tierDiscount} جنيه على كل أوردر! 🚀🔥`
        : `🥈 عاش يا نجم الطيارين! كملت تارجت الـ ${newTierData.weeklyTarget} طلب في ${newTierData.tierDaysWindow} أيام واترقيت لـ (${newTierData.tierBadgeText}) وعمولتك بقت مخفضة بـ ${newTierData.tierDiscount} جنيه! حافظ على مستواك عشان توصل للماسي 💎🛵`;

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

    const referralActive = s.referralRewardActive !== false;
    const referralRewardAmt = Math.max(0, roundMoney(s.referralRewardAmount ?? 50));
    const requiredReferralTrips = Math.max(1, Number(s.referralRequiredOrders ?? 2));
    const tripsTextAr = formatArabicTripsText(requiredReferralTrips);

    let claimReferralNow = false;
    if (referralActive && referralRewardAmt > 0 && freshCap.referred_by_phone && !freshCap.referral_reward_claimed) {
      const { count } = await supabase.from('orders')
        .select('id', { count: 'exact', head: true })
        .eq('assigned_courier_phone', cap.phone)
        .eq('status', 'مكتمل');

      if ((count || 0) >= requiredReferralTrips) {
        claimReferralNow = true;
      }
    }

    await supabase.from('captains').update({
      points: newCapPts,
      admin_notices: capNotices.slice(0, 10),
      referral_reward_claimed: freshCap.referral_reward_claimed || claimReferralNow
    }).eq('phone', cap.phone);

    if (claimReferralNow && freshCap.referred_by_phone) {
      const { data: refCaptain } = await supabase.from('captains').select('*').eq('phone', freshCap.referred_by_phone).maybeSingle();
      if (refCaptain) {
        await supabase.rpc('adjust_captain_wallet_atomic', {
          p_phone: refCaptain.phone,
          p_amount: referralRewardAmt,
          p_reason: `هدية دعوة الكابتن ${freshCap.full_name} بعد إتمام ${tripsTextAr} 🎁`
        });

        const refNotices = Array.isArray(refCaptain.admin_notices) ? refCaptain.admin_notices : [];
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
});

app.post('/api/orders/:id/release', authenticateCaptain, async (req, res) => {
  const reason = String(req.body?.reason || '').trim();
  if (!reason) {
    return res.status(400).json({ success: false, message: 'برجاء كتابة سبب الاعتذار وإلغاء الاستلام أولاً ⚠️' });
  }

  const { data: releasedRows, error } = await supabase.from('orders')
    .update({
      status: 'في انتظار كابتن',
      assigned_courier_phone: null,
      fee_refunded: true,
      admin_resolution_note: `اعتذار الكابتن (${req.user.full_name}): ${reason}`
    })
    .eq('id', req.params.id)
    .eq('assigned_courier_phone', req.user.phone)
    .in('status', ['تم قبول الطلب', 'الكابتن وصل للاستلام'])
    .select();

  const order = releasedRows && releasedRows[0];
  if (error || !order) {
    return res.status(400).json({ success: false, message: 'لا يمكن التنازل عن الطلب بعد استلام الطرد فعلياً ⚠️' });
  }

  if (order.fee_deducted && order.platform_fee > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: req.user.phone,
      p_amount: roundMoney(order.platform_fee),
      p_reason: `رد عمولة للاعتذار عن طلب ${order.id}`
    });
  }

  if (order.discount_applied > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: req.user.phone,
      p_amount: -Math.abs(roundMoney(order.discount_applied)),
      p_reason: `استرداد فرق خصم للاعتذار عن طلب ${order.id}`
    });
  }

  await logAdminAudit(
    'اعتذار كابتن عن طلب',
    order.id,
    `اعتذر الكابتن ${req.user.full_name} (${req.user.phone}) وعاد الطلب للرادار — السبب: ${reason}`,
    req.user.full_name
  );

  notifyAdminsPush('captain', {
    title: `🔄 اعتذار كابتن عن طلب (${order.id})`,
    body: `اعتذر الكابتن ${req.user.full_name} (${req.user.phone}) وعاد الطلب للرادار — السبب: ${reason}`
  });

  const custPhone = order.customer_phone || order.client_phone;
  if (custPhone) {
    sendPushNotificationToPhone(custPhone, {
      title: `تحديث بخصوص طلبك (${order.id}) 🔄`,
      body: `اعتذر الكابتن عن استلام الطلب (${reason})، وتمت إعادة طلبك للرادار فوراً لاختيار كابتن آخر 🛵`
    });
  }

  broadcastPushToAvailableCaptains({
    title: 'أوردر عاد للرادار الآن! 📡🛵',
    body: `طلب (${order.id}) من ${order.pickup_zone} إلى ${order.dropoff_zone} متاح الآن على الرادار.. الحق اقبله! 🚀`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تسجيل اعتذارك وإبلاغ الإدارة وإعادة الطلب للرادار 🔄', state });
});

app.post('/api/captain/availability', authenticateCaptain, async (req, res) => {
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
});

app.post('/api/captain/notices/:noticeId/dismiss', authenticateCaptain, async (req, res) => {
  const notices = Array.isArray(req.user.admin_notices) ? req.user.admin_notices : [];
  const filtered = notices.filter(n => String(n.id) !== String(req.params.noticeId));
  await supabase.from('captains').update({ admin_notices: filtered }).eq('phone', req.user.phone);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// [FIX-06 & NEW-SEC-03] التحقق الصارم من ملكية العميل للطلب عبر كوكي الجلسة قبل الإلغاء
app.post('/api/orders/:id/cancel', async (req, res) => {
  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing || !['في انتظار كابتن', 'تم قبول الطلب'].includes(existing.status)) {
    return res.status(400).json({ success: false, message: 'لا يمكن الإلغاء.. الطلب قيد التنفيذ ⚠️' });
  }

  if (!verifyCustomerOrderOwnership(req, existing)) {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بإلغاء هذا الطلب 🔒⚠️' });
  }

  const { data: updated, error } = await supabase.from('orders')
    .update({ status: 'ملغي من العميل', fee_refunded: true })
    .eq('id', req.params.id)
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
    await supabase.rpc('adjust_customer_wallet_atomic', {
      p_phone: custPhone,
      p_amount: roundMoney(refundWalletAmt),
      p_reason: `استرداد خصم محفظة لطلب ملغي ${order.id}`
    });
  }

  if (meta.promoCode && custPhone) {
    await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
  }

  if (order.assigned_courier_phone) {
    if (order.fee_deducted && order.platform_fee > 0) {
      await supabase.rpc('adjust_captain_wallet_atomic', {
        p_phone: order.assigned_courier_phone,
        p_amount: roundMoney(order.platform_fee),
        p_reason: `رد عمولة لطلب ملغي من العميل ${order.id}`
      });
    }
    if (order.discount_applied > 0) {
      await supabase.rpc('adjust_captain_wallet_atomic', {
        p_phone: order.assigned_courier_phone,
        p_amount: -Math.abs(roundMoney(order.discount_applied)),
        p_reason: `إلغاء تعويض خصم لطلب ملغي ${order.id}`
      });
    }
    sendPushNotificationToPhone(order.assigned_courier_phone, {
      title: `تم إلغاء الطلب ${order.id} ❌`,
      body: 'قام العميل بإلغاء الطلب وتم رد العمولة لمحفظتك فوراً ولا يهمك يا بطل 🛵💪'
    });
  }

  notifyAdminsPush('customer', {
    title: `❌ إلغاء طلب من العميل (${order.id})`,
    body: `ألغى العميل (${custPhone}) الطلب من ${order.pickup_zone} إلى ${order.dropoff_zone}`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم الإلغاء ورصيدك وكودك محفوظين يا نجم ✅', state });
});

// [FIX-06 & NEW-SEC-03] التحقق من ملكية العميل للطلب واكتماله قبل التقييم
app.post('/api/orders/:id/rate', async (req, res) => {
  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing) {
    return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });
  }
  if (!verifyCustomerOrderOwnership(req, existing)) {
    return res.status(403).json({ success: false, message: 'غير مصرح لك بتقييم هذا الطلب 🔒⚠️' });
  }
  if (existing.status !== 'مكتمل') {
    return res.status(400).json({ success: false, message: 'لا يمكن تقييم الطلب قبل اكتمال التسليم ⚠️' });
  }
  if (existing.rating !== null && existing.rating !== undefined) {
    return res.status(400).json({ success: false, message: 'تم تقييم هذا المشوار مسبقاً يا باشا ⭐' });
  }

  const rating = Math.min(5, Math.max(1, Number(req.body.rating) || 5));
  await supabase.from('orders').update({ rating }).eq('id', req.params.id);
  notifyAdminsPush('customer', {
    title: `⭐ تقييم جديد للطلب (${req.params.id})`,
    body: `قام العميل بتقييم الكابتن بـ ${rating} نجوم.`
  });
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// [FIX-06 & NEW-SEC-03] التحقق من ملكية العميل للطلب واكتماله قبل تقديم اعتراض
app.post('/api/orders/:id/dispute', async (req, res) => {
  const reason = String(req.body.reason || '').trim();
  if (!reason) return res.status(400).json({ success: false, message: 'اكتب سبب الاعتراض ⚠️' });

  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing) {
    return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });
  }
  if (!verifyCustomerOrderOwnership(req, existing)) {
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
  }).eq('id', req.params.id);

  notifyAdminsPush('customer', {
    title: `⚠️ اعتراض وشكوى على طلب (${req.params.id})`,
    body: `سجّل العميل اعتراضاً: "${reason}" — يرجى المراجعة من غرفة العمليات.`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// ==========================================
// 9. مسارات غرفة العمليات المركزية (Admin) مع التحقق الصارم من الصلاحيات
// ==========================================
app.post('/api/admin/settings', authenticateAdmin, async (req, res) => {
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

  if (body.platformFee !== undefined && !requireAdminPerm(req, res, ['manageCommissions'])) return;

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
      body.tierDiamondDiscount !== undefined) &&
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
    (Array.isArray(body.packageTypes) || body.surgeAction !== undefined) &&
    !requireAdminPerm(req, res, ['managePricing', 'manageSettings'])
  ) {
    return;
  }

  if (
    (body.broadcastMessage !== undefined ||
      body.broadcastTarget !== undefined ||
      body.supportWhatsapp !== undefined ||
      body.waitingTimeoutMinutes !== undefined ||
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

  if (body.platformFee !== undefined) updates.platform_fee = roundMoney(body.platformFee);
  if (body.broadcastMessage !== undefined) updates.broadcast_message = String(body.broadcastMessage);
  if (body.supportWhatsapp !== undefined) updates.support_whatsapp = String(body.supportWhatsapp).trim();
  if (body.waitingTimeoutMinutes !== undefined) updates.waiting_timeout_minutes = Number(body.waitingTimeoutMinutes);
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
    if (dbCol) updates[dbCol] = Number(body.loyaltyField.value);
  }

  const partialIncentives = {};
  if (body.welcomeBonusActive !== undefined) partialIncentives.welcomeBonusActive = Boolean(body.welcomeBonusActive);
  if (body.welcomeBonusAmount !== undefined) partialIncentives.welcomeBonusAmount = Math.max(0, roundMoney(body.welcomeBonusAmount));
  if (body.referralRewardActive !== undefined) partialIncentives.referralRewardActive = Boolean(body.referralRewardActive);
  if (body.referralRewardAmount !== undefined) partialIncentives.referralRewardAmount = Math.max(0, roundMoney(body.referralRewardAmount));
  if (body.referralRequiredOrders !== undefined) partialIncentives.referralRequiredOrders = Math.max(1, Number(body.referralRequiredOrders));
  if (body.broadcastTarget !== undefined) partialIncentives.broadcastTarget = String(body.broadcastTarget).trim();

  if (body.adminPushMasterEnabled !== undefined) partialIncentives.adminPushMasterEnabled = Boolean(body.adminPushMasterEnabled);
  if (body.adminPushCustomersEnabled !== undefined) partialIncentives.adminPushCustomersEnabled = Boolean(body.adminPushCustomersEnabled);
  if (body.adminPushCaptainsEnabled !== undefined) partialIncentives.adminPushCaptainsEnabled = Boolean(body.adminPushCaptainsEnabled);

  if (body.tierWeeklyOrdersTarget !== undefined) {
    partialIncentives.tierWeeklyOrdersTarget = Math.max(1, Number(body.tierWeeklyOrdersTarget));
  }
  const effDaysWin = body.tierDaysWindow !== undefined
    ? Math.max(1, Number(body.tierDaysWindow))
    : Math.max(1, Number(prevSettings.tierDaysWindow ?? 7));

  if (body.tierDaysWindow !== undefined) {
    partialIncentives.tierDaysWindow = effDaysWin;
  }
  if (body.tierConsecutiveDaysForDiamond !== undefined) {
    const consDays = Math.max(effDaysWin, Number(body.tierConsecutiveDaysForDiamond));
    partialIncentives.tierConsecutiveDaysForDiamond = consDays;
    partialIncentives.tierWeeksForDiamond = Math.max(1, Math.ceil(consDays / effDaysWin));
  } else if (body.tierWeeksForDiamond !== undefined) {
    const wks = Math.max(1, Number(body.tierWeeksForDiamond));
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
    } else {
      curOverrides[body.tierManualOverride.phone] = tVal;
    }
    partialIncentives.tierManualOverrides = curOverrides;
  }

  if (body.surgeAction === 'start') {
    const pct = Math.max(1, Number(body.surgePercent ?? 20));
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

  const customBasePricing = (body.pricing && typeof body.pricing === 'object') ? body.pricing : null;
  const updatedIncentives = await saveIncentivesToDatabase(rawState, partialIncentives, updates, customBasePricing);

  let auditDetails = 'تعديل في إعدادات التشغيل أو التسعير';
  if (body.surgeAction === 'start') {
    auditDetails = `تفعيل وقت الذروة (+${partialIncentives.surgePercent}%) لمدة ${partialIncentives.surgeDurationMinutes} دقيقة`;
  } else if (body.surgeAction === 'stop') {
    auditDetails = 'إيقاف وقت الذروة والعودة للتسعير الطبيعي';
  } else if (isChangingPushSwitches) {
    auditDetails = `تحديث مفاتيح إشعارات Push الأدمن (العام: ${updatedIncentives.adminPushMasterEnabled ? 'مفعل' : 'متوقف'} | العملاء: ${updatedIncentives.adminPushCustomersEnabled ? 'مفعل' : 'متوقف'} | الكباتن: ${updatedIncentives.adminPushCaptainsEnabled ? 'مفعل' : 'متوقف'})`;
  } else if (body.tierWeeklyOrdersTarget !== undefined || body.tierPlatinumDiscount !== undefined || body.tierDaysWindow !== undefined) {
    auditDetails = `تحديث مستويات الكباتن (${updatedIncentives.tierWeeklyOrdersTarget} طلب خلال ${updatedIncentives.tierDaysWindow} يوم - الماسي ${updatedIncentives.tierConsecutiveDaysForDiamond} يوم - خصم بلاتيني ${updatedIncentives.tierPlatinumDiscount}ج - ماسي ${updatedIncentives.tierDiamondDiscount}ج)`;
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
});

app.post('/api/admin/promo-codes', authenticateAdmin, async (req, res) => {
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
});

app.post('/api/admin/promo-codes/delete', authenticateAdmin, async (req, res) => {
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
});

app.post('/api/admin/wallets/captain-topup', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!phone || amt <= 0) return res.status(400).json({ success: false });

  await supabase.rpc('adjust_captain_wallet_atomic', {
    p_phone: phone,
    p_amount: amt,
    p_reason: 'شحن رصيد من الإدارة ⚡'
  });

  const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', phone).maybeSingle();
  if (cap) {
    const notices = Array.isArray(cap.admin_notices) ? cap.admin_notices : [];
    notices.unshift({
      id: 'topup-' + Date.now(),
      text: `⚡ تم شحن محفظتك بمبلغ ${amt} جنيه من الإدارة بنجاح.. طير في الميدان يا بطل! 🛵`,
      type: 'reward',
      at: Date.now()
    });
    await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);
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
});

app.post('/api/admin/wallets/captain-deduct', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount, reason } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!phone || amt <= 0 || !reason) return res.status(400).json({ success: false });

  await supabase.rpc('adjust_captain_wallet_atomic', {
    p_phone: phone,
    p_amount: -Math.abs(amt),
    p_reason: `خصم إداري: ${reason}`
  });

  const { data: cap } = await supabase.from('captains').select('full_name, admin_notices').eq('phone', phone).maybeSingle();
  if (cap) {
    const notices = Array.isArray(cap.admin_notices) ? cap.admin_notices : [];
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
});

app.post('/api/admin/wallets/customer-compensate', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets'])) return;
  const { phone: rawPhone, amount, reason } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const amt = roundMoney(amount);
  if (!isValidEgyptianPhoneServer(phone) || amt <= 0) return res.status(400).json({ success: false });

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

  await supabase.rpc('adjust_customer_wallet_atomic', {
    p_phone: phone,
    p_amount: amt,
    p_reason: reason ? `هدية وتعويض: ${reason}` : 'رصيد هدية من إدارة العنابي 🎁'
  });

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
});

app.post('/api/admin/captains/custom-fee', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageCommissions'])) return;
  const { phone: rawPhone, customFee, reason, reset } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  const updates = reset
    ? { custom_fee: null, custom_fee_reason: null }
    : { custom_fee: roundMoney(customFee), custom_fee_reason: reason || 'تخصيص من الإدارة' };

  await supabase.from('captains').update(updates).eq('phone', phone);
  await logAdminAudit('عمولة خاصة', phone, reset ? 'إرجاع للعمولة العامة/المستويات' : `تحديد عمولة ${customFee} ج`, req.admin.name);

  if (!reset) {
    sendPushNotificationToPhone(phone, {
      title: 'تحديث عمولتك الخاصة 🎯🛵',
      body: `الإدارة خصصت لك عمولة (${roundMoney(customFee)} ج) — السبب: ${reason || 'تقديراً لمجهودك يا بطل!'}`
    });
  }

  notifyAdminsPush('platform', {
    title: `🎯 تحديث عمولة كابتن (${phone})`,
    body: `${reset ? 'إرجاع الكابتن للعمولة العامة/المستويات' : `تخصيص عمولة ${customFee} ج — ${reason || ''}`} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/:phone/status', authenticateAdmin, async (req, res) => {
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

  if (status === 'معتمد') {
    const rawState = await fetchRawDatabaseState(false);
    const s = rawState.settings || {};
    const welcomeActive = s.welcomeBonusActive !== false;
    const welcomeBonus = Math.max(0, roundMoney(s.welcomeBonusAmount ?? 7));

    const txList = Array.isArray(currentCap.wallet_transactions) ? currentCap.wallet_transactions : [];
    const notices = Array.isArray(currentCap.admin_notices) ? currentCap.admin_notices : [];

    if (welcomeActive && welcomeBonus > 0) {
      const alreadyReceivedWelcome = txList.some(t => t && String(t.title || '').includes('هدية التسجيل'));

      if (!alreadyReceivedWelcome) {
        await supabase.rpc('adjust_captain_wallet_atomic', {
          p_phone: phone,
          p_amount: welcomeBonus,
          p_reason: `هدية التسجيل الترحيبية (${welcomeBonus} ج) 🎁`
        });
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

  await logAdminAudit('حالة كابتن', phone, `تغيير الحالة إلى ${status}${reason ? ' - السبب: ' + reason : ''}`, req.admin.name);
  notifyAdminsPush('platform', {
    title: `🛵 تحديث حالة كابتن (${status})`,
    body: `الكابتن ${currentCap.full_name} (${phone}) أصبح: ${status}${reason ? ' — السبب: ' + reason : ''} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/reset-password', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageCaptains'])) return;
  const { phone: rawPhone, newPass } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  if (!phone || !newPass || String(newPass).length < 4) {
    return res.status(400).json({ success: false, message: 'كلمة المرور قصيرة جداً ⚠️' });
  }
  const { data: cap } = await supabase.from('captains').select('full_name, session_version').eq('phone', phone).maybeSingle();
  if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

  const hashed = await bcrypt.hash(String(newPass), 10);
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
});

app.post('/api/admin/customers/reset-pin', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageWallets', 'manageSettings'])) return;
  const { phone: rawPhone, newPin } = req.body || {};
  const phone = normalizePhoneServer(rawPhone);
  if (!isValidEgyptianPhoneServer(phone) || !/^[0-9]{4}$/.test(String(newPin || '').trim())) {
    return res.status(400).json({ success: false, message: 'رقم الهاتف أو رمز الـ PIN (4 أرقام) غير صالح ⚠️' });
  }
  const hashedPin = await bcrypt.hash(String(newPin).trim(), 10);
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
});

// [FIX-04] منع تكرار عداد الطلبات المكتملة ومعالجة الاسترداد المالي الإداري بدقة
app.post('/api/admin/orders/:id/manage', authenticateAdmin, async (req, res) => {
  if (!requireAdminPerm(req, res, ['manageOrders'])) return;
  const { action, reason } = req.body || {};
  const orderId = req.params.id;
  const manageLockKey = `admin_order_manage:${orderId}`;
  if (promoRedeemLocks.has(manageLockKey)) {
    return res.status(429).json({ success: false, message: 'جاري تنفيذ إجراء إداري على هذا الطلب حالياً ⏳' });
  }
  promoRedeemLocks.add(manageLockKey);

  try {
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود' });

    const isAlreadyCancelled = String(order.status || '').includes('ملغي');
    if ((action === 'cancel' || action === 'resolve_cancel' || action === 'radar') && isAlreadyCancelled) {
      return res.status(400).json({ success: false, message: 'الطلب ملغي بالفعل مسبقاً ⚠️' });
    }
    if (action === 'radar' && order.status === 'في انتظار كابتن') {
      return res.status(400).json({ success: false, message: 'الطلب موجود على الرادار بالفعل ⚠️' });
    }

    const custPhone = order.customer_phone || order.client_phone;
    const meta = decodeOrderMetaFromNotes(order.customer_notes || '');

    if (action === 'radar') {
      if (order.assigned_courier_phone) {
        if (order.fee_deducted && !order.fee_refunded && order.platform_fee > 0) {
          await supabase.rpc('adjust_captain_wallet_atomic', {
            p_phone: order.assigned_courier_phone,
            p_amount: roundMoney(order.platform_fee),
            p_reason: `رد عمولة لإعادة طلب ${order.id} للرادار إدارياً`
          });
        }
        if (order.discount_applied > 0 && !order.fee_refunded) {
          await supabase.rpc('adjust_captain_wallet_atomic', {
            p_phone: order.assigned_courier_phone,
            p_amount: -Math.abs(roundMoney(order.discount_applied)),
            p_reason: `استرداد تعويض خصم لإعادة طلب ${order.id} للرادار`
          });
        }
      }
      await supabase.from('orders').update({
        status: 'في انتظار كابتن',
        assigned_courier_phone: null,
        fee_refunded: true,
        admin_resolution_note: reason ? `إعادة للرادار: ${reason}` : null
      }).eq('id', orderId);
    } else if (action === 'resolve_cancel' || (action === 'cancel' && order.status === 'قيد مراجعة الاعتراض')) {
      // إلغاء إداري بعد شكوى العميل (الكابتن بالفعل سلّم المشوار وقبض الحساب من العميل، فلا تُرد عمولة المنصة للكابتن أبداً، ويمكن للإدارة تعويض العميل يدوياً من قسم المحافظ)
      await supabase.from('orders').update({
        status: 'تمت التسوية الإدارية',
        fee_refunded: false,
        admin_resolution_note: reason || 'شكوتك تمت مراجعتها من قبل الادارة وجارى التحقيق مع الطرف الآخر '
      }).eq('id', orderId);
    } else if (action === 'cancel') {
      // إلغاء إداري لطلب جارٍ قبل التسليم
      const refundWalletAmt = meta.walletDiscount > 0
        ? meta.walletDiscount
        : Math.max(0, roundMoney((order.discount_applied || 0) - (meta.promoDiscount || 0)));

      if (refundWalletAmt > 0 && custPhone) {
        await supabase.rpc('adjust_customer_wallet_atomic', {
          p_phone: custPhone,
          p_amount: roundMoney(refundWalletAmt),
          p_reason: `رد خصم لطلب ملغي إدارياً ${order.id}`
        });
      }
      if (meta.promoCode && custPhone && !isAlreadyCancelled) {
        await releasePromoCodeUsageForCancelledOrder(meta.promoCode, custPhone);
      }
      if (order.assigned_courier_phone && !order.fee_refunded) {
        if (order.fee_deducted && order.platform_fee > 0) {
          await supabase.rpc('adjust_captain_wallet_atomic', {
            p_phone: order.assigned_courier_phone,
            p_amount: roundMoney(order.platform_fee),
            p_reason: `رد عمولة لطلب ملغي إدارياً قبل التسليم ${order.id}`
          });
        }
        if (order.discount_applied > 0) {
          await supabase.rpc('adjust_captain_wallet_atomic', {
            p_phone: order.assigned_courier_phone,
            p_amount: -Math.abs(roundMoney(order.discount_applied)),
            p_reason: `إلغاء تعويض خصم لطلب ملغي إدارياً ${order.id}`
          });
        }
      }
      await supabase.from('orders').update({
        status: 'ملغي إدارياً',
        fee_refunded: true,
        admin_resolution_note: reason || 'تم إلغاء الطلب بواسطة الإدارة'
      }).eq('id', orderId);
    } else if (action === 'resolve_complete') {
      const wasAlreadyCompletedBeforeDispute = (order.status === 'مكتمل' || order.status === 'قيد مراجعة الاعتراض');
      await supabase.from('orders').update({
        status: 'مكتمل',
        admin_resolution_note: 'تمت المراجعة واعتماد اكتمال الطلب بواسطة الإدارة ✅'
      }).eq('id', orderId);
      if (!wasAlreadyCompletedBeforeDispute) {
        await recordAnalyticsMetricEvent('completedOrders', 1);
      }
    }

    await logAdminAudit('تدخل في طلب', orderId, `الإجراء: ${action} ${reason ? '- ' + reason : ''}`, req.admin.name);
    notifyAdminsPush('platform', {
      title: `⚖️ تدخل إداري في طلب (${orderId})`,
      body: `الإجراء: ${action}${reason ? ' — السبب: ' + reason : ''} (بواسطة: ${req.admin.name})`
    });

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, state });
  } finally {
    promoRedeemLocks.delete(manageLockKey);
  }
});

// [FIX-03] إلزام التحقق من كلمة المرور الحالية عند تحديث بيانات الأدمن الرئيسي
app.post('/api/admin/accounts/master', authenticateAdmin, async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'هذا الإجراء مخصص للأدمن الرئيسي فقط 👑⛔' });
  }
  const { name, username, currentPassword, newPassword } = req.body || {};
  if (!currentPassword) {
    return res.status(400).json({ success: false, message: 'برجاء إدخال كلمة المرور الحالية للتأكيد ⚠️' });
  }

  const { data: master } = await supabase.from('admins').select('*').eq('is_master', true).limit(1).maybeSingle();

  if (master) {
    const valid = await bcrypt.compare(String(currentPassword), master.password_hash || '');
    if (!valid) {
      return res.status(401).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة ⚠️' });
    }
  }

  const updates = {
    name: name || (master ? master.name : 'الأدمن الرئيسي'),
    username: username || (master ? master.username : 'ennaby1')
  };
  if (newPassword) {
    updates.password_hash = await bcrypt.hash(String(newPassword), 10);
  }

  if (master) {
    await supabase.from('admins').update(updates).eq('username', master.username);
  } else {
    updates.password_hash = updates.password_hash || await bcrypt.hash(String(currentPassword), 10);
    updates.is_master = true;
    updates.status = 'نشط';
    await supabase.from('admins').insert([updates]);
  }

  const newToken = jwt.sign({ username: updates.username, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('admin_session', newToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000, sameSite: 'lax' });
  req.cookies = { ...req.cookies, admin_session: newToken };

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم حفظ وتحديث بيانات الأدمن الرئيسي ✅', state });
});

app.post('/api/admin/accounts/sub', authenticateAdmin, async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'إدارة حسابات وصلاحيات المسؤولين متاحة للأدمن الرئيسي فقط 👑⛔' });
  }
  const { origUsername, name, username, password, permissions } = req.body || {};
  const cleanName = String(name || '').trim();
  const cleanUser = String(username || '').trim();
  const cleanOrig = origUsername ? String(origUsername).trim() : '';

  if (!cleanName || !cleanUser) {
    return res.status(400).json({ success: false, message: 'الاسم واسم المستخدم مطلوبان ⚠️' });
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
  if (password) {
    updates.password_hash = await bcrypt.hash(String(password), 10);
  }

  if (cleanOrig) {
    const { error: updErr } = await supabase.from('admins').update(updates).eq('username', cleanOrig).eq('is_master', false);
    if (updErr) {
      return res.status(400).json({ success: false, message: 'تعذر تعديل المسؤول (تأكد من عدم تكرار اسم المستخدم) ⚠️' });
    }
  } else {
    if (!password) return res.status(400).json({ success: false, message: 'كلمة المرور مطلوبة للمسؤول الجديد ⚠️' });
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
});

app.post('/api/admin/accounts/:username/toggle', authenticateAdmin, async (req, res) => {
  if (!req.admin || !req.admin.is_master) {
    return res.status(403).json({ success: false, message: 'تغيير حالة المسؤولين متاح للأدمن الرئيسي فقط 👑⛔' });
  }
  const targetUser = req.params.username;
  const { data: acc } = await supabase.from('admins').select('status, is_master').eq('username', targetUser).maybeSingle();
  if (!acc || acc.is_master) return res.status(404).json({ success: false });

  const newStatus = acc.status === 'نشط' ? 'معطل' : 'نشط';
  await supabase.from('admins').update({ status: newStatus }).eq('username', targetUser);
  await logAdminAudit('حالة مسؤول', targetUser, `تغيير الحالة إلى ${newStatus}`, req.admin.name);
  notifyAdminsPush('platform', {
    title: `🛡️ تغيير حالة مسؤول (@${targetUser})`,
    body: `تم تغيير حالة المسؤول إلى: ${newStatus} (بواسطة: ${req.admin.name})`
  });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/push-broadcast', authenticateAdmin, async (req, res) => {
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
    const publicSubs = (allSubs || []).filter(s => !String(s.phone || '').startsWith('admin:'));
    if (publicSubs.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'لا توجد هواتف مشتركة في الإشعارات حالياً ⚠️'
      });
    }

    let targetSubs = publicSubs;
    if (target === 'captains' || target === 'customers') {
      const { data: captainsRows } = await supabase.from('captains').select('phone');
      const captainPhones = new Set((captainsRows || []).map(c => String(c.phone).trim()));
      if (target === 'captains') {
        targetSubs = publicSubs.filter(s => captainPhones.has(String(s.phone).trim()));
      } else if (target === 'customers') {
        targetSubs = publicSubs.filter(s => !captainPhones.has(String(s.phone).trim()));
      }
    }

    if (targetSubs.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'لا توجد هواتف مسجلة لهذه الفئة حالياً ⚠️'
      });
    }

    const payloadStr = JSON.stringify({
      title: cleanTitle,
      body: cleanBody,
      url: '/'
    });

    let sentCount = 0;
    const expiredPhones = [];

    await Promise.allSettled(
      targetSubs.map(async (subRow) => {
        if (!subRow || !subRow.subscription) return;
        try {
          await webpush.sendNotification(subRow.subscription, payloadStr);
          sentCount++;
        } catch (err) {
          if (err.statusCode === 410 || err.statusCode === 404) {
            expiredPhones.push(subRow.phone);
          }
        }
      })
    );

    if (expiredPhones.length > 0) {
      await supabase.from('push_subscriptions').delete().in('phone', expiredPhones);
    }

    const targetLabels = { all: 'الجميع', customers: 'العملاء', captains: 'الكباتن' };
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
      message: `تم إرسال الإشعار بنجاح إلى ${sentCount} هاتف 📲✅`,
      state
    });
  } catch (err) {
    console.error('Push broadcast error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إرسال الإشعارات ⚠️' });
  }
});

// ==========================================
// 10. المهام المجدولة (Vercel Cron) لتنظيف الطلبات المنتهية
// ==========================================
app.get('/api/cron/cleanup-orders', async (req, res) => {
  if (req.headers['x-vercel-cron'] !== '1' && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ success: false });
  }
  lastLazyCleanupRun = 0;
  const rawState = await fetchRawDatabaseState(false);
  const canceledCount = await runLazyExpiredOrdersCleanup(rawState.settings.waitingTimeoutMinutes);
  res.json({ success: true, canceled: canceledCount });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running securely on http://localhost:${PORT}`));
}
module.exports = app;