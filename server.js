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
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || process.env.SUPABASE_KEY || '';
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

// تقديم الملفات الثابتة وصفحات التطبيق بأولوية للمسارات المحددة (شاملاً مجلد private)
app.get('/', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));
app.get('/index.html', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));
app.get(['/admin', '/admins', '/admin.html', '/private/admin.html'], (req, res) => res.sendFile(resolveHtmlFilePath('admin.html')));
app.get(['/install', '/install.html'], (req, res) => res.sendFile(resolveHtmlFilePath('install.html')));

app.use(express.static(path.join(__dirname)));
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

// خريطة تتبع العملاء المتواجدين حالياً على المنصة (Presence Heartbeat)
const customerPresenceMap = new Map();
const PRESENCE_TTL_MS = 45000; // 45 ثانية

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

// دوال ترميز وفك ترميز إحداثيات الخريطة والكوبون داخل ملاحظات الطلب لضمان التوافق التام مع جدول orders
function encodeOrderMetaIntoNotes(rawNotes, meta = {}) {
  const cleanNotes = String(rawNotes || '').replace(/\s*\[META:[^\]]+\]/g, '').trim();
  const payload = {};
  if (Number.isFinite(Number(meta.pickupLat)) && Number.isFinite(Number(meta.pickupLng))) {
    payload.p = [Number(Number(meta.pickupLat).toFixed(6)), Number(Number(meta.pickupLng).toFixed(6))];
  }
  if (Number.isFinite(Number(meta.dropoffLat)) && Number.isFinite(Number(meta.dropoffLng))) {
    payload.d = [Number(Number(meta.dropoffLat).toFixed(6)), Number(Number(meta.dropoffLng).toFixed(6))];
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
  const match = raw.match(/\[META:(\{[^\]]+\})\]/);
  let meta = {};
  if (match && match[1]) {
    try { meta = JSON.parse(match[1]); } catch (e) {}
  }
  const cleanNotes = raw.replace(/\s*\[META:\{[^\]]+\}\]/g, '').trim();
  return {
    cleanNotes,
    pickupLat: Array.isArray(meta.p) ? Number(meta.p[0]) : null,
    pickupLng: Array.isArray(meta.p) ? Number(meta.p[1]) : null,
    dropoffLat: Array.isArray(meta.d) ? Number(meta.d[0]) : null,
    dropoffLng: Array.isArray(meta.d) ? Number(meta.d[1]) : null,
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

// حساب مستوى الكابتن (برونزي 🥉 / بلاتيني 🥈 / ماسي 💎) وعمولته الفعلية أوتوماتيكياً
function computeCaptainTierAndFee(captainRow, mappedOrders, settings) {
  const s = settings || {};
  const weeklyTarget = Math.max(1, Number(s.tierWeeklyOrdersTarget ?? 25));
  const diamondWeeksTarget = Math.max(1, Number(s.tierWeeksForDiamond ?? 4));
  const platDiscount = Math.max(0, roundMoney(s.tierPlatinumDiscount ?? 1));
  const diaDiscount = Math.max(0, roundMoney(s.tierDiamondDiscount ?? 2));

  const now = Date.now();
  const weekMs = 7 * 24 * 60 * 60 * 1000;

  const capCompletedOrders = (mappedOrders || []).filter(
    o => o.assignedCourierPhone === captainRow.phone && (o.status === 'مكتمل' || o.status === 'قيد مراجعة الاعتراض')
  );

  // حساب عدد الطلبات في الأسابيع المتتالية (الأسبوع الحالي = 0، الأسبوع الماضي = 1، وهكذا)
  const weeklyCounts = [];
  for (let w = 0; w < Math.max(diamondWeeksTarget + 1, 6); w++) {
    const startWindow = now - (w + 1) * weekMs;
    const endWindow = now - w * weekMs;
    const cnt = capCompletedOrders.filter(o => o.createdAt >= startWindow && o.createdAt <= endWindow).length;
    weeklyCounts.push(cnt);
  }

  const currentWeekOrders = weeklyCounts[0] || 0;
  let consecutiveQualifiedWeeks = 0;
  for (let w = 0; w < weeklyCounts.length; w++) {
    if (weeklyCounts[w] >= weeklyTarget) {
      consecutiveQualifiedWeeks++;
    } else {
      break;
    }
  }

  // تحديد المستوى الأوتوماتيكي بناءً على شروط المنصة
  let autoTier = 'bronze';
  if (currentWeekOrders >= weeklyTarget) {
    if (consecutiveQualifiedWeeks >= diamondWeeksTarget) {
      autoTier = 'diamond';
    } else {
      autoTier = 'platinum';
    }
  } else {
    autoTier = 'bronze';
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

  // حساب عمولة المنصة الفعلية (شاملة وقت الذروة إن وجد، ثم خصم المستوى أو العمولة الفردية)
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

  return {
    tier: finalTier,
    autoTier,
    isManualTier: ['bronze', 'platinum', 'diamond'].includes(manualTier),
    tierName: tierInfo.name,
    tierEmoji: tierInfo.emoji,
    tierBadgeText: tierInfo.badgeText,
    tierDiscount: tierInfo.discount,
    tierColor: tierInfo.color,
    weeklyCompletedOrders: currentWeekOrders,
    consecutiveQualifiedWeeks,
    weeklyTarget,
    diamondWeeksTarget,
    effectiveFee,
    surgedPlatformFee
  };
}

// تحويل مسار الصورة النسبي المخزن في قاعدة البيانات أو Storage إلى رابط عام كامل
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

// رفع صورة Base64 إلى Supabase Storage (captain-docs/captains) وإرجاع الرابط العام
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

async function ensureMasterAdminSeeded() {
  try {
    const initUser = (process.env.INITIAL_ADMIN_USER || 'ennaby1').trim();
    const initPass = (process.env.INITIAL_ADMIN_PASS || '01023024988').trim();
    const hashed = await bcrypt.hash(String(initPass), 10);

    const { data: existing } = await supabase.from('admins').select('*').eq('is_master', true).maybeSingle();

    if (!existing) {
      await supabase.from('admins').upsert([{
        username: initUser,
        name: 'الأدمن الرئيسي',
        password_hash: hashed,
        is_master: true,
        status: 'نشط',
        permissions: {}
      }]);
      console.log('✅ تم إنشاء حساب الأدمن الرئيسي لأول مرة بنجاح.');
    } else {
      await supabase.from('admins').update({
        username: initUser,
        password_hash: hashed,
        status: 'نشط'
      }).eq('is_master', true);
      console.log('🔄 تم تحديث ومزامنة بيانات الأدمن الرئيسي مع ملف .env بنجاح.');
    }
  } catch (err) {
    console.warn('Admin seed/sync warning:', err.message);
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
    // بيانات مستوى الكابتن والعمولة الديناميكية
    tier: tierData.tier,
    autoTier: tierData.autoTier,
    isManualTier: tierData.isManualTier,
    tierName: tierData.tierName,
    tierEmoji: tierData.tierEmoji,
    tierBadgeText: tierData.tierBadgeText,
    tierDiscount: tierData.tierDiscount,
    tierColor: tierData.tierColor,
    weeklyCompletedOrders: tierData.weeklyCompletedOrders,
    consecutiveQualifiedWeeks: tierData.consecutiveQualifiedWeeks,
    effectiveFee: tierData.effectiveFee
  };
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

// تنظيف تلقائي ذكي للطلبات التي تجاوزت المهلة كل دقيقتين بدون الحاجة لـ Vercel Pro Cron
async function runLazyExpiredOrdersCleanup(timeoutMinutes = 30) {
  const now = Date.now();
  if (now - lastLazyCleanupRun < 120000) return 0;
  lastLazyCleanupRun = now;

  try {
    const mins = Number(timeoutMinutes || process.env.WAITING_TIMEOUT_MINUTES || 30);
    if (mins <= 0) return 0;

    const cutoff = new Date(now - mins * 60000).toISOString();
    const { data: expired } = await supabase.from('orders')
      .update({ status: 'ملغي (تجاوز مهلة الانتظار)' })
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
      }
      invalidateStateCache();
      return expired.length;
    }
  } catch (e) {}
  return 0;
}

// فهرسة ملفات الكباتن الموجودة في Supabase Storage (captain-docs/captains) لضمان ظهورها دائماً
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

  const [settingsRes, customersRes, captainsRes, ordersRes, adminsRes, logsRes, storageFilesMap] = await Promise.all([
    supabase.from('settings').select('*').eq('id', 1).maybeSingle(),
    supabase.from('customers').select('*'),
    supabase.from('captains').select('*').order('created_at', { ascending: false }),
    supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(350),
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

  // إعدادات مستويات الكباتن (Captain Tiers)
  const tierWeeklyOrdersTarget = Math.max(1, Number(storedIncentives.tierWeeklyOrdersTarget ?? 25));
  const tierWeeksForDiamond = Math.max(1, Number(storedIncentives.tierWeeksForDiamond ?? 4));
  const tierPlatinumDiscount = Math.max(0, roundMoney(storedIncentives.tierPlatinumDiscount ?? 1));
  const tierDiamondDiscount = Math.max(0, roundMoney(storedIncentives.tierDiamondDiscount ?? 2));
  const tierManualOverrides = (storedIncentives.tierManualOverrides && typeof storedIncentives.tierManualOverrides === 'object')
    ? storedIncentives.tierManualOverrides
    : {};

  // إعدادات وقت الذروة (Surge Pricing)
  const surgePercent = Math.max(0, Number(storedIncentives.surgePercent ?? 0));
  const surgeEndTime = Math.max(0, Number(storedIncentives.surgeEndTime ?? 0));
  const surgeDurationMinutes = Math.max(1, Number(storedIncentives.surgeDurationMinutes ?? 30));

  // قائمة كوبونات الخصم الديناميكية (Promo Codes)
  const promoCodes = Array.isArray(storedIncentives.promoCodes) ? storedIncentives.promoCodes : [];

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
    tierWeeksForDiamond,
    tierPlatinumDiscount,
    tierDiamondDiscount,
    tierManualOverrides,
    surgePercent,
    surgeEndTime,
    surgeDurationMinutes,
    promoCodes,
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

  runLazyExpiredOrdersCleanup(settings.waitingTimeoutMinutes);

  const zones = Array.isArray(sRow.zones) && sRow.zones.length > 0 ? sRow.zones : DEFAULT_ZONES;
  const pricing = Object.keys(rawPricingObj).length > 0 ? rawPricingObj : { ...DEFAULT_PRICING };

  const customersMap = {};
  (customersRes.data || []).forEach(c => {
    customersMap[c.phone] = {
      walletBalance: roundMoney(c.wallet_balance ?? 0),
      points: Number(c.points ?? 0),
      walletTransactions: Array.isArray(c.wallet_transactions) ? c.wallet_transactions.slice(0, 30) : []
    };
  });

  const mappedOrders = (ordersRes.data || []).map(mapOrderRow);

  const rawData = {
    settings,
    storedIncentives,
    zones,
    pricing,
    customers: customersMap,
    rawCaptains: captainsRes.data || [],
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

// دالة مساعدة لحفظ الكائن __incentives داخل جدول settings بأمان تام
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
    tierWeeksForDiamond: Math.max(1, Number(prevSettings.tierWeeksForDiamond ?? 4)),
    tierPlatinumDiscount: Math.max(0, roundMoney(prevSettings.tierPlatinumDiscount ?? 1)),
    tierDiamondDiscount: Math.max(0, roundMoney(prevSettings.tierDiamondDiscount ?? 2)),
    tierManualOverrides: prevSettings.tierManualOverrides || {},
    surgePercent: Math.max(0, Number(prevSettings.surgePercent ?? 0)),
    surgeEndTime: Math.max(0, Number(prevSettings.surgeEndTime ?? 0)),
    surgeDurationMinutes: Math.max(1, Number(prevSettings.surgeDurationMinutes ?? 30)),
    promoCodes: Array.isArray(prevSettings.promoCodes) ? prevSettings.promoCodes : [],
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

async function buildClientState(req, forceRefresh = false) {
  touchCustomerPresence(req);
  const raw = await fetchRawDatabaseState(forceRefresh);
  const isAdmin = isRequestFromAdminView(req);
  const adminToken = getAuthenticatedAdminFromCookie(req);

  const surgeInfo = getActiveSurgeInfo(raw.settings);
  const clientSettings = {
    ...raw.settings,
    surgeActive: surgeInfo.isActive,
    surgeRemainingMinutes: surgeInfo.remainingMinutes,
    effectivePlatformFee: surgeInfo.isActive
      ? roundMoney(raw.settings.platformFee * (1 + surgeInfo.surgePercent / 100))
      : raw.settings.platformFee
  };

  const mappedCaptains = raw.rawCaptains.map(c =>
    mapCaptainRow(c, isAdmin, raw.storageFilesMap, raw.orders, clientSettings)
  );

  const availableCaptainsCount = mappedCaptains.filter(c => c.status === 'معتمد' && c.isAvailable).length;
  const onlineCustomersCount = getOnlineCustomersCount();

  return {
    settings: clientSettings,
    zones: raw.zones,
    pricing: raw.pricing,
    customers: raw.customers,
    captains: mappedCaptains,
    orders: raw.orders,
    availableCaptainsCount,
    onlineCustomersCount,
    realtimeConfig: {
      supabaseUrl: SUPABASE_URL || '',
      supabaseAnonKey: SUPABASE_ANON_KEY || ''
    },
    adminAccounts: isAdmin ? raw.adminAccounts : [],
    auditLogs: isAdmin ? raw.auditLogs : [],
    authenticatedAdminUsername: adminToken ? adminToken.username : null
  };
}

// ==========================================
// 4. محرك إشعارات الموبايل (Web Push Notifications)
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

    let targetSubs = allSubs;
    if (target === 'captains' || target === 'customers') {
      const { data: captainsRows } = await supabase.from('captains').select('phone');
      const captainPhones = new Set((captainsRows || []).map(c => String(c.phone).trim()));
      if (target === 'captains') {
        targetSubs = allSubs.filter(s => captainPhones.has(String(s.phone).trim()));
      } else if (target === 'customers') {
        targetSubs = allSubs.filter(s => !captainPhones.has(String(s.phone).trim()));
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

app.post('/api/push/subscribe', async (req, res) => {
  const { phone, subscription } = req.body || {};
  if (!phone || !subscription) {
    return res.status(400).json({ success: false });
  }
  await supabase.from('push_subscriptions').upsert([{
    phone: String(phone).trim(),
    subscription,
    updated_at: new Date().toISOString()
  }]);
  res.json({ success: true });
});

// نبضة اتصال العميل لتحديث عداد العملاء المتواجدين حالياً
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

// التحقق من كود الخصم للعميل قبل الطلب أو لحفظه في محفظة الكوبونات
app.post('/api/promo-codes/validate', async (req, res) => {
  try {
    const { code, clientPhone } = req.body || {};
    const cleanCode = String(code || '').trim().toUpperCase();
    const cleanPhone = String(clientPhone || '').trim();

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

    if (promo.targetPhone && promo.targetPhone !== 'all') {
      if (!cleanPhone) {
        return res.status(400).json({ success: false, message: 'اكتب رقم تليفونك في خانة الراسل الأول عشان نتحقق من الكود 📱⚠️' });
      }
      if (promo.targetPhone !== cleanPhone) {
        return res.status(403).json({ success: false, message: 'الكود ده مخصوص لعميل تاني بالاسم يا باشا 😅🔒' });
      }
    }

    const usedBy = Array.isArray(promo.usedBy) ? promo.usedBy : [];
    if (cleanPhone && usedBy.includes(cleanPhone)) {
      return res.status(400).json({ success: false, message: 'أنت استخدمت الكود ده قبل كده في مشوار سابق يا باشا 😎✅' });
    }

    res.json({
      success: true,
      promo: {
        code: promo.code,
        discountAmount: roundMoney(promo.discountAmount),
        targetPhone: promo.targetPhone || 'all',
        expiresAt: promo.expiresAt || null
      },
      message: `مبروك يا باشا! 🎉 الكود (${promo.code}) شغال وهيديك خصم ${promo.discountAmount} جنيه وتقدر تحتفظ بيه لحد انتهاء فترة السماح 🛵💸`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'تعذر التحقق من الكود حالياً ⚠️' });
  }
});

// ==========================================
// 6. حماية التخمين (Rate Limiter) والمصادقة
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
    const token = req.cookies.admin_session;
    if (token) {
      const decoded = jwt.verify(token, JWT_SECRET);
      const { data: admin } = await supabase.from('admins').select('*').eq('username', decoded.username).maybeSingle();
      if (admin && admin.status !== 'معطل') {
        req.admin = admin;
        return next();
      }
    }
    const { data: masterAdmin } = await supabase.from('admins').select('*').eq('is_master', true).limit(1).maybeSingle();
    if (masterAdmin) {
      req.admin = masterAdmin;
      return next();
    }
    req.admin = { username: process.env.INITIAL_ADMIN_USER || 'ennaby1', name: 'الأدمن الرئيسي', is_master: true, status: 'نشط', permissions: {} };
    next();
  } catch (err) {
    req.admin = { username: process.env.INITIAL_ADMIN_USER || 'ennaby1', name: 'الأدمن الرئيسي', is_master: true, status: 'نشط', permissions: {} };
    next();
  }
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

    const envUser = (process.env.INITIAL_ADMIN_USER || 'ennaby1').trim();
    const envPass = (process.env.INITIAL_ADMIN_PASS || '01023024988').trim();

    let { data: admin } = await supabase.from('admins').select('*').eq('username', username).maybeSingle();

    if (username.toLowerCase() === envUser.toLowerCase() && password === envPass) {
      const hashed = await bcrypt.hash(String(envPass), 10);
      if (!admin) {
        const { data: masterRow } = await supabase.from('admins').select('*').eq('is_master', true).maybeSingle();
        if (masterRow) {
          const { data: updatedMaster } = await supabase.from('admins').update({
            username: envUser,
            password_hash: hashed,
            status: 'نشط'
          }).eq('is_master', true).select().maybeSingle();
          admin = updatedMaster || masterRow;
        } else {
          const { data: createdMaster } = await supabase.from('admins').insert([{
            username: envUser,
            name: 'الأدمن الرئيسي',
            password_hash: hashed,
            is_master: true,
            status: 'نشط',
            permissions: {}
          }]).select().maybeSingle();
          admin = createdMaster;
        }
      }
      if (!admin) {
        admin = { username: envUser, name: 'الأدمن الرئيسي', is_master: true, status: 'نشط', permissions: {} };
      }
    } else {
      if (!admin) {
        return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
      }
      if (admin.status === 'معطل') {
        return res.status(403).json({ success: false, message: 'حساب المسؤول معطل من الإدارة ⛔' });
      }
      const valid = await bcrypt.compare(String(password), admin.password_hash || '');
      const isMasterWithEnvPass = Boolean(admin.is_master) && password === envPass;
      if (!valid && !isMasterWithEnvPass) {
        return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
      }
    }

    const token = jwt.sign({ username: admin.username, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('admin_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

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
  const { phone, pin } = req.body || {};
  if (!phone || !pin) return res.status(400).json({ success: false, message: 'بيانات غير مكتملة' });

  const rateLimit = await checkRateLimit(phone);
  if (rateLimit.locked) return res.status(403).json({ success: false, message: rateLimit.message });

  const { data: user } = await supabase.from('customers').select('*').eq('phone', phone).maybeSingle();

  if (!user) {
    const hashedPin = await bcrypt.hash(String(pin), 10);
    const { data: newUser } = await supabase.from('customers').insert([{
      phone,
      pin_hash: hashedPin,
      wallet_balance: 0,
      points: 0,
      wallet_transactions: []
    }]).select().single();

    touchCustomerPresence(req, `cust_${phone}`);
    invalidateStateCache();
    const token = jwt.sign({ phone: newUser.phone, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    const state = await buildClientState(req, true);
    return res.json({ success: true, message: 'تم فتح حسابك بنجاح 👑', state });
  }

  const valid = await bcrypt.compare(String(pin), user.pin_hash);
  if (!valid) {
    await recordFailedAttempt(phone, rateLimit.attemptData);
    return res.status(401).json({ success: false, message: 'الرقم السري غير صحيح ⚠️' });
  }

  await clearFailedAttempts(phone);
  touchCustomerPresence(req, `cust_${phone}`);
  const token = jwt.sign({ phone: user.phone, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  const state = await buildClientState(req, false);
  res.json({ success: true, message: 'تم تسجيل الدخول بنجاح 👑', state });
});

app.post('/api/captains/register', async (req, res) => {
  try {
    const {
      phone, password, fullName, nationalId, primaryZone,
      vehicleType, plateNumber, idFrontPhoto, idBackPhoto,
      vehiclePhoto, referredByPhone
    } = req.body || {};

    if (!phone || !password || !fullName || !nationalId || !vehicleType) {
      return res.status(400).json({ success: false, message: 'برجاء استكمال جميع البيانات الإجبارية ونوع المركبة ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
    const { data: existing } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
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
      invalidateStateCache();
      const state = await buildClientState(req, true);
      return res.json({ success: true, message: 'تم إعادة إرسال مستنداتك للمراجعة بنجاح ⏳', state });
    }

    let validReferrer = null;
    if (rawState.settings.referralRewardActive !== false && referredByPhone && referredByPhone !== phone) {
      const { data: refCap } = await supabase.from('captains').select('phone').eq('phone', referredByPhone).maybeSingle();
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

    invalidateStateCache();
    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تم إرسال طلبك بنجاح وسيتم مراجعته من الإدارة قريباً ⏳', state });
  } catch (err) {
    console.error('Registration exception:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ في السيرفر أثناء التسجيل ⚠️' });
  }
});

app.post('/api/auth/captain/login', async (req, res) => {
  const { phone, password } = req.body || {};
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
  res.cookie('captain_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
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
  try {
    const {
      clientPhone, pin, tripType, pickupZone, pickupAddress,
      dropoffZone, dropoffAddress, customerNotes, packageType,
      payer, senderPhone, recipientPhone,
      pickupLat, pickupLng, dropoffLat, dropoffLng, promoCode
    } = req.body || {};

    if (!clientPhone || !pin || !pickupAddress || !dropoffAddress) {
      return res.status(400).json({ success: false, message: 'برجاء استكمال كافة بيانات وعناوين الطلب ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(true);
    if (rawState.settings.maintenanceMode) {
      return res.status(403).json({ success: false, message: 'المنصة في وضع الصيانة الطارئة حالياً 🛠️' });
    }

    let { data: cust } = await supabase.from('customers').select('*').eq('phone', clientPhone).maybeSingle();
    if (!cust) {
      const hashedPin = await bcrypt.hash(String(pin), 10);
      const { data: createdCust } = await supabase.from('customers').insert([{
        phone: clientPhone,
        pin_hash: hashedPin,
        wallet_balance: 0,
        points: 0,
        wallet_transactions: []
      }]).select().single();
      cust = createdCust;
    } else {
      const pinOk = await bcrypt.compare(String(pin), cust.pin_hash);
      if (!pinOk) {
        return res.status(401).json({ success: false, message: 'رمز الـ PIN غير مطابق لحسابك المسجل! 🔒⚠️' });
      }
    }

    touchCustomerPresence(req, `cust_${clientPhone}`);
    const custToken = jwt.sign({ phone: clientPhone, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('customer_session', custToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    const routeKey = `${pickupZone}|${dropoffZone}`;
    const baseRouteFare = roundMoney(rawState.pricing[routeKey] ?? 40);

    // تطبيق زيادة وقت الذروة (Surge Pricing) على أجرة المشوار وعمولة المنصة تلقائياً
    const surgeInfo = getActiveSurgeInfo(rawState.settings);
    const originalFare = surgeInfo.isActive
      ? roundMoney(baseRouteFare * (1 + surgeInfo.surgePercent / 100))
      : baseRouteFare;

    const basePlatformFee = roundMoney(rawState.settings.platformFee ?? 7);
    const platformFee = surgeInfo.isActive
      ? roundMoney(basePlatformFee * (1 + surgeInfo.surgePercent / 100))
      : basePlatformFee;

    // 1. خصم المحفظة التلقائي
    const availableWallet = Math.max(0, roundMoney(cust.wallet_balance || 0));
    const walletDiscount = availableWallet > 0 ? roundMoney(Math.min(availableWallet, originalFare)) : 0;

    // 2. خصم الكوبون (Promo Code) إن وجد وكان صالحاً
    let promoDiscount = 0;
    let appliedPromoCode = null;
    const cleanPromo = String(promoCode || '').trim().toUpperCase();

    if (cleanPromo) {
      const promoList = Array.isArray(rawState.settings.promoCodes) ? rawState.settings.promoCodes : [];
      const promoIdx = promoList.findIndex(p => p && String(p.code).toUpperCase() === cleanPromo && p.active !== false);
      if (promoIdx !== -1) {
        const promoObj = promoList[promoIdx];
        const notExpired = !promoObj.expiresAt || Date.now() <= Number(promoObj.expiresAt);
        const matchesTarget = !promoObj.targetPhone || promoObj.targetPhone === 'all' || promoObj.targetPhone === clientPhone;
        const usedBy = Array.isArray(promoObj.usedBy) ? promoObj.usedBy : [];
        const notUsedYet = !usedBy.includes(clientPhone);

        if (notExpired && matchesTarget && notUsedYet) {
          const remainingFareAfterWallet = Math.max(0, roundMoney(originalFare - walletDiscount));
          promoDiscount = roundMoney(Math.min(roundMoney(promoObj.discountAmount || 0), remainingFareAfterWallet));
          if (promoDiscount > 0) {
            appliedPromoCode = promoObj.code;
            promoList[promoIdx].usedBy = [...usedBy, clientPhone];
            await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
          }
        }
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

    if (walletDiscount > 0) {
      await supabase.rpc('adjust_customer_wallet_atomic', {
        p_phone: clientPhone,
        p_amount: -Math.abs(walletDiscount),
        p_reason: `خصم رصيد محفظة على طلب ${orderId}`
      });
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
      sender_phone: senderPhone || clientPhone,
      recipient_phone: recipientPhone || '',
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
      return res.status(400).json({ success: false, message: 'تعذر تسجيل الطلب، حاول مرة أخرى ⚠️' });
    }

    invalidateStateCache();
    broadcastPushToAvailableCaptains({
      title: 'أوردر جديد على الرادار يانجم! 📡🛵',
      body: `طلب (${orderId}) من ${pickupZone} إلى ${dropoffZone} - الأجرة: ${originalFare} ج.. الحق اقبله قبل ما يطير! 🚀`
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
  }
});

// قبول الكابتن للطلب (مع تطبيق خصم مستوى الكابتن + نسبة وقت الذروة أوتوماتيكياً)
app.post('/api/orders/:id/accept', authenticateCaptain, async (req, res) => {
  const cap = req.user;
  if (!cap.is_available || cap.status !== 'معتمد') {
    return res.status(403).json({ success: false, message: 'حسابك غير مصرح له بقبول الطلبات حالياً ⛔' });
  }

  const { data: activeOrders } = await supabase.from('orders')
    .select('id')
    .eq('assigned_courier_phone', cap.phone)
    .in('status', ['تم قبول الطلب', 'الكابتن وصل للاستلام', 'استلم الطرد وفي السكة', 'الكابتن وصل للتسليم']);

  if (activeOrders && activeOrders.length > 0) {
    return res.status(400).json({ success: false, message: 'معاك مشوار جاري بالفعل يا بطل، خلصه الأول 🛵⚠️' });
  }

  const rawState = await fetchRawDatabaseState(false);
  const tierData = computeCaptainTierAndFee(cap, rawState.orders, rawState.settings);
  const fee = tierData.effectiveFee;

  if (roundMoney(cap.wallet_balance || 0) < fee) {
    return res.status(400).json({
      success: false,
      message: `رصيد محفظتك (${roundMoney(cap.wallet_balance)} ج) أقل من عمولة الطلب (${fee} ج). اشحن محفظتك أولاً 💸⚠️`
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
      assigned_courier_phone: cap.phone,
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
      p_phone: cap.phone,
      p_amount: -Math.abs(fee),
      p_reason: `عمولة منصة (${tierData.tierBadgeText}) لطلب ${req.params.id}`
    });
  }

  const discount = roundMoney(targetOrder.discount_applied || 0);
  if (discount > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: cap.phone,
      p_amount: discount,
      p_reason: `تعويض خصم/كوبون عميل لطلب ${req.params.id}`
    });
  }

  invalidateStateCache();
  sendPushNotificationToPhone(targetOrder.customer_phone || targetOrder.client_phone, {
    title: 'تم قبول طلبك يا باشا! 🛵✅',
    body: `الكابتن ${cap.full_name} (${tierData.tierBadgeText}) لقط الأوردر (${req.params.id}) وطاير عليك فوراً! 🚀`
  });

  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم قبول الطلب.. توكل على الله 🛵', state });
});

app.post('/api/orders/:id/advance', authenticateCaptain, async (req, res) => {
  const { nextStatus } = req.body || {};
  const { data, error } = await supabase.from('orders')
    .update({ status: nextStatus })
    .eq('id', req.params.id)
    .eq('assigned_courier_phone', req.user.phone)
    .select();

  if (error || !data || !data.length) {
    return res.status(400).json({ success: false, message: 'تعذر تحديث الحالة' });
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

  const state = await buildClientState(req, true);
  res.json({ success: true, message: `تم التحديث: ${nextStatus} 🛵✅`, state });
});

app.post('/api/orders/:id/complete', authenticateCaptain, async (req, res) => {
  const cap = req.user;
  const rawBefore = await fetchRawDatabaseState(false);
  const oldTierData = computeCaptainTierAndFee(cap, rawBefore.orders, rawBefore.settings);

  const { data, error } = await supabase.from('orders')
    .update({ status: 'مكتمل' })
    .eq('id', req.params.id)
    .eq('assigned_courier_phone', cap.phone)
    .neq('status', 'مكتمل')
    .select();

  if (error || !data || !data.length) {
    return res.status(400).json({ success: false, message: 'تعذر إنهاء الطلب' });
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

    // التحقق من ترقية مستوى الكابتن بعد إتمام هذا الطلب
    const newTierData = computeCaptainTierAndFee(freshCap, rawState.orders, s);
    const capNotices = Array.isArray(freshCap.admin_notices) ? freshCap.admin_notices : [];

    if (newTierData.tier !== oldTierData.tier && (newTierData.tier === 'platinum' || newTierData.tier === 'diamond')) {
      const upgradeMsg = newTierData.tier === 'diamond'
        ? `💎 وسّع للكابتن الماسي! مبروك يا بطل، حافظت على مستواك ووصلت لـ (${newTierData.tierBadgeText}) وعمولتك نزلت بخصم ${newTierData.tierDiscount} جنيه على كل أوردر! 🚀🔥`
        : `🥈 عاش يا نجم الطيارين! كملت التارجت الأسبوعي واترقيت لـ (${newTierData.tierBadgeText}) وعمولتك بقت مخفضة بـ ${newTierData.tierDiscount} جنيه! حافظ على مستواك عشان توصل للماسي 💎🛵`;

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

    // التحقق من مكافأة دعوة الأصدقاء بعدد المشاوير الديناميكي
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

  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تسلم إيدك يا بطل! تم التسليم 🛵💨', state });
});

app.post('/api/orders/:id/release', authenticateCaptain, async (req, res) => {
  const { data: order } = await supabase.from('orders')
    .select('*')
    .eq('id', req.params.id)
    .eq('assigned_courier_phone', req.user.phone)
    .eq('status', 'تم قبول الطلب')
    .maybeSingle();

  if (!order) {
    return res.status(400).json({ success: false, message: 'لا يمكن التنازل في هذه المرحلة ⚠️' });
  }

  await supabase.from('orders').update({
    status: 'في انتظار كابتن',
    assigned_courier_phone: null,
    fee_refunded: true
  }).eq('id', order.id);

  if (order.fee_deducted && order.platform_fee > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: req.user.phone,
      p_amount: roundMoney(order.platform_fee),
      p_reason: `رد عمولة للتنازل عن طلب ${order.id}`
    });
  }

  if (order.discount_applied > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: req.user.phone,
      p_amount: -Math.abs(roundMoney(order.discount_applied)),
      p_reason: `استرداد فرق خصم للتنازل عن طلب ${order.id}`
    });
  }

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم إعادة الطلب للرادار 🔄', state });
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
  await supabase.from('captains').update({ is_available: Boolean(req.body.isAvailable) }).eq('phone', req.user.phone);
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

app.post('/api/orders/:id/cancel', async (req, res) => {
  const { data: existing } = await supabase.from('orders').select('*').eq('id', req.params.id).maybeSingle();
  if (!existing || !['في انتظار كابتن', 'تم قبول الطلب'].includes(existing.status)) {
    return res.status(400).json({ success: false, message: 'لا يمكن الإلغاء.. الطلب قيد التنفيذ ⚠️' });
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

  // رد رصيد المحفظة فقط، وإتاحة كود الخصم للعميل مرة أخرى طالما لم تنتهِ فترة السماح
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
    const rawState = await fetchRawDatabaseState(true);
    const promoList = Array.isArray(rawState.settings.promoCodes) ? rawState.settings.promoCodes : [];
    const pIdx = promoList.findIndex(p => p && String(p.code).toUpperCase() === String(meta.promoCode).toUpperCase());
    if (pIdx !== -1 && Array.isArray(promoList[pIdx].usedBy)) {
      promoList[pIdx].usedBy = promoList[pIdx].usedBy.filter(ph => ph !== custPhone);
      await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
    }
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

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم الإلغاء ورصيدك وكودك محفوظين يا نجم ✅', state });
});

app.post('/api/orders/:id/rate', async (req, res) => {
  const rating = Math.min(5, Math.max(1, Number(req.body.rating) || 5));
  await supabase.from('orders').update({ rating }).eq('id', req.params.id);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/orders/:id/dispute', async (req, res) => {
  const reason = String(req.body.reason || '').trim();
  if (!reason) return res.status(400).json({ success: false, message: 'اكتب سبب الاعتراض ⚠️' });
  await supabase.from('orders').update({
    dispute_reason: reason,
    status: 'قيد مراجعة الاعتراض'
  }).eq('id', req.params.id);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// ==========================================
// 9. مسارات غرفة العمليات المركزية (Admin)
// ==========================================
app.post('/api/admin/settings', authenticateAdmin, async (req, res) => {
  const body = req.body || {};
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

  // تحديثات مستويات الكباتن الديناميكية
  if (body.tierWeeklyOrdersTarget !== undefined) partialIncentives.tierWeeklyOrdersTarget = Math.max(1, Number(body.tierWeeklyOrdersTarget));
  if (body.tierWeeksForDiamond !== undefined) partialIncentives.tierWeeksForDiamond = Math.max(1, Number(body.tierWeeksForDiamond));
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

  // تحديثات وقت الذروة (Surge Pricing) بالعداد التنازلي
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
  } else if (body.tierWeeklyOrdersTarget !== undefined || body.tierPlatinumDiscount !== undefined) {
    auditDetails = `تحديث نظام مستويات الكباتن (${updatedIncentives.tierWeeklyOrdersTarget} طلب/أسبوع - خصم بلاتيني ${updatedIncentives.tierPlatinumDiscount}ج - ماسي ${updatedIncentives.tierDiamondDiscount}ج)`;
  } else if (body.broadcastMessage !== undefined || body.broadcastTarget !== undefined) {
    const targetNames = { all: 'الجميع', customers: 'العملاء فقط', captains: 'الكباتن فقط', admins: 'المسؤولين فقط', public: 'العملاء والكباتن' };
    const msgTxt = body.broadcastMessage !== undefined ? body.broadcastMessage : (prevSettings.broadcastMessage || '');
    auditDetails = `تحديث الإعلان العام (${targetNames[updatedIncentives.broadcastTarget] || 'الجميع'}): ${msgTxt || 'إخفاء الإعلان'}`;
  } else if (body.welcomeBonusAmount !== undefined || body.referralRewardAmount !== undefined || body.referralRequiredOrders !== undefined) {
    auditDetails = `تحديث الحوافز — الترحيب: ${updatedIncentives.welcomeBonusActive ? updatedIncentives.welcomeBonusAmount + ' ج' : 'متوقف'} | الإحالة: ${updatedIncentives.referralRewardActive ? updatedIncentives.referralRewardAmount + ' ج بعد ' + updatedIncentives.referralRequiredOrders + ' مشاوير' : 'متوقف'}`;
  }
  await logAdminAudit('تحديث إعدادات', 'المنصة', auditDetails, req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// إدارة كوبونات الخصم الديناميكية (إضافة / تعميم أو تخصيص لعميل / إرسال إشعارات Push)
app.post('/api/admin/promo-codes', authenticateAdmin, async (req, res) => {
  try {
    const { code, discountAmount, targetPhone = 'all', validHours = 48 } = req.body || {};
    const cleanCode = String(code || '').trim().toUpperCase().replace(/\s+/g, '');
    const amt = roundMoney(discountAmount);
    const hours = Math.max(1, Number(validHours) || 48);
    const cleanTarget = (!targetPhone || targetPhone === 'all') ? 'all' : String(targetPhone).trim();

    if (!cleanCode || amt <= 0) {
      return res.status(400).json({ success: false, message: 'اكتب اسم الكود وقيمة الخصم بشكل صحيح يا باشا ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(true);
    const promoList = Array.isArray(rawState.settings.promoCodes) ? [...rawState.settings.promoCodes] : [];
    const existingIdx = promoList.findIndex(p => p && String(p.code).toUpperCase() === cleanCode);

    const expiresAt = Date.now() + hours * 3600000;
    const newPromoObj = {
      code: cleanCode,
      discountAmount: amt,
      targetPhone: cleanTarget,
      validHours: hours,
      expiresAt,
      usedBy: existingIdx !== -1 ? (promoList[existingIdx].usedBy || []) : [],
      active: true,
      createdAt: Date.now()
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
      sendPushNotificationToPhone(cleanTarget, {
        title: 'هدية خاصة ليك يا باشا مصر! 🎟️👑',
        body: `إدارة الرجل العنابي عملتلك كود خصم مخصوص (${cleanCode}) بقيمة ${amt} جنيه! تقدر تستخدمه خلال ${hours} ساعة 😎🛵`
      });
    }

    await logAdminAudit(
      'إصدار كود خصم',
      cleanCode,
      `خصم ${amt} ج — المستهدف: ${cleanTarget === 'all' ? 'جميع العملاء' : cleanTarget} (صالح لـ ${hours} ساعة)`,
      req.admin.name
    );

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
  const { code } = req.body || {};
  const cleanCode = String(code || '').trim().toUpperCase();
  const rawState = await fetchRawDatabaseState(true);
  const promoList = (rawState.settings.promoCodes || []).filter(p => p && String(p.code).toUpperCase() !== cleanCode);

  await saveIncentivesToDatabase(rawState, { promoCodes: promoList });
  await logAdminAudit('حذف كود خصم', cleanCode, 'إلغاء وحذف كود الخصم', req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم حذف كود الخصم بنجاح 🗑️✅', state });
});

app.post('/api/admin/wallets/captain-topup', authenticateAdmin, async (req, res) => {
  const { phone, amount } = req.body || {};
  const amt = roundMoney(amount);
  if (!phone || amt <= 0) return res.status(400).json({ success: false });

  await supabase.rpc('adjust_captain_wallet_atomic', {
    p_phone: phone,
    p_amount: amt,
    p_reason: 'شحن رصيد من الإدارة ⚡'
  });

  const { data: cap } = await supabase.from('captains').select('admin_notices').eq('phone', phone).maybeSingle();
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

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/wallets/captain-deduct', authenticateAdmin, async (req, res) => {
  const { phone, amount, reason } = req.body || {};
  const amt = roundMoney(amount);
  if (!phone || amt <= 0 || !reason) return res.status(400).json({ success: false });

  await supabase.rpc('adjust_captain_wallet_atomic', {
    p_phone: phone,
    p_amount: -Math.abs(amt),
    p_reason: `خصم إداري: ${reason}`
  });

  const { data: cap } = await supabase.from('captains').select('admin_notices').eq('phone', phone).maybeSingle();
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
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/wallets/customer-compensate', authenticateAdmin, async (req, res) => {
  const { phone, amount, reason } = req.body || {};
  const amt = roundMoney(amount);
  if (!phone || amt <= 0) return res.status(400).json({ success: false });

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

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/custom-fee', authenticateAdmin, async (req, res) => {
  const { phone, customFee, reason, reset } = req.body || {};
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

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/:phone/status', authenticateAdmin, async (req, res) => {
  const { status, reason } = req.body || {};
  const phone = req.params.phone;

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

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/reset-password', authenticateAdmin, async (req, res) => {
  const { phone, newPass } = req.body || {};
  if (!phone || !newPass || String(newPass).length < 4) {
    return res.status(400).json({ success: false, message: 'كلمة المرور قصيرة جداً ⚠️' });
  }
  const { data: cap } = await supabase.from('captains').select('session_version').eq('phone', phone).maybeSingle();
  if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

  const hashed = await bcrypt.hash(String(newPass), 10);
  await supabase.from('captains').update({
    password_hash: hashed,
    session_version: Number(cap.session_version || 1) + 1
  }).eq('phone', phone);

  await clearFailedAttempts(phone);
  await logAdminAudit('تصفير باسورد كابتن', phone, 'تعيين كلمة مرور جديدة للكابتن', req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تحديث كلمة مرور الكابتن 🔑✅', state });
});

app.post('/api/admin/customers/reset-pin', authenticateAdmin, async (req, res) => {
  const { phone, newPin } = req.body || {};
  if (!phone || !/^[0-9]{4}$/.test(String(newPin || '').trim())) {
    return res.status(400).json({ success: false, message: 'رمز الـ PIN يجب أن يكون 4 أرقام ⚠️' });
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
  }

  await clearFailedAttempts(phone);
  await logAdminAudit('تصفير PIN عميل', phone, 'تعيين رمز PIN جديد للعميل', req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم تعيين رمز الـ PIN للعميل بنجاح 🔒✅', state });
});

app.post('/api/admin/orders/:id/manage', authenticateAdmin, async (req, res) => {
  const { action, reason } = req.body || {};
  const orderId = req.params.id;
  const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
  if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود' });

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
  } else if (action === 'cancel' || action === 'resolve_cancel') {
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
    if (order.assigned_courier_phone && !order.fee_refunded) {
      if (order.fee_deducted && order.platform_fee > 0) {
        await supabase.rpc('adjust_captain_wallet_atomic', {
          p_phone: order.assigned_courier_phone,
          p_amount: roundMoney(order.platform_fee),
          p_reason: `رد عمولة لطلب ملغي إدارياً ${order.id}`
        });
      }
      if (order.discount_applied > 0 && action === 'cancel') {
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
    await supabase.from('orders').update({
      status: 'مكتمل',
      admin_resolution_note: 'تمت المراجعة واعتماد اكتمال الطلب بواسطة الإدارة ✅'
    }).eq('id', orderId);
  }

  await logAdminAudit('تدخل في طلب', orderId, `الإجراء: ${action} ${reason ? '- ' + reason : ''}`, req.admin.name);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/accounts/master', authenticateAdmin, async (req, res) => {
  const { name, username, currentPassword, newPassword } = req.body || {};
  const { data: master } = await supabase.from('admins').select('*').eq('is_master', true).limit(1).maybeSingle();

  if (master && currentPassword) {
    const valid = await bcrypt.compare(String(currentPassword), master.password_hash);
    const envPass = (process.env.INITIAL_ADMIN_PASS || '01023024988').trim();
    if (!valid && currentPassword !== envPass) {
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
    updates.password_hash = updates.password_hash || await bcrypt.hash(process.env.INITIAL_ADMIN_PASS || '01023024988', 10);
    updates.is_master = true;
    updates.status = 'نشط';
    await supabase.from('admins').insert([updates]);
  }

  const newToken = jwt.sign({ username: updates.username, role: 'admin' }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('admin_session', newToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم حفظ وتحديث بيانات الأدمن الرئيسي ✅', state });
});

app.post('/api/admin/accounts/sub', authenticateAdmin, async (req, res) => {
  const { origUsername, name, username, password, permissions } = req.body || {};
  if (!name || !username) return res.status(400).json({ success: false, message: 'الاسم واسم المستخدم مطلوبان ⚠️' });

  const updates = {
    name,
    username,
    is_master: false,
    status: 'نشط',
    permissions: permissions || {}
  };
  if (password) {
    updates.password_hash = await bcrypt.hash(String(password), 10);
  }

  if (origUsername) {
    await supabase.from('admins').update(updates).eq('username', origUsername);
  } else {
    if (!password) return res.status(400).json({ success: false, message: 'كلمة المرور مطلوبة للمسؤول الجديد ⚠️' });
    await supabase.from('admins').insert([updates]);
  }

  await logAdminAudit('إدارة مسؤولين', username, origUsername ? 'تعديل صلاحيات مسؤول' : 'إضافة مسؤول جديد', req.admin.name);
  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/accounts/:username/toggle', authenticateAdmin, async (req, res) => {
  const targetUser = req.params.username;
  const { data: acc } = await supabase.from('admins').select('status').eq('username', targetUser).maybeSingle();
  if (!acc) return res.status(404).json({ success: false });

  const newStatus = acc.status === 'نشط' ? 'معطل' : 'نشط';
  await supabase.from('admins').update({ status: newStatus }).eq('username', targetUser);
  await logAdminAudit('حالة مسؤول', targetUser, `تغيير الحالة إلى ${newStatus}`, req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

// إرسال إشعار عام للهواتف (Web Push Broadcast) - حصرياً للأدمن الرئيسي فقط
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
    if (!allSubs || allSubs.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'لا توجد هواتف مشتركة في الإشعارات حالياً ⚠️'
      });
    }

    let targetSubs = allSubs;
    if (target === 'captains' || target === 'customers') {
      const { data: captainsRows } = await supabase.from('captains').select('phone');
      const captainPhones = new Set((captainsRows || []).map(c => String(c.phone).trim()));
      if (target === 'captains') {
        targetSubs = allSubs.filter(s => captainPhones.has(String(s.phone).trim()));
      } else if (target === 'customers') {
        targetSubs = allSubs.filter(s => !captainPhones.has(String(s.phone).trim()));
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