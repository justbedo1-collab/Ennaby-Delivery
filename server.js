require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

// ============================================================================
// 1. التحقق الإلزامي من متغيرات البيئة (Zero-Fallback Security)
// ============================================================================
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k] || String(process.env[k]).trim() === '');

if (missingEnv.length > 0) {
  console.error(`❌ [خطأ أمني حرج] متغيرات البيئة التالية مفقودة في ملف .env أو إعدادات Railway: ${missingEnv.join(', ')}`);
  console.error('برجاء إضافة SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY و JWT_SECRET (لا يقل عن 16 حرفاً) قبل تشغيل السيرفر.');
  process.exit(1);
}

const JWT_SECRET = String(process.env.JWT_SECRET).trim();
if (JWT_SECRET.length < 16) {
  console.error('❌ [خطأ أمني حرج] قيمة JWT_SECRET قصيرة جداً! يجب أن لا تقل عن 16 حرفاً لضمان عدم تزوير التوكن.');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT);

// دعم البروكسي العكسي لمنصات الاستضافة السحابية (Railway / Render)
app.set('trust proxy', 1);

// الاتصال الآمن بقاعدة بيانات Supabase (Service Role Key على الخادم فقط)
const supabase = createClient(
  process.env.SUPABASE_URL.trim(),
  process.env.SUPABASE_SERVICE_ROLE_KEY.trim(),
  { auth: { persistSession: false } }
);

// ============================================================================
// 2. إعدادات الحماية (Security Headers, CORS, Rate Limiting, Body Limits)
// ============================================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  next();
});

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    // السماح للطلبات من نفس السيرفر (Same-Origin) أو النطاقات المعتمدة أو بيئة التطوير المحلية
    if (!origin) return callback(null, true);
    if (!IS_PROD && (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:'))) {
      return callback(null, true);
    }
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('غير مسموح بالوصول من هذا النطاق (CORS Policy)'));
  },
  credentials: true
}));

// تقليص حد البيانات إلى 6 ميجابايت بدلاً من 25 ميجابايت لمنع هجمات استنزاف الذاكرة (DoS)
app.use(express.json({ limit: '6mb' }));
app.use(express.urlencoded({ extended: true, limit: '6mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// محرك تحديد معدل الطلبات (Rate Limiter) مدمج لحماية مسارات الدخول والطلبات من التخمين والسبام
const rateLimitStore = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of rateLimitStore.entries()) {
    if (now > val.resetAt) rateLimitStore.delete(key);
  }
}, 60 * 1000).unref();

function createRateLimiter({ windowMs, max, message }) {
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    const key = `${req.baseUrl || ''}${req.path}:${ip}`;
    const now = Date.now();
    let entry = rateLimitStore.get(key);
    if (!entry || now > entry.resetAt) {
      entry = { count: 1, resetAt: now + windowMs };
      rateLimitStore.set(key, entry);
      return next();
    }
    entry.count += 1;
    if (entry.count > max) {
      return res.status(429).json({
        success: false,
        message: message || 'تم تجاوز الحد المسموح من المحاولات، يرجى الانتظار قليلاً ثم المحاولة ⚠️'
      });
    }
    return next();
  };
}

const authLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: 'محاولات تسجيل دخول كثيرة جداً! يرجى الانتظار 15 دقيقة للمحاولة مجدداً 🔒⚠️'
});

const writeLimiter = createRateLimiter({
  windowMs: 5 * 60 * 1000,
  max: 45,
  message: 'عدد كبير من العمليات المتتالية، يرجى التمهل قليلاً 🛵⚠️'
});

// ============================================================================
// 3. الثوابت والدوال المساعدة وتشفير كلمات المرور القياسي (scrypt / timingSafeEqual)
// ============================================================================
const DEFAULT_ZONES = ['المنصورة', 'طلخا', 'سندوب', 'جديلة'];
const DEFAULT_PRICING = {
  'المنصورة|المنصورة': 40, 'طلخا|طلخا': 35, 'سندوب|سندوب': 35, 'جديلة|جديلة': 35,
  'المنصورة|طلخا': 50, 'طلخا|المنصورة': 50, 'المنصورة|سندوب': 50, 'سندوب|المنصورة': 50,
  'المنصورة|جديلة': 50, 'جديلة|المنصورة': 50, 'طلخا|سندوب': 70, 'سندوب|طلخا': 70,
  'طلخا|جديلة': 70, 'جديلة|طلخا': 70, 'سندوب|جديلة': 70, 'جديلة|سندوب': 70
};
const DEFAULT_PACKAGE_TYPES = [
  'طرد خفيف (أقل من 3 كجم) - شنطة أو ورق',
  'طرد متوسط (3 إلى 8 كجم) - كرتونة',
  'أكل أو حلويات (حاجة حساسة ع الميزان)'
];
const DEFAULT_SETTINGS = {
  platformFee: 7,
  customerPointsPerOrder: 5,
  customerRewardThreshold: 100,
  customerRewardCash: 10,
  courierPointsPerOrder: 5,
  courierRewardThreshold: 100,
  courierRewardCash: 10,
  supportWhatsapp: '201507800875',
  broadcastMessage: '',
  maintenanceMode: false,
  allowCaptainRegistration: true,
  waitingTimeoutMinutes: 30,
  packageTypes: DEFAULT_PACKAGE_TYPES
};

const ACTIVE_COURIER_STATUSES = [
  'تم قبول الطلب',
  'الكابتن وصل للاستلام',
  'استلم الطرد وفي السكة',
  'الكابتن وصل للتسليم'
];

const MAX_MANUAL_WALLET_TX = 5000;
const REFERRAL_REWARD_CASH = 50;
const REFERRAL_TARGET_ORDERS = 2;

// تشفير قياسي آمن جداً لكلمات المرور على السيرفر فقط (Node.js Native crypto.scrypt)
function hashPasswordSecure(plainText) {
  const str = String(plainText ?? '');
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(str, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return `scrypt$16384$8$1$${salt}$${derivedKey}`;
}

// دالة التشفير القديمة فقط للتحقق عند ترقية الحسابات القديمة تلقائياً إلى scrypt
function legacyFnVHash(plainText) {
  const str = String(plainText ?? '');
  if (str.startsWith('ennaby_h1$')) return str;
  let h1 = 0x811c9dc5;
  let h2 = 0x1000193;
  const salted = `ENNABY_SALT_V31::${str}::MANSOURA`;
  for (let i = 0; i < salted.length; i++) {
    const ch = salted.charCodeAt(i);
    h1 ^= ch;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = ((h2 << 5) + h2 + ch) >>> 0;
  }
  return `ennaby_h1$${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

function verifyPasswordSecure(inputPlain, storedHash) {
  if (!inputPlain || !storedHash) return { valid: false, needsRehash: false };
  const plain = String(inputPlain);
  const stored = String(storedHash);

  if (stored.startsWith('scrypt$')) {
    try {
      const parts = stored.split('$');
      const N = Number(parts[1]) || 16384;
      const r = Number(parts[2]) || 8;
      const p = Number(parts[3]) || 1;
      const salt = parts[4];
      const keyHex = parts[5];
      if (!salt || !keyHex) return { valid: false, needsRehash: false };
      const keyBuf = Buffer.from(keyHex, 'hex');
      const derivedBuf = crypto.scryptSync(plain, salt, keyBuf.length, { N, r, p });
      const match = keyBuf.length === derivedBuf.length && crypto.timingSafeEqual(keyBuf, derivedBuf);
      return { valid: match, needsRehash: false };
    } catch (e) {
      return { valid: false, needsRehash: false };
    }
  }

  // دعم الترقية التلقائية للحسابات المخزنة سابقاً بـ ennaby_h1$
  if (stored.startsWith('ennaby_h1$')) {
    const match = legacyFnVHash(plain) === stored;
    return { valid: match, needsRehash: match };
  }

  return { valid: false, needsRehash: false };
}

function normalizeDigits(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632))
    .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776));
}

function normalizePhone(raw) {
  let s = normalizeDigits(raw).replace(/[\s\-()]/g, '');
  if (s.startsWith('+20')) s = '0' + s.slice(3);
  else if (s.startsWith('0020')) s = '0' + s.slice(4);
  else if (s.startsWith('20') && s.length === 12 && /^201[0125]\d{8}$/.test(s)) s = '0' + s.slice(2);
  return s;
}

function isValidEgyptianPhone(phone) {
  return /^01[0125][0-9]{8}$/.test(normalizePhone(phone));
}

function normalizeWhatsappNumber(raw) {
  let s = normalizeDigits(raw).replace(/[^0-9]/g, '');
  if (/^01[0125]\d{8}$/.test(s)) s = '2' + s;
  else if (s.startsWith('0020')) s = s.slice(2);
  return /^20\d{10}$/.test(s) ? s : '';
}

function roundMoney(val) {
  const num = Number(normalizeDigits(val));
  if (!Number.isFinite(num)) return 0;
  return Math.round((num + Number.EPSILON) * 100) / 100;
}

function formatCairoDateTime(ts) {
  const num = Number(ts) || Date.now();
  try {
    return new Date(num).toLocaleString('ar-EG', {
      timeZone: 'Africa/Cairo',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (e) {
    return new Date(num).toISOString();
  }
}

function maskPhone(phone) {
  const p = String(phone || '').trim();
  if (p.length < 7) return 'مخفي للخصوصية 🔒';
  return p.slice(0, 3) + '*****' + p.slice(-3);
}

// توليد رقم طلب فريد لا يتصادم أبداً باستخدام crypto.randomUUID
function generateOrderId() {
  const randomHex = crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase();
  return `ORD-${randomHex}`;
}

function orderStatusToDb(arStatus) {
  const s = String(arStatus || '').trim();
  if (s === 'في انتظار كابتن' || s === 'PENDING') return 'PENDING';
  if (s === 'تم قبول الطلب' || s === 'الكابتن وصل للاستلام' || s === 'ACCEPTED') return 'ACCEPTED';
  if (s === 'استلم الطرد وفي السكة' || s === 'الكابتن وصل للتسليم' || s === 'IN_TRANSIT') return 'IN_TRANSIT';
  if (s === 'مكتمل' || s === 'COMPLETED') return 'COMPLETED';
  if (s === 'قيد مراجعة الاعتراض' || s === 'DISPUTED') return 'DISPUTED';
  if (s.includes('ملغي') || s === 'CANCELLED') return 'CANCELLED';
  return 'PENDING';
}

function resolveExactOrderStatus(orderRow) {
  if (orderRow.exact_status && String(orderRow.exact_status).trim()) {
    return String(orderRow.exact_status).trim();
  }
  const s = String(orderRow.status || '').trim().toUpperCase();
  if (s === 'PENDING') return 'في انتظار كابتن';
  if (s === 'ACCEPTED') return 'تم قبول الطلب';
  if (s === 'IN_TRANSIT' || s === 'PICKED_UP') return 'استلم الطرد وفي السكة';
  if (s === 'COMPLETED' || s === 'DELIVERED') return 'مكتمل';
  if (s === 'DISPUTED') return 'قيد مراجعة الاعتراض';
  if (s.includes('CANCEL')) return 'ملغي من العميل';
  return orderRow.status || 'في انتظار كابتن';
}

function captainStatusToDb(arStatus) {
  const s = String(arStatus || '').trim();
  if (s === 'معتمد' || s === 'APPROVED') return 'APPROVED';
  if (s === 'موقوف' || s === 'SUSPENDED') return 'SUSPENDED';
  if (s === 'مرفوض' || s === 'REJECTED') return 'REJECTED';
  return 'PENDING';
}

function captainStatusFromDb(dbStatus) {
  const s = String(dbStatus || '').trim().toUpperCase();
  if (s === 'APPROVED' || s === 'ACTIVE' || dbStatus === 'معتمد') return 'معتمد';
  if (s === 'SUSPENDED' || dbStatus === 'موقوف') return 'موقوف';
  if (s === 'REJECTED' || dbStatus === 'مرفوض') return 'مرفوض';
  return 'قيد المراجعة';
}

// ============================================================================
// 4. إدارة الكوكيز والتوكن والتحقق من الصلاحيات (JWT + RBAC Middlewares)
// ============================================================================
function setRoleCookie(res, cookieName, payload, maxAgeMs) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: Math.floor(maxAgeMs / 1000) });
  res.cookie(cookieName, token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeMs
  });
  return token;
}

function clearRoleCookie(res, cookieName) {
  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    path: '/'
  });
}

function verifyTokenFromReq(req, cookieName) {
  try {
    let token = req.cookies ? req.cookies[cookieName] : null;
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.slice(7);
    }
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

async function getAuthenticatedAdmin(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_adm_token');
  if (!decoded || decoded.role !== 'admin' || !decoded.username) return null;

  const { data: admin } = await supabase
    .from('admins')
    .select('*')
    .eq('username', decoded.username)
    .maybeSingle();

  if (!admin) return null;
  if (!admin.is_master && (String(admin.status).toUpperCase() === 'DISABLED' || admin.status === 'معطل')) {
    return null;
  }
  if (decoded.sessionVersion && admin.session_version && Number(decoded.sessionVersion) !== Number(admin.session_version)) {
    return null;
  }
  return admin;
}

async function getAuthenticatedCaptain(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_cour_token');
  if (!decoded || decoded.role !== 'captain' || !decoded.phone) return null;

  const { data: captain } = await supabase
    .from('captains')
    .select('*')
    .eq('phone', normalizePhone(decoded.phone))
    .maybeSingle();

  return captain || null;
}

async function getAuthenticatedCustomer(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_cust_token') || verifyTokenFromReq(req, 'ennaby_token');
  if (!decoded || decoded.role !== 'customer' || !decoded.phone) return null;

  const { data: customer } = await supabase
    .from('customers')
    .select('*')
    .eq('phone', normalizePhone(decoded.phone))
    .maybeSingle();

  return customer || null;
}

function requireAdmin(permKey = null) {
  return async (req, res, next) => {
    try {
      const admin = await getAuthenticatedAdmin(req);
      if (!admin) {
        return res.status(401).json({ success: false, message: 'انتهت جلسة الإدارة أو غير مصرح لك بالدخول، يرجى تسجيل الدخول أولاً 🔒' });
      }
      if (permKey === 'MASTER_ONLY' && !admin.is_master) {
        await recordAuditLogInDb({
          actor: `${admin.name} (${admin.username})`,
          actionType: 'محاولة غير مصرح بها',
          target: 'إدارة المسؤولين',
          details: 'محاولة وصول لقسم الأدمن الرئيسي فقط',
          result: 'مرفوض ⛔'
        });
        return res.status(403).json({ success: false, message: 'هذا الإجراء مخصص للأدمن الرئيسي فقط 👑⛔' });
      }
      if (permKey && permKey !== 'MASTER_ONLY' && !admin.is_master) {
        const perms = admin.permissions || {};
        if (!perms[permKey]) {
          await recordAuditLogInDb({
            actor: `${admin.name} (${admin.username})`,
            actionType: 'محاولة غير مصرح بها',
            target: permKey,
            details: `محاولة تنفيذ إجراء بدون صلاحية (${permKey})`,
            result: 'مرفوض ⛔'
          });
          return res.status(403).json({ success: false, message: 'حسابك الإداري لا يملك صلاحية تنفيذ هذا الإجراء 🛡️⛔' });
        }
      }
      req.admin = admin;
      next();
    } catch (err) {
      console.error('Admin Auth Middleware Error:', err);
      res.status(500).json({ success: false, message: 'خطأ في التحقق من صلاحية المسؤول' });
    }
  };
}

async function requireCaptain(req, res, next) {
  try {
    const captain = await getAuthenticatedCaptain(req);
    if (!captain) {
      return res.status(401).json({ success: false, message: 'يرجى تسجيل دخول الكابتن أولاً 🛵🔒' });
    }
    req.captain = captain;
    next();
  } catch (err) {
    res.status(500).json({ success: false, message: 'خطأ في التحقق من جلسة الكابتن' });
  }
}

// ============================================================================
// 5. العمليات المالية الذرية (Atomic Transactions) وتخزين المستندات الآمن
// ============================================================================
async function adjustCustomerWalletAtomic({ customerId, delta, type, title, orderId = null, byAdmin = 'SYSTEM' }) {
  const cleanDelta = roundMoney(delta);
  const txTypeDb = cleanDelta < 0 ? 'DEBIT' : 'CREDIT';

  // المحاولة الأولى: استخدام دالة PostgreSQL الذرية (SELECT ... FOR UPDATE)
  const { data: rpcBal, error: rpcErr } = await supabase.rpc('adjust_customer_wallet_atomic', {
    p_customer_id: customerId,
    p_delta: cleanDelta,
    p_tx_type: txTypeDb,
    p_title: String(title || 'حركة مالية'),
    p_order_id: orderId,
    p_performed_by: byAdmin || 'SYSTEM'
  });

  if (!rpcErr && rpcBal !== null && rpcBal !== undefined) {
    return roundMoney(rpcBal);
  }

  // مسار احتياطي متوافق في حال لم يتم تنفيذ ملف الـ SQL للـ RPC بعد
  const { data: cust, error: fetchErr } = await supabase
    .from('customers')
    .select('id, wallet_balance')
    .eq('id', customerId)
    .single();

  if (fetchErr || !cust) throw new Error('العميل غير موجود');
  const newBalance = roundMoney(Number(cust.wallet_balance || 0) + cleanDelta);
  if (newBalance < 0) throw new Error('رصيد محفظة العميل غير كافٍ');

  const { error: upErr } = await supabase
    .from('customers')
    .update({ wallet_balance: newBalance })
    .eq('id', customerId);
  if (upErr) throw upErr;

  const { error: txErr } = await supabase.from('wallet_transactions').insert([{
    user_type: 'CUSTOMER',
    customer_id: customerId,
    order_id: orderId,
    type: txTypeDb,
    amount: Math.abs(cleanDelta),
    title: String(title || ''),
    description: String(title || ''),
    performed_by: byAdmin || 'SYSTEM'
  }]);
  if (txErr) console.error('[Wallet Transaction Log Error - Customer]:', txErr.message);

  return newBalance;
}

async function adjustCaptainWalletAtomic({ captainId, delta, type, title, orderId = null, byAdmin = 'SYSTEM', allowNegativeClamp = false }) {
  const cleanDelta = roundMoney(delta);
  const txTypeDb = cleanDelta < 0 ? 'DEBIT' : 'CREDIT';

  const { data: rpcBal, error: rpcErr } = await supabase.rpc('adjust_captain_wallet_atomic', {
    p_captain_id: captainId,
    p_delta: cleanDelta,
    p_tx_type: txTypeDb,
    p_title: String(title || 'حركة مالية'),
    p_order_id: orderId,
    p_performed_by: byAdmin || 'SYSTEM',
    p_allow_negative: Boolean(allowNegativeClamp)
  });

  if (!rpcErr && rpcBal !== null && rpcBal !== undefined) {
    return roundMoney(rpcBal);
  }

  const { data: cap, error: fetchErr } = await supabase
    .from('captains')
    .select('id, wallet_balance')
    .eq('id', captainId)
    .single();

  if (fetchErr || !cap) throw new Error('الكابتن غير موجود');
  let newBalance = roundMoney(Number(cap.wallet_balance || 0) + cleanDelta);
  if (newBalance < 0 && !allowNegativeClamp) {
    throw new Error('رصيد محفظة الكابتن غير كافٍ');
  }
  if (newBalance < 0) newBalance = 0;

  const { error: upErr } = await supabase
    .from('captains')
    .update({ wallet_balance: newBalance })
    .eq('id', captainId);
  if (upErr) throw upErr;

  const { error: txErr } = await supabase.from('wallet_transactions').insert([{
    user_type: 'CAPTAIN',
    captain_id: captainId,
    order_id: orderId,
    type: txTypeDb,
    amount: Math.abs(cleanDelta),
    title: String(title || ''),
    description: String(title || ''),
    performed_by: byAdmin || 'SYSTEM'
  }]);
  if (txErr) console.error('[Wallet Transaction Log Error - Captain]:', txErr.message);

  return newBalance;
}

async function recordAuditLogInDb({ actor, actionType, target, details, result = 'نجاح' }) {
  const { error } = await supabase.from('audit_logs').insert([{
    actor: String(actor || 'النظام'),
    action_type: String(actionType || 'عملية إدارية'),
    action: String(actionType || 'عملية إدارية'),
    target: String(target || '-'),
    details: String(details || ''),
    result: String(result || 'نجاح')
  }]);
  if (error) {
    console.warn('[Audit Log Insert Warning]:', error.message);
  }
}

// رفع مستندات الكابتن مع فحص صارم للنوع والحجم (أقصى حد 5 ميجابايت للصورة) وحفظ المسار الدائم
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME_TYPES = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp'
};

async function uploadCaptainDocumentSecure(phone, docKey, dataUrl) {
  if (!dataUrl || typeof dataUrl !== 'string') return null;
  if (dataUrl.startsWith('storage://') || dataUrl.startsWith('https://')) return dataUrl;

  const matches = dataUrl.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
  if (!matches) {
    throw new Error(`صيغة صورة (${docKey}) غير صالحة`);
  }

  const mimeType = matches[1].toLowerCase();
  const ext = ALLOWED_MIME_TYPES[mimeType];
  if (!ext) {
    throw new Error('نوع الصورة غير مدعوم! يرجى رفع صورة بصيغة JPG أو PNG أو WEBP فقط');
  }

  const buffer = Buffer.from(matches[2], 'base64');
  if (buffer.length > MAX_IMAGE_BYTES) {
    throw new Error('حجم الصورة يتجاوز الحد الأقصى المسموح (5 ميجابايت)');
  }

  const filePath = `captains/${normalizePhone(phone)}_${docKey}_${Date.now()}.${ext}`;
  const { error: upErr } = await supabase.storage
    .from('captain-docs')
    .upload(filePath, buffer, { contentType: mimeType, upsert: true });

  if (upErr) {
    console.error('[Storage Upload Error]:', upErr.message);
    throw new Error('تعذر رفع الصورة إلى خزنة المستندات السحابية');
  }

  return `storage://captain-docs/${filePath}`;
}

async function resolveStorageUrlForAdmin(storedRef) {
  if (!storedRef || typeof storedRef !== 'string') return null;
  if (storedRef.startsWith('storage://captain-docs/')) {
    const filePath = storedRef.replace('storage://captain-docs/', '');
    const { data } = await supabase.storage
      .from('captain-docs')
      .createSignedUrl(filePath, 2 * 60 * 60); // رابط موقع مؤقت لمدة ساعتين للإدارة فقط
    return (data && data.signedUrl) ? data.signedUrl : null;
  }
  return storedRef;
}

// ============================================================================
// 6. قراءة وتحديث الإعدادات والمناطق والتسعير من جدول settings السحابي
// ============================================================================
async function getPlatformConfigFromDb() {
  const { data: rows } = await supabase.from('settings').select('*').limit(1);
  const sRow = (rows && rows[0]) ? rows[0] : {};

  const zones = Array.isArray(sRow.zones_json) && sRow.zones_json.length > 0
    ? sRow.zones_json
    : DEFAULT_ZONES;

  const pricing = (sRow.pricing_json && typeof sRow.pricing_json === 'object' && Object.keys(sRow.pricing_json).length > 0)
    ? sRow.pricing_json
    : DEFAULT_PRICING;

  const packageTypes = Array.isArray(sRow.package_types_json) && sRow.package_types_json.length > 0
    ? sRow.package_types_json
    : DEFAULT_PACKAGE_TYPES;

  const settings = {
    platformFee: sRow.platform_fee !== undefined && sRow.platform_fee !== null ? roundMoney(sRow.platform_fee) : DEFAULT_SETTINGS.platformFee,
    customerPointsPerOrder: Number(sRow.customer_points_per_order) > 0 ? Number(sRow.customer_points_per_order) : DEFAULT_SETTINGS.customerPointsPerOrder,
    customerRewardThreshold: Number(sRow.customer_reward_threshold) >= 5 ? Number(sRow.customer_reward_threshold) : DEFAULT_SETTINGS.customerRewardThreshold,
    customerRewardCash: Number(sRow.customer_reward_cash) > 0 ? roundMoney(sRow.customer_reward_cash) : DEFAULT_SETTINGS.customerRewardCash,
    courierPointsPerOrder: Number(sRow.courier_points_per_order) > 0 ? Number(sRow.courier_points_per_order) : DEFAULT_SETTINGS.courierPointsPerOrder,
    courierRewardThreshold: Number(sRow.courier_reward_threshold) >= 5 ? Number(sRow.courier_reward_threshold) : DEFAULT_SETTINGS.courierRewardThreshold,
    courierRewardCash: Number(sRow.courier_reward_cash) > 0 ? roundMoney(sRow.courier_reward_cash) : DEFAULT_SETTINGS.courierRewardCash,
    supportWhatsapp: sRow.support_whatsapp || DEFAULT_SETTINGS.supportWhatsapp,
    broadcastMessage: sRow.broadcast_message !== undefined && sRow.broadcast_message !== null ? String(sRow.broadcast_message) : '',
    maintenanceMode: Boolean(sRow.maintenance_mode),
    allowCaptainRegistration: sRow.allow_captain_registration !== undefined && sRow.allow_captain_registration !== null ? Boolean(sRow.allow_captain_registration) : true,
    waitingTimeoutMinutes: sRow.waiting_timeout_minutes !== undefined && sRow.waiting_timeout_minutes !== null ? Number(sRow.waiting_timeout_minutes) : 30,
    packageTypes
  };

  return { settings, zones, pricing, settingsRowId: sRow.id || 1 };
}

// تهيئة جدول settings وحساب الأدمن الأولي من متغيرات البيئة فقط (بدون أي باسورد افتراضي في الكود)
async function initializeDatabaseOnStartup() {
  try {
    const { data: existingSettings } = await supabase.from('settings').select('id').limit(1);
    if (!existingSettings || existingSettings.length === 0) {
      await supabase.from('settings').insert([{
        id: 1,
        platform_fee: DEFAULT_SETTINGS.platformFee,
        support_whatsapp: DEFAULT_SETTINGS.supportWhatsapp,
        broadcast_message: '',
        maintenance_mode: false,
        allow_captain_registration: true,
        waiting_timeout_minutes: 30
      }]);
    }

    const { data: existingAdmins } = await supabase.from('admins').select('id, username, password_hash');
    if (!existingAdmins || existingAdmins.length === 0) {
      const initUser = (process.env.INITIAL_ADMIN_USER || '').trim();
      const initPass = (process.env.INITIAL_ADMIN_PASS || '').trim();
      if (initUser && initPass) {
        await supabase.from('admins').insert([{
          username: initUser,
          password_hash: hashPasswordSecure(initPass),
          name: 'الأدمن الرئيسي',
          is_master: true,
          status: 'ACTIVE',
          session_version: 1,
          permissions: {
            viewDashboard: true, viewCaptains: true, manageCaptains: true,
            viewOrders: true, manageOrders: true, manageWallets: true,
            manageCommissions: true, managePricing: true, manageSettings: true
          }
        }]);
        console.log(`✅ [Security Init] تم إنشاء حساب الأدمن الرئيسي (${initUser}) المشفر بـ scrypt من متغيرات البيئة.`);
      } else {
        console.warn('⚠️ [تنبيه] جدول admins فارغ حالياً. لإضافة أدمن رئيسي أول مرة، ضع INITIAL_ADMIN_USER و INITIAL_ADMIN_PASS في ملف .env');
      }
    }
  } catch (err) {
    console.warn('[Startup Init Warning]:', err.message);
  }
}

// ============================================================================
// 7. بناء الحالة المفلترة حسب الصلاحيات والدور (Role-Filtered State Builder)
//    لا يُسرّب أبداً كلمات المرور أو بيانات المستخدمين الآخرين!
// ============================================================================
async function buildScopedStateForRequest(req) {
  const [config, adminUser, captainUser, customerUser] = await Promise.all([
    getPlatformConfigFromDb(),
    getAuthenticatedAdmin(req),
    getAuthenticatedCaptain(req),
    getAuthenticatedCustomer(req)
  ]);

// مسار للأدمن لإعادة تعيين كلمة مرور كابتن يطلبها عبر دعم الواتساب
app.post('/api/admin/captains/reset-password', requireAdmin('manageCaptains'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const newPass = String(req.body.newPass || '').trim();

    if (!isValidEgyptianPhone(phone) || !newPass || newPass.length < 4) {
      return res.status(400).json({ success: false, message: 'رقم الهاتف أو كلمة المرور الجديدة غير صالحة (يجب ألا تقل عن 4 أحرف) ⚠️' });
    }

    const { data: cap } = await supabase.from('captains').select('id, full_name').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير مسجل في المنصة ⚠️' });

    const newHash = hashPasswordSecure(newPass);
    const { error } = await supabase.from('captains').update({ password_hash: newHash }).eq('id', cap.id);
    if (error) throw error;

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: 'إعادة تعيين كلمة مرور كابتن',
      target: `${cap.full_name} (${phone})`,
      details: 'تم تعيين كلمة مرور جديدة بناءً على طلب الدعم عبر واتساب'
    });

    res.json({
      success: true,
      message: `تم تغيير كلمة المرور للكابتن (${cap.full_name}) بنجاح. أرسلها له على الواتساب 🔑✅`
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إعادة تعيين كلمة المرور' });
  }
});

  const { settings, zones, pricing } = config;
  const resultState = {
    settings,
    zones,
    pricing,
    customers: {},
    captains: [],
    orders: [],
    adminAccounts: [],
    auditLogs: []
  };

  // أ) إذا كان المستخدم أدمن موثقاً: نُرجع فقط الأقسام المصرح له بها بدون أي كلمات مرور أو هاش!
  if (adminUser) {
    const perms = adminUser.is_master ? {
      viewDashboard: true, viewCaptains: true, manageCaptains: true,
      viewOrders: true, manageOrders: true, manageWallets: true,
      manageCommissions: true, managePricing: true, manageSettings: true
    } : (adminUser.permissions || {});

    const [
      { data: dbCustomers },
      { data: dbCaptains },
      { data: dbOrders },
      { data: dbAdmins },
      { data: dbWalletTxs },
      { data: dbAuditLogs },
      { data: dbAlerts }
    ] = await Promise.all([
      (perms.viewDashboard || perms.manageWallets || perms.viewOrders || perms.manageOrders)
        ? supabase.from('customers').select('*').order('created_at', { ascending: false }).limit(500)
        : Promise.resolve({ data: [] }),
      (perms.viewDashboard || perms.viewCaptains || perms.manageCaptains || perms.manageWallets || perms.manageCommissions || perms.viewOrders)
        ? supabase.from('captains').select('*').order('created_at', { ascending: true })
        : Promise.resolve({ data: [] }),
      (perms.viewDashboard || perms.viewOrders || perms.manageOrders || perms.viewCaptains)
        ? supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(300)
        : Promise.resolve({ data: [] }),
      supabase.from('admins').select('id, username, name, is_master, status, created_at, session_version, permissions').order('created_at', { ascending: true }),
      (perms.viewDashboard || perms.manageWallets)
        ? supabase.from('wallet_transactions').select('*').order('created_at', { ascending: false }).limit(200)
        : Promise.resolve({ data: [] }),
      (adminUser.is_master || perms.viewDashboard)
        ? supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(150)
        : Promise.resolve({ data: [] }),
      supabase.from('system_alerts').select('*').order('created_at', { ascending: false }).limit(100)
    ]);

    const customerIdToPhone = {};
    (dbCustomers || []).forEach(c => {
      const ph = normalizePhone(c.phone);
      if (!ph) return;
      customerIdToPhone[c.id] = ph;
      resultState.customers[ph] = {
        id: c.id,
        phone: ph,
        walletBalance: roundMoney(c.wallet_balance || 0),
        points: Math.max(0, Number(c.points) || 0),
        walletTransactions: []
      };
    });

    const captainIdToPhone = {};
    const captainTxMap = {};
    (dbCaptains || []).forEach(cap => {
      const ph = normalizePhone(cap.phone);
      if (ph) {
        captainIdToPhone[cap.id] = ph;
        captainTxMap[ph] = [];
      }
    });

    (dbWalletTxs || []).forEach(t => {
      const isDebit = String(t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم';
      const ts = t.created_at ? new Date(t.created_at).getTime() : Date.now();
      const txItem = {
        type: isDebit ? 'خصم' : 'إيداع',
        amount: roundMoney(t.amount || 0),
        title: t.title || t.description || 'حركة مالية',
        at: ts,
        time: formatCairoDateTime(ts),
        by: t.performed_by && t.performed_by !== 'SYSTEM' ? t.performed_by : null
      };
      if (t.customer_id && customerIdToPhone[t.customer_id] && resultState.customers[customerIdToPhone[t.customer_id]]) {
        resultState.customers[customerIdToPhone[t.customer_id]].walletTransactions.push(txItem);
      } else if (t.captain_id && captainIdToPhone[t.captain_id] && captainTxMap[captainIdToPhone[t.captain_id]]) {
        captainTxMap[captainIdToPhone[t.captain_id]].push(txItem);
      }
    });

    resultState.captains = await Promise.all((dbCaptains || []).map(async c => {
      const ph = normalizePhone(c.phone);
      const canSeeDocs = perms.viewCaptains || perms.manageCaptains;
      const [frontUrl, backUrl, vehUrl] = canSeeDocs ? await Promise.all([
        resolveStorageUrlForAdmin(c.id_front_url),
        resolveStorageUrlForAdmin(c.id_back_url),
        resolveStorageUrlForAdmin(c.vehicle_photo_url)
      ]) : [null, null, null];

      const notices = Array.isArray(c.admin_notices_json) && c.admin_notices_json.length > 0
        ? c.admin_notices_json
        : (dbAlerts || []).filter(a => a.captain_id === c.id && !a.is_dismissed).map(a => ({
            id: String(a.id),
            type: a.alert_type || 'info',
            text: a.message,
            at: a.created_at ? new Date(a.created_at).getTime() : Date.now()
          }));

      return {
        id: c.id,
        phone: ph,
        fullName: c.full_name || 'كابتن عنابي',
        nationalId: canSeeDocs ? (c.national_id || '') : 'مخفي 🔒',
        primaryZone: c.primary_zone || 'المنصورة',
        vehicleType: c.vehicle_type || 'موتوسيكل',
        plateNumber: c.plate_number || 'دراجة معفية',
        idFrontPhoto: frontUrl,
        idBackPhoto: backUrl,
        vehiclePhoto: vehUrl,
        walletBalance: roundMoney(c.wallet_balance ?? 0),
        walletTransactions: captainTxMap[ph] || [],
        points: Math.max(0, Number(c.points) || 0),
        status: captainStatusFromDb(c.status),
        suspendReason: c.suspend_reason || '',
        rejectReason: c.reject_reason || '',
        isAvailable: Boolean(c.is_available),
        customFee: c.custom_fee !== undefined && c.custom_fee !== null ? roundMoney(c.custom_fee) : null,
        customFeeReason: c.custom_fee_reason || '',
        adminNotices: notices,
        referredByPhone: c.referred_by_phone || '',
        referralRewardPaid: Boolean(c.referral_reward_paid),
        referralsCount: Math.max(0, Number(c.referrals_count) || 0),
        lifetimeCompleted: Math.max(0, Number(c.lifetime_completed) || 0),
        lifetimeCancelled: Math.max(0, Number(c.lifetime_cancelled) || 0),
        lifetimeNetEarnings: roundMoney(c.lifetime_net_earnings ?? 0)
      };
    }));

    resultState.orders = (dbOrders || []).map(o => formatOrderRowForClient(o, customerIdToPhone, captainIdToPhone, 'admin'));

    resultState.adminAccounts = (dbAdmins || [])
      .filter(a => adminUser.is_master || a.username === adminUser.username)
      .map((a, idx) => ({
        id: a.id || ('ADM-' + (idx + 1)),
        username: a.username,
        name: a.name || 'مسؤول المنصة',
        isMaster: Boolean(a.is_master),
        status: (String(a.status || '').toUpperCase() === 'DISABLED' || a.status === 'معطل') ? 'معطل' : 'نشط',
        createdAt: a.created_at ? new Date(a.created_at).getTime() : Date.now(),
        sessionVersion: Number(a.session_version) || 1,
        permissions: a.is_master ? {
          viewDashboard: true, viewCaptains: true, manageCaptains: true,
          viewOrders: true, manageOrders: true, manageWallets: true,
          manageCommissions: true, managePricing: true, manageSettings: true
        } : (a.permissions || {})
      }));

    resultState.auditLogs = (dbAuditLogs || []).map(l => {
      const ts = l.created_at ? new Date(l.created_at).getTime() : Date.now();
      return {
        id: String(l.id || ('AUD-' + ts)),
        actor: l.actor || 'الإدارة',
        actionType: l.action_type || l.action || 'عملية إدارية',
        target: l.target || '-',
        details: l.details || '',
        result: l.result || 'نجاح',
        at: ts,
        time: formatCairoDateTime(ts)
      };
    });

    return resultState;
  }

  // ب) إذا كان المستخدم كابتن موثقاً: نُرجع بيانات هذا الكابتن فقط + طلبات الرادار وطلباته الخاصة
  if (captainUser) {
    const capPh = normalizePhone(captainUser.phone);
    const [
      { data: capTxs },
      { data: capAlerts },
      { data: radarAndMyOrders }
    ] = await Promise.all([
      supabase.from('wallet_transactions').select('*').eq('captain_id', captainUser.id).order('created_at', { ascending: false }).limit(60),
      supabase.from('system_alerts').select('*').eq('captain_id', captainUser.id).eq('is_dismissed', false).order('created_at', { ascending: false }).limit(20),
      supabase.from('orders').select('*').or(`status.eq.PENDING,captain_id.eq.${captainUser.id}`).order('created_at', { ascending: false }).limit(120)
    ]);

    const formattedTxs = (capTxs || []).map(t => {
      const isDebit = String(t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم';
      const ts = t.created_at ? new Date(t.created_at).getTime() : Date.now();
      return {
        type: isDebit ? 'خصم' : 'إيداع',
        amount: roundMoney(t.amount || 0),
        title: t.title || t.description || 'حركة مالية',
        at: ts,
        time: formatCairoDateTime(ts),
        by: t.performed_by && t.performed_by !== 'SYSTEM' ? t.performed_by : null
      };
    });

    const notices = Array.isArray(captainUser.admin_notices_json) && captainUser.admin_notices_json.length > 0
      ? captainUser.admin_notices_json
      : (capAlerts || []).map(a => ({
          id: String(a.id),
          type: a.alert_type || 'info',
          text: a.message,
          at: a.created_at ? new Date(a.created_at).getTime() : Date.now()
        }));

    resultState.captains = [{
      id: captainUser.id,
      phone: capPh,
      fullName: captainUser.full_name || 'كابتن عنابي',
      nationalId: captainUser.national_id || '',
      primaryZone: captainUser.primary_zone || 'المنصورة',
      vehicleType: captainUser.vehicle_type || 'موتوسيكل',
      plateNumber: captainUser.plate_number || 'دراجة معفية',
      walletBalance: roundMoney(captainUser.wallet_balance ?? 0),
      walletTransactions: formattedTxs,
      points: Math.max(0, Number(captainUser.points) || 0),
      status: captainStatusFromDb(captainUser.status),
      suspendReason: captainUser.suspend_reason || '',
      rejectReason: captainUser.reject_reason || '',
      isAvailable: Boolean(captainUser.is_available),
      customFee: captainUser.custom_fee !== undefined && captainUser.custom_fee !== null ? roundMoney(captainUser.custom_fee) : null,
      customFeeReason: captainUser.custom_fee_reason || '',
      adminNotices: notices,
      referredByPhone: captainUser.referred_by_phone || '',
      referralRewardPaid: Boolean(captainUser.referral_reward_paid),
      referralsCount: Math.max(0, Number(captainUser.referrals_count) || 0),
      lifetimeCompleted: Math.max(0, Number(captainUser.lifetime_completed) || 0),
      lifetimeCancelled: Math.max(0, Number(captainUser.lifetime_cancelled) || 0),
      lifetimeNetEarnings: roundMoney(captainUser.lifetime_net_earnings ?? 0)
    }];

    const capIdMap = { [captainUser.id]: capPh };
    resultState.orders = (radarAndMyOrders || []).map(o => formatOrderRowForClient(o, {}, capIdMap, 'captain', capPh));
  }

  // ج) إذا كان المستخدم عميلاً موثقاً: نُرجع محفظته ونقاطه وطلباته الخاصة فقط!
  if (customerUser) {
    const custPh = normalizePhone(customerUser.phone);
    const [
      { data: custTxs },
      { data: custOrders }
    ] = await Promise.all([
      supabase.from('wallet_transactions').select('*').eq('customer_id', customerUser.id).order('created_at', { ascending: false }).limit(50),
      supabase.from('orders').select('*').eq('customer_id', customerUser.id).order('created_at', { ascending: false }).limit(60)
    ]);

    resultState.customers[custPh] = {
      id: customerUser.id,
      phone: custPh,
      walletBalance: roundMoney(customerUser.wallet_balance || 0),
      points: Math.max(0, Number(customerUser.points) || 0),
      walletTransactions: (custTxs || []).map(t => {
        const isDebit = String(t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم';
        const ts = t.created_at ? new Date(t.created_at).getTime() : Date.now();
        return {
          type: isDebit ? 'خصم' : 'إيداع',
          amount: roundMoney(t.amount || 0),
          title: t.title || t.description || 'حركة مالية',
          at: ts,
          time: formatCairoDateTime(ts),
          by: t.performed_by && t.performed_by !== 'SYSTEM' ? t.performed_by : null
        };
      })
    };

    const custIdMap = { [customerUser.id]: custPh };
    const existingOrderIds = new Set(resultState.orders.map(o => o.id));
    (custOrders || []).forEach(o => {
      if (!existingOrderIds.has(o.id)) {
        resultState.orders.push(formatOrderRowForClient(o, custIdMap, {}, 'customer'));
      }
    });
  }

  return resultState;
}

function formatOrderRowForClient(o, customerIdToPhone, captainIdToPhone, viewerRole, viewerPhone = '') {
  const createdAt = o.created_at ? new Date(o.created_at).getTime() : Date.now();
  const isFetch = String(o.trip_type || '').toUpperCase() === 'FETCH';
  const arStatus = resolveExactOrderStatus(o);
  const resolvedClientPhone = (o.customer_id && customerIdToPhone[o.customer_id])
    || (isFetch ? normalizePhone(o.recipient_phone) : normalizePhone(o.sender_phone));
  const resolvedCourierPhone = (o.captain_id && captainIdToPhone[o.captain_id]) || null;

  // حماية الخصوصية: إخفاء أرقام هواتف العميل والمستلم عن الكابتن قبل القبول أو بعد التسليم النهائي
  const isWaiting = arStatus === 'في انتظار كابتن';
  const isDelivered = arStatus === 'مكتمل' || arStatus === 'قيد مراجعة الاعتراض';
  const shouldMaskPhonesForCaptain = viewerRole === 'captain' && (isWaiting || isDelivered || resolvedCourierPhone !== viewerPhone);

  return {
    id: o.id,
    createdAt,
    pickedUpAt: o.picked_up_at ? new Date(o.picked_up_at).getTime() : null,
    deliveredAt: o.delivered_at ? new Date(o.delivered_at).getTime() : null,
    time: formatCairoDateTime(createdAt),
    tripType: isFetch ? 'fetch' : 'send',
    clientPhone: shouldMaskPhonesForCaptain ? maskPhone(resolvedClientPhone) : resolvedClientPhone,
    customerPhone: shouldMaskPhonesForCaptain ? maskPhone(resolvedClientPhone) : resolvedClientPhone,
    senderPhone: shouldMaskPhonesForCaptain ? maskPhone(o.sender_phone) : normalizePhone(o.sender_phone),
    recipientPhone: shouldMaskPhonesForCaptain ? maskPhone(o.recipient_phone) : normalizePhone(o.recipient_phone),
    otherPartyPhone: shouldMaskPhonesForCaptain
      ? 'مخفي للخصوصية 🔒'
      : (isFetch ? normalizePhone(o.sender_phone) : normalizePhone(o.recipient_phone)),
    pickupZone: o.pickup_zone || 'المنصورة',
    pickupAddress: o.pickup_address || '',
    dropoffZone: o.dropoff_zone || 'المنصورة',
    dropoffAddress: o.dropoff_address || '',
    customerNotes: o.customer_notes || '',
    packageType: o.package_type || '',
    originalFare: roundMoney(o.original_fare ?? o.fare ?? 0),
    discountApplied: roundMoney(o.discount_applied ?? 0),
    fare: roundMoney(o.fare ?? 0),
    platformFee: roundMoney(o.platform_fee ?? 7),
    courierNet: roundMoney(o.courier_net ?? 0),
    payer: o.payer || 'الراسل',
    status: arStatus,
    assignedCourierPhone: isWaiting ? null : resolvedCourierPhone,
    feeDeducted: Boolean(o.fee_deducted ?? !isWaiting),
    feeRefunded: Boolean(o.fee_refunded ?? false),
    discountRefunded: Boolean(o.discount_refunded ?? false),
    pointsAwarded: Boolean(o.points_awarded ?? (arStatus === 'مكتمل')),
    disputeCount: Math.max(0, Number(o.dispute_count) || (o.dispute_reason ? 1 : 0)),
    releaseCount: Math.max(0, Number(o.release_count) || 0),
    lastReleaseReason: o.last_release_reason || '',
    releasedByPhones: Array.isArray(o.released_by_json) ? o.released_by_json : [],
    disputeReason: o.dispute_reason || null,
    adminResolutionNote: o.admin_resolution_note || null,
    rating: (o.rating !== null && o.rating !== undefined) ? Number(o.rating) : null
  };
}

// ============================================================================
// 8. مسارات المصادقة الآمنة (Authentication Endpoints)
// ============================================================================

app.get('/api/health', (req, res) => {
  res.json({
    status: 'success',
    environment: IS_PROD ? 'production' : 'development',
    message: 'خادم منصة الرجل العنابي V32 المؤمّن يعمل بكفاءة عالية! 🛵🛡️'
  });
});

// جلب الحالة المفلترة حسب توكن المستخدم الحالي (لا يكشف أي بيانات لغير المصرح لهم)
app.get('/api/bootstrap', async (req, res) => {
  try {
    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, state: scopedState });
  } catch (error) {
    console.error('Bootstrap Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء جلب البيانات' });
  }
});

// 1) تسجيل دخول العميل برقم الهاتف
app.post('/api/auth/customer/login', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!isValidEgyptianPhone(phone)) {
    return res.status(400).json({ success: false, message: 'برجاء إدخال رقم هاتف مصري صحيح (11 رقم يبدأ بـ 01) 📱⚠️' });
  }

  try {
    let { data: customer, error: fetchError } = await supabase
      .from('customers')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (!customer) {
      const { data: newCustomer, error: insertError } = await supabase
        .from('customers')
        .insert([{ phone, wallet_balance: 0, points: 0 }])
        .select()
        .single();
      if (insertError) throw insertError;
      customer = newCustomer;
    } else if (fetchError) {
      throw fetchError;
    }

    setRoleCookie(res, 'ennaby_cust_token', {
      id: customer.id,
      role: 'customer',
      phone: customer.phone
    }, 30 * 24 * 60 * 60 * 1000);

    // تحديث الكوكي في req مؤقتاً لبناء الحالة المفلترة للعميل فوراً
    req.cookies = { ...(req.cookies || {}), ennaby_cust_token: jwt.sign({ id: customer.id, role: 'customer', phone: customer.phone }, JWT_SECRET) };
    const scopedState = await buildScopedStateForRequest(req);
    const custFull = scopedState.customers[phone] || {
      id: customer.id,
      phone: customer.phone,
      walletBalance: roundMoney(customer.wallet_balance || 0),
      points: Number(customer.points) || 0,
      walletTransactions: []
    };

    res.json({
      success: true,
      message: 'تم ربط حسابك السحابي بنجاح 🛵👑',
      customer: {
        id: customer.id,
        phone: customer.phone,
        balance: custFull.walletBalance,
        points: custFull.points,
        walletTransactions: custFull.walletTransactions
      },
      state: scopedState
    });
  } catch (error) {
    console.error('Customer Login Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ داخلي في الخادم' });
  }
});

// 2) تسجيل دخول الكابتن (التحقق من الباسورد المشفر على السيرفر فقط)
app.post('/api/auth/captain/login', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const password = String(req.body.password || '').trim();

  if (!isValidEgyptianPhone(phone) || !password) {
    return res.status(400).json({ success: false, message: 'برجاء إدخال رقم الهاتف وكلمة المرور بشكل صحيح ⚠️' });
  }

  try {
    const { data: cap } = await supabase
      .from('captains')
      .select('*')
      .eq('phone', phone)
      .maybeSingle();

    if (!cap) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    }

    const { valid, needsRehash } = verifyPasswordSecure(password, cap.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    }

    // ترقية التشفير تلقائياً إلى scrypt إذا كان الحساب قديماً
    if (needsRehash) {
      await supabase.from('captains').update({ password_hash: hashPasswordSecure(password) }).eq('id', cap.id);
    }

    const arStatus = captainStatusFromDb(cap.status);
    if (arStatus === 'مرفوض') {
      return res.status(403).json({
        success: false,
        status: 'مرفوض',
        rejectReason: cap.reject_reason || 'المستندات المرفوعة غير واضحة أو تحتاج لتحديث',
        captainProfile: {
          phone: cap.phone,
          fullName: cap.full_name,
          nationalId: cap.national_id,
          primaryZone: cap.primary_zone,
          vehicleType: cap.vehicle_type,
          plateNumber: cap.plate_number
        },
        message: 'تم رفض المستندات، يمكنك إعادة رفع صور واضحة الآن 📄⚠️'
      });
    }

    if (arStatus === 'معتمد' && !cap.is_available) {
      await supabase.from('captains').update({ is_available: true }).eq('id', cap.id);
      cap.is_available = true;
    }

    const token = setRoleCookie(res, 'ennaby_cour_token', {
      id: cap.id,
      role: 'captain',
      phone: cap.phone
    }, 14 * 24 * 60 * 60 * 1000);

    req.cookies = { ...(req.cookies || {}), ennaby_cour_token: token };
    const scopedState = await buildScopedStateForRequest(req);

    res.json({
      success: true,
      message: `أهلاً بك يا كابتن ${cap.full_name} 🛵✅`,
      captain: scopedState.captains[0] || null,
      state: scopedState
    });
  } catch (error) {
    console.error('Captain Login Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تسجيل الدخول' });
  }
});

app.post('/api/auth/captain/logout', (req, res) => {
  clearRoleCookie(res, 'ennaby_cour_token');
  res.json({ success: true, message: 'تم تسجيل خروج الكابتن بنجاح 👋' });
});

// 3) تسجيل دخول الإدارة (التحقق الصارم من الباسورد المشفر وحالة الحساب على السيرفر)
app.post('/api/auth/admin/login', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'برجاء إدخال اسم المستخدم وكلمة المرور ⚠️' });
  }

  try {
    const { data: admins } = await supabase.from('admins').select('*');
    const admin = (admins || []).find(a => String(a.username || '').toLowerCase() === username.toLowerCase());

    if (!admin) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    }

    const { valid, needsRehash } = verifyPasswordSecure(password, admin.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    }

    if (!admin.is_master && (String(admin.status).toUpperCase() === 'DISABLED' || admin.status === 'معطل')) {
      return res.status(403).json({ success: false, message: 'عفواً! تم تعطيل هذا الحساب الإداري بواسطة الأدمن الرئيسي ⛔' });
    }

    if (needsRehash) {
      await supabase.from('admins').update({ password_hash: hashPasswordSecure(password) }).eq('id', admin.id);
    }

    const token = setRoleCookie(res, 'ennaby_adm_token', {
      id: admin.id,
      role: 'admin',
      username: admin.username,
      isMaster: Boolean(admin.is_master),
      sessionVersion: Number(admin.session_version) || 1
    }, 8 * 60 * 60 * 1000);


    
    await recordAuditLogInDb({
      actor: `${admin.name} (${admin.username})`,
      actionType: 'تسجيل دخول إداري',
      target: admin.username,
      details: `دخول ناجح (${admin.is_master ? 'أدمن رئيسي' : 'مسؤول فرعي'})`
    });

    req.cookies = { ...(req.cookies || {}), ennaby_adm_token: token };
    const scopedState = await buildScopedStateForRequest(req);

    res.json({
      success: true,
      message: `أهلاً بك يا ${admin.name} في غرفة العمليات المركزية 🛡️✅`,
      admin: {
        id: admin.id,
        username: admin.username,
        name: admin.name,
        isMaster: Boolean(admin.is_master),
        permissions: admin.is_master ? {
          viewDashboard: true, viewCaptains: true, manageCaptains: true,
          viewOrders: true, manageOrders: true, manageWallets: true,
          manageCommissions: true, managePricing: true, manageSettings: true
        } : (admin.permissions || {})
      },
      state: scopedState
    });
  } catch (error) {
    console.error('Admin Login Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تسجيل دخول الإدارة' });
  }
});

app.post('/api/auth/admin/logout', async (req, res) => {
  const admin = await getAuthenticatedAdmin(req);
  if (admin) {
    await recordAuditLogInDb({
      actor: `${admin.name} (${admin.username})`,
      actionType: 'تسجيل خروج إداري',
      target: admin.username,
      details: 'خروج من غرفة العمليات'
    });
  }
  clearRoleCookie(res, 'ennaby_adm_token');
  res.json({ success: true, message: 'تم تسجيل الخروج من لوحة الإدارة 👋' });
});

// ============================================================================
// 9. مسارات الطلبات والعملاء (Server-Side Price & Discount Validation)
// ============================================================================

// إنشاء طلب جديد (السيرفر يحسب السعر والعمولة والخصم ويتحقق من الصيانة والمناطق)
app.post('/api/orders', writeLimiter, async (req, res) => {
  try {
    const { settings, zones, pricing } = await getPlatformConfigFromDb();
    if (settings.maintenanceMode) {
      return res.status(503).json({ success: false, message: 'عفواً يا باشا! المنصة في صيانة سريعة حالياً وراجعين فوراً 🛠️' });
    }

    const clientPhone = normalizePhone(req.body.clientPhone);
    const pickupZone = String(req.body.pickupZone || '').trim();
    const pickupAddress = String(req.body.pickupAddress || '').trim();
    const dropoffZone = String(req.body.dropoffZone || '').trim();
    const dropoffAddress = String(req.body.dropoffAddress || '').trim();
    const customerNotes = String(req.body.customerNotes || '').trim().slice(0, 500);
    const packageType = String(req.body.packageType || settings.packageTypes[0] || '').trim();
    const isFetch = req.body.tripType === 'fetch';
    const senderPhone = normalizePhone(req.body.senderPhone);
    const recipientPhone = normalizePhone(req.body.recipientPhone);
    const payer = String(req.body.payer || (isFetch ? 'العميل عند الاستلام بالباب 🏠' : 'الراسل')).trim();

    if (!zones.includes(pickupZone) || !zones.includes(dropoffZone)) {
      return res.status(400).json({ success: false, message: 'برجاء اختيار منطقة استلام وتسليم صحيحة من القائمة 📍⚠️' });
    }
    if (!pickupAddress || !dropoffAddress) {
      return res.status(400).json({ success: false, message: 'برجاء كتابة عنوان الاستلام والتسليم بالتفصيل 📍⚠️' });
    }
    if (!isValidEgyptianPhone(clientPhone) || !isValidEgyptianPhone(senderPhone) || !isValidEgyptianPhone(recipientPhone)) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال أرقام هواتف مصرية صحيحة (11 رقم يبدأ بـ 01) 📱⚠️' });
    }

    // حساب السعر الأصلي من جدول الأسعار على السيرفر حصرياً (لا نثق بأي سعر قادم من المتصفح!)
    const routeKey = `${pickupZone}|${dropoffZone}`;
    if (pricing[routeKey] === undefined) {
      return res.status(400).json({ success: false, message: 'عفواً هذا المسار ليس له تسعير معتمد حالياً! ⚠️' });
    }
    const serverOriginalFare = Math.max(0, roundMoney(pricing[routeKey]));
    const serverPlatformFee = Math.max(0, roundMoney(settings.platformFee));
    const serverCourierNet = Math.max(0, roundMoney(serverOriginalFare - serverPlatformFee));

    // جلب أو إنشاء سجل العميل في جدول customers
    let { data: customer } = await supabase
      .from('customers')
      .select('*')
      .eq('phone', clientPhone)
      .maybeSingle();

    if (!customer) {
      const { data: createdCust, error: createErr } = await supabase
        .from('customers')
        .insert([{ phone: clientPhone, wallet_balance: 0, points: 0 }])
        .select()
        .single();
      if (createErr) throw createErr;
      customer = createdCust;
    }

    const availableWallet = Math.max(0, roundMoney(customer.wallet_balance || 0));
    const serverDiscount = availableWallet > 0 ? roundMoney(Math.min(availableWallet, serverOriginalFare)) : 0;
    const serverFinalFare = Math.max(0, roundMoney(serverOriginalFare - serverDiscount));
    const orderId = generateOrderId();

    // أولاً: إدراج الطلب في جدول orders قبل خصم الرصيد لضمان عدم ضياع أموال العميل لو فشل الإدراج!
    const { data: order, error: insertError } = await supabase
      .from('orders')
      .insert([{
        id: orderId,
        customer_id: customer.id,
        trip_type: isFetch ? 'FETCH' : 'SEND',
        pickup_zone: pickupZone,
        pickup_address: pickupAddress,
        dropoff_zone: dropoffZone,
        dropoff_address: dropoffAddress,
        customer_notes: customerNotes,
        package_type: packageType,
        payer,
        sender_phone: senderPhone,
        recipient_phone: recipientPhone,
        original_fare: serverOriginalFare,
        discount_applied: serverDiscount,
        fare: serverFinalFare,
        platform_fee: serverPlatformFee,
        courier_net: serverCourierNet,
        status: 'PENDING',
        exact_status: 'في انتظار كابتن'
      }])
      .select()
      .single();

    if (insertError) throw insertError;

    // ثانياً: خصم الرصيد ذرياً بعد نجاح إنشاء الطلب، وفي حال فشل الخصم نحذف الطلب فوراً (Rollback)
    if (serverDiscount > 0) {
      try {
        await adjustCustomerWalletAtomic({
          customerId: customer.id,
          delta: -serverDiscount,
          type: 'خصم',
          title: `استخدام رصيد خصم على طلب (${orderId})`,
          orderId
        });
      } catch (walletErr) {
        await supabase.from('orders').delete().eq('id', orderId);
        throw walletErr;
      }
    }

    const token = setRoleCookie(res, 'ennaby_cust_token', {
      id: customer.id,
      role: 'customer',
      phone: customer.phone
    }, 30 * 24 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_cust_token: token };

    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: `تم إرسال طلبك (${orderId}) ورجالة العنابي هيستلموه فوراً 🚀`,
      order,
      state: scopedState
    });
  } catch (error) {
    console.error('Order Creation Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تأكيد الطلب' });
  }
});

// إلغاء الطلب من العميل (مع استرداد ذري لخصم العميل وعمولة الكابتن)
app.post('/api/orders/:id/cancel', writeLimiter, async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });

    const custUser = await getAuthenticatedCustomer(req);
    if (custUser && order.customer_id && custUser.id !== order.customer_id) {
      return res.status(403).json({ success: false, message: 'غير مصرح لك بإلغاء هذا الطلب ⛔' });
    }

    const arStatus = resolveExactOrderStatus(order);
    if (arStatus !== 'في انتظار كابتن' && arStatus !== 'تم قبول الطلب') {
      return res.status(400).json({ success: false, message: 'عفواً يا باشا! الكابتن استلم الطرد بالفعل ولا يمكن الإلغاء 🛵✋' });
    }

    // إذا كان الكابتن قد قبل الطلب وخصمت منه العمولة، نردها له ونعكس تعويض الخصم
    if (arStatus === 'تم قبول الطلب' && order.captain_id && order.fee_deducted && !order.fee_refunded) {
      const lockedFee = roundMoney(order.platform_fee);
      const lockedDiscount = roundMoney(order.discount_applied);
      if (lockedFee > 0) {
        await adjustCaptainWalletAtomic({
          captainId: order.captain_id,
          delta: lockedFee,
          type: 'استرداد',
          title: `استرداد عمولة إلغاء طلب (${order.id})`,
          orderId: order.id
        });
      }
      if (lockedDiscount > 0) {
        await adjustCaptainWalletAtomic({
          captainId: order.captain_id,
          delta: -lockedDiscount,
          type: 'خصم',
          title: `عكس تعويض خصم لطلب ملغي (${order.id})`,
          orderId: order.id,
          allowNegativeClamp: true
        });
      }
    }

    if (order.captain_id) {
      const { data: cap } = await supabase.from('captains').select('lifetime_cancelled').eq('id', order.captain_id).maybeSingle();
      if (cap) {
        await supabase.from('captains').update({ lifetime_cancelled: (Number(cap.lifetime_cancelled) || 0) + 1 }).eq('id', order.captain_id);
      }
    }

    // استرداد رصيد الخصم لمحفظة العميل
    if (roundMoney(order.discount_applied) > 0 && !order.discount_refunded && order.customer_id) {
      await adjustCustomerWalletAtomic({
        customerId: order.customer_id,
        delta: roundMoney(order.discount_applied),
        type: 'إيداع',
        title: `استرداد رصيد خصم لطلب ملغي (${order.id})`,
        orderId: order.id
      });
    }

    await supabase.from('orders').update({
      status: 'CANCELLED',
      exact_status: 'ملغي من العميل',
      fee_refunded: true,
      discount_refunded: true
    }).eq('id', order.id);

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم إلغاء طلبك (${orderId}) بنجاح ✅`, state: scopedState });
  } catch (error) {
    console.error('Customer Cancel Order Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إلغاء الطلب' });
  }
});

// تقييم الكابتن بعد اكتمال الطلب
app.post('/api/orders/:id/rate', writeLimiter, async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const stars = Math.min(5, Math.max(1, Math.round(Number(req.body.rating) || 5)));

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });
    if (order.rating !== null && order.rating !== undefined) {
      return res.status(400).json({ success: false, message: 'تم تقييم هذا المشوار مسبقاً ولا يمكن تعديله ⭐' });
    }

    await supabase.from('orders').update({ rating: stars }).eq('id', orderId);
    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'شكراً لتقييمك الجميل! 🛵⭐', state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ التقييم' });
  }
});

// فتح اعتراض من العميل
app.post('/api/orders/:id/dispute', writeLimiter, async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const reason = String(req.body.reason || '').trim().slice(0, 500);
    if (!reason) return res.status(400).json({ success: false, message: 'اكتب سبب الاعتراض ⚠️' });

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || resolveExactOrderStatus(order) !== 'مكتمل') {
      return res.status(400).json({ success: false, message: 'لا يمكن فتح اعتراض على هذا الطلب حالياً ⚠️' });
    }
    if ((Number(order.dispute_count) || 0) >= 1 || order.dispute_reason) {
      return res.status(400).json({ success: false, message: 'الحد الأقصى للاعتراض هو مرة واحدة لكل طلب ⚠️' });
    }

    await supabase.from('orders').update({
      status: 'DISPUTED',
      exact_status: 'قيد مراجعة الاعتراض',
      dispute_reason: reason,
      dispute_count: 1,
      admin_resolution_note: null
    }).eq('id', orderId);

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'تم رفع الاعتراض للإدارة لبحثه وحسمه 🛡️', state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تسجيل الاعتراض' });
  }
});

// ============================================================================
// 10. مسارات الكباتن (التسجيل، الاستعداد، قبول الطلب، التحديث، التنازل، التسليم)
// ============================================================================

app.post('/api/captains/register', writeLimiter, async (req, res) => {
  try {
    const { settings, zones } = await getPlatformConfigFromDb();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || '').trim();
    const fullName = String(req.body.fullName || '').trim();
    const nationalId = normalizeDigits(req.body.nationalId || '').trim();
    const primaryZone = String(req.body.primaryZone || zones[0] || 'المنصورة').trim();
    const vehicleType = String(req.body.vehicleType || 'موتوسيكل').trim();
    const plateNumber = vehicleType === 'دراجة' ? 'دراجة معفية' : String(req.body.plateNumber || '').trim();
    const referredByPhone = req.body.referredByPhone ? normalizePhone(req.body.referredByPhone) : '';

    if (!fullName || fullName.split(/\s+/).length < 3) {
      return res.status(400).json({ success: false, message: 'اكتب الاسم ثلاثي كاملاً من واقع البطاقة ⚠️' });
    }
    if (!isValidEgyptianPhone(phone)) {
      return res.status(400).json({ success: false, message: 'رقم هاتف الكابتن غير صحيح ⚠️' });
    }
    if (!/^[0-9]{14}$/.test(nationalId)) {
      return res.status(400).json({ success: false, message: 'الرقم القومي يجب أن يكون 14 رقماً صحيحاً ⚠️' });
    }
    if (!password) {
      return res.status(400).json({ success: false, message: 'اكتب كلمة مرور للحساب ⚠️' });
    }
    if (vehicleType !== 'دراجة' && !plateNumber) {
      return res.status(400).json({ success: false, message: 'رقم لوحة المركبة إجباري ⚠️' });
    }

    const { data: existingCap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    const isRejectedReupload = existingCap && captainStatusFromDb(existingCap.status) === 'مرفوض';

    if (!isRejectedReupload && !settings.allowCaptainRegistration) {
      return res.status(403).json({ success: false, message: 'باب تسجيل الكباتن الجدد مغلق حالياً لاكتمال العدد 🛵' });
    }
    if (existingCap && !isRejectedReupload) {
      return res.status(400).json({ success: false, message: 'رقم الهاتف مسجل بالفعل ككابتن في المنصة ⚠️' });
    }

    // التحقق من عدم تكرار الرقم القومي لكابتن آخر
    const { data: dupNat } = await supabase.from('captains').select('phone').eq('national_id', nationalId).maybeSingle();
    if (dupNat && normalizePhone(dupNat.phone) !== phone) {
      return res.status(400).json({ success: false, message: 'الرقم القومي مسجل بالفعل لكابتن آخر في المنصة ⚠️' });
    }

    if (referredByPhone) {
      if (referredByPhone === phone) {
        return res.status(400).json({ success: false, message: 'مينفعش تكتب رقمك الشخصي في خانة دعوة الصديق يا نجم! 😂⚠️' });
      }
      const { data: refCap } = await supabase.from('captains').select('id').eq('phone', referredByPhone).maybeSingle();
      if (!refCap) {
        return res.status(400).json({ success: false, message: 'رقم موبايل الصديق غير مسجل ككابتن في المنصة ⚠️' });
      }
    }

    const [frontRef, backRef, vehRef] = await Promise.all([
      uploadCaptainDocumentSecure(phone, 'idFront', req.body.idFrontPhoto),
      uploadCaptainDocumentSecure(phone, 'idBack', req.body.idBackPhoto),
      vehicleType === 'دراجة' ? Promise.resolve(null) : uploadCaptainDocumentSecure(phone, 'vehicle', req.body.vehiclePhoto)
    ]);

    if (!frontRef || !backRef || (vehicleType !== 'دراجة' && !vehRef)) {
      return res.status(400).json({ success: false, message: 'رفع صور البطاقة (وش وضهر) وصورة المركبة إجباري ⚠️' });
    }

    const passHash = hashPasswordSecure(password);

    if (isRejectedReupload) {
      const { error: upErr } = await supabase.from('captains').update({
        full_name: fullName,
        national_id: nationalId,
        password_hash: passHash,
        primary_zone: primaryZone,
        vehicle_type: vehicleType,
        plate_number: plateNumber,
        id_front_url: frontRef,
        id_back_url: backRef,
        vehicle_photo_url: vehRef,
        status: 'PENDING',
        reject_reason: '',
        is_available: false
      }).eq('id', existingCap.id);
      if (upErr) throw upErr;
    } else {
      const { error: insErr } = await supabase.from('captains').insert([{
        phone,
        password_hash: passHash,
        full_name: fullName,
        national_id: nationalId,
        primary_zone: primaryZone,
        vehicle_type: vehicleType,
        plate_number: plateNumber,
        id_front_url: frontRef,
        id_back_url: backRef,
        vehicle_photo_url: vehRef,
        wallet_balance: 0,
        points: 0,
        status: 'PENDING',
        is_available: false,
        referred_by_phone: referredByPhone
      }]);
      if (insErr) throw insErr;
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'تم إرسال طلب تسجيل الكابتن وحفظ المستندات بأمان 🛵✅', state: scopedState });
  } catch (error) {
    console.error('Captain Registration Error:', error.message);
    res.status(400).json({ success: false, message: error.message || 'حدث خطأ أثناء تسجيل الكابتن' });
  }
});

// تغيير حالة استعداد الكابتن
app.post('/api/captain/availability', requireCaptain, async (req, res) => {
  try {
    const cap = req.captain;
    const arStatus = captainStatusFromDb(cap.status);
    if (arStatus === 'قيد المراجعة') {
      return res.status(403).json({ success: false, message: 'حسابك لسة بيتراجع ياطيااار 😎' });
    }

    const isAvailable = Boolean(req.body.isAvailable);
    await supabase.from('captains').update({ is_available: isAvailable }).eq('id', cap.id);
    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: isAvailable ? 'أنت الآن متاح لاستقبال الطلبات على الرادار 📡✅' : 'تم إيقاف استقبال الطلبات الجديدة مؤقتاً ⏸️',
      state: scopedState
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تحديث حالة الاستعداد' });
  }
});

// إخفاء إشعار إداري للكابتن
app.post('/api/captain/notices/:noticeId/dismiss', requireCaptain, async (req, res) => {
  try {
    const cap = req.captain;
    const noticeId = String(req.params.noticeId || '');
    const currentNotices = Array.isArray(cap.admin_notices_json) ? cap.admin_notices_json : [];
    const updatedNotices = currentNotices.filter(n => String(n.id) !== noticeId);

    await supabase.from('captains').update({ admin_notices_json: updatedNotices }).eq('id', cap.id);
    await supabase.from('system_alerts').update({ is_dismissed: true }).eq('captain_id', cap.id).eq('id', noticeId);

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'تعذر تحديث الإشعارات' });
  }
});

// قبول الطلب من الكابتن (فحص الرصيد، خصم العمولة ذرياً، تعويض خصم العميل، ومنع أخذ أكثر من طلب)
app.post('/api/orders/:id/accept', requireCaptain, writeLimiter, async (req, res) => {
  try {
    const { settings } = await getPlatformConfigFromDb();
    if (settings.maintenanceMode) {
      return res.status(503).json({ success: false, message: 'المنصة في صيانة حالياً ولا يمكن قبول طلبات جديدة 🛠️' });
    }

    const cap = req.captain;
    const arCapStatus = captainStatusFromDb(cap.status);
    if (arCapStatus === 'قيد المراجعة') {
      return res.status(403).json({ success: false, message: 'حسابك لسة بيتراجع ياطيااار 😎' });
    }
    if (arCapStatus !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك موقوف أو غير معتمد حالياً لقبول الطلبات! ⚠️' });
    }

    // التأكد من عدم وجود طلب جاري مع الكابتن
    const { data: myActiveOrders } = await supabase
      .from('orders')
      .select('id, status, exact_status')
      .eq('captain_id', cap.id)
      .in('status', ['ACCEPTED', 'IN_TRANSIT']);

    const hasActive = (myActiveOrders || []).some(o => ACTIVE_COURIER_STATUSES.includes(resolveExactOrderStatus(o)));
    if (hasActive) {
      return res.status(400).json({ success: false, message: 'متبقاش طماع ودى الاوردر الى معاك الاول 😂🛵' });
    }

    const orderId = String(req.params.id || '').trim();
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.status !== 'PENDING' || order.captain_id) {
      return res.status(409).json({ success: false, message: 'الطلب طار يا بطل كابتن تاني خطفه قبلك بثانية 😂🛵' });
    }

    const effectiveFee = (cap.custom_fee !== null && cap.custom_fee !== undefined && Number.isFinite(Number(cap.custom_fee)))
      ? Math.max(0, roundMoney(cap.custom_fee))
      : Math.max(0, roundMoney(settings.platformFee));

    if (effectiveFee > 0 && roundMoney(cap.wallet_balance) < effectiveFee) {
      return res.status(400).json({ success: false, message: `رصيدك أقل من عمولة الطلب (${effectiveFee} ج)، يرجى الشحن أولاً! ⚠️` });
    }

    const courierNet = Math.max(0, roundMoney(Number(order.original_fare || order.fare) - effectiveFee));

    // حجز الطلب ذرياً بشرط أن يكون لا يزال PENDING وبلا كابتن
    const { data: updatedOrd, error: lockErr } = await supabase
      .from('orders')
      .update({
        captain_id: cap.id,
        status: 'ACCEPTED',
        exact_status: 'تم قبول الطلب',
        platform_fee: effectiveFee,
        courier_net: courierNet,
        fee_deducted: true,
        fee_refunded: false
      })
      .eq('id', orderId)
      .eq('status', 'PENDING')
      .is('captain_id', null)
      .select()
      .maybeSingle();

    if (lockErr || !updatedOrd) {
      return res.status(409).json({ success: false, message: 'الطلب طار يا بطل كابتن تاني خطفه قبلك بثانية 😂🛵' });
    }

    // خصم العمولة وتعويض خصم العميل ذرياً
    try {
      if (effectiveFee > 0) {
        await adjustCaptainWalletAtomic({
          captainId: cap.id,
          delta: -effectiveFee,
          type: 'خصم',
          title: `عمولة منصة عن طلب (${orderId})`,
          orderId
        });
      }
      if (roundMoney(order.discount_applied) > 0) {
        await adjustCaptainWalletAtomic({
          captainId: cap.id,
          delta: roundMoney(order.discount_applied),
          type: 'إيداع',
          title: `تعويض خصم العميل عن طلب (${orderId})`,
          orderId
        });
      }
    } catch (walletErr) {
      // التراجع الفوري وإعادة الطلب للرادار لو فشل خصم المحفظة
      await supabase.from('orders').update({
        captain_id: null,
        status: 'PENDING',
        exact_status: 'في انتظار كابتن',
        fee_deducted: false
      }).eq('id', orderId);
      return res.status(400).json({ success: false, message: walletErr.message || 'رصيد المحفظة غير كافٍ' });
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: 'عاش يا بطل! تم قبول الطلب وتفاصيل التواصل متاحة لك 🚀',
      state: scopedState
    });
  } catch (error) {
    console.error('Accept Order Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء قبول الطلب' });
  }
});

// التدرج في مراحل التوصيل للكابتن
app.post('/api/orders/:id/advance', requireCaptain, writeLimiter, async (req, res) => {
  try {
    const cap = req.captain;
    if (captainStatusFromDb(cap.status) !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك غير معتمد حالياً لتنفيذ هذا الإجراء! ⛔' });
    }

    const orderId = String(req.params.id || '').trim();
    const nextStatus = String(req.body.nextStatus || '').trim();
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();

    if (!order || order.captain_id !== cap.id) {
      return res.status(403).json({ success: false, message: 'عذراً، هذا الطلب غير مخصص لحسابك! ⚠️' });
    }

    const currentExact = resolveExactOrderStatus(order);
    const allowedTransitions = {
      'تم قبول الطلب': 'الكابتن وصل للاستلام',
      'الكابتن وصل للاستلام': 'استلم الطرد وفي السكة',
      'استلم الطرد وفي السكة': 'الكابتن وصل للتسليم'
    };

    if (allowedTransitions[currentExact] !== nextStatus) {
      return res.status(400).json({ success: false, message: 'انتقال حالة غير صالح للطلب ⚠️' });
    }

    const updatePayload = {
      status: orderStatusToDb(nextStatus),
      exact_status: nextStatus
    };
    if (nextStatus === 'استلم الطرد وفي السكة') {
      updatePayload.picked_up_at = new Date().toISOString();
    }

    await supabase.from('orders').update(updatePayload).eq('id', orderId);
    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم تحديث حالة المشوار: ${nextStatus} 🛵✅`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تحديث حالة المشوار' });
  }
});

// تنازل الكابتن عن الطلب قبل الاستلام مع رد العمولة
app.post('/api/orders/:id/release', requireCaptain, writeLimiter, async (req, res) => {
  try {
    const cap = req.captain;
    const orderId = String(req.params.id || '').trim();
    const reason = String(req.body.reason || '').trim().slice(0, 300);
    if (!reason) {
      return res.status(400).json({ success: false, message: 'برجاء كتابة سبب التنازل عن الطلب أولاً ⚠️' });
    }

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.captain_id !== cap.id) {
      return res.status(403).json({ success: false, message: 'هذا الطلب غير مسند لحسابك ⚠️' });
    }
    if (resolveExactOrderStatus(order) !== 'تم قبول الطلب') {
      return res.status(400).json({ success: false, message: 'لا يمكن التنازل عن الطلب بعد الوصول أو استلام الطرد! ⚠️' });
    }

    if (order.fee_deducted && !order.fee_refunded) {
      const lockedFee = roundMoney(order.platform_fee);
      const lockedDiscount = roundMoney(order.discount_applied);
      if (lockedFee > 0) {
        await adjustCaptainWalletAtomic({
          captainId: cap.id,
          delta: lockedFee,
          type: 'استرداد',
          title: `استرداد عمولة تنازل عن طلب (${orderId})`,
          orderId
        });
      }
      if (lockedDiscount > 0) {
        await adjustCaptainWalletAtomic({
          captainId: cap.id,
          delta: -lockedDiscount,
          type: 'خصم',
          title: `عكس تعويض خصم لتنازل عن طلب (${orderId})`,
          orderId,
          allowNegativeClamp: true
        });
      }
    }

    const { settings } = await getPlatformConfigFromDb();
    const generalFee = roundMoney(settings.platformFee);
    const releasedArr = Array.isArray(order.released_by_json) ? order.released_by_json : [];
    releasedArr.push({ phone: normalizePhone(cap.phone), at: Date.now(), reason });

    await supabase.from('orders').update({
      captain_id: null,
      status: 'PENDING',
      exact_status: 'في انتظار كابتن',
      platform_fee: generalFee,
      courier_net: Math.max(0, roundMoney(Number(order.original_fare || order.fare) - generalFee)),
      fee_deducted: false,
      fee_refunded: false,
      release_count: (Number(order.release_count) || 0) + 1,
      last_release_reason: reason,
      released_by_json: releasedArr
    }).eq('id', orderId);

    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: 'تم التنازل عن الطلب وإعادته للرادار ورد العمولة لمحفظتك 🔄',
      state: scopedState
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء التنازل عن الطلب' });
  }
});

// إتمام تسليم الطلب (حساب النقاط والمكافآت ومكافأة الـ 50 ج لدعوة الأصدقاء على السيرفر حصرياً)
app.post('/api/orders/:id/complete', requireCaptain, writeLimiter, async (req, res) => {
  try {
    const cap = req.captain;
    if (captainStatusFromDb(cap.status) !== 'معتمد') {
      return res.status(403).json({ success: false, message: 'حسابك غير معتمد حالياً لإنهاء الطلب! ⛔' });
    }

    const orderId = String(req.params.id || '').trim();
    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order || order.captain_id !== cap.id) {
      return res.status(403).json({ success: false, message: 'عذراً، لا تملك صلاحية إنهاء هذا الطلب! ⚠️' });
    }
    if (resolveExactOrderStatus(order) !== 'الكابتن وصل للتسليم') {
      return res.status(400).json({ success: false, message: 'يجب الوصول لمكان التسليم أولاً قبل إتمام الطلب ⚠️' });
    }

    const { settings } = await getPlatformConfigFromDb();
    const courPtsPerOrder = Math.max(1, Number(settings.courierPointsPerOrder) || 5);
    const courThreshold = Math.max(5, Number(settings.courierRewardThreshold) || 100);
    const courRewardCash = Math.max(1, roundMoney(settings.courierRewardCash ?? 10));

    const custPtsPerOrder = Math.max(1, Number(settings.customerPointsPerOrder) || 5);
    const custThreshold = Math.max(5, Number(settings.customerRewardThreshold) || 100);
    const custRewardCash = Math.max(1, roundMoney(settings.customerRewardCash ?? 10));

    await supabase.from('orders').update({
      status: 'COMPLETED',
      exact_status: 'مكتمل',
      delivered_at: new Date().toISOString(),
      points_awarded: true
    }).eq('id', orderId);

    if (!order.points_awarded) {
      // 1. منح النقاط والمكافآت للكابتن
      let newCapPoints = (Number(cap.points) || 0) + courPtsPerOrder;
      let capRewardsCount = 0;
      while (newCapPoints >= courThreshold) {
        newCapPoints -= courThreshold;
        capRewardsCount += 1;
      }
      await supabase.from('captains').update({ points: newCapPoints }).eq('id', cap.id);

      for (let i = 0; i < capRewardsCount; i++) {
        await adjustCaptainWalletAtomic({
          captainId: cap.id,
          delta: courRewardCash,
          type: 'مكافأة',
          title: `مكافأة إكمال ${courThreshold} نقطة عنابي 🎁`,
          orderId
        });
      }

      // 2. فحص برنامج دعوة أصدقاء الكابتن (50 ج عند إكمال مشوارين)
      if (cap.referred_by_phone && !cap.referral_reward_paid) {
        const { count: completedCount } = await supabase
          .from('orders')
          .select('id', { count: 'exact', head: true })
          .eq('captain_id', cap.id)
          .eq('status', 'COMPLETED');

        const totalComp = (Number(completedCount) || 0) + (Number(cap.lifetime_completed) || 0);
        if (totalComp >= REFERRAL_TARGET_ORDERS) {
          const { data: refCap } = await supabase
            .from('captains')
            .select('*')
            .eq('phone', normalizePhone(cap.referred_by_phone))
            .maybeSingle();

          if (refCap) {
            await adjustCaptainWalletAtomic({
              captainId: refCap.id,
              delta: REFERRAL_REWARD_CASH,
              type: 'مكافأة',
              title: `مكافأة دعوة صديق (${cap.full_name}) لإكماله مشوارين 😎🎁`,
              orderId
            });
            const refNotices = Array.isArray(refCap.admin_notices_json) ? refCap.admin_notices_json : [];
            refNotices.unshift({
              id: 'REF-' + Date.now(),
              type: 'reward',
              text: 'واااالعة معاك يانجم جالك 50 جنيه هدية عشان صاحبك طلع مشوارين 😎',
              at: Date.now()
            });
            await supabase.from('captains').update({
              referrals_count: (Number(refCap.referrals_count) || 0) + 1,
              admin_notices_json: refNotices
            }).eq('id', refCap.id);
          }
          await supabase.from('captains').update({ referral_reward_paid: true }).eq('id', cap.id);
        }
      }

      // 3. منح النقاط والمكافآت للعميل
      if (order.customer_id) {
        const { data: cust } = await supabase.from('customers').select('*').eq('id', order.customer_id).maybeSingle();
        if (cust) {
          let newCustPoints = (Number(cust.points) || 0) + custPtsPerOrder;
          let custRewardsCount = 0;
          while (newCustPoints >= custThreshold) {
            newCustPoints -= custThreshold;
            custRewardsCount += 1;
          }
          await supabase.from('customers').update({ points: newCustPoints }).eq('id', cust.id);

          for (let i = 0; i < custRewardsCount; i++) {
            await adjustCustomerWalletAtomic({
              customerId: cust.id,
              delta: custRewardCash,
              type: 'مكافأة',
              title: `هدية إكمال ${custThreshold} نقطة عنابي بوينتس 🎉`,
              orderId
            });
          }
        }
      }
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: 'تسلم إيدك يا بطل! تم تسليم الأوردر وإيداع أرباحك ومحفظتك جاهزة للمشوار الجاي 🛵💨',
      state: scopedState
    });
  } catch (error) {
    console.error('Complete Order Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء إنهاء الطلب' });
  }
});

// ============================================================================
// 11. مسارات الإدارة المحمية بنظام الصلاحيات (Admin RBAC Endpoints)
// ============================================================================

// اعتماد أو إيقاف أو رفض كابتن
app.post('/api/admin/captains/:phone/status', requireAdmin('manageCaptains'), async (req, res) => {
  try {
    const phone = normalizePhone(req.params.phone);
    const targetStatusAr = String(req.body.status || '').trim();
    const reason = String(req.body.reason || '').trim().slice(0, 300);
    const adminName = `${req.admin.name} (${req.admin.username})`;

    const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

    const dbStatus = captainStatusToDb(targetStatusAr);
    const updatePayload = { status: dbStatus };

    if (targetStatusAr === 'موقوف') {
      updatePayload.suspend_reason = reason || 'مراجعة إدارية';
      updatePayload.is_available = false;

      // إعادة أي طلب نشط مع الكابتن الموقوف إلى الرادار ورد عمولته
      const { data: activeOrds } = await supabase
        .from('orders')
        .select('*')
        .eq('captain_id', cap.id)
        .in('status', ['ACCEPTED', 'IN_TRANSIT']);

      for (const ord of (activeOrds || [])) {
        if (ord.fee_deducted && !ord.fee_refunded) {
          const lockedFee = roundMoney(ord.platform_fee);
          const lockedDiscount = roundMoney(ord.discount_applied);
          if (lockedFee > 0) {
            await adjustCaptainWalletAtomic({
              captainId: cap.id,
              delta: lockedFee,
              type: 'استرداد',
              title: `استرداد عمولة لإيقاف الحساب (${ord.id})`,
              orderId: ord.id,
              byAdmin: req.admin.name
            });
          }
          if (lockedDiscount > 0) {
            await adjustCaptainWalletAtomic({
              captainId: cap.id,
              delta: -lockedDiscount,
              type: 'خصم',
              title: `عكس تعويض خصم (${ord.id})`,
              orderId: ord.id,
              byAdmin: req.admin.name,
              allowNegativeClamp: true
            });
          }
        }
        await supabase.from('orders').update({
          captain_id: null,
          status: 'PENDING',
          exact_status: 'في انتظار كابتن',
          fee_deducted: false,
          fee_refunded: false
        }).eq('id', ord.id);
      }
      await recordAuditLogInDb({ actor: adminName, actionType: 'إيقاف حساب كابتن', target: `${cap.full_name} (${cap.phone})`, details: `السبب: ${updatePayload.suspend_reason}` });
    } else if (targetStatusAr === 'مرفوض') {
      updatePayload.reject_reason = reason || 'يرجى إعادة رفع صور واضحة للمستندات';
      updatePayload.is_available = false;
      await recordAuditLogInDb({ actor: adminName, actionType: 'رفض مستندات كابتن', target: `${cap.full_name} (${cap.phone})`, details: `السبب: ${updatePayload.reject_reason}` });
    } else {
      updatePayload.suspend_reason = '';
      updatePayload.reject_reason = '';
      updatePayload.is_available = true;
      await recordAuditLogInDb({ actor: adminName, actionType: 'اعتماد حساب كابتن', target: `${cap.full_name} (${cap.phone})`, details: 'تم اعتماد الحساب وتفعيل الاستعداد' });
    }

    await supabase.from('captains').update(updatePayload).eq('id', cap.id);
    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم تحديث حالة الكابتن ${cap.full_name} إلى (${targetStatusAr}) ✅`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تحديث حالة الكابتن' });
  }
});

// تخصيص أو إلغاء عمولة فردية لكابتن
app.post('/api/admin/captains/custom-fee', requireAdmin('manageCommissions'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const reset = Boolean(req.body.reset);
    const { settings, pricing } = await getPlatformConfigFromDb();
    const minFare = Math.min(...Object.values(pricing).map(Number).filter(v => v > 0), 35);

    const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

    const notices = Array.isArray(cap.admin_notices_json) ? cap.admin_notices_json : [];
    const actor = `${req.admin.name} (${req.admin.username})`;

    if (reset) {
      notices.unshift({
        id: 'N-' + Date.now(),
        type: 'info',
        text: `تم إرجاع عمولتك إلى عمولة المنصة العامة (${settings.platformFee} جنيه) دلوقتى 🛵`,
        at: Date.now()
      });
      await supabase.from('captains').update({
        custom_fee: null,
        custom_fee_reason: '',
        admin_notices_json: notices.slice(0, 15)
      }).eq('id', cap.id);
      await recordAuditLogInDb({ actor, actionType: 'إلغاء عمولة فردية', target: `${cap.full_name} (${cap.phone})`, details: 'إرجاع الكابتن لعمولة المنصة العامة' });
    } else {
      const feeVal = roundMoney(req.body.customFee);
      const reason = String(req.body.reason || '').trim().slice(0, 200);
      if (feeVal < 0 || feeVal > minFare || !reason) {
        return res.status(400).json({ success: false, message: `برجاء إدخال عمولة صحيحة بين 0 و ${minFare} ج مع كتابة السبب ⚠️` });
      }
      notices.unshift({
        id: 'N-' + Date.now(),
        type: 'fee',
        text: `انت شغال على عمولة "${feeVal} جنيه" دلوقتى — السبب: ${reason} 🛵`,
        at: Date.now()
      });
      await supabase.from('captains').update({
        custom_fee: feeVal,
        custom_fee_reason: reason,
        admin_notices_json: notices.slice(0, 15)
      }).eq('id', cap.id);
      await recordAuditLogInDb({ actor, actionType: 'عمولة فردية لكابتن', target: `${cap.full_name} (${cap.phone})`, details: `تحديد عمولة خاصة (${feeVal} ج) — السبب: ${reason}` });
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'تم تحديث إعدادات عمولة الكابتن بنجاح 🎯✅', state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ العمولة الفردية' });
  }
});

// شحن يدوي لمحفظة كابتن
app.post('/api/admin/wallets/captain-topup', requireAdmin('manageWallets'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const amount = roundMoney(req.body.amount);
    if (!phone || amount <= 0 || amount > MAX_MANUAL_WALLET_TX) {
      return res.status(400).json({ success: false, message: `حدد كابتن ومبلغ شحن صحيح بين 1 و ${MAX_MANUAL_WALLET_TX} ج ⚠️` });
    }

    const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

    await adjustCaptainWalletAtomic({
      captainId: cap.id,
      delta: amount,
      type: 'شحن',
      title: 'شحن رصيد يدوي من الإدارة',
      byAdmin: req.admin.name
    });

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: 'شحن محفظة كابتن',
      target: `${cap.full_name} (${cap.phone})`,
      details: `شحن مبلغ ${amount} ج`
    });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم شحن ${amount} ج لمحفظة الكابتن ${cap.full_name} بنجاح ✅`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء شحن المحفظة' });
  }
});

// خصم إداري من محفظة كابتن مع إشعار السبب
app.post('/api/admin/wallets/captain-deduct', requireAdmin('manageWallets'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const amount = roundMoney(req.body.amount);
    const reason = String(req.body.reason || '').trim().slice(0, 250);

    if (!phone || amount <= 0 || amount > MAX_MANUAL_WALLET_TX || !reason) {
      return res.status(400).json({ success: false, message: 'حدد الكابتن ومبلغ الخصم مع كتابة سبب الخصم ⚠️' });
    }

    const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير موجود ⚠️' });

    await adjustCaptainWalletAtomic({
      captainId: cap.id,
      delta: -amount,
      type: 'خصم',
      title: `خصم إداري: ${reason}`,
      byAdmin: req.admin.name,
      allowNegativeClamp: true
    });

    const notices = Array.isArray(cap.admin_notices_json) ? cap.admin_notices_json : [];
    notices.unshift({
      id: 'DED-' + Date.now(),
      type: 'deduct',
      text: `⚠️ تم خصم (${amount} جنيه) من محفظتك بواسطة الإدارة — السبب: ${reason}`,
      at: Date.now()
    });
    await supabase.from('captains').update({ admin_notices_json: notices.slice(0, 15) }).eq('id', cap.id);

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: 'خصم من محفظة كابتن',
      target: `${cap.full_name} (${cap.phone})`,
      details: `خصم مبلغ ${amount} ج — السبب: ${reason}`
    });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم خصم ${amount} ج من محفظة الكابتن ${cap.full_name} وإرسال الإشعار ⚠️`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تنفيذ الخصم' });
  }
});

// تعويض أو إضافة رصيد لمحفظة عميل
app.post('/api/admin/wallets/customer-compensate', requireAdmin('manageWallets'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const amount = roundMoney(req.body.amount);
    const reason = String(req.body.reason || '').trim().slice(0, 250) || 'هدية وتعويض من إدارة الرجل العنابي 🎁';

    if (!isValidEgyptianPhone(phone) || amount <= 0 || amount > MAX_MANUAL_WALLET_TX) {
      return res.status(400).json({ success: false, message: `برجاء إدخال رقم هاتف صحيح ومبلغ تعويض بين 1 و ${MAX_MANUAL_WALLET_TX} ج ⚠️` });
    }

    let { data: cust } = await supabase.from('customers').select('*').eq('phone', phone).maybeSingle();
    if (!cust) {
      const { data: created } = await supabase.from('customers').insert([{ phone, wallet_balance: 0, points: 0 }]).select().single();
      cust = created;
    }

    await adjustCustomerWalletAtomic({
      customerId: cust.id,
      delta: amount,
      type: 'تعويض',
      title: reason,
      byAdmin: req.admin.name
    });

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: 'تعويض محفظة عميل',
      target: phone,
      details: `إضافة ${amount} ج — السبب: ${reason}`
    });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم إضافة ${amount} ج رصيد تعويض لمحفظة العميل (${phone}) بنجاح 🎁✅`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تعويض العميل' });
  }
});

// الفصل في الاعتراضات أو التدخل الإداري في الطلبات
app.post('/api/admin/orders/:id/manage', requireAdmin('manageOrders'), async (req, res) => {
  try {
    const orderId = String(req.params.id || '').trim();
    const action = String(req.body.action || '').trim(); // 'radar' | 'complete' | 'cancel' | 'resolve_complete' | 'resolve_cancel'
    const reason = String(req.body.reason || '').trim().slice(0, 300);
    const actor = `${req.admin.name} (${req.admin.username})`;

    const { data: order } = await supabase.from('orders').select('*').eq('id', orderId).maybeSingle();
    if (!order) return res.status(404).json({ success: false, message: 'الطلب غير موجود ⚠️' });

    const { settings } = await getPlatformConfigFromDb();

    if (action === 'resolve_complete' || action === 'complete') {
      await supabase.from('orders').update({
        status: 'COMPLETED',
        exact_status: 'مكتمل',
        delivered_at: order.delivered_at || new Date().toISOString(),
        admin_resolution_note: action === 'resolve_complete'
          ? 'تم فحص الشكوى واعتماد اكتمال الطلب ✅'
          : `إتمام إداري: ${reason || 'قرار الإدارة'}`
      }).eq('id', orderId);

      await recordAuditLogInDb({ actor, actionType: 'اعتماد اكتمال طلب', target: orderId, details: reason || 'اعتماد الاكتمال' });
    } else if (action === 'radar') {
      if (order.captain_id && order.fee_deducted && !order.fee_refunded) {
        const lockedFee = roundMoney(order.platform_fee);
        const lockedDiscount = roundMoney(order.discount_applied);
        if (lockedFee > 0) {
          await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: lockedFee, type: 'استرداد', title: `رد عمولة لإعادة الطلب للرادار (${orderId})`, orderId, byAdmin: req.admin.name });
        }
        if (lockedDiscount > 0) {
          await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: -lockedDiscount, type: 'خصم', title: `عكس تعويض خصم (${orderId})`, orderId, byAdmin: req.admin.name, allowNegativeClamp: true });
        }
      }
      await supabase.from('orders').update({
        captain_id: null,
        status: 'PENDING',
        exact_status: 'في انتظار كابتن',
        fee_deducted: false,
        fee_refunded: false,
        admin_resolution_note: `إعادة للرادار: ${reason || 'قرار الإدارة'}`
      }).eq('id', orderId);

      await recordAuditLogInDb({ actor, actionType: 'إعادة طلب للرادار', target: orderId, details: `السبب: ${reason}` });
    } else if (action === 'cancel' || action === 'resolve_cancel') {
      if (order.captain_id && order.fee_deducted && !order.fee_refunded) {
        const lockedFee = roundMoney(order.platform_fee);
        const lockedDiscount = roundMoney(order.discount_applied);
        if (lockedFee > 0) {
          await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: lockedFee, type: 'استرداد', title: `استرداد عمولة إلغاء إداري (${orderId})`, orderId, byAdmin: req.admin.name });
        }
        if (lockedDiscount > 0) {
          await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: -lockedDiscount, type: 'خصم', title: `عكس تعويض خصم لطلب ملغي إدارياً (${orderId})`, orderId, byAdmin: req.admin.name, allowNegativeClamp: true });
        }
      }

      if (roundMoney(order.discount_applied) > 0 && !order.discount_refunded && order.customer_id) {
        await adjustCustomerWalletAtomic({
          customerId: order.customer_id,
          delta: roundMoney(order.discount_applied),
          type: 'إيداع',
          title: `استرداد رصيد خصم لطلب ملغي من الإدارة (${orderId})`,
          orderId,
          byAdmin: req.admin.name
        });
      }

      if (order.points_awarded) {
        const courPts = Math.max(1, Number(settings.courierPointsPerOrder) || 5);
        const custPts = Math.max(1, Number(settings.customerPointsPerOrder) || 5);
        if (order.captain_id) {
          const { data: cap } = await supabase.from('captains').select('points').eq('id', order.captain_id).maybeSingle();
          if (cap) await supabase.from('captains').update({ points: Math.max(0, (Number(cap.points) || 0) - courPts) }).eq('id', order.captain_id);
        }
        if (order.customer_id) {
          const { data: cust } = await supabase.from('customers').select('points').eq('id', order.customer_id).maybeSingle();
          if (cust) await supabase.from('customers').update({ points: Math.max(0, (Number(cust.points) || 0) - custPts) }).eq('id', order.customer_id);
        }
      }

      await supabase.from('orders').update({
        status: 'CANCELLED',
        exact_status: 'ملغي من الإدارة',
        fee_refunded: true,
        discount_refunded: true,
        points_awarded: false,
        admin_resolution_note: action === 'resolve_cancel'
          ? 'تم قبول الشكوى وإلغاء الطلب ورد المستحقات ❌'
          : `إلغاء إداري: ${reason || 'قرار الإدارة'}`
      }).eq('id', orderId);

      await recordAuditLogInDb({ actor, actionType: 'إلغاء إداري لطلب', target: orderId, details: reason || 'قبول شكوى وإلغاء الطلب' });
    } else {
      return res.status(400).json({ success: false, message: 'إجراء غير معروف ⚠️' });
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم تنفيذ الإجراء الإداري على الطلب (${orderId}) بنجاح ✅`, state: scopedState });
  } catch (error) {
    console.error('Admin Order Manage Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تنفيذ الإجراء الإداري' });
  }
});

// تحديث إعدادات المنصة والعمولة ونقاط الولاء والمناطق والتسعير
app.post('/api/admin/settings', requireAdmin(), async (req, res) => {
  try {
    const adm = req.admin;
    const perms = adm.is_master ? { manageSettings: true, manageCommissions: true, managePricing: true } : (adm.permissions || {});
    const { settings, zones, pricing, settingsRowId } = await getPlatformConfigFromDb();
    const actor = `${adm.name} (${adm.username})`;

    const updateDb = {};
    let auditTitle = 'تحديث إعدادات المنصة';
    let auditDetails = '';

    // أ) تحديثات العمولة العامة وعنابي بوينتس (تتطلب صلاحية manageCommissions)
    if (req.body.platformFee !== undefined || req.body.loyaltyField) {
      if (!perms.manageCommissions) {
        return res.status(403).json({ success: false, message: 'لا تملك صلاحية إدارة العمولات ونظام عنابي بوينتس 🛡️⛔' });
      }
      if (req.body.platformFee !== undefined) {
        const newFee = roundMoney(req.body.platformFee);
        const minFare = Math.min(...Object.values(pricing).map(Number).filter(v => v > 0), 35);
        if (newFee < 0 || newFee > minFare) {
          return res.status(400).json({ success: false, message: `العمولة يجب أن تكون بين 0 و ${minFare} ج ⚠️` });
        }
        updateDb.platform_fee = newFee;
        auditTitle = 'تعديل العمولة العامة';
        auditDetails = `تغيير عمولة المنصة إلى ${newFee} ج`;

        // تحديث الطلبات المنتظرة بالرادار
        const { data: pendingOrds } = await supabase.from('orders').select('id, original_fare, fare').eq('status', 'PENDING');
        for (const po of (pendingOrds || [])) {
          const orig = roundMoney(po.original_fare ?? po.fare);
          await supabase.from('orders').update({
            platform_fee: newFee,
            courier_net: Math.max(0, roundMoney(orig - newFee))
          }).eq('id', po.id);
        }
      }
      if (req.body.loyaltyField) {
        const { key, value } = req.body.loyaltyField;
        const colMap = {
          customerPointsPerOrder: 'customer_points_per_order',
          customerRewardThreshold: 'customer_reward_threshold',
          customerRewardCash: 'customer_reward_cash',
          courierPointsPerOrder: 'courier_points_per_order',
          courierRewardThreshold: 'courier_reward_threshold',
          courierRewardCash: 'courier_reward_cash'
        };
        if (!colMap[key]) return res.status(400).json({ success: false, message: 'حقل غير صالح' });
        updateDb[colMap[key]] = key.includes('Cash') ? roundMoney(value) : Math.round(Number(value));
        auditTitle = 'تحديث عنابي بوينتس';
        auditDetails = `${key} = ${updateDb[colMap[key]]}`;
      }
    }

    // ب) تحديثات المناطق والأوزان وجدول الأسعار (تتطلب صلاحية managePricing)
    if (req.body.zones !== undefined || req.body.pricing !== undefined || req.body.packageTypes !== undefined) {
      if (!perms.managePricing) {
        return res.status(403).json({ success: false, message: 'لا تملك صلاحية إدارة المناطق والأوزان والتسعير 🛡️⛔' });
      }
      if (Array.isArray(req.body.zones) && req.body.zones.length > 0) {
        updateDb.zones_json = req.body.zones.map(z => String(z).trim()).filter(Boolean);
        auditTitle = 'تحديث المناطق الجغرافية';
        auditDetails = `عدد المناطق: ${updateDb.zones_json.length}`;
      }
      if (req.body.pricing && typeof req.body.pricing === 'object') {
        const cleanPricing = {};
        Object.keys(req.body.pricing).forEach(k => {
          const v = roundMoney(req.body.pricing[k]);
          if (v > 0) cleanPricing[k] = v;
        });
        updateDb.pricing_json = cleanPricing;
        auditTitle = 'تحديث جدول الأسعار';
        auditDetails = `تم اعتماد ${Object.keys(cleanPricing).length} مسار`;
      }
      if (Array.isArray(req.body.packageTypes) && req.body.packageTypes.length > 0) {
        updateDb.package_types_json = req.body.packageTypes.map(w => String(w).trim()).filter(Boolean);
        auditTitle = 'تحديث أوزان وأحجام الطرود';
        auditDetails = `عدد الاختيارات: ${updateDb.package_types_json.length}`;
      }
    }

    // ج) تحديثات الإعدادات العامة والصيانة والإعلان (تتطلب صلاحية manageSettings)
    if (
      req.body.broadcastMessage !== undefined ||
      req.body.supportWhatsapp !== undefined ||
      req.body.waitingTimeoutMinutes !== undefined ||
      req.body.maintenanceMode !== undefined ||
      req.body.allowCaptainRegistration !== undefined
    ) {
      if (!perms.manageSettings) {
        return res.status(403).json({ success: false, message: 'لا تملك صلاحية إدارة الإعدادات العامة والصيانة 🛡️⛔' });
      }
      if (req.body.broadcastMessage !== undefined) {
        updateDb.broadcast_message = String(req.body.broadcastMessage || '').trim().slice(0, 400);
        auditDetails = updateDb.broadcast_message || 'إخفاء الإعلان العام';
      }
      if (req.body.supportWhatsapp !== undefined) {
        const validWa = normalizeWhatsappNumber(req.body.supportWhatsapp);
        if (!validWa) return res.status(400).json({ success: false, message: 'رقم واتساب غير صالح ⚠️' });
        updateDb.support_whatsapp = validWa;
        auditDetails = `رقم الدعم: ${validWa}`;
      }
      if (req.body.waitingTimeoutMinutes !== undefined) {
        updateDb.waiting_timeout_minutes = Math.max(0, Math.round(Number(req.body.waitingTimeoutMinutes) || 0));
        auditDetails = `مهلة الانتظار: ${updateDb.waiting_timeout_minutes} دقيقة`;
      }
      if (req.body.maintenanceMode !== undefined) {
        updateDb.maintenance_mode = Boolean(req.body.maintenanceMode);
      }
      if (req.body.allowCaptainRegistration !== undefined) {
        updateDb.allow_captain_registration = Boolean(req.body.allowCaptainRegistration);
      }
    }

    await supabase.from('settings').update(updateDb).eq('id', settingsRowId);
    await recordAuditLogInDb({ actor, actionType: auditTitle, target: 'إعدادات المنصة', details: auditDetails || 'تم حفظ التعديلات' });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'تم حفظ الإعدادات وتطبيقها سحابياً بنجاح ⚙️✅', state: scopedState });
  } catch (error) {
    console.error('Admin Settings Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ الإعدادات' });
  }
});

// إدارة حساب الأدمن الرئيسي (Master Admin Only)
app.post('/api/admin/accounts/master', requireAdmin('MASTER_ONLY'), async (req, res) => {
  try {
    const master = req.admin;
    const newName = String(req.body.name || '').trim();
    const newUsername = String(req.body.username || '').trim();
    const currentPassword = String(req.body.currentPassword || '');
    const newPassword = String(req.body.newPassword || '').trim();

    if (!newName || !newUsername || /\s/.test(newUsername) || newUsername.length < 3) {
      return res.status(400).json({ success: false, message: 'برجاء كتابة الاسم واسم مستخدم صالح (3 أحرف على الأقل بدون مسافات) ⚠️' });
    }

    const { valid } = verifyPasswordSecure(currentPassword, master.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة! لا يمكن حفظ التغييرات الحساسة 🔒⚠️' });
    }

    const { data: allAdmins } = await supabase.from('admins').select('id, username');
    const duplicate = (allAdmins || []).find(a => a.id !== master.id && a.username.toLowerCase() === newUsername.toLowerCase());
    if (duplicate) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم هذا مستخدم بالفعل لحساب مسؤول آخر! ⚠️' });
    }

    const newSessionVersion = (Number(master.session_version) || 1) + 1;
    const updatePayload = {
      name: newName,
      username: newUsername,
      session_version: newSessionVersion
    };
    if (newPassword) {
      updatePayload.password_hash = hashPasswordSecure(newPassword);
    }

    await supabase.from('admins').update(updatePayload).eq('id', master.id);

    const token = setRoleCookie(res, 'ennaby_adm_token', {
      id: master.id,
      role: 'admin',
      username: newUsername,
      isMaster: true,
      sessionVersion: newSessionVersion
    }, 8 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_adm_token: token };

    await recordAuditLogInDb({
      actor: `${newName} (${newUsername})`,
      actionType: 'تحديث الحساب الرئيسي',
      target: newUsername,
      details: `تحديث بيانات الأدمن الرئيسي${newPassword ? ' وتغيير كلمة المرور المشفرة' : ''}`
    });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: 'تم تحديث بيانات حساب الأدمن الرئيسي وتأمين الجلسة بنجاح 👑✅', state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تحديث حساب الأدمن الرئيسي' });
  }
});

// إنشاء أو تعديل مسؤول فرعي وصلاحياته (Master Admin Only)
app.post('/api/admin/accounts/sub', requireAdmin('MASTER_ONLY'), async (req, res) => {
  try {
    const origUsername = String(req.body.origUsername || '').trim();
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '').trim();
    const permissions = (req.body.permissions && typeof req.body.permissions === 'object') ? req.body.permissions : {};

    if (!name || !username || /\s/.test(username) || username.length < 3) {
      return res.status(400).json({ success: false, message: 'برجاء إدخال اسم المسؤول واسم مستخدم صالح ⚠️' });
    }

    const { data: allAdmins } = await supabase.from('admins').select('*');
    const existingTarget = origUsername ? (allAdmins || []).find(a => a.username === origUsername && !a.is_master) : null;

    if (origUsername && !existingTarget) {
      return res.status(404).json({ success: false, message: 'حساب المسؤول الفرعي غير موجود ⚠️' });
    }

    const duplicate = (allAdmins || []).find(a => {
      if (existingTarget && a.id === existingTarget.id) return false;
      return a.username.toLowerCase() === username.toLowerCase();
    });
    if (duplicate) {
      return res.status(400).json({ success: false, message: 'اسم المستخدم مسجل بالفعل لمسؤول آخر! ⚠️' });
    }

    const actor = `${req.admin.name} (${req.admin.username})`;

    if (existingTarget) {
      const updatePayload = {
        name,
        username,
        permissions,
        session_version: (Number(existingTarget.session_version) || 1) + 1
      };
      if (password) {
        updatePayload.password_hash = hashPasswordSecure(password);
      }
      await supabase.from('admins').update(updatePayload).eq('id', existingTarget.id);
      await recordAuditLogInDb({ actor, actionType: 'تعديل مسؤول وصلاحياته', target: `${name} (${username})`, details: 'تحديث بيانات وصلاحيات المسؤول الفرعي' });
    } else {
      if (!password) {
        return res.status(400).json({ success: false, message: 'برجاء إدخال كلمة مرور للمسؤول الجديد ⚠️' });
      }
      await supabase.from('admins').insert([{
        username,
        password_hash: hashPasswordSecure(password),
        name,
        is_master: false,
        status: 'ACTIVE',
        session_version: 1,
        permissions
      }]);
      await recordAuditLogInDb({ actor, actionType: 'إنشاء مسؤول فرعي جديد', target: `${name} (${username})`, details: 'إنشاء حساب مسؤول فرعي بصلاحيات محددة' });
    }

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم حفظ واعتماد بيانات وصلاحيات المسؤول «${name}» بنجاح 🛡️✅`, state: scopedState });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء حفظ حساب المسؤول' });
  }
});

// تعطيل أو تنشيط مسؤول فرعي وإبطال جلسته فوراً (Master Admin Only)
app.post('/api/admin/accounts/:username/toggle', requireAdmin('MASTER_ONLY'), async (req, res) => {
  try {
    const targetUsername = String(req.params.username || '').trim();
    const { data: target } = await supabase
      .from('admins')
      .select('*')
      .eq('username', targetUsername)
      .eq('is_master', false)
      .maybeSingle();

    if (!target) {
      return res.status(404).json({ success: false, message: 'حساب المسؤول الفرعي غير موجود ⚠️' });
    }

    const isCurrentlyDisabled = String(target.status).toUpperCase() === 'DISABLED' || target.status === 'معطل';
    const nextStatusDb = isCurrentlyDisabled ? 'ACTIVE' : 'DISABLED';

    await supabase.from('admins').update({
      status: nextStatusDb,
      session_version: (Number(target.session_version) || 1) + 1
    }).eq('id', target.id);

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: nextStatusDb === 'DISABLED' ? 'تعطيل حساب مسؤول' : 'تنشيط حساب مسؤول',
      target: `${target.name} (${target.username})`,
      details: `تم تغيير حالة الحساب إلى (${nextStatusDb === 'DISABLED' ? 'معطل' : 'نشط'})`
    });

    const scopedState = await buildScopedStateForRequest(req);
    res.json({
      success: true,
      message: nextStatusDb === 'DISABLED' ? `تم تعطيل حساب المسؤول «${target.name}» وإيقاف جلسته فوراً ⛔` : `تم إعادة تنشيط حساب المسؤول «${target.name}» بنجاح ✅`,
      state: scopedState
    });
  } catch (error) {
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تغيير حالة المسؤول' });
  }
});

// ============================================================================
// 12. مهمة دورية على السيرفر لإلغاء الطلبات المنتظرة التي تجاوزت المهلة تلقائياً
// ============================================================================
async function cancelExpiredWaitingOrdersOnServer() {
  try {
    const { settings } = await getPlatformConfigFromDb();
    const timeoutMins = Number(settings.waitingTimeoutMinutes);
    if (!Number.isFinite(timeoutMins) || timeoutMins <= 0) return;

    const cutoffIso = new Date(Date.now() - timeoutMins * 60 * 1000).toISOString();
    const { data: expiredOrders } = await supabase
      .from('orders')
      .select('*')
      .eq('status', 'PENDING')
      .lt('created_at', cutoffIso);

    for (const ord of (expiredOrders || [])) {
      if (roundMoney(ord.discount_applied) > 0 && !ord.discount_refunded && ord.customer_id) {
        await adjustCustomerWalletAtomic({
          customerId: ord.customer_id,
          delta: roundMoney(ord.discount_applied),
          type: 'إيداع',
          title: `استرداد خصم لانتهاء مهلة انتظار الطلب (${ord.id})`,
          orderId: ord.id
        });
      }
      await supabase.from('orders').update({
        status: 'CANCELLED',
        exact_status: 'ملغي (لم يتوفر كابتن)',
        discount_refunded: true
      }).eq('id', ord.id);
    }
  } catch (e) {
    console.warn('[Expired Orders Check Warning]:', e.message);
  }
}

setInterval(cancelExpiredWaitingOrdersOnServer, 60 * 1000).unref();

// تشغيل الخادم
app.listen(PORT, async () => {
  await initializeDatabaseOnStartup();
  console.log(`🚀 [الرجل العنابي V32 - Production Ready] الخادم يعمل بأمان كامل على المنفذ: ${PORT}`);
});
