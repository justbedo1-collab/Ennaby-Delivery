require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs'); // مكتبة التشفير الأساسية
const { createClient } = require('@supabase/supabase-js');
const path = require('path');

// ============================================================================
// 1. التحقق الإلزامي من متغيرات البيئة (Zero-Fallback Security)
// ============================================================================
const REQUIRED_ENV = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'JWT_SECRET'];
const missingEnv = REQUIRED_ENV.filter(k => !process.env[k] || String(process.env[k]).trim() === '');

if (missingEnv.length > 0) {
  console.error(`❌ [خطأ أمني حرج] متغيرات البيئة التالية مفقودة في ملف .env: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const JWT_SECRET = String(process.env.JWT_SECRET).trim();
if (JWT_SECRET.length < 16) {
  console.error('❌ [خطأ أمني حرج] قيمة JWT_SECRET قصيرة جداً! يجب أن لا تقل عن 16 حرفاً.');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT) || Boolean(process.env.VERCEL);

app.set('trust proxy', 1);

const supabase = createClient(
  process.env.SUPABASE_URL.trim(),
  process.env.SUPABASE_SERVICE_ROLE_KEY.trim(),
  { auth: { persistSession: false } }
);

// ============================================================================
// 2. إعدادات الحماية
// ============================================================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '0');
  next();
});

const allowedOrigins = (process.env.ALLOWED_ORIGIN || '').split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (!IS_PROD && (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:'))) {
      return callback(null, true);
    }
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('غير مسموح بالوصول من هذا النطاق'));
  },
  credentials: true
}));

app.use(express.json({ limit: '6mb' }));
app.use(express.urlencoded({ extended: true, limit: '6mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

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
      return res.status(429).json({ success: false, message: message || 'تم تجاوز الحد المسموح ⚠️' });
    }
    return next();
  };
}

const authLimiter = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 15, message: 'محاولات دخول كثيرة! انتظر 15 دقيقة 🔒' });
const writeLimiter = createRateLimiter({ windowMs: 5 * 60 * 1000, max: 45, message: 'برجاء التمهل قليلاً 🛵' });

// ============================================================================
// 3. الثوابت والدوال المساعدة وتشفير كلمات المرور
// ============================================================================
const DEFAULT_ZONES = ['المنصورة', 'طلخا', 'سندوب', 'جديلة'];
const DEFAULT_PRICING = {
  'المنصورة|المنصورة': 40, 'طلخا|طلخا': 35, 'سندوب|سندوب': 35, 'جديلة|جديلة': 35,
  'المنصورة|طلخا': 50, 'طلخا|المنصورة': 50, 'المنصورة|سندوب': 50, 'سندوب|المنصورة': 50,
  'المنصورة|جديلة': 50, 'جديلة|المنصورة': 50, 'طلخا|سندوب': 70, 'سندوب|طلخا': 70,
  'طلخا|جديلة': 70, 'جديلة|طلخا': 70, 'سندوب|جديلة': 70, 'جديلة|سندوب': 70
};
const DEFAULT_PACKAGE_TYPES = ['طرد خفيف (أقل من 3 كجم) - شنطة أو ورق', 'طرد متوسط (3 إلى 8 كجم) - كرتونة', 'أكل أو حلويات (حاجة حساسة ع الميزان)'];
const DEFAULT_SETTINGS = {
  platformFee: 7, customerPointsPerOrder: 5, customerRewardThreshold: 100, customerRewardCash: 10,
  courierPointsPerOrder: 5, courierRewardThreshold: 100, courierRewardCash: 10,
  supportWhatsapp: '201507800875', broadcastMessage: '', maintenanceMode: false,
  allowCaptainRegistration: true, waitingTimeoutMinutes: 30, packageTypes: DEFAULT_PACKAGE_TYPES
};
const MAX_MANUAL_WALLET_TX = 5000;
const REFERRAL_REWARD_CASH = 50;
const REFERRAL_TARGET_ORDERS = 2;

async function hashPasswordSecure(plainText) {
  return await bcrypt.hash(String(plainText ?? ''), 10);
}

function legacyFnVHash(plainText) {
  const str = String(plainText ?? '');
  if (str.startsWith('ennaby_h1$')) return str;
  let h1 = 0x811c9dc5, h2 = 0x1000193;
  const salted = `ENNABY_SALT_V31::${str}::MANSOURA`;
  for (let i = 0; i < salted.length; i++) {
    const ch = salted.charCodeAt(i);
    h1 ^= ch;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = ((h2 << 5) + h2 + ch) >>> 0;
  }
  return `ennaby_h1$${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

async function verifyPasswordSecure(inputPlain, storedHash) {
  if (!inputPlain || !storedHash) return { valid: false, needsRehash: false };
  const plain = String(inputPlain);
  const stored = String(storedHash);

  if (stored.startsWith('ennaby_h1$')) {
    const match = legacyFnVHash(plain) === stored;
    return { valid: match, needsRehash: match }; 
  }
  if (stored.startsWith('scrypt$')) {
    try {
      const parts = stored.split('$');
      const salt = parts[4], keyHex = parts[5];
      const keyBuf = Buffer.from(keyHex, 'hex');
      const derivedBuf = crypto.scryptSync(plain, salt, keyBuf.length, { N: 16384, r: 8, p: 1 });
      const match = crypto.timingSafeEqual(keyBuf, derivedBuf);
      return { valid: match, needsRehash: true }; 
    } catch (e) { return { valid: false, needsRehash: false }; }
  }
  
  const match = await bcrypt.compare(plain, stored);
  return { valid: match, needsRehash: false };
}

function normalizeDigits(str) { return str == null ? '' : String(str).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 1632)).replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 1776)); }
function normalizePhone(raw) {
  let s = normalizeDigits(raw).replace(/[\s\-()]/g, '');
  if (s.startsWith('+20')) s = '0' + s.slice(3);
  else if (s.startsWith('0020')) s = '0' + s.slice(4);
  else if (s.startsWith('20') && s.length === 12 && /^201[0125]\d{8}$/.test(s)) s = '0' + s.slice(2);
  return s;
}
function isValidEgyptianPhone(phone) { return /^01[0125][0-9]{8}$/.test(normalizePhone(phone)); }
function normalizeWhatsappNumber(raw) {
  let s = normalizeDigits(raw).replace(/[^0-9]/g, '');
  if (/^01[0125]\d{8}$/.test(s)) s = '2' + s;
  else if (s.startsWith('0020')) s = s.slice(2);
  return /^20\d{10}$/.test(s) ? s : '';
}
function roundMoney(val) { const num = Number(normalizeDigits(val)); return Number.isFinite(num) ? Math.round((num + Number.EPSILON) * 100) / 100 : 0; }
function formatCairoDateTime(ts) {
  try { return new Date(Number(ts) || Date.now()).toLocaleString('ar-EG', { timeZone: 'Africa/Cairo', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
  catch (e) { return new Date(Number(ts) || Date.now()).toISOString(); }
}
function maskPhone(phone) { const p = String(phone || '').trim(); return p.length < 7 ? 'مخفي للخصوصية 🔒' : p.slice(0, 3) + '*****' + p.slice(-3); }
function generateOrderId() { return `ORD-${crypto.randomUUID().replace(/-/g, '').slice(0, 8).toUpperCase()}`; }

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
  if (orderRow.exact_status && String(orderRow.exact_status).trim()) return String(orderRow.exact_status).trim();
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
// 4. إدارة الكوكيز والتوكن
// ============================================================================
function setRoleCookie(res, cookieName, payload, maxAgeMs) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: Math.floor(maxAgeMs / 1000) });
  res.cookie(cookieName, token, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', path: '/', maxAge: maxAgeMs });
  return token;
}
function clearRoleCookie(res, cookieName) {
  res.clearCookie(cookieName, { httpOnly: true, secure: IS_PROD, sameSite: 'lax', path: '/' });
}
function verifyTokenFromReq(req, cookieName) {
  try {
    let token = req.cookies ? req.cookies[cookieName] : null;
    if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) token = req.headers.authorization.slice(7);
    return token ? jwt.verify(token, JWT_SECRET) : null;
  } catch (e) { return null; }
}

async function getAuthenticatedAdmin(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_adm_token');
  if (!decoded || decoded.role !== 'admin' || !decoded.username) return null;
  const { data: admin } = await supabase.from('admins').select('*').eq('username', decoded.username).maybeSingle();
  if (!admin || (!admin.is_master && (String(admin.status).toUpperCase() === 'DISABLED' || admin.status === 'معطل'))) return null;
  if (decoded.sessionVersion && admin.session_version && Number(decoded.sessionVersion) !== Number(admin.session_version)) return null;
  return admin;
}

async function getAuthenticatedCaptain(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_cour_token');
  if (!decoded || decoded.role !== 'captain' || !decoded.phone) return null;
  const { data: captain } = await supabase.from('captains').select('*').eq('phone', normalizePhone(decoded.phone)).maybeSingle();
  return captain || null;
}

async function getAuthenticatedCustomer(req) {
  const decoded = verifyTokenFromReq(req, 'ennaby_cust_token') || verifyTokenFromReq(req, 'ennaby_token');
  if (!decoded || decoded.role !== 'customer' || !decoded.phone) return null;
  const { data: customer } = await supabase.from('customers').select('*').eq('phone', normalizePhone(decoded.phone)).maybeSingle();
  return customer || null;
}

function requireAdmin(permKey = null) {
  return async (req, res, next) => {
    try {
      const admin = await getAuthenticatedAdmin(req);
      if (!admin) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً 🔒' });
      if (permKey === 'MASTER_ONLY' && !admin.is_master) return res.status(403).json({ success: false, message: 'هذا الإجراء مخصص للأدمن الرئيسي فقط 👑⛔' });
      if (permKey && permKey !== 'MASTER_ONLY' && !admin.is_master && !(admin.permissions || {})[permKey]) {
        return res.status(403).json({ success: false, message: 'لا تملك صلاحية تنفيذ هذا الإجراء 🛡️⛔' });
      }
      req.admin = admin;
      next();
    } catch (err) { res.status(500).json({ success: false, message: 'خطأ في التحقق من صلاحية المسؤول' }); }
  };
}

async function requireCaptain(req, res, next) {
  try {
    const captain = await getAuthenticatedCaptain(req);
    if (!captain) return res.status(401).json({ success: false, message: 'يرجى تسجيل دخول الكابتن أولاً 🛵🔒' });
    req.captain = captain;
    next();
  } catch (err) { res.status(500).json({ success: false, message: 'خطأ في التحقق من جلسة الكابتن' }); }
}

// ============================================================================
// 5. العمليات المالية وتخزين المستندات
// ============================================================================
async function adjustCustomerWalletAtomic({ customerId, delta, type, title, orderId = null, byAdmin = 'SYSTEM' }) {
  const cleanDelta = roundMoney(delta), txTypeDb = cleanDelta < 0 ? 'DEBIT' : 'CREDIT';
  const { data: rpcBal, error: rpcErr } = await supabase.rpc('adjust_customer_wallet_atomic', { p_customer_id: customerId, p_delta: cleanDelta, p_tx_type: txTypeDb, p_title: String(title || ''), p_order_id: orderId, p_performed_by: byAdmin });
  if (!rpcErr && rpcBal !== null && rpcBal !== undefined) return roundMoney(rpcBal);

  const { data: cust } = await supabase.from('customers').select('id, wallet_balance').eq('id', customerId).single();
  const newBalance = roundMoney(Number(cust.wallet_balance || 0) + cleanDelta);
  if (newBalance < 0) throw new Error('رصيد العميل غير كافٍ');
  await supabase.from('customers').update({ wallet_balance: newBalance }).eq('id', customerId);
  await supabase.from('wallet_transactions').insert([{ user_type: 'CUSTOMER', customer_id: customerId, order_id: orderId, type: txTypeDb, amount: Math.abs(cleanDelta), title: String(title || ''), performed_by: byAdmin }]);
  return newBalance;
}

async function adjustCaptainWalletAtomic({ captainId, delta, type, title, orderId = null, byAdmin = 'SYSTEM', allowNegativeClamp = false }) {
  const cleanDelta = roundMoney(delta), txTypeDb = cleanDelta < 0 ? 'DEBIT' : 'CREDIT';
  const { data: rpcBal, error: rpcErr } = await supabase.rpc('adjust_captain_wallet_atomic', { p_captain_id: captainId, p_delta: cleanDelta, p_tx_type: txTypeDb, p_title: String(title || ''), p_order_id: orderId, p_performed_by: byAdmin, p_allow_negative: allowNegativeClamp });
  if (!rpcErr && rpcBal !== null && rpcBal !== undefined) return roundMoney(rpcBal);

  const { data: cap } = await supabase.from('captains').select('id, wallet_balance').eq('id', captainId).single();
  let newBalance = roundMoney(Number(cap.wallet_balance || 0) + cleanDelta);
  if (newBalance < 0 && !allowNegativeClamp) throw new Error('رصيد الكابتن غير كافٍ');
  if (newBalance < 0) newBalance = 0;
  await supabase.from('captains').update({ wallet_balance: newBalance }).eq('id', captainId);
  await supabase.from('wallet_transactions').insert([{ user_type: 'CAPTAIN', captain_id: captainId, order_id: orderId, type: txTypeDb, amount: Math.abs(cleanDelta), title: String(title || ''), performed_by: byAdmin }]);
  return newBalance;
}

async function recordAuditLogInDb({ actor, actionType, target, details, result = 'نجاح' }) {
  await supabase.from('audit_logs').insert([{ actor: String(actor || 'النظام'), action_type: String(actionType || ''), action: String(actionType || ''), target: String(target || '-'), details: String(details || ''), result: String(result || 'نجاح') }]);
}

const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const ALLOWED_MIME_TYPES = { 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

async function uploadCaptainDocumentSecure(phone, docKey, dataUrl) {
  if (!dataUrl || typeof dataUrl !== 'string') return null;
  if (dataUrl.startsWith('storage://') || dataUrl.startsWith('https://')) return dataUrl;
  const matches = dataUrl.match(/^data:(image\/[a-zA-Z0-9+.-]+);base64,(.+)$/);
  if (!matches) throw new Error(`صيغة صورة (${docKey}) غير صالحة`);
  const mimeType = matches[1].toLowerCase(), ext = ALLOWED_MIME_TYPES[mimeType];
  if (!ext) throw new Error('يرجى رفع صورة بصيغة JPG أو PNG أو WEBP فقط');
  const buffer = Buffer.from(matches[2], 'base64');
  if (buffer.length > MAX_IMAGE_BYTES) throw new Error('حجم الصورة يتجاوز الحد المسموح (5 ميجابايت)');
  const filePath = `captains/${normalizePhone(phone)}_${docKey}_${Date.now()}.${ext}`;
  const { error } = await supabase.storage.from('captain-docs').upload(filePath, buffer, { contentType: mimeType, upsert: true });
  if (error) throw new Error('تعذر رفع الصورة السحابية');
  return `storage://captain-docs/${filePath}`;
}

async function resolveStorageUrlForAdmin(storedRef) {
  if (!storedRef || typeof storedRef !== 'string') return null;
  if (storedRef.startsWith('storage://captain-docs/')) {
    const { data } = await supabase.storage.from('captain-docs').createSignedUrl(storedRef.replace('storage://captain-docs/', ''), 2 * 60 * 60);
    return data?.signedUrl || null;
  }
  return storedRef;
}

// ============================================================================
// 6. الإعدادات والتهيئة
// ============================================================================
async function getPlatformConfigFromDb() {
  const { data: rows } = await supabase.from('settings').select('*').limit(1);
  const sRow = rows?.[0] || {};
  return {
    settings: {
      platformFee: sRow.platform_fee ?? DEFAULT_SETTINGS.platformFee,
      customerPointsPerOrder: Number(sRow.customer_points_per_order) || DEFAULT_SETTINGS.customerPointsPerOrder,
      customerRewardThreshold: Number(sRow.customer_reward_threshold) || DEFAULT_SETTINGS.customerRewardThreshold,
      customerRewardCash: Number(sRow.customer_reward_cash) || DEFAULT_SETTINGS.customerRewardCash,
      courierPointsPerOrder: Number(sRow.courier_points_per_order) || DEFAULT_SETTINGS.courierPointsPerOrder,
      courierRewardThreshold: Number(sRow.courier_reward_threshold) || DEFAULT_SETTINGS.courierRewardThreshold,
      courierRewardCash: Number(sRow.courier_reward_cash) || DEFAULT_SETTINGS.courierRewardCash,
      supportWhatsapp: sRow.support_whatsapp || DEFAULT_SETTINGS.supportWhatsapp,
      broadcastMessage: sRow.broadcast_message || '',
      maintenanceMode: Boolean(sRow.maintenance_mode),
      allowCaptainRegistration: sRow.allow_captain_registration ?? true,
      waitingTimeoutMinutes: sRow.waiting_timeout_minutes ?? 30,
      packageTypes: Array.isArray(sRow.package_types_json) && sRow.package_types_json.length ? sRow.package_types_json : DEFAULT_PACKAGE_TYPES
    },
    zones: Array.isArray(sRow.zones_json) && sRow.zones_json.length ? sRow.zones_json : DEFAULT_ZONES,
    pricing: (sRow.pricing_json && Object.keys(sRow.pricing_json).length) ? sRow.pricing_json : DEFAULT_PRICING,
    settingsRowId: sRow.id || 1
  };
}

async function initializeDatabaseOnStartup() {
  try {
    const { data: existingSettings } = await supabase.from('settings').select('id').limit(1);
    if (!existingSettings?.length) {
      await supabase.from('settings').insert([{ id: 1, platform_fee: DEFAULT_SETTINGS.platformFee }]);
    }
    const { data: existingAdmins } = await supabase.from('admins').select('id');
    if (!existingAdmins?.length) {
      const initUser = (process.env.INITIAL_ADMIN_USER || '').trim();
      const initPass = (process.env.INITIAL_ADMIN_PASS || '').trim();
      if (initUser && initPass) {
        await supabase.from('admins').insert([{
          username: initUser,
          password_hash: await hashPasswordSecure(initPass),
          name: 'الأدمن الرئيسي',
          is_master: true,
          status: 'ACTIVE',
          session_version: 1,
          permissions: { viewDashboard: true, viewCaptains: true, manageCaptains: true, viewOrders: true, manageOrders: true, manageWallets: true, manageCommissions: true, managePricing: true, manageSettings: true }
        }]);
      }
    }
  } catch (err) { console.warn('[Startup Init Warning]:', err.message); }
}

// ============================================================================
// 7. بناء الحالة المفلترة
// ============================================================================
async function buildScopedStateForRequest(req) {
  const [config, adminUser, captainUser, customerUser] = await Promise.all([
    getPlatformConfigFromDb(), getAuthenticatedAdmin(req), getAuthenticatedCaptain(req), getAuthenticatedCustomer(req)
  ]);
  const { settings, zones, pricing } = config;
  const resultState = { settings, zones, pricing, customers: {}, captains: [], orders: [], adminAccounts: [], auditLogs: [] };

  if (adminUser) {
    const perms = adminUser.is_master ? { viewDashboard: true, viewCaptains: true, manageCaptains: true, viewOrders: true, manageOrders: true, manageWallets: true, manageCommissions: true, managePricing: true, manageSettings: true } : (adminUser.permissions || {});
    const [ { data: dbCustomers }, { data: dbCaptains }, { data: dbOrders }, { data: dbAdmins }, { data: dbWalletTxs }, { data: dbAuditLogs }, { data: dbAlerts } ] = await Promise.all([
      (perms.viewDashboard || perms.manageWallets || perms.viewOrders || perms.manageOrders) ? supabase.from('customers').select('*').order('created_at', { ascending: false }).limit(500) : Promise.resolve({ data: [] }),
      (perms.viewDashboard || perms.viewCaptains || perms.manageCaptains || perms.manageWallets || perms.manageCommissions || perms.viewOrders) ? supabase.from('captains').select('*').order('created_at', { ascending: true }) : Promise.resolve({ data: [] }),
      (perms.viewDashboard || perms.viewOrders || perms.manageOrders || perms.viewCaptains) ? supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(300) : Promise.resolve({ data: [] }),
      supabase.from('admins').select('id, username, name, is_master, status, created_at, session_version, permissions').order('created_at', { ascending: true }),
      (perms.viewDashboard || perms.manageWallets) ? supabase.from('wallet_transactions').select('*').order('created_at', { ascending: false }).limit(200) : Promise.resolve({ data: [] }),
      (adminUser.is_master || perms.viewDashboard) ? supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(150) : Promise.resolve({ data: [] }),
      supabase.from('system_alerts').select('*').order('created_at', { ascending: false }).limit(100)
    ]);

    const customerIdToPhone = {}, captainIdToPhone = {}, captainTxMap = {};
    (dbCustomers || []).forEach(c => { const ph = normalizePhone(c.phone); if (ph) { customerIdToPhone[c.id] = ph; resultState.customers[ph] = { id: c.id, phone: ph, walletBalance: roundMoney(c.wallet_balance), points: Number(c.points) || 0, walletTransactions: [] }; } });
    (dbCaptains || []).forEach(c => { const ph = normalizePhone(c.phone); if (ph) { captainIdToPhone[c.id] = ph; captainTxMap[ph] = []; } });

    (dbWalletTxs || []).forEach(t => {
      const txItem = { type: (t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم' ? 'خصم' : 'إيداع', amount: roundMoney(t.amount), title: t.title || t.description || '', at: new Date(t.created_at).getTime(), time: formatCairoDateTime(t.created_at), by: t.performed_by !== 'SYSTEM' ? t.performed_by : null };
      if (t.customer_id && resultState.customers[customerIdToPhone[t.customer_id]]) resultState.customers[customerIdToPhone[t.customer_id]].walletTransactions.push(txItem);
      else if (t.captain_id && captainTxMap[captainIdToPhone[t.captain_id]]) captainTxMap[captainIdToPhone[t.captain_id]].push(txItem);
    });

    resultState.captains = await Promise.all((dbCaptains || []).map(async c => {
      const canSeeDocs = perms.viewCaptains || perms.manageCaptains;
      const [frontUrl, backUrl, vehUrl] = canSeeDocs ? await Promise.all([ resolveStorageUrlForAdmin(c.id_front_url), resolveStorageUrlForAdmin(c.id_back_url), resolveStorageUrlForAdmin(c.vehicle_photo_url) ]) : [null, null, null];
      return {
        id: c.id, phone: normalizePhone(c.phone), fullName: c.full_name, nationalId: canSeeDocs ? c.national_id : 'مخفي 🔒', primaryZone: c.primary_zone, vehicleType: c.vehicle_type, plateNumber: c.plate_number,
        idFrontPhoto: frontUrl, idBackPhoto: backUrl, vehiclePhoto: vehUrl, walletBalance: roundMoney(c.wallet_balance), walletTransactions: captainTxMap[normalizePhone(c.phone)] || [], points: Number(c.points) || 0, status: captainStatusFromDb(c.status), isAvailable: Boolean(c.is_available),
        customFee: c.custom_fee != null ? roundMoney(c.custom_fee) : null, customFeeReason: c.custom_fee_reason || '',
        adminNotices: c.admin_notices_json || (dbAlerts || []).filter(a => a.captain_id === c.id && !a.is_dismissed).map(a => ({ id: String(a.id), type: a.alert_type, text: a.message, at: new Date(a.created_at).getTime() })),
        referralsCount: Number(c.referrals_count) || 0, lifetimeCompleted: Number(c.lifetime_completed) || 0
      };
    }));

    resultState.orders = (dbOrders || []).map(o => formatOrderRowForClient(o, customerIdToPhone, captainIdToPhone, 'admin'));
    resultState.adminAccounts = (dbAdmins || []).filter(a => adminUser.is_master || a.username === adminUser.username).map(a => ({ id: a.id, username: a.username, name: a.name, isMaster: Boolean(a.is_master), status: a.status === 'DISABLED' || a.status === 'معطل' ? 'معطل' : 'نشط', permissions: a.permissions || {} }));
    resultState.auditLogs = (dbAuditLogs || []).map(l => ({ id: String(l.id), actor: l.actor, actionType: l.action_type || l.action, target: l.target, details: l.details, result: l.result, time: formatCairoDateTime(l.created_at) }));
  }

  if (captainUser) {
    const capPh = normalizePhone(captainUser.phone);
    const [ { data: capTxs }, { data: radarOrders } ] = await Promise.all([
      supabase.from('wallet_transactions').select('*').eq('captain_id', captainUser.id).order('created_at', { ascending: false }).limit(60),
      supabase.from('orders').select('*').or(`status.eq.PENDING,captain_id.eq.${captainUser.id}`).order('created_at', { ascending: false }).limit(120)
    ]);
    resultState.captains = [{
      id: captainUser.id, phone: capPh, fullName: captainUser.full_name, nationalId: captainUser.national_id, primaryZone: captainUser.primary_zone, vehicleType: captainUser.vehicle_type, plateNumber: captainUser.plate_number,
      walletBalance: roundMoney(captainUser.wallet_balance), points: Number(captainUser.points) || 0, status: captainStatusFromDb(captainUser.status), isAvailable: Boolean(captainUser.is_available),
      walletTransactions: (capTxs || []).map(t => ({ type: (t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم' ? 'خصم' : 'إيداع', amount: roundMoney(t.amount), title: t.title || t.description || '', time: formatCairoDateTime(t.created_at) })),
      adminNotices: captainUser.admin_notices_json || []
    }];
    resultState.orders = (radarOrders || []).map(o => formatOrderRowForClient(o, {}, { [captainUser.id]: capPh }, 'captain', capPh));
  }

  if (customerUser) {
    const custPh = normalizePhone(customerUser.phone);
    const [ { data: custTxs }, { data: custOrders } ] = await Promise.all([
      supabase.from('wallet_transactions').select('*').eq('customer_id', customerUser.id).order('created_at', { ascending: false }).limit(50),
      supabase.from('orders').select('*').eq('customer_id', customerUser.id).order('created_at', { ascending: false }).limit(60)
    ]);
    resultState.customers[custPh] = {
      id: customerUser.id, phone: custPh, walletBalance: roundMoney(customerUser.wallet_balance), points: Number(customerUser.points) || 0,
      walletTransactions: (custTxs || []).map(t => ({ type: (t.type || '').toUpperCase() === 'DEBIT' || t.type === 'خصم' ? 'خصم' : 'إيداع', amount: roundMoney(t.amount), title: t.title || t.description || '', time: formatCairoDateTime(t.created_at) }))
    };
    const custIdMap = { [customerUser.id]: custPh }, existingOrdIds = new Set(resultState.orders.map(o => o.id));
    (custOrders || []).forEach(o => { if (!existingOrdIds.has(o.id)) resultState.orders.push(formatOrderRowForClient(o, custIdMap, {}, 'customer')); });
  }

  return resultState;
}

function formatOrderRowForClient(o, customerIdToPhone, captainIdToPhone, viewerRole, viewerPhone = '') {
  const isFetch = String(o.trip_type || '').toUpperCase() === 'FETCH';
  const arStatus = resolveExactOrderStatus(o);
  const resolvedClientPhone = (o.customer_id && customerIdToPhone[o.customer_id]) || (isFetch ? normalizePhone(o.recipient_phone) : normalizePhone(o.sender_phone));
  const resolvedCourierPhone = (o.captain_id && captainIdToPhone[o.captain_id]) || null;
  const shouldMask = viewerRole === 'captain' && (arStatus === 'في انتظار كابتن' || arStatus === 'مكتمل' || arStatus === 'قيد مراجعة الاعتراض' || resolvedCourierPhone !== viewerPhone);

  return {
    id: o.id, createdAt: new Date(o.created_at).getTime(), time: formatCairoDateTime(o.created_at), tripType: isFetch ? 'fetch' : 'send',
    clientPhone: shouldMask ? maskPhone(resolvedClientPhone) : resolvedClientPhone,
    senderPhone: shouldMask ? maskPhone(o.sender_phone) : normalizePhone(o.sender_phone),
    recipientPhone: shouldMask ? maskPhone(o.recipient_phone) : normalizePhone(o.recipient_phone),
    pickupZone: o.pickup_zone, pickupAddress: o.pickup_address, dropoffZone: o.dropoff_zone, dropoffAddress: o.dropoff_address, customerNotes: o.customer_notes || '', packageType: o.package_type || '',
    originalFare: roundMoney(o.original_fare ?? o.fare ?? 0), discountApplied: roundMoney(o.discount_applied ?? 0), fare: roundMoney(o.fare ?? 0), platformFee: roundMoney(o.platform_fee ?? 7), courierNet: roundMoney(o.courier_net ?? 0), payer: o.payer || 'الراسل',
    status: arStatus, assignedCourierPhone: arStatus === 'في انتظار كابتن' ? null : resolvedCourierPhone,
    feeDeducted: Boolean(o.fee_deducted), feeRefunded: Boolean(o.fee_refunded), rating: o.rating != null ? Number(o.rating) : null, disputeReason: o.dispute_reason || null
  };
}

// ============================================================================
// 8. مسارات المصادقة
// ============================================================================
app.get('/api/health', (req, res) => res.json({ status: 'success', environment: IS_PROD ? 'production' : 'development', message: 'خادم منصة الرجل العنابي V33 المؤمّن يعمل بكفاءة عالية! 🛵🛡️' }));
app.get('/api/bootstrap', async (req, res) => { try { res.json({ success: true, state: await buildScopedStateForRequest(req) }); } catch (error) { res.status(500).json({ success: false, message: 'حدث خطأ أثناء جلب البيانات' }); } });

// ✅ تسجيل دخول العميل برقم الهاتف وكلمة المرور (الـ PIN)
app.post('/api/auth/customer/login', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const pin = normalizeDigits(req.body.pin || '').trim();

  if (!isValidEgyptianPhone(phone)) return res.status(400).json({ success: false, message: 'برجاء إدخال رقم هاتف مصري صحيح 📱⚠️' });
  if (!/^[0-9]{4}$/.test(pin)) return res.status(400).json({ success: false, message: 'برجاء إدخال رمز PIN مكون من 4 أرقام 🔒⚠️' });

  try {
    let { data: customer } = await supabase.from('customers').select('*').eq('phone', phone).maybeSingle();
    
    if (!customer) {
      const pinHash = await bcrypt.hash(pin, 10);
      const { data: nCust } = await supabase.from('customers').insert([{ phone, pin_hash: pinHash, wallet_balance: 0, points: 0 }]).select().single();
      customer = nCust;
    } else {
      if (!customer.pin_hash) {
        // تحديث وتشفير حساب العميل القديم
        const pinHash = await bcrypt.hash(pin, 10);
        await supabase.from('customers').update({ pin_hash: pinHash }).eq('id', customer.id);
        customer.pin_hash = pinHash;
      } else {
        const isMatch = await bcrypt.compare(pin, customer.pin_hash);
        if (!isMatch) {
          return res.status(401).json({ success: false, message: 'رقم الهاتف أو رمز الـ PIN غير صحيح! 🔒⚠️' });
        }
      }
    }

    const token = setRoleCookie(res, 'ennaby_cust_token', { id: customer.id, role: 'customer', phone: customer.phone }, 30 * 24 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_cust_token: token };
    res.json({ success: true, message: 'تم فتح حسابك بنجاح 🛵👑', state: await buildScopedStateForRequest(req) });
  } catch (e) { res.status(500).json({ success: false, message: 'حدث خطأ داخلي' }); }
});

app.post('/api/auth/captain/login', authLimiter, async (req, res) => {
  const phone = normalizePhone(req.body.phone), password = String(req.body.password || '').trim();
  if (!isValidEgyptianPhone(phone) || !password) return res.status(400).json({ success: false, message: 'برجاء إدخال البيانات بشكل صحيح ⚠️' });
  try {
    const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    
    const { valid, needsRehash } = await verifyPasswordSecure(password, cap.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    if (needsRehash) {
      await supabase.from('captains').update({ password_hash: await hashPasswordSecure(password) }).eq('id', cap.id);
    }

    if (captainStatusFromDb(cap.status) === 'مرفوض') return res.status(403).json({ success: false, message: 'تم رفض المستندات، يمكنك إرسال أوراق واضحة 📄⚠️' });
    const token = setRoleCookie(res, 'ennaby_cour_token', { id: cap.id, role: 'captain', phone: cap.phone }, 14 * 24 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_cour_token: token };
    res.json({ success: true, message: `أهلاً بك يا كابتن ${cap.full_name} 🛵✅`, state: await buildScopedStateForRequest(req) });
  } catch (e) { res.status(500).json({ success: false, message: 'خطأ أثناء الدخول' }); }
});

app.post('/api/auth/captain/logout', (req, res) => { clearRoleCookie(res, 'ennaby_cour_token'); res.json({ success: true, message: 'تم تسجيل الخروج 👋' }); });

app.post('/api/auth/admin/login', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim(), password = String(req.body.password || '');
  if (!username || !password) return res.status(400).json({ success: false, message: 'أدخل اسم المستخدم وكلمة المرور ⚠️' });
  try {
    const { data: admins } = await supabase.from('admins').select('*');
    const admin = (admins || []).find(a => String(a.username || '').toLowerCase() === username.toLowerCase());
    if (!admin) return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });

    const { valid, needsRehash } = await verifyPasswordSecure(password, admin.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'بيانات الدخول غير صحيحة! ⚠️' });
    
    if (!admin.is_master && (String(admin.status).toUpperCase() === 'DISABLED' || admin.status === 'معطل')) return res.status(403).json({ success: false, message: 'عفواً تم تعطيل حسابك ⛔' });
    if (needsRehash) {
      await supabase.from('admins').update({ password_hash: await hashPasswordSecure(password) }).eq('id', admin.id);
    }

    const token = setRoleCookie(res, 'ennaby_adm_token', { id: admin.id, role: 'admin', username: admin.username, isMaster: Boolean(admin.is_master), sessionVersion: Number(admin.session_version) || 1 }, 8 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_adm_token: token };
    res.json({ success: true, message: `أهلاً بك يا ${admin.name} 🛡️✅`, state: await buildScopedStateForRequest(req) });
  } catch (e) { res.status(500).json({ success: false, message: 'خطأ أثناء تسجيل دخول الإدارة' }); }
});

app.post('/api/auth/admin/logout', (req, res) => { clearRoleCookie(res, 'ennaby_adm_token'); res.json({ success: true, message: 'تم تسجيل الخروج 👋' }); });

// ============================================================================
// 9. الطلبات والكباتن (الأوامر الحساسة)
// ============================================================================

// ✅ إنشاء طلب جديد مع التحقق من الـ PIN السري
app.post('/api/orders', writeLimiter, async (req, res) => {
  try {
    const { settings, zones, pricing } = await getPlatformConfigFromDb();
    if (settings.maintenanceMode) {
      return res.status(503).json({ success: false, message: 'عفواً يا باشا! المنصة في صيانة سريعة حالياً وراجعين فوراً 🛠️' });
    }

    const clientPhone = normalizePhone(req.body.clientPhone);
    const pin = normalizeDigits(req.body.pin || '').trim();
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

    if (!zones.includes(pickupZone) || !zones.includes(dropoffZone)) return res.status(400).json({ success: false, message: 'برجاء اختيار منطقة استلام وتسليم صحيحة من القائمة 📍⚠️' });
    if (!pickupAddress || !dropoffAddress) return res.status(400).json({ success: false, message: 'برجاء كتابة عنوان الاستلام والتسليم بالتفصيل 📍⚠️' });
    if (!isValidEgyptianPhone(clientPhone) || !isValidEgyptianPhone(senderPhone) || !isValidEgyptianPhone(recipientPhone)) return res.status(400).json({ success: false, message: 'برجاء إدخال أرقام هواتف مصرية صحيحة 📱⚠️' });
    if (!/^[0-9]{4}$/.test(pin)) return res.status(400).json({ success: false, message: 'برجاء إدخال رمز PIN السري (4 أرقام) لتأكيد الطلب وحماية محفظتك 🔒⚠️' });

    const routeKey = `${pickupZone}|${dropoffZone}`;
    if (pricing[routeKey] === undefined) return res.status(400).json({ success: false, message: 'عفواً هذا المسار ليس له تسعير معتمد حالياً! ⚠️' });

    // ✅ التحقق من العميل ورمز الـ PIN قبل إنشاء الطلب
    let { data: customer } = await supabase.from('customers').select('*').eq('phone', clientPhone).maybeSingle();
    if (!customer) {
      const pinHash = await bcrypt.hash(pin, 10);
      const { data: createdCust, error: createErr } = await supabase.from('customers').insert([{ phone: clientPhone, pin_hash: pinHash, wallet_balance: 0, points: 0 }]).select().single();
      if (createErr) throw createErr;
      customer = createdCust;
    } else {
      if (!customer.pin_hash) {
        const pinHash = await bcrypt.hash(pin, 10);
        await supabase.from('customers').update({ pin_hash: pinHash }).eq('id', customer.id);
      } else {
        const isMatch = await bcrypt.compare(pin, customer.pin_hash);
        if (!isMatch) return res.status(401).json({ success: false, message: 'رمز الـ PIN غير صحيح! تأكد منه لحماية محفظتك 🔒⚠️' });
      }
    }

    const serverOriginalFare = Math.max(0, roundMoney(pricing[routeKey]));
    const serverPlatformFee = Math.max(0, roundMoney(settings.platformFee));
    const serverCourierNet = Math.max(0, roundMoney(serverOriginalFare - serverPlatformFee));
    const availableWallet = Math.max(0, roundMoney(customer.wallet_balance || 0));
    const serverDiscount = availableWallet > 0 ? roundMoney(Math.min(availableWallet, serverOriginalFare)) : 0;
    const serverFinalFare = Math.max(0, roundMoney(serverOriginalFare - serverDiscount));
    const orderId = generateOrderId();

    const { data: order, error: insertError } = await supabase.from('orders').insert([{
      id: orderId, customer_id: customer.id, trip_type: isFetch ? 'FETCH' : 'SEND',
      pickup_zone: pickupZone, pickup_address: pickupAddress, dropoff_zone: dropoffZone, dropoff_address: dropoffAddress,
      customer_notes: customerNotes, package_type: packageType, payer, sender_phone: senderPhone, recipient_phone: recipientPhone,
      original_fare: serverOriginalFare, discount_applied: serverDiscount, fare: serverFinalFare, platform_fee: serverPlatformFee,
      courier_net: serverCourierNet, status: 'PENDING', exact_status: 'في انتظار كابتن'
    }]).select().single();
    
    if (insertError) throw insertError;

    if (serverDiscount > 0) {
      try {
        await adjustCustomerWalletAtomic({ customerId: customer.id, delta: -serverDiscount, type: 'خصم', title: `استخدام رصيد خصم على طلب (${orderId})`, orderId });
      } catch (walletErr) {
        await supabase.from('orders').delete().eq('id', orderId);
        throw walletErr;
      }
    }

    const token = setRoleCookie(res, 'ennaby_cust_token', { id: customer.id, role: 'customer', phone: customer.phone }, 30 * 24 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_cust_token: token };

    const scopedState = await buildScopedStateForRequest(req);
    res.json({ success: true, message: `تم إرسال طلبك (${orderId}) ورجالة العنابي هيستلموه فوراً 🚀`, order, state: scopedState });
  } catch (error) {
    console.error('Order Creation Error:', error.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تأكيد الطلب' });
  }
});

// المسارات الأخرى للطلبات...
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

    if (arStatus === 'تم قبول الطلب' && order.captain_id && order.fee_deducted && !order.fee_refunded) {
      const lockedFee = roundMoney(order.platform_fee);
      const lockedDiscount = roundMoney(order.discount_applied);
      if (lockedFee > 0) await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: lockedFee, type: 'استرداد', title: `استرداد عمولة إلغاء طلب (${order.id})`, orderId: order.id });
      if (lockedDiscount > 0) await adjustCaptainWalletAtomic({ captainId: order.captain_id, delta: -lockedDiscount, type: 'خصم', title: `عكس تعويض خصم لطلب ملغي (${order.id})`, orderId: order.id, allowNegativeClamp: true });
    }

    if (order.captain_id) {
      const { data: cap } = await supabase.from('captains').select('lifetime_cancelled').eq('id', order.captain_id).maybeSingle();
      if (cap) await supabase.from('captains').update({ lifetime_cancelled: (Number(cap.lifetime_cancelled) || 0) + 1 }).eq('id', order.captain_id);
    }

    if (roundMoney(order.discount_applied) > 0 && !order.discount_refunded && order.customer_id) {
      await adjustCustomerWalletAtomic({ customerId: order.customer_id, delta: roundMoney(order.discount_applied), type: 'إيداع', title: `استرداد رصيد خصم لطلب ملغي (${order.id})`, orderId: order.id });
    }

    await supabase.from('orders').update({ status: 'CANCELLED', exact_status: 'ملغي من العميل', fee_refunded: true, discount_refunded: true }).eq('id', order.id);
    res.json({ success: true, message: `تم إلغاء طلبك (${orderId}) بنجاح ✅`, state: await buildScopedStateForRequest(req) });
  } catch (error) { res.status(500).json({ success: false, message: 'حدث خطأ أثناء إلغاء الطلب' }); }
});

app.post('/api/captains/register', writeLimiter, async (req, res) => {
  try {
    const { settings, zones } = await getPlatformConfigFromDb();
    const phone = normalizePhone(req.body.phone), password = String(req.body.password || '').trim(), fullName = String(req.body.fullName || '').trim(), nationalId = normalizeDigits(req.body.nationalId || '').trim();
    if (!fullName || !isValidEgyptianPhone(phone) || !password) return res.status(400).json({ success: false, message: 'تأكد من إدخال جميع البيانات وكلمة مرور صالحة ⚠️' });

    const passHash = await hashPasswordSecure(password);
    const [frontRef, backRef, vehRef] = await Promise.all([ uploadCaptainDocumentSecure(phone, 'idFront', req.body.idFrontPhoto), uploadCaptainDocumentSecure(phone, 'idBack', req.body.idBackPhoto), uploadCaptainDocumentSecure(phone, 'vehicle', req.body.vehiclePhoto) ]);
    const { error: insErr } = await supabase.from('captains').insert([{ phone, password_hash: passHash, full_name: fullName, national_id: nationalId, id_front_url: frontRef, id_back_url: backRef, vehicle_photo_url: vehRef, status: 'PENDING', is_available: false }]);
    if (insErr) throw insErr;
    res.json({ success: true, message: 'تم إرسال طلب تسجيل الكابتن وحفظ المستندات بأمان 🛵✅', state: await buildScopedStateForRequest(req) });
  } catch (error) { res.status(400).json({ success: false, message: error.message }); }
});

// ============================================================================
// 10. الإدارة الآمنة (Admin Routes)
// ============================================================================

app.post('/api/admin/captains/reset-password', requireAdmin('manageCaptains'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone), newPass = String(req.body.newPass || '').trim();
    if (!isValidEgyptianPhone(phone) || !newPass || newPass.length < 4) return res.status(400).json({ success: false, message: 'رقم الهاتف أو كلمة المرور الجديدة غير صالحة ⚠️' });
    
    const { data: cap } = await supabase.from('captains').select('id, full_name').eq('phone', phone).maybeSingle();
    if (!cap) return res.status(404).json({ success: false, message: 'الكابتن غير مسجل ⚠️' });

    const newHash = await hashPasswordSecure(newPass);
    await supabase.from('captains').update({ password_hash: newHash }).eq('id', cap.id);

    await recordAuditLogInDb({ actor: `${req.admin.name}`, actionType: 'إعادة تعيين باسورد كابتن', target: cap.full_name });
    res.json({ success: true, message: `تم تغيير الباسورد للكابتن (${cap.full_name}) أرسله له على الواتساب 🔑✅` });
  } catch (err) { res.status(500).json({ success: false, message: 'حدث خطأ أثناء التعيين' }); }
});

// ✅ مسار جديد للإدارة لتصفير وتحديث رمز PIN للعميل (إذا نسيه)
app.post('/api/admin/customers/reset-pin', requireAdmin('manageWallets'), async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const newPin = normalizeDigits(req.body.newPin || '').trim();

    if (!isValidEgyptianPhone(phone)) return res.status(400).json({ success: false, message: 'رقم هاتف العميل غير صحيح 📱⚠️' });
    if (!/^[0-9]{4}$/.test(newPin)) return res.status(400).json({ success: false, message: 'رمز الـ PIN الجديد يجب أن يكون 4 أرقام بالضبط 🔒⚠️' });

    const { data: cust } = await supabase.from('customers').select('id, phone').eq('phone', phone).maybeSingle();
    if (!cust) return res.status(404).json({ success: false, message: 'عفواً.. العميل غير مسجل في قاعدة البيانات ⚠️' });

    const newHash = await bcrypt.hash(newPin, 10);
    await supabase.from('customers').update({ pin_hash: newHash }).eq('id', cust.id);

    await recordAuditLogInDb({
      actor: `${req.admin.name} (${req.admin.username})`,
      actionType: 'تصفير PIN عميل',
      target: phone,
      details: 'تم تعيين رمز PIN جديد للعميل'
    });

    res.json({ success: true, message: `تم تصفير وتحديث رمز الـ PIN للعميل (${phone}) بنجاح 🔒✅` });
  } catch (err) {
    console.error('Reset Customer PIN Error:', err.message);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تصفير الـ PIN' });
  }
});

app.post('/api/admin/accounts/master', requireAdmin('MASTER_ONLY'), async (req, res) => {
  try {
    const master = req.admin, newName = String(req.body.name || '').trim(), newUsername = String(req.body.username || '').trim(), currentPassword = String(req.body.currentPassword || ''), newPassword = String(req.body.newPassword || '').trim();
    const { valid } = await verifyPasswordSecure(currentPassword, master.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: 'كلمة المرور الحالية غير صحيحة! 🔒⚠️' });
    
    const updatePayload = { name: newName, username: newUsername, session_version: (Number(master.session_version) || 1) + 1 };
    if (newPassword) updatePayload.password_hash = await hashPasswordSecure(newPassword);
    
    await supabase.from('admins').update(updatePayload).eq('id', master.id);
    const token = setRoleCookie(res, 'ennaby_adm_token', { id: master.id, role: 'admin', username: newUsername, isMaster: true, sessionVersion: updatePayload.session_version }, 8 * 60 * 60 * 1000);
    req.cookies = { ...(req.cookies || {}), ennaby_adm_token: token };
    res.json({ success: true, message: 'تم تحديث بياناتك وتأمين الجلسة بنجاح 👑✅', state: await buildScopedStateForRequest(req) });
  } catch (error) { res.status(500).json({ success: false, message: 'خطأ' }); }
});

// استرجاع دالة إنشاء وتعديل المسؤولين الفرعيين
app.post('/api/admin/accounts/sub', requireAdmin('MASTER_ONLY'), async (req, res) => {
  try {
    const { origUsername, name, username, password, permissions } = req.body;
    if (!name || !username || username.length < 3) return res.status(400).json({ success: false, message: 'برجاء إدخال بيانات صحيحة ⚠️' });

    const { data: allAdmins } = await supabase.from('admins').select('*');
    const existingTarget = origUsername ? (allAdmins || []).find(a => a.username === origUsername && !a.is_master) : null;
    if (origUsername && !existingTarget) return res.status(404).json({ success: false, message: 'المسؤول غير موجود ⚠️' });

    const duplicate = (allAdmins || []).find(a => (existingTarget && a.id === existingTarget.id) ? false : a.username.toLowerCase() === username.toLowerCase());
    if (duplicate) return res.status(400).json({ success: false, message: 'اسم المستخدم مسجل لمسؤول آخر! ⚠️' });

    if (existingTarget) {
      const updatePayload = { name, username, permissions, session_version: (Number(existingTarget.session_version) || 1) + 1 };
      if (password) updatePayload.password_hash = await hashPasswordSecure(password);
      await supabase.from('admins').update(updatePayload).eq('id', existingTarget.id);
      await recordAuditLogInDb({ actor: req.admin.name, actionType: 'تعديل مسؤول', target: username });
    } else {
      if (!password) return res.status(400).json({ success: false, message: 'كلمة المرور مطلوبة للمسؤول الجديد ⚠️' });
      await supabase.from('admins').insert([{
        username, password_hash: await hashPasswordSecure(password), name, is_master: false, status: 'ACTIVE', session_version: 1, permissions
      }]);
      await recordAuditLogInDb({ actor: req.admin.name, actionType: 'إنشاء مسؤول فرعي', target: username });
    }
    res.json({ success: true, message: `تم تحديث بيانات المسؤول بنجاح 🛡️✅`, state: await buildScopedStateForRequest(req) });
  } catch (error) { res.status(500).json({ success: false, message: 'خطأ أثناء حفظ الحساب' }); }
});

// ============================================================================
// 11. عزل لوحة الإدارة تماماً بمسار محمي
// ============================================================================

app.get('/admins', async (req, res) => {
  const admin = await getAuthenticatedAdmin(req);
  if (!admin) {
    // عرض شاشة تسجيل دخول احترافية ومدمجة للأدمن لو لم يكن مسجلاً للدخول
    return res.send(`
      <!DOCTYPE html>
      <html lang="ar" dir="rtl">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>دخول غرفة العمليات | الرجل العنابي 🛡️</title>
        <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&display=swap" rel="stylesheet">
        <style>
          body { font-family: 'Cairo', sans-serif; background: #FAF7F4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
          .login-card { background: #fff; padding: 30px; border-radius: 20px; box-shadow: 0 10px 30px rgba(123,63,82,0.15); width: 100%; max-width: 380px; text-align: center; border: 1px solid rgba(123,63,82,0.1); }
          .badge { width: 55px; height: 55px; background: #302A2D; color: #FBC02D; border-radius: 16px; display: flex; align-items: center; justify-content: center; font-size: 26px; margin: 0 auto 15px; }
          h2 { color: #7B3F52; font-size: 20px; font-weight: 900; margin-bottom: 5px; }
          p { color: #665E62; font-size: 12px; margin-bottom: 20px; }
          .input-group { margin-bottom: 12px; text-align: right; }
          label { font-size: 11px; font-weight: 700; color: #665E62; display: block; margin-bottom: 4px; }
          input { width: 100%; padding: 12px; border-radius: 12px; border: 1.5px solid #E8DFE3; background: #FAF7F4; font-size: 13px; font-weight: 600; outline: none; box-sizing: border-box; font-family: 'Cairo', sans-serif; }
          input:focus { border-color: #7B3F52; background: #fff; }
          button { background: #7B3F52; color: #fff; border: none; border-radius: 12px; padding: 12px; width: 100%; font-size: 14px; font-weight: 800; cursor: pointer; margin-top: 10px; font-family: 'Cairo', sans-serif; box-shadow: 0 4px 12px rgba(123,63,82,0.25); }
          button:active { background: #5F2E3E; }
          .msg { font-size: 12px; font-weight: 700; margin-top: 12px; }
        </style>
      </head>
      <body>
        <div class="login-card">
          <div class="badge">🛡️</div>
          <h2>غرفة العمليات المركزية</h2>
          <p>سجّل الدخول بحساب المسؤول للمتابعة</p>
          <form id="adminLoginForm" onsubmit="handleLogin(event)">
            <div class="input-group">
              <label>اسم المستخدم</label>
              <input type="text" id="username" required placeholder="اسم المستخدم الإداري">
            </div>
            <div class="input-group">
              <label>كلمة المرور السرية</label>
              <input type="password" id="password" required placeholder="••••••••">
            </div>
            <button type="submit">تسجيل الدخول 🚀</button>
          </form>
          <div id="errorMsg" class="msg" style="color: #D32F2F; display: none;"></div>
        </div>

        <script>
          async function handleLogin(e) {
            e.preventDefault();
            const u = document.getElementById('username').value.trim();
            const p = document.getElementById('password').value;
            const errEl = document.getElementById('errorMsg');
            errEl.style.display = 'none';

            try {
              const res = await fetch('/api/auth/admin/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: u, password: p })
              });
              const data = await res.json();
              if(res.ok && data.success) {
                window.location.reload(); // تحديث الصفحة لفتح اللوحة مباشرة بعد حفظ الكوكي
              } else {
                errEl.innerText = data.message || 'بيانات الدخول غير صحيحة!';
                errEl.style.display = 'block';
              }
            } catch (err) {
              errEl.innerText = 'حدث خطأ في الاتصال بالخادم';
              errEl.style.display = 'block';
            }
          }
        </script>
      </body>
      </html>
    `);
  }
  res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});

app.get('/install', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'install.html'));
});

// مهمة دورية لإلغاء الطلبات المتأخرة
setInterval(async () => {
  try {
    const { settings } = await getPlatformConfigFromDb();
    const timeoutMins = Number(settings.waitingTimeoutMinutes);
    if (!Number.isFinite(timeoutMins) || timeoutMins <= 0) return;

    const cutoffIso = new Date(Date.now() - timeoutMins * 60 * 1000).toISOString();
    const { data: expiredOrders } = await supabase.from('orders').select('*').eq('status', 'PENDING').lt('created_at', cutoffIso);

    for (const ord of (expiredOrders || [])) {
      if (roundMoney(ord.discount_applied) > 0 && !ord.discount_refunded && ord.customer_id) {
        await adjustCustomerWalletAtomic({ customerId: ord.customer_id, delta: roundMoney(ord.discount_applied), type: 'إيداع', title: `استرداد خصم لانتهاء مهلة انتظار الطلب (${ord.id})`, orderId: ord.id });
      }
      await supabase.from('orders').update({ status: 'CANCELLED', exact_status: 'ملغي (لم يتوفر كابتن)', discount_refunded: true }).eq('id', ord.id);
    }
  } catch (e) {}
}, 60 * 1000).unref();

app.listen(PORT, async () => {
  await initializeDatabaseOnStartup();
  console.log(`🚀 [الرجل العنابي V33 - PIN Secured] الخادم يعمل بأمان على منفذ: ${PORT}`);
});