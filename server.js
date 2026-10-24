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
const JWT_SECRET = process.env.JWT_SECRET || 'ENNABY_SUPER_SECRET_KEY_V31_2026';

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

function resolveHtmlFilePath(filename) {
  const rootFile = path.join(__dirname, filename);
  if (fs.existsSync(rootFile)) return rootFile;
  const publicFile = path.join(__dirname, 'public', filename);
  if (fs.existsSync(publicFile)) return publicFile;
  return rootFile;
}

// تقديم الملفات الثابتة وصفحات التطبيق بأولوية للمجلد الرئيسي ثم public
app.get('/', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));
app.get('/index.html', (req, res) => res.sendFile(resolveHtmlFilePath('index.html')));
app.get('/admin', (req, res) => res.sendFile(resolveHtmlFilePath('admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(resolveHtmlFilePath('admin.html')));
app.get('/install', (req, res) => res.sendFile(resolveHtmlFilePath('install.html')));
app.get('/install.html', (req, res) => res.sendFile(resolveHtmlFilePath('install.html')));
app.use(express.static(path.join(__dirname)));
if (fs.existsSync(path.join(__dirname, 'public'))) {
  app.use(express.static(path.join(__dirname, 'public')));
}

// ==========================================
// 3. دوال مساعدة وتخزين مؤقت لتوفير الاستضافة
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

function roundMoney(val) {
  const num = Number(val);
  if (!Number.isFinite(num)) return 0;
  return Math.round((num + Number.EPSILON) * 100) / 100;
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

let stateCache = {
  raw: null,
  lastFetched: 0,
  ttlMs: 4000
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

function mapCaptainRow(c, includePhotos = false) {
  const frontPhoto = c.id_front_photo || c.id_front_url || null;
  const backPhoto = c.id_back_photo || c.id_back_url || null;
  const vehPhoto = c.vehicle_photo || c.vehicle_photo_url || c.vehicle_url || null;

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
    suspendReason: c.suspend_reason || null,
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
    adminNotices: Array.isArray(c.admin_notices) ? c.admin_notices : []
  };
}

function mapOrderRow(o) {
  const createdMs = o.created_at ? new Date(o.created_at).getTime() : Date.now();
  return {
    id: o.id,
    customerPhone: o.customer_phone || o.client_phone || '',
    clientPhone: o.client_phone || o.customer_phone || '',
    tripType: o.trip_type || 'send',
    pickupZone: o.pickup_zone || 'المنصورة',
    pickupAddress: o.pickup_address || '',
    dropoffZone: o.dropoff_zone || 'المنصورة',
    dropoffAddress: o.dropoff_address || '',
    customerNotes: o.customer_notes || '',
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
  if (now - lastLazyCleanupRun < 120000) return 0; // يعمل بحد أقصى مرة كل دقيقتين
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
        if (order.discount_applied > 0 && custPhone) {
          await supabase.rpc('adjust_customer_wallet_atomic', {
            p_phone: custPhone,
            p_amount: roundMoney(order.discount_applied),
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

async function fetchRawDatabaseState(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && stateCache.raw && (now - stateCache.lastFetched < stateCache.ttlMs)) {
    return stateCache.raw;
  }

  const [settingsRes, customersRes, captainsRes, ordersRes, adminsRes, logsRes] = await Promise.all([
    supabase.from('settings').select('*').eq('id', 1).maybeSingle(),
    supabase.from('customers').select('*'),
    supabase.from('captains').select('*').order('created_at', { ascending: false }),
    supabase.from('orders').select('*').order('created_at', { ascending: false }).limit(250),
    supabase.from('admins').select('*').order('created_at', { ascending: true }),
    supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(50)
  ]);

  const sRow = settingsRes.data || {};
  const settings = {
    platformFee: roundMoney(sRow.platform_fee ?? 7),
    customerPointsPerOrder: Number(sRow.customer_points_per_order ?? 5),
    customerRewardThreshold: Number(sRow.customer_reward_threshold ?? 100),
    customerRewardCash: roundMoney(sRow.customer_reward_cash ?? 10),
    courierPointsPerOrder: Number(sRow.courier_points_per_order ?? 5),
    courierRewardThreshold: Number(sRow.courier_reward_threshold ?? 100),
    courierRewardCash: roundMoney(sRow.courier_reward_cash ?? 10),
    supportWhatsapp: sRow.support_whatsapp || '201507800875',
    broadcastMessage: sRow.broadcast_message || '',
    waitingTimeoutMinutes: Number(sRow.waiting_timeout_minutes ?? 30),
    maintenanceMode: Boolean(sRow.maintenance_mode),
    allowCaptainRegistration: sRow.allow_captain_registration !== false,
    packageTypes: Array.isArray(sRow.package_types) && sRow.package_types.length > 0 ? sRow.package_types : DEFAULT_PACKAGE_TYPES
  };

  // تشغيل الفحص الذاتي للطلبات المعلقة في الخلفية دون تعطيل الطلب الحالي
  runLazyExpiredOrdersCleanup(settings.waitingTimeoutMinutes);

  const zones = Array.isArray(sRow.zones) && sRow.zones.length > 0 ? sRow.zones : DEFAULT_ZONES;
  const pricing = (sRow.pricing && typeof sRow.pricing === 'object') ? sRow.pricing : DEFAULT_PRICING;

  const customersMap = {};
  (customersRes.data || []).forEach(c => {
    customersMap[c.phone] = {
      walletBalance: roundMoney(c.wallet_balance ?? 0),
      points: Number(c.points ?? 0),
      walletTransactions: Array.isArray(c.wallet_transactions) ? c.wallet_transactions.slice(0, 30) : []
    };
  });

  const rawData = {
    settings,
    zones,
    pricing,
    customers: customersMap,
    rawCaptains: captainsRes.data || [],
    orders: (ordersRes.data || []).map(mapOrderRow),
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

async function buildClientState(req, forceRefresh = false) {
  const raw = await fetchRawDatabaseState(forceRefresh);
  const isAdmin = isRequestFromAdminView(req);
  const adminToken = getAuthenticatedAdminFromCookie(req);

  return {
    settings: raw.settings,
    zones: raw.zones,
    pricing: raw.pricing,
    customers: raw.customers,
    captains: raw.rawCaptains.map(c => mapCaptainRow(c, isAdmin)),
    orders: raw.orders,
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

// ==========================================
// 5. مسار المزامنة الرئيسي (Bootstrap)
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

// مسار تسجيل دخول الأدمن (غرفة العمليات المركزية)
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

    // إذا دخل الأدمن ببيانات ملف .env مباشرة
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
  const token = jwt.sign({ phone: user.phone, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  const state = await buildClientState(req, false);
  res.json({ success: true, message: 'تم تسجيل الدخول بنجاح 👑', state });
});

// تسجيل كابتن جديد + إضافة 7 جنيه رصيد ترحيبي لأول مشوار مجاناً
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

    const { data: existing } = await supabase.from('captains').select('*').eq('phone', phone).maybeSingle();
    const hashedPassword = await bcrypt.hash(String(password), 10);

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
        id_front_photo: idFrontPhoto || existing.id_front_photo,
        id_back_photo: idBackPhoto || existing.id_back_photo,
        vehicle_photo: vehiclePhoto || existing.vehicle_photo,
        status: 'قيد المراجعة',
        suspend_reason: null,
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
    if (referredByPhone && referredByPhone !== phone) {
      const { data: refCap } = await supabase.from('captains').select('phone').eq('phone', referredByPhone).maybeSingle();
      if (refCap) validReferrer = refCap.phone;
    }

    const welcomeBonus = 7.00;
    const initialTransactions = [{
      title: 'هدية التسجيل (أول مشوار مجاناً بدون عمولة) 🎁',
      amount: welcomeBonus,
      type: 'إضافة',
      at: Date.now()
    }];

    const initialNotices = [{
      id: 'welcome-' + Date.now(),
      text: '🎁 مبروك يا بطل! نزل في محفظتك 7 جنيه هدية تسجيل عشان تجرب أول مشوار مجاناً بدون عمولة المنصة 🛵💪',
      type: 'reward',
      at: Date.now()
    }];

    const { error } = await supabase.from('captains').insert([{
      phone,
      password_hash: hashedPassword,
      full_name: fullName,
      national_id: nationalId,
      primary_zone: primaryZone || 'المنصورة',
      vehicle_type: vehicleType,
      plate_number: plateNumber || 'بدون لوحة',
      id_front_photo: idFrontPhoto || null,
      id_back_photo: idBackPhoto || null,
      vehicle_photo: vehiclePhoto || null,
      status: 'قيد المراجعة',
      is_available: false,
      wallet_balance: welcomeBonus,
      points: 0,
      referred_by_phone: validReferrer,
      referral_reward_claimed: false,
      referrals_count: 0,
      wallet_transactions: initialTransactions,
      admin_notices: initialNotices,
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
    return res.status(403).json({
      success: false,
      status: 'مرفوض',
      rejectReason: cap.suspend_reason || 'يرجى رفع صور واضحة للمستندات',
      captainProfile: mapCaptainRow(cap, false),
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
      payer, senderPhone, recipientPhone
    } = req.body || {};

    if (!clientPhone || !pin || !pickupAddress || !dropoffAddress) {
      return res.status(400).json({ success: false, message: 'برجاء استكمال كافة بيانات وعناوين الطلب ⚠️' });
    }

    const rawState = await fetchRawDatabaseState(false);
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

    const custToken = jwt.sign({ phone: clientPhone, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('customer_session', custToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    const routeKey = `${pickupZone}|${dropoffZone}`;
    const originalFare = roundMoney(rawState.pricing[routeKey] ?? 40);
    const availableWallet = Math.max(0, roundMoney(cust.wallet_balance || 0));
    const discountApplied = availableWallet > 0 ? roundMoney(Math.min(availableWallet, originalFare)) : 0;
    const finalFare = Math.max(0, roundMoney(originalFare - discountApplied));
    const platformFee = roundMoney(rawState.settings.platformFee ?? 7);
    const courierNet = Math.max(0, roundMoney(originalFare - platformFee));

    const existingIds = new Set((rawState.orders || []).map(o => o.id));
    let orderId = `#ORD-${Math.floor(1000 + Math.random() * 9000)}`;
    while (existingIds.has(orderId)) {
      orderId = `#ORD-${Math.floor(10000 + Math.random() * 90000)}`;
    }

    if (discountApplied > 0) {
      await supabase.rpc('adjust_customer_wallet_atomic', {
        p_phone: clientPhone,
        p_amount: -Math.abs(discountApplied),
        p_reason: `خصم رصيد هدية على طلب ${orderId}`
      });
    }

    const { error: ordErr } = await supabase.from('orders').insert([{
      id: orderId,
      customer_phone: clientPhone,
      client_phone: clientPhone,
      trip_type: tripType === 'fetch' ? 'fetch' : 'send',
      pickup_zone: pickupZone,
      pickup_address: pickupAddress,
      dropoff_zone: dropoffZone,
      dropoff_address: dropoffAddress,
      customer_notes: customerNotes || '',
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
      title: 'أوردر جديد على الرادار 📡🛵',
      body: `طلب (${orderId}) من ${pickupZone} إلى ${dropoffZone} - الأجرة: ${originalFare} ج`
    });

    const state = await buildClientState(req, true);
    res.json({ success: true, message: 'تم إرسال طلبك بنجاح 🚀', state });
  } catch (err) {
    console.error('Create order error:', err);
    res.status(500).json({ success: false, message: 'حدث خطأ أثناء تأكيد الطلب ⚠️' });
  }
});

// قبول الكابتن للطلب
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
  const fee = cap.custom_fee !== null && cap.custom_fee !== undefined
    ? roundMoney(cap.custom_fee)
    : roundMoney(rawState.settings.platformFee ?? 7);

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
      p_reason: `عمولة منصة لطلب ${req.params.id}`
    });
  }

  const discount = roundMoney(targetOrder.discount_applied || 0);
  if (discount > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', {
      p_phone: cap.phone,
      p_amount: discount,
      p_reason: `تعويض خصم عميل لطلب ${req.params.id}`
    });
  }

  invalidateStateCache();
  sendPushNotificationToPhone(targetOrder.customer_phone || targetOrder.client_phone, {
    title: 'تم قبول طلبك 🛵✅',
    body: `الكابتن ${cap.full_name} قبل طلبك (${req.params.id}) وفي طريقه إليك!`
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
  sendPushNotificationToPhone(order.customer_phone || order.client_phone, {
    title: `تحديث في طلبك ${order.id} 🛵`,
    body: nextStatus
  });

  const state = await buildClientState(req, true);
  res.json({ success: true, message: `تم التحديث: ${nextStatus} 🛵✅`, state });
});

app.post('/api/orders/:id/complete', authenticateCaptain, async (req, res) => {
  const cap = req.user;
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
  const rawState = await fetchRawDatabaseState(false);
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
    }

    let claimReferralNow = false;
    if (freshCap.referred_by_phone && !freshCap.referral_reward_claimed) {
      const { count } = await supabase.from('orders')
        .select('id', { count: 'exact', head: true })
        .eq('assigned_courier_phone', cap.phone)
        .eq('status', 'مكتمل');

      if ((count || 0) >= 2) {
        claimReferralNow = true;
      }
    }

    await supabase.from('captains').update({
      points: newCapPts,
      referral_reward_claimed: freshCap.referral_reward_claimed || claimReferralNow
    }).eq('phone', cap.phone);

    if (claimReferralNow && freshCap.referred_by_phone) {
      const { data: refCaptain } = await supabase.from('captains').select('*').eq('phone', freshCap.referred_by_phone).maybeSingle();
      if (refCaptain) {
        await supabase.rpc('adjust_captain_wallet_atomic', {
          p_phone: refCaptain.phone,
          p_amount: 50,
          p_reason: `هدية دعوة الكابتن ${freshCap.full_name} بعد إتمام مشوارين 🎁`
        });
        await supabase.from('captains').update({
          referrals_count: Number(refCaptain.referrals_count || 0) + 1
        }).eq('phone', refCaptain.phone);
      }
    }
  }

  invalidateStateCache();
  sendPushNotificationToPhone(custPhone, {
    title: 'تم تسليم طلبك بنجاح 🎉',
    body: `الحمد لله الأوردر (${order.id}) اتسلم.. شكراً لثقتك في الرجل العنابي 🛵❤️`
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

  if (order.discount_applied > 0 && custPhone) {
    await supabase.rpc('adjust_customer_wallet_atomic', {
      p_phone: custPhone,
      p_amount: roundMoney(order.discount_applied),
      p_reason: `استرداد خصم لطلب ملغي ${order.id}`
    });
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
      body: 'قام العميل بإلغاء الطلب وتم رد العمولة لمحفظتك فوراً.'
    });
  }

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, message: 'تم الإلغاء ورصيدك محفوظ يا نجم ✅', state });
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
  const updates = {};

  if (body.platformFee !== undefined) updates.platform_fee = roundMoney(body.platformFee);
  if (body.broadcastMessage !== undefined) updates.broadcast_message = String(body.broadcastMessage);
  if (body.supportWhatsapp !== undefined) updates.support_whatsapp = String(body.supportWhatsapp).trim();
  if (body.waitingTimeoutMinutes !== undefined) updates.waiting_timeout_minutes = Number(body.waitingTimeoutMinutes);
  if (body.maintenanceMode !== undefined) updates.maintenance_mode = Boolean(body.maintenanceMode);
  if (body.allowCaptainRegistration !== undefined) updates.allow_captain_registration = Boolean(body.allowCaptainRegistration);
  if (Array.isArray(body.zones)) updates.zones = body.zones;
  if (body.pricing && typeof body.pricing === 'object') updates.pricing = body.pricing;
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

  await supabase.from('settings').upsert({ id: 1, ...updates });
  await logAdminAudit('تحديث إعدادات', 'المنصة', 'تعديل في إعدادات التشغيل أو التسعير', req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
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
      text: `⚡ تم شحن محفظتك بمبلغ ${amt} جنيه من الإدارة بنجاح!`,
      type: 'reward',
      at: Date.now()
    });
    await supabase.from('captains').update({ admin_notices: notices.slice(0, 10) }).eq('phone', phone);
  }

  await logAdminAudit('شحن محفظة كابتن', phone, `شحن مبلغ ${amt} ج`, req.admin.name);
  sendPushNotificationToPhone(phone, {
    title: 'تم شحن محفظتك 💰✅',
    body: `تم إضافة ${amt} جنيه إلى محفظتك من إدارة الرجل العنابي 🛵`
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
    title: 'هدية في محفظتك 🎁👑',
    body: `تم إضافة ${amt} جنيه رصيد هدية في محفظتك تتخصم تلقائياً من مشوارك القادم!`
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
  await logAdminAudit('عمولة خاصة', phone, reset ? 'إرجاع للعمولة العامة' : `تحديد عمولة ${customFee} ج`, req.admin.name);

  invalidateStateCache();
  const state = await buildClientState(req, true);
  res.json({ success: true, state });
});

app.post('/api/admin/captains/:phone/status', authenticateAdmin, async (req, res) => {
  const { status, reason } = req.body || {};
  const phone = req.params.phone;
  await supabase.from('captains').update({
    status,
    suspend_reason: reason || null,
    is_available: status === 'معتمد' ? true : false
  }).eq('phone', phone);

  await logAdminAudit('حالة كابتن', phone, `تغيير الحالة إلى ${status}`, req.admin.name);
  if (status === 'معتمد') {
    sendPushNotificationToPhone(phone, {
      title: 'تم اعتماد حسابك يا بطل! 🛵🎉',
      body: 'أهلاً بك في رجالة العنابي! حسابك معتمد الآن ومعاك 7 جنيه هدية لأول مشوار مجاناً.'
    });
  }

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
    if (order.discount_applied > 0 && custPhone) {
      await supabase.rpc('adjust_customer_wallet_atomic', {
        p_phone: custPhone,
        p_amount: roundMoney(order.discount_applied),
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

// ==========================================
// 10. المهام المجدولة (Vercel Cron) لتنظيف الطلبات المنتهية
// ==========================================
app.get('/api/cron/cleanup-orders', async (req, res) => {
  if (req.headers['x-vercel-cron'] !== '1' && process.env.NODE_ENV === 'production') {
    return res.status(401).json({ success: false });
  }
  lastLazyCleanupRun = 0; // السماح بالتنفيذ الفوري
  const rawState = await fetchRawDatabaseState(false);
  const canceledCount = await runLazyExpiredOrdersCleanup(rawState.settings.waitingTimeoutMinutes);
  res.json({ success: true, canceled: canceledCount });
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running securely on http://localhost:${PORT}`));
}
module.exports = app;