require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const webpush = require('web-push');
const helmet = require('helmet');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

app.use(helmet());
app.use(cors({ 
  origin: process.env.NODE_ENV === 'production' ? process.env.ALLOWED_ORIGIN : true, 
  credentials: true 
}));
app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());

webpush.setVapidDetails(
  'mailto:support@ennaby.com',
  process.env.VAPID_PUBLIC_KEY || 'BOyNefapT_wxw5HHpZFaPsQvyj9OIfV9owv8-9cJd5RMcfdGMK9c0j7D8zv1nNlWBd2K6DB-1v_YhzW2z2xxklc',
  process.env.VAPID_PRIVATE_KEY || 'KvjK8OyYPhFEUdIOgmPEBqxgAMw48AU98sI4GfYTeqw'
);

// ==========================================
// حماية التخمين العشوائي للرقم السري (Rate Limiter)
// ==========================================
async function checkRateLimit(phone) {
  const { data: attempt } = await supabase.from('login_attempts').select('*').eq('phone', phone).single();
  if (attempt && attempt.locked_until && new Date(attempt.locked_until) > new Date()) {
    return { locked: true, message: 'حسابك مقفول مؤقتاً بسبب محاولات متكررة. جرب كمان 15 دقيقة 🔒' };
  }
  return { locked: false, attemptData: attempt };
}

async function recordFailedAttempt(phone, attemptData) {
  const attempts = (attemptData?.attempts || 0) + 1;
  const updates = { attempts, locked_until: attempts >= 5 ? new Date(Date.now() + 15 * 60000).toISOString() : null };
  await supabase.from('login_attempts').upsert({ phone, ...updates });
}

async function clearFailedAttempts(phone) {
  await supabase.from('login_attempts').delete().eq('phone', phone);
}

// ==========================================
// Middlewares (التحقق والأمان)
// ==========================================
async function authenticateCustomer(req, res, next) {
  const token = req.cookies.customer_session;
  if (!token) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data: user } = await supabase.from('customers').select('*').eq('phone', decoded.phone).single();
    if (!user) return res.status(401).json({ success: false, message: 'الحساب غير موجود' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'الجلسة غير صالحة' });
  }
}

async function authenticateCaptain(req, res, next) {
  const token = req.cookies.captain_session;
  if (!token) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول أولاً' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data: captain } = await supabase.from('captains').select('*').eq('phone', decoded.phone).single();
    if (!captain || captain.session_version !== decoded.session_version) {
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
  const token = req.cookies.admin_session;
  if (!token) return res.status(401).json({ success: false, message: 'يرجى تسجيل الدخول كأدمن' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const { data: admin } = await supabase.from('admins').select('*').eq('username', decoded.username).single();
    if (!admin || admin.status === 'معطل') return res.status(401).json({ success: false, message: 'حساب الإدارة معطل' });
    req.admin = admin;
    next();
  } catch (err) {
    res.status(401).json({ success: false, message: 'جلسة الإدارة غير صالحة' });
  }
}

// ==========================================
// مسارات المصادقة
// ==========================================
app.post('/api/auth/customer/login', async (req, res) => {
  const { phone, pin } = req.body;
  const rateLimit = await checkRateLimit(phone);
  if (rateLimit.locked) return res.status(403).json({ success: false, message: rateLimit.message });

  const { data: user } = await supabase.from('customers').select('*').eq('phone', phone).single();
  
  if (!user) {
    const hashedPin = await bcrypt.hash(pin, 10);
    const { data: newUser } = await supabase.from('customers').insert([{ phone, pin_hash: hashedPin }]).select().single();
    const token = jwt.sign({ phone: newUser.phone, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
    return res.json({ success: true, message: 'تم فتح حسابك بنجاح 👑' });
  }

  const valid = await bcrypt.compare(pin, user.pin_hash);
  if (!valid) {
    await recordFailedAttempt(phone, rateLimit.attemptData);
    return res.status(401).json({ success: false, message: 'الرقم السري غير صحيح ⚠️' });
  }

  await clearFailedAttempts(phone);
  const token = jwt.sign({ phone: user.phone, role: 'customer' }, process.env.JWT_SECRET, { expiresIn: '30d' });
  res.cookie('customer_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  res.json({ success: true, message: 'تم تسجيل الدخول بنجاح 👑' });
});

app.post('/api/auth/captain/login', async (req, res) => {
  const { phone, password } = req.body;
  const rateLimit = await checkRateLimit(phone);
  if (rateLimit.locked) return res.status(403).json({ success: false, message: rateLimit.message });

  const { data: cap } = await supabase.from('captains').select('*').eq('phone', phone).single();
  if (!cap) return res.status(401).json({ success: false, message: 'رقم الهاتف غير مسجل كابتن ⚠️' });
  if (cap.status === 'مرفوض') return res.status(403).json({ success: false, status: 'مرفوض', rejectReason: cap.suspend_reason });

  const valid = await bcrypt.compare(password, cap.password_hash);
  if (!valid) {
    await recordFailedAttempt(phone, rateLimit.attemptData);
    return res.status(401).json({ success: false, message: 'كلمة المرور غير صحيحة ⚠️' });
  }

  await clearFailedAttempts(phone);
  const token = jwt.sign({ phone: cap.phone, role: 'captain', session_version: cap.session_version }, process.env.JWT_SECRET, { expiresIn: '14d' });
  res.cookie('captain_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  res.json({ success: true, message: 'منور الميدان يا بطل 🛵' });
});

// ==========================================
// مسارات الكابتن
// ==========================================
app.post('/api/orders/:id/accept', authenticateCaptain, async (req, res) => {
  const cap = req.user;
  if (!cap.is_available || cap.status !== 'معتمد') return res.status(403).json({ success: false, message: 'حسابك غير مصرح له بقبول الطلبات حالياً ⛔' });
const vehType = req.body.vehicleType || req.body.vehicle_type || req.body.vehicle || 'موتوسيكل';
  // تحديث شرطي يمنع أي كابتن آخر من أخذه في نفس اللحظة
  const { data: accepted, error } = await supabase.from('orders')
    .update({ status: 'تم قبول الطلب', assigned_courier_phone: cap.phone })
    .eq('id', req.params.id).eq('status', 'في انتظار كابتن').select();

  if (error || !accepted.length) return res.status(400).json({ success: false, message: 'عفواً.. الأوردر راح لكابتن تاني قبلك 🏃‍♂️' });

  const fee = cap.custom_fee !== null ? cap.custom_fee : 7;
  if (fee > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', { p_phone: cap.phone, p_amount: -Math.abs(fee), p_reason: `عمولة منصة لطلب #${req.params.id}` });
  }
  res.json({ success: true, message: 'تم قبول الطلب.. توكل على الله 🛵' });
});

app.post('/api/orders/:id/advance', authenticateCaptain, async (req, res) => {
  const { nextStatus } = req.body;
  const { data, error } = await supabase.from('orders').update({ status: nextStatus })
    .eq('id', req.params.id).eq('assigned_courier_phone', req.user.phone).select();
  if (error || !data.length) return res.status(400).json({ success: false, message: 'تعذر تحديث الحالة' });
  res.json({ success: true, message: `تم التحديث: ${nextStatus} 🛵✅` });
});

app.post('/api/orders/:id/complete', authenticateCaptain, async (req, res) => {
  const { data, error } = await supabase.from('orders').update({ status: 'مكتمل' })
    .eq('id', req.params.id).eq('assigned_courier_phone', req.user.phone).neq('status', 'مكتمل').select();
  if (error || !data.length) return res.status(400).json({ success: false, message: 'تعذر إنهاء الطلب' });
  res.json({ success: true, message: 'تسلم إيدك يا بطل! تم التسليم 🛵💨' });
});

app.post('/api/orders/:id/release', authenticateCaptain, async (req, res) => {
  const { data: order } = await supabase.from('orders').select('*').eq('id', req.params.id).eq('assigned_courier_phone', req.user.phone).eq('status', 'تم قبول الطلب').single();
  if (!order) return res.status(400).json({ success: false, message: 'لا يمكن التنازل في هذه المرحلة ⚠️' });

  await supabase.from('orders').update({ status: 'في انتظار كابتن', assigned_courier_phone: null }).eq('id', order.id);
  if (order.platform_fee > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', { p_phone: req.user.phone, p_amount: order.platform_fee, p_reason: `رد عمولة للتنازل عن طلب #${order.id}` });
  }
  res.json({ success: true, message: 'تم إعادة الطلب للرادار 🔄' });
});

app.post('/api/captain/availability', authenticateCaptain, async (req, res) => {
  await supabase.from('captains').update({ is_available: req.body.isAvailable }).eq('phone', req.user.phone);
  res.json({ success: true });
});

app.post('/api/captain/notices/:noticeId/dismiss', authenticateCaptain, async (req, res) => {
  // Logic to remove notice from JSON array in Supabase
  res.json({ success: true });
});

// ==========================================
// مسارات العميل
// ==========================================
app.post('/api/orders/:id/cancel', authenticateCustomer, async (req, res) => {
  // التحديث الشرطي لمنع الإلغاء المزدوج واسترداد الرصيد مرتين
  const { data: updated, error } = await supabase.from('orders')
    .update({ status: 'ملغي من العميل' })
    .eq('id', req.params.id).eq('customer_phone', req.user.phone)
    .in('status', ['في انتظار كابتن', 'تم قبول الطلب']).select();

  if (error || !updated.length) return res.status(400).json({ success: false, message: 'لا يمكن الإلغاء.. الطلب قيد التنفيذ ⚠️' });

  const order = updated[0];
  if (order.discount_applied > 0) {
    await supabase.rpc('adjust_customer_wallet_atomic', { p_phone: req.user.phone, p_amount: order.discount_applied, p_reason: `استرداد خصم لطلب ملغي #${order.id}` });
  }
  if (order.assigned_courier_phone && order.platform_fee > 0) {
    await supabase.rpc('adjust_captain_wallet_atomic', { p_phone: order.assigned_courier_phone, p_amount: order.platform_fee, p_reason: `رد عمولة لطلب ملغي من العميل #${order.id}` });
  }
  res.json({ success: true, message: 'تم الإلغاء ورصيدك محفوظ يا نجم ✅' });
});

app.post('/api/orders/:id/rate', authenticateCustomer, async (req, res) => {
  await supabase.from('orders').update({ rating: req.body.rating }).eq('id', req.params.id).eq('customer_phone', req.user.phone);
  res.json({ success: true });
});

app.post('/api/orders/:id/dispute', authenticateCustomer, async (req, res) => {
  await supabase.from('orders').update({ dispute_reason: req.body.reason, status: 'قيد مراجعة الاعتراض' }).eq('id', req.params.id).eq('customer_phone', req.user.phone);
  res.json({ success: true });
});

// ==========================================
// مسارات الإدارة (المفقودة)
// ==========================================
app.post('/api/admin/settings', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageSettings) return res.status(403).json({ success: false });
  // Updates settings logic here
  res.json({ success: true });
});

app.post('/api/admin/wallets/captain-topup', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageWallets) return res.status(403).json({ success: false });
  await supabase.rpc('adjust_captain_wallet_atomic', { p_phone: req.body.phone, p_amount: req.body.amount, p_reason: 'شحن رصيد من الإدارة' });
  res.json({ success: true });
});

app.post('/api/admin/wallets/captain-deduct', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageWallets) return res.status(403).json({ success: false });
  await supabase.rpc('adjust_captain_wallet_atomic', { p_phone: req.body.phone, p_amount: -Math.abs(req.body.amount), p_reason: req.body.reason });
  res.json({ success: true });
});

app.post('/api/admin/wallets/customer-compensate', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageWallets) return res.status(403).json({ success: false });
  await supabase.rpc('adjust_customer_wallet_atomic', { p_phone: req.body.phone, p_amount: req.body.amount, p_reason: req.body.reason });
  res.json({ success: true });
});

app.post('/api/admin/captains/custom-fee', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageCommissions) return res.status(403).json({ success: false });
  const updates = req.body.reset ? { custom_fee: null, custom_fee_reason: null } : { custom_fee: req.body.customFee, custom_fee_reason: req.body.reason };
  await supabase.from('captains').update(updates).eq('phone', req.body.phone);
  res.json({ success: true });
});

app.post('/api/admin/captains/:phone/status', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageCaptains) return res.status(403).json({ success: false });
  await supabase.from('captains').update({ status: req.body.status, suspend_reason: req.body.reason || null }).eq('phone', req.params.phone);
  res.json({ success: true });
});

app.post('/api/admin/orders/:id/manage', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master && !req.admin.permissions?.manageOrders) return res.status(403).json({ success: false });
  // Handle resolve_complete, resolve_cancel, radar, cancel
  res.json({ success: true });
});

app.post('/api/admin/accounts/:username/toggle', authenticateAdmin, async (req, res) => {
  if (!req.admin.is_master) return res.status(403).json({ success: false });
  const { data: acc } = await supabase.from('admins').select('status').eq('username', req.params.username).single();
  await supabase.from('admins').update({ status: acc.status === 'نشط' ? 'معطل' : 'نشط' }).eq('username', req.params.username);
  res.json({ success: true });
});

// ==========================================
// Vercel Cron
// ==========================================
app.get('/api/cron/cleanup-orders', async (req, res) => {
  if (req.headers['x-vercel-cron'] !== '1' && process.env.NODE_ENV === 'production') return res.status(401).json({ success: false });
  const timeoutMinutes = parseInt(process.env.WAITING_TIMEOUT_MINUTES || '30', 10);
  const cutoff = new Date(Date.now() - timeoutMinutes * 60000).toISOString();

  const { data: expired } = await supabase.from('orders')
    .update({ status: 'ملغي (تجاوز مهلة الانتظار)' })
    .eq('status', 'في انتظار كابتن')
    .lt('created_at', cutoff).select();

  if (expired && expired.length > 0) {
    for (const order of expired) {
      if (order.discount_applied > 0) {
        await supabase.rpc('adjust_customer_wallet_atomic', { p_phone: order.customer_phone, p_amount: order.discount_applied, p_reason: `رد تعويض مهلة طلب #${order.id}` });
      }
    }
  }
  res.json({ success: true, canceled: expired ? expired.length : 0 });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running securely on port ${PORT}`));
module.exports = app;