require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const app = express();
// On AWS the request passes through CloudFront and the load balancer (2 proxies).
// This makes the rate limiter see the real visitor IP instead of the proxy's.
app.set('trust proxy', 2);
app.use(express.json());
app.use(express.static('public'));

// Limit attempts on login, signup, and code endpoints (guessing protection)
const strict = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' }
});
app.use(['/api/login', '/api/register', '/api/verify', '/api/resend', '/api/forgot', '/api/reset'], strict);

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
const okFile = /\.(pdf|docx?|pptx?|txt|png|jpe?g)$/i;
const s3 = new S3Client({ region: process.env.AWS_REGION || 'ap-south-1' });
const db = mysql.createPool({
  host: process.env.DB_HOST, user: process.env.DB_USER,
  password: process.env.DB_PASS, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 10
});

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------
// If SMTP_HOST is set, real emails are sent. Otherwise they are printed in this terminal.
const mailer = process.env.SMTP_HOST ? nodemailer.createTransport({
  pool: true,
  host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

// Link used by the buttons in emails. Set APP_URL in .env to your CloudFront address once deployed.
const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// One shared layout for every email. Inline styles, because email apps ignore <style> blocks.
function layout({ preheader, title, body, button, footer }) {
  const btn = button ? `
    <tr><td style="padding:8px 32px 28px">
      <a href="${esc(button.url)}" style="display:inline-block;background:#1e2a4a;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 26px;border-radius:6px">${esc(button.label)}</a>
    </td></tr>` : '';
  return `<!doctype html>
<html><body style="margin:0;padding:0;background:#f4f6fa;font-family:'Segoe UI',Arial,sans-serif;color:#1e2a4a">
<span style="display:none;max-height:0;overflow:hidden;opacity:0">${esc(preheader)}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6fa;padding:32px 12px"><tr><td align="center">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border:1px solid #c8d0e4;border-radius:10px;overflow:hidden">
    <tr><td style="background:#1e2a4a;padding:18px 32px;color:#ffffff;font-family:Georgia,serif;font-size:20px;font-weight:bold">Resource Hub</td></tr>
    <tr><td style="padding:28px 32px 8px;font-family:Georgia,serif;font-size:22px;font-weight:bold">${esc(title)}</td></tr>
    <tr><td style="padding:0 32px 20px;font-size:15px;line-height:1.6;color:#33405f">${body}</td></tr>
    ${btn}
    <tr><td style="padding:16px 32px;background:#f4f6fa;border-top:1px solid #c8d0e4;font-size:12px;line-height:1.5;color:#5d6784">${footer || 'You received this email because of activity on Resource Hub, a note-sharing site for our class.'}</td></tr>
  </table>
</td></tr></table>
</body></html>`;
}

// No await on purpose: the page gets its reply right away while the email goes out in the background.
function notify(to, subject, text, html) {
  if (mailer) {
    mailer.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to, subject, text, html })
      .catch(e => console.error('Mail failed:', e.message));
  } else console.log(`[DEV] Email to ${to}: ${subject} | ${text}`);
}

function codeEmail(email, purpose, code) {
  const reset = purpose === 'reset';
  const title = reset ? 'Reset your password' : 'Confirm your email';
  const intro = reset
    ? 'We received a request to reset your Resource Hub password. Enter this code on the reset page:'
    : 'Thanks for signing up for Resource Hub. Enter this code to confirm your email address:';
  const html = layout({
    preheader: `Your code is ${code}. It expires in 10 minutes.`,
    title,
    body: `<p style="margin:0 0 18px">${intro}</p>
      <div style="margin:0 0 18px;padding:16px;text-align:center;background:#fff8d6;border:1.5px dashed #c8a900;border-radius:8px;font-family:Consolas,'Courier New',monospace;font-size:34px;font-weight:bold;letter-spacing:10px;color:#1e2a4a">${code}</div>
      <p style="margin:0 0 6px">This code expires in <b>10 minutes</b>.</p>
      <p style="margin:0">${reset ? 'If you didn’t ask for a reset, you can ignore this email. Your password won’t change.' : 'If you didn’t create an account, you can ignore this email.'}</p>`,
    footer: 'Never share this code with anyone. Resource Hub staff will never ask you for it.'
  });
  const text = `${title}\n\n${intro}\n\n${code}\n\nThis code expires in 10 minutes.\n${reset ? 'If you didn’t ask for a reset, ignore this email.' : 'If you didn’t create an account, ignore this email.'}`;
  return { subject: `${code} is your Resource Hub ${reset ? 'reset' : 'verification'} code`, text, html };
}

// ---------------------------------------------------------------------------

const norm = e => (e || '').trim().toLowerCase();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const h = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Something went wrong. Try again.' }); });
const sign = u => ({
  name: u.name, role: u.role,
  token: jwt.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: '2h' })
});

// The admin is the person whose email is ADMIN_EMAIL in .env. They manage everyone else.
const adminEmail = norm(process.env.ADMIN_EMAIL);
if (!adminEmail) console.warn('WARNING: ADMIN_EMAIL is not set in .env, so nobody can manage users.');

// Optional extra filter on who may register (empty = anyone can request an account).
const list = v => (v || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const allowedDomains = list(process.env.ALLOWED_DOMAINS), allowedEmails = list(process.env.ALLOWED_EMAILS);
const isAllowed = email =>
  email === adminEmail || (!allowedDomains.length && !allowedEmails.length) ||
  allowedEmails.includes(email) || allowedDomains.includes(email.split('@')[1]);

async function sendOtp(email, purpose) {
  const [recent] = await db.query(
    'SELECT 1 FROM otps WHERE email=? AND purpose=? AND created_at > DATE_SUB(NOW(), INTERVAL 30 SECOND)', [email, purpose]);
  if (recent.length) return; // 30-second cooldown stops email spam
  const code = String(crypto.randomInt(100000, 1000000));
  await db.query('DELETE FROM otps WHERE email=? AND purpose=?', [email, purpose]);
  await db.query('INSERT INTO otps(email,purpose,code_hash,expires_at) VALUES(?,?,?,DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
    [email, purpose, sha(code)]);
  const m = codeEmail(email, purpose, code);
  notify(email, m.subject, m.text, m.html);
}

async function checkOtp(email, purpose, code) {
  const [r] = await db.query('SELECT * FROM otps WHERE email=? AND purpose=? AND expires_at > NOW()', [email, purpose]);
  if (!r.length) return false;
  if (r[0].attempts >= 5) { await db.query('DELETE FROM otps WHERE id=?', [r[0].id]); return false; }
  if (r[0].code_hash !== sha(String(code || '').trim())) {
    await db.query('UPDATE otps SET attempts=attempts+1 WHERE id=?', [r[0].id]);
    return false;
  }
  await db.query('DELETE FROM otps WHERE id=?', [r[0].id]);
  return true;
}

// Looks the user up in the database on every request, so a suspended or deleted
// user is blocked immediately, even if they still hold an unexpired token.
const auth = async (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').split(' ')[1];
    const p = jwt.verify(t, process.env.JWT_SECRET);
    const [r] = await db.query('SELECT id, name, role, approved, suspended FROM users WHERE id=?', [p.id]);
    if (!r.length || !r[0].approved) return res.status(401).json({ error: 'Please log in again.' });
    if (r[0].suspended) return res.status(403).json({ error: 'This account has been suspended.', suspended: true });
    req.user = r[0];
    next();
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
};

const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only.' });

// Records an admin action in the activity log.
const audit = (req, action, detail) =>
  db.query('INSERT INTO audit_log(actor, action, detail) VALUES(?,?,?)', [req.user.name, action, String(detail).slice(0, 255)]);

app.get('/health', (req, res) => res.status(200).send('OK'));

app.post('/api/register', h(async (req, res) => {
  const name = (req.body.name || '').trim(), email = norm(req.body.email), password = req.body.password || '';
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter your name and a valid email.' });
  if (!isAllowed(email)) return res.status(403).json({ error: 'Registration is limited to approved email addresses.' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const [u] = await db.query('SELECT verified FROM users WHERE email=?', [email]);
  if (u.length && u[0].verified) return res.status(400).json({ error: 'This email is already registered. Log in instead.' });
  const hash = await bcrypt.hash(password, 10);
  if (u.length) await db.query('UPDATE users SET name=?, password_hash=? WHERE email=?', [name, hash, email]);
  else await db.query('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)', [name, email, hash]);
  await sendOtp(email, 'verify');
  res.status(201).json({ message: 'We sent a 6-digit code to your email.' });
}));

app.post('/api/verify', h(async (req, res) => {
  const email = norm(req.body.email);
  if (!(await checkOtp(email, 'verify', req.body.code))) return res.status(400).json({ error: 'That code is wrong or has expired.' });
  await db.query('UPDATE users SET verified=1 WHERE email=?', [email]);
  if (email === adminEmail) await db.query("UPDATE users SET approved=1, role='admin' WHERE email=?", [email]);
  const [u] = await db.query('SELECT id,name,role,approved FROM users WHERE email=?', [email]);
  if (!u[0].approved) {
    if (adminEmail) {
      notify(adminEmail, `New account request from ${u[0].name}`,
        `${u[0].name} (${email}) verified their email and is waiting for your approval.\n\nLog in to review: ${APP_URL}`,
        layout({
          preheader: `${u[0].name} is waiting for your approval.`,
          title: 'New account request',
          body: `<p style="margin:0 0 14px">Someone has verified their email and wants to join Resource Hub.</p>
            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 14px;font-size:15px">
              <tr><td style="padding:2px 14px 2px 0;color:#5d6784">Name</td><td><b>${esc(u[0].name)}</b></td></tr>
              <tr><td style="padding:2px 14px 2px 0;color:#5d6784">Email</td><td><b>${esc(email)}</b></td></tr>
            </table>
            <p style="margin:0">Open the <b>Admin</b> area and approve or reject them from the Overview or Users tab.</p>`,
          button: { label: 'Review request', url: APP_URL },
          footer: 'You get this email because you are the Resource Hub admin.'
        }));
    }
    return res.json({ pending: true });
  }
  res.json(sign(u[0]));
}));

app.post('/api/resend', h(async (req, res) => {
  const email = norm(req.body.email), purpose = req.body.purpose === 'reset' ? 'reset' : 'verify';
  const [u] = await db.query('SELECT verified FROM users WHERE email=?', [email]);
  if (u.length && !!u[0].verified === (purpose === 'reset')) await sendOtp(email, purpose);
  res.json({ message: 'If that email is eligible, a new code is on its way.' });
}));

app.post('/api/login', h(async (req, res) => {
  const email = norm(req.body.email);
  const [rows] = await db.query('SELECT * FROM users WHERE email=?', [email]);
  if (!rows.length || !(await bcrypt.compare(req.body.password || '', rows[0].password_hash)))
    return res.status(401).json({ error: 'Wrong email or password.' });
  if (!rows[0].verified) return res.status(403).json({ error: 'Verify your email to continue.', needsVerify: true });
  if (!rows[0].approved) return res.status(403).json({ error: 'Your account is waiting for admin approval.', pending: true });
  if (rows[0].suspended) return res.status(403).json({ error: 'This account has been suspended. Contact the admin.' });
  res.json(sign(rows[0]));
}));

app.post('/api/forgot', h(async (req, res) => {
  const email = norm(req.body.email);
  const [u] = await db.query('SELECT id FROM users WHERE email=? AND verified=1', [email]);
  if (u.length) await sendOtp(email, 'reset');
  res.json({ message: 'If that email is registered, a code is on its way.' });
}));

app.post('/api/reset', h(async (req, res) => {
  const email = norm(req.body.email), password = req.body.password || '';
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (!(await checkOtp(email, 'reset', req.body.code))) return res.status(400).json({ error: 'That code is wrong or has expired.' });
  await db.query('UPDATE users SET password_hash=? WHERE email=?', [await bcrypt.hash(password, 10), email]);
  res.json({ message: 'Password updated.' });
}));

// ---------------------------------------------------------------------------
// Admin dashboard (every route below is admin-only, checked against the database)
// ---------------------------------------------------------------------------
const admin = [auth, adminOnly];

app.get('/api/admin/stats', ...admin, h(async (req, res) => {
  const [[s]] = await db.query(`SELECT
    (SELECT COUNT(*) FROM users WHERE verified=1 AND approved=1) AS members,
    (SELECT COUNT(*) FROM users WHERE verified=1 AND approved=0) AS pending,
    (SELECT COUNT(*) FROM users WHERE suspended=1) AS suspended,
    (SELECT COUNT(*) FROM notes) AS notes`);
  const [events] = await db.query('SELECT actor, action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 6');
  res.json({ ...s, events });
}));

app.get('/api/admin/users', ...admin, h(async (req, res) => {
  const [users] = await db.query(`SELECT u.id, u.name, u.email, u.role, u.approved, u.suspended, u.created_at,
    (SELECT COUNT(*) FROM notes n WHERE n.user_id=u.id) AS notes
    FROM users u WHERE u.verified=1 ORDER BY u.approved, u.id`);
  res.json({ users });
}));

app.post('/api/admin/approve', ...admin, h(async (req, res) => {
  const [u] = await db.query('SELECT name, email FROM users WHERE id=? AND approved=0 AND verified=1', [req.body.id]);
  if (!u.length) return res.status(404).json({ error: 'That request no longer exists.' });
  await db.query('UPDATE users SET approved=1 WHERE id=?', [req.body.id]);
  await audit(req, 'approved user', `${u[0].name} (${u[0].email})`);
  notify(u[0].email, 'Your Resource Hub account is approved',
    `Hi ${u[0].name},\n\nYour account has been approved. You can now log in and start sharing notes:\n${APP_URL}`,
    layout({
      preheader: 'You can now log in to Resource Hub.',
      title: 'You’re in!',
      body: `<p style="margin:0 0 14px">Hi ${esc(u[0].name)},</p>
        <p style="margin:0 0 14px">Your Resource Hub account has been approved. You can now log in with the email and password you signed up with.</p>
        <p style="margin:0">Browse notes shared by your classmates, or upload your own for everyone to use.</p>`,
      button: { label: 'Log in to Resource Hub', url: APP_URL }
    }));
  res.json({ message: 'Approved' });
}));

app.post('/api/admin/reject', ...admin, h(async (req, res) => {
  const [u] = await db.query('SELECT name, email FROM users WHERE id=? AND approved=0', [req.body.id]);
  if (!u.length) return res.status(404).json({ error: 'That request no longer exists.' });
  await db.query('DELETE FROM users WHERE id=?', [req.body.id]);
  await db.query('DELETE FROM otps WHERE email=?', [u[0].email]);
  await audit(req, 'rejected user', `${u[0].name} (${u[0].email})`);
  notify(u[0].email, 'Update on your Resource Hub request',
    `Hi ${u[0].name},\n\nWe couldn’t approve your Resource Hub account request. If you think this is a mistake, please contact the admin directly.`,
    layout({
      preheader: 'An update on your account request.',
      title: 'Account request update',
      body: `<p style="margin:0 0 14px">Hi ${esc(u[0].name)},</p>
        <p style="margin:0 0 14px">We couldn’t approve your Resource Hub account request this time.</p>
        <p style="margin:0">If you think this is a mistake, please contact the admin directly.</p>`
    }));
  res.json({ message: 'Rejected' });
}));

// Suspend / reactivate. Admins can't be suspended, and nobody can suspend themselves.
const setSuspended = value => h(async (req, res) => {
  const [u] = await db.query("SELECT name, email FROM users WHERE id=? AND role<>'admin' AND approved=1", [req.body.id]);
  if (!u.length) return res.status(400).json({ error: 'That account can’t be changed.' });
  await db.query('UPDATE users SET suspended=? WHERE id=?', [value, req.body.id]);
  await audit(req, value ? 'suspended user' : 'reactivated user', `${u[0].name} (${u[0].email})`);
  res.json({ message: 'Done' });
});
app.post('/api/admin/suspend', ...admin, setSuspended(1));
app.post('/api/admin/unsuspend', ...admin, setSuspended(0));

// Deleting a user also deletes their notes (and the files in S3).
app.post('/api/admin/delete-user', ...admin, h(async (req, res) => {
  const [u] = await db.query("SELECT id, name, email FROM users WHERE id=? AND role<>'admin'", [req.body.id]);
  if (!u.length || u[0].email === adminEmail) return res.status(400).json({ error: 'That account can’t be deleted.' });
  const [files] = await db.query('SELECT s3_key FROM notes WHERE user_id=?', [u[0].id]);
  const results = await Promise.allSettled(files.map(f =>
    s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET, Key: f.s3_key }))));
  results.filter(r => r.status === 'rejected').forEach(r => console.error('S3 delete failed:', r.reason.message));
  await db.query('DELETE FROM notes WHERE user_id=?', [u[0].id]);
  await db.query('DELETE FROM otps WHERE email=?', [u[0].email]);
  await db.query('DELETE FROM users WHERE id=?', [u[0].id]);
  await audit(req, 'deleted user', `${u[0].name} (${u[0].email}) and ${files.length} note(s)`);
  res.json({ message: 'Deleted' });
}));

app.get('/api/admin/notes', ...admin, h(async (req, res) => {
  const [notes] = await db.query(
    'SELECT n.id, n.title, u.name AS author, u.email, n.created_at FROM notes n JOIN users u ON n.user_id=u.id ORDER BY n.id DESC');
  res.json({ notes });
}));

app.delete('/api/admin/notes/:id', ...admin, h(async (req, res) => {
  const [n] = await db.query('SELECT id, title, s3_key FROM notes WHERE id=?', [req.params.id]);
  if (!n.length) return res.status(404).json({ error: 'Note not found.' });
  await s3.send(new DeleteObjectCommand({ Bucket: process.env.S3_BUCKET, Key: n[0].s3_key }));
  await db.query('DELETE FROM notes WHERE id=?', [n[0].id]);
  await audit(req, 'deleted note', n[0].title);
  res.json({ message: 'Deleted' });
}));

app.get('/api/admin/activity', ...admin, h(async (req, res) => {
  const [events] = await db.query('SELECT actor, action, detail, created_at FROM audit_log ORDER BY id DESC LIMIT 100');
  res.json({ events });
}));

// ---------------------------------------------------------------------------
// Notes (logged-in, approved, not suspended)
// ---------------------------------------------------------------------------
const previewable = /\.(pdf|png|jpe?g|txt)$/i;           // file types a browser can show directly
const origName = key => key.replace(/^\d+-/, '');         // strip the timestamp prefix we add on upload
const cleanSubject = s => (s || '').trim().replace(/\s+/g, ' ').slice(0, 60);

app.get('/api/notes', auth, h(async (req, res) => {
  const [rows] = await db.query(`SELECT n.id, n.title, n.subject, n.s3_key, n.downloads, n.created_at, u.name AS author,
    (SELECT COUNT(*) FROM likes l WHERE l.note_id=n.id) AS likes,
    EXISTS(SELECT 1 FROM likes l WHERE l.note_id=n.id AND l.user_id=?) AS liked,
    (SELECT COUNT(*) FROM comments c WHERE c.note_id=n.id) AS comments
    FROM notes n JOIN users u ON n.user_id=u.id ORDER BY n.id DESC`, [req.user.id]);
  // The storage key stays on the server; the page only learns whether a preview is possible.
  res.json(rows.map(({ s3_key, ...n }) => ({ ...n, liked: !!n.liked, previewable: previewable.test(s3_key) })));
}));

app.post('/api/notes', auth, upload.single('file'), h(async (req, res) => {
  const title = (req.body.title || '').trim(), subject = cleanSubject(req.body.subject);
  if (!req.file || !title || !subject) return res.status(400).json({ error: 'Add a title, a subject and choose a file.' });
  if (!okFile.test(req.file.originalname)) return res.status(400).json({ error: 'Only PDF, Word, PowerPoint, text and image files are allowed.' });
  const key = `${Date.now()}-${req.file.originalname.replace(/[^\w.\-]/g, '_')}`;
  await s3.send(new PutObjectCommand({
    Bucket: process.env.S3_BUCKET, Key: key, Body: req.file.buffer, ContentType: req.file.mimetype
  }));
  await db.query('INSERT INTO notes(title,subject,s3_key,user_id) VALUES(?,?,?,?)', [title, subject, key, req.user.id]);
  res.status(201).json({ message: 'Uploaded' });
}));

// Gives a 60-second link to the file. ?mode=view shows it in the browser, otherwise it downloads (and counts).
app.get('/api/notes/:id/file', auth, h(async (req, res) => {
  const view = req.query.mode === 'view';
  const [rows] = await db.query('SELECT s3_key FROM notes WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Note not found.' });
  if (view && !previewable.test(rows[0].s3_key)) return res.status(400).json({ error: 'This file type can’t be previewed. Download it instead.' });
  if (!view) await db.query('UPDATE notes SET downloads=downloads+1 WHERE id=?', [req.params.id]);
  const name = origName(rows[0].s3_key).replace(/["\\]/g, '');
  const url = await getSignedUrl(s3, new GetObjectCommand({
    Bucket: process.env.S3_BUCKET, Key: rows[0].s3_key,
    ResponseContentDisposition: `${view ? 'inline' : 'attachment'}; filename="${name}"`
  }), { expiresIn: 60 });
  res.json({ url });
}));

// Like / unlike (one tap toggles).
app.post('/api/notes/:id/like', auth, h(async (req, res) => {
  const [n] = await db.query('SELECT id FROM notes WHERE id=?', [req.params.id]);
  if (!n.length) return res.status(404).json({ error: 'Note not found.' });
  const [del] = await db.query('DELETE FROM likes WHERE note_id=? AND user_id=?', [req.params.id, req.user.id]);
  if (!del.affectedRows) await db.query('INSERT INTO likes(note_id,user_id) VALUES(?,?)', [req.params.id, req.user.id]);
  const [[c]] = await db.query('SELECT COUNT(*) AS likes FROM likes WHERE note_id=?', [req.params.id]);
  res.json({ liked: !del.affectedRows, likes: c.likes });
}));

// Comments
app.get('/api/notes/:id/comments', auth, h(async (req, res) => {
  const [rows] = await db.query(`SELECT c.id, c.body, c.created_at, u.name AS author, (c.user_id=?) AS mine
    FROM comments c JOIN users u ON c.user_id=u.id WHERE c.note_id=? ORDER BY c.id`, [req.user.id, req.params.id]);
  res.json({ comments: rows.map(c => ({ ...c, canDelete: !!c.mine || req.user.role === 'admin' })) });
}));

app.post('/api/notes/:id/comments', auth, h(async (req, res) => {
  const body = (req.body.body || '').trim();
  if (!body || body.length > 500) return res.status(400).json({ error: 'Write a comment of up to 500 characters.' });
  const [n] = await db.query('SELECT id FROM notes WHERE id=?', [req.params.id]);
  if (!n.length) return res.status(404).json({ error: 'Note not found.' });
  await db.query('INSERT INTO comments(note_id,user_id,body) VALUES(?,?,?)', [req.params.id, req.user.id, body]);
  res.status(201).json({ message: 'Posted' });
}));

// Authors can delete their own comments; admins can delete any (and it's logged).
app.delete('/api/comments/:id', auth, h(async (req, res) => {
  const [c] = await db.query(`SELECT c.id, c.user_id, c.body, u.name AS author, n.title
    FROM comments c JOIN users u ON c.user_id=u.id JOIN notes n ON c.note_id=n.id WHERE c.id=?`, [req.params.id]);
  if (!c.length) return res.status(404).json({ error: 'Comment not found.' });
  const mine = c[0].user_id === req.user.id;
  if (!mine && req.user.role !== 'admin') return res.status(403).json({ error: 'You can only delete your own comments.' });
  await db.query('DELETE FROM comments WHERE id=?', [c[0].id]);
  if (!mine) await audit(req, 'deleted comment', `by ${c[0].author} on “${c[0].title}”`);
  res.json({ message: 'Deleted' });
}));

// DEMO ONLY: burns CPU so you can show auto scaling. Remove before real use.
app.get('/api/load', (req, res) => {
  let x = 0;
  for (let i = 0; i < 5e7; i++) x += Math.sqrt(i);
  res.json({ x });
});

app.listen(process.env.PORT || 3000, () => console.log('Server running'));