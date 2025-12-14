// server/index.js
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import fsSync from 'fs';
import crypto from 'crypto';

// Load env vars from .env (if present)
dotenv.config();

// __dirname shim for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Basic config
const PORT = process.env.PORT || 4100;
const NODE_ENV = process.env.NODE_ENV || 'development';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;
const APP_BASE_URL =
  process.env.APP_BASE_URL || `http://localhost:${PORT || 4100}`;
const IS_PROD = NODE_ENV === 'production';

// Root of repo
const ROOT_DIR = path.join(__dirname, '..');

// Where user spaces (per-tenant dirs) will live
const SPACES_ROOT = path.join(ROOT_DIR, 'spaces');

// Simple metadata files
const SPACES_META_PATH = path.join(ROOT_DIR, 'spaces.meta.json');
const USERS_META_PATH = path.join(ROOT_DIR, 'users.meta.json');
const TOKENS_META_PATH = path.join(ROOT_DIR, 'magicTokens.meta.json');
const SESSIONS_META_PATH = path.join(ROOT_DIR, 'sessions.meta.json');

const app = express();

// ───────────────── Generic helpers ─────────────────

function generateId(prefix = '') {
  return prefix + crypto.randomBytes(16).toString('hex');
}

async function readJsonArray(filePath) {
  try {
    if (!fsSync.existsSync(filePath)) return [];
    const raw = await fs.readFile(filePath, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('[meta] failed to read', filePath, err);
    return [];
  }
}

async function writeJsonArray(filePath, arr) {
  try {
    const json = JSON.stringify(arr, null, 2);
    await fs.writeFile(filePath, json, 'utf8');
  } catch (err) {
    console.error('[meta] failed to write', filePath, err);
    throw err;
  }
}

// ───────────────── Spaces helpers ─────────────────

async function ensureSpacesRoot() {
  try {
    await fs.mkdir(SPACES_ROOT, { recursive: true });
  } catch (err) {
    console.error('[spaces] failed to ensure spaces root', err);
    throw err;
  }
}

async function loadSpacesMeta() {
  return readJsonArray(SPACES_META_PATH);
}

async function saveSpacesMeta(spaces) {
  return writeJsonArray(SPACES_META_PATH, spaces);
}

function isValidSlug(slug) {
  return typeof slug === 'string' && /^[a-z0-9-]{3,32}$/.test(slug);
}

async function getUserSpaceBySlug(slug, user) {
  if (!user) return null;
  const spaces = await loadSpacesMeta();
  const normalizedEmail = (user.email || '').trim().toLowerCase();
  return spaces.find(
    (s) =>
      s.slug === slug &&
      s.status === 'active' &&
      s.ownerEmail &&
      s.ownerEmail === normalizedEmail
  );
}

function resolveSpacePath(space, relPath) {
  const base = space.dirPath;
  const input = relPath || '.';

  // Normalize to POSIX style and ensure leading slash for normalization
  const normalized = path.posix.normalize('/' + input);

  // Block path traversal
  if (normalized.includes('..')) {
    throw Object.assign(new Error('bad_path'), { status: 400 });
  }

  // Join with actual filesystem path
  const full = path.join(base, '.' + normalized);

  if (!full.startsWith(base)) {
    throw Object.assign(new Error('escape_root'), { status: 400 });
  }

  return full;
}

function isEditableTextFile(filePath) {
  const ext = (path.extname(filePath) || '').toLowerCase();
  const allowed = ['.html', '.htm', '.css', '.js', '.mjs', '.json', '.txt'];
  return allowed.includes(ext);
}


// ───────────────── Users / auth helpers ─────────────────

function isValidEmail(email) {
  return typeof email === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);
}

async function loadUsersMeta() {
  return readJsonArray(USERS_META_PATH);
}

async function saveUsersMeta(users) {
  return writeJsonArray(USERS_META_PATH, users);
}

async function loadTokensMeta() {
  return readJsonArray(TOKENS_META_PATH);
}

async function saveTokensMeta(tokens) {
  return writeJsonArray(TOKENS_META_PATH, tokens);
}

async function loadSessionsMeta() {
  return readJsonArray(SESSIONS_META_PATH);
}

async function saveSessionsMeta(sessions) {
  return writeJsonArray(SESSIONS_META_PATH, sessions);
}

// Dev-mode magic link email sender
async function sendMagicLinkEmail(email, url) {
  // For now we just log it. Later, plug in SendGrid here.
  if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_FROM) {
    console.log(
      `[magic-link] dev mode: would send to ${email}: ${url}`
    );
    return;
  }

  // TODO: integrate SendGrid (e.g. @sendgrid/mail) using SENDGRID_API_KEY / SENDGRID_FROM
  console.log(
    '[magic-link] SENDGRID_API_KEY is set but SendGrid integration is not yet implemented.'
  );
}

// Attach req.user + req.session if sid cookie exists
async function sessionMiddleware(req, res, next) {
  try {
    const sid = req.cookies?.sid || null;
    if (!sid) return next();

    const sessions = await loadSessionsMeta();
    const session = sessions.find((s) => s.id === sid);
    if (!session) return next();

    const users = await loadUsersMeta();
    const user = users.find((u) => u.id === session.userId);
    if (!user) return next();

    req.session = session;
    req.user = user;
    next();
  } catch (err) {
    console.error('[session] error loading session', err);
    next();
  }
}

// Admin auth middleware using x-admin-token header
function requireAdmin(req, res, next) {
  console.log('[admin] incoming', req.method, req.originalUrl);

  if (!ADMIN_TOKEN) {
    console.log('[admin] ADMIN_TOKEN missing, admin routes disabled');
    return res
      .status(503)
      .json({ error: 'admin_disabled', reason: 'missing_ADMIN_TOKEN' });
  }

  const token = req.get('x-admin-token');
  if (!token) {
    console.log('[admin] missing x-admin-token header');
    return res
      .status(401)
      .json({ error: 'unauthorized', reason: 'no_token' });
  }
  if (token !== ADMIN_TOKEN) {
    console.log('[admin] bad admin token:', token);
    return res
      .status(401)
      .json({ error: 'unauthorized', reason: 'bad_token' });
  }

  console.log('[admin] auth ok');
  next();
}

function requireUser(req, res, next) {
  if (!req.user) {
    return res
      .status(401)
      .json({ error: 'not_logged_in', message: 'No active session' });
  }
  next();
}


// ───────────────── Middlewares ─────────────────

// Trust proxy if you’re behind Nginx later
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', true);
}

// JSON + urlencoded body parsing
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false }));

// Cookies
app.use(cookieParser());

// Sessions (loads req.user if sid cookie present)
app.use(sessionMiddleware);

// Basic security headers
app.use(
  helmet({
    contentSecurityPolicy: false, // we’ll tune CSP later per domain
  })
);

// CORS – for now, wide open in dev
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// Logs
if (NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// ───────────────── Health / version ─────────────────

app.get('/health', async (req, res) => {
  await ensureSpacesRoot();
  res.json({
    ok: true,
    env: NODE_ENV,
    time: new Date().toISOString(),
    spacesRoot: SPACES_ROOT,
  });
});

app.get('/api/version', (req, res) => {
  res.json({
    name: 'portals-iframes',
    version: '0.1.0',
    env: NODE_ENV,
  });
});

// ───────────────── Magic-link auth ─────────────────

// Start magic link: POST /api/auth/magic/start { email }
app.post('/api/auth/magic/start', async (req, res, next) => {
  try {
    const { email } = req.body || {};
    const normalizedEmail = (email || '').trim().toLowerCase();

    if (!isValidEmail(normalizedEmail)) {
      return res
        .status(400)
        .json({ error: 'bad_email', message: 'Invalid email address' });
    }

    const tokens = await loadTokensMeta();
    const token = generateId('mt_');
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 min

    tokens.push({
      id: token,
      email: normalizedEmail,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      usedAt: null,
    });
    await saveTokensMeta(tokens);

    const verifyUrl = `${APP_BASE_URL.replace(/\/+$/, '')}/api/auth/magic/verify?token=${encodeURIComponent(
      token
    )}`;

    await sendMagicLinkEmail(normalizedEmail, verifyUrl);

    console.log(
      `[auth] magic link created for ${normalizedEmail}, token ${token}`
    );

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Verify magic link: GET /api/auth/magic/verify?token=...
app.get('/api/auth/magic/verify', async (req, res, next) => {
  try {
    const { token } = req.query || {};
    if (!token || typeof token !== 'string') {
      return res.status(400).json({ error: 'bad_token' });
    }

    const tokens = await loadTokensMeta();
    const idx = tokens.findIndex((t) => t.id === token);
    if (idx === -1) {
      return res
        .status(400)
        .json({ error: 'invalid_token', message: 'Token not found' });
    }

    const t = tokens[idx];
    if (t.usedAt) {
      return res
        .status(400)
        .json({ error: 'used_token', message: 'Token already used' });
    }

    const now = new Date();
    if (new Date(t.expiresAt).getTime() < now.getTime()) {
      return res
        .status(400)
        .json({ error: 'expired_token', message: 'Token expired' });
    }

    const users = await loadUsersMeta();
    let user = users.find((u) => u.email === t.email);

    if (!user) {
      user = {
        id: generateId('u_'),
        email: t.email,
        createdAt: now.toISOString(),
        roles: ['user'],
      };
      users.push(user);
      await saveUsersMeta(users);
      console.log('[auth] created new user', user);
    } else {
      console.log('[auth] existing user login', user.id, user.email);
    }

    // Mark token as used
    tokens[idx] = { ...t, usedAt: now.toISOString() };
    await saveTokensMeta(tokens);

    // Create session
    const sessions = await loadSessionsMeta();
    const sessionId = generateId('sid_');
    const session = {
      id: sessionId,
      userId: user.id,
      email: user.email,
      createdAt: now.toISOString(),
      userAgent: req.get('user-agent') || null,
      ip: req.ip || null,
    };
    sessions.push(session);
    await saveSessionsMeta(sessions);

    // Set cookie
    res.cookie('sid', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD, // in prod, cookie only over HTTPS
      maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
    });

    // For now, just return JSON. Later the frontend can redirect after this.
    res.json({ ok: true, user });
  } catch (err) {
    next(err);
  }
});

// Current user: GET /api/me
app.get('/api/me', async (req, res, next) => {
  try {
    if (!req.user) {
      return res
        .status(401)
        .json({ error: 'not_logged_in', message: 'No active session' });
    }

    const spaces = await loadSpacesMeta();

    // For now, associate spaces by ownerEmail === user.email (if set).
    const mySpaces = spaces.filter(
      (s) => s.ownerEmail && s.ownerEmail === req.user.email
    );

    res.json({
      ok: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        roles: req.user.roles || [],
      },
      spaces: mySpaces,
    });
  } catch (err) {
    next(err);
  }
});

// ───────────────── Authenticated space file APIs ─────────────────

// List files in a space directory
// GET /api/spaces/:slug/files?path=subdir/
app.get('/api/spaces/:slug/files', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const relPath = req.query.path || '.';

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    const dirPath = resolveSpacePath(space, relPath);

    const dirents = await fs.readdir(dirPath, { withFileTypes: true });

    const items = await Promise.all(
      dirents.map(async (d) => {
        const full = path.join(dirPath, d.name);
        const stat = await fs.stat(full);
        return {
          name: d.name,
          isDir: d.isDirectory(),
          size: stat.size,
          mtime: stat.mtime,
        };
      })
    );

    res.json({
      ok: true,
      path: relPath,
      items,
    });
  } catch (err) {
    next(err);
  }
});

// Get a single file's contents
// GET /api/spaces/:slug/file?path=relative/path.ext
app.get('/api/spaces/:slug/file', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const relPath = req.query.path;

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }
    if (!relPath) {
      return res.status(400).json({ error: 'missing_path' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    const filePath = resolveSpacePath(space, relPath);

    if (!isEditableTextFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    const content = await fs.readFile(filePath, 'utf8');

    res.json({
      ok: true,
      path: relPath,
      content,
    });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ error: 'file_not_found' });
    }
    next(err);
  }
});

// Save a text file in a space
// POST /api/spaces/:slug/file
// body: { path, content }
app.post('/api/spaces/:slug/file', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const { path: relPath, content } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }
    if (!relPath || typeof content !== 'string') {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    const filePath = resolveSpacePath(space, relPath);

    if (!isEditableTextFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    // Ensure parent directories exist
    const dirName = path.dirname(filePath);
    await fs.mkdir(dirName, { recursive: true });

    await fs.writeFile(filePath, content, 'utf8');

    // TODO: update stored quota if/when we track it per write

    res.json({
      ok: true,
      path: relPath,
    });
  } catch (err) {
    next(err);
  }
});


// ───────────────── Admin routes (manual provisioning) ─────────────────

// List spaces metadata (admin only)
app.get('/api/admin/spaces', requireAdmin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const spaces = await loadSpacesMeta();
    res.json({ spaces });
  } catch (err) {
    next(err);
  }
});

// Create a new space: POST /api/admin/spaces
// Body: { slug, quotaMb?, ownerEmail? }
app.post('/api/admin/spaces', requireAdmin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug, quotaMb, ownerEmail } = req.body || {};

    if (!isValidSlug(slug)) {
      console.log('[admin] invalid slug:', slug);
      return res.status(400).json({
        error: 'bad_slug',
        message:
          'Slug must be 3-32 chars of lowercase letters, digits, or hyphens.',
      });
    }

    const spaces = await loadSpacesMeta();
    if (spaces.find((s) => s.slug === slug)) {
      console.log('[admin] slug already exists:', slug);
      return res
        .status(409)
        .json({ error: 'space_exists', slug, message: 'slug already in use' });
    }

    const now = new Date().toISOString();
    const dirPath = path.join(SPACES_ROOT, slug);

    console.log('[admin] creating dir:', dirPath);

    if (fsSync.existsSync(dirPath)) {
      console.log('[admin] directory already exists on disk for slug:', slug);
      return res.status(409).json({
        error: 'dir_exists',
        slug,
        message: 'directory already exists on disk',
      });
    }

    await fs.mkdir(dirPath, { recursive: true });

    const starterHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${slug} overlay</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      width: 100%;
      background: transparent;
      color: #e5e7eb;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    body {
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(15, 23, 42, 0.6);
      box-sizing: border-box;
    }
    .hud {
      padding: 12px 16px;
      border-radius: 8px;
      border: 1px solid rgba(148, 163, 184, 0.7);
      background: rgba(15, 23, 42, 0.9);
      box-shadow: 0 0 24px rgba(59, 130, 246, 0.35);
    }
    .hud-title {
      font-size: 14px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: #93c5fd;
      margin: 0 0 4px;
    }
    .hud-body {
      font-size: 13px;
      color: #e5e7eb;
      margin: 0;
    }
  </style>
</head>
<body>
  <div class="hud">
    <p class="hud-title">Space: ${slug}</p>
    <p class="hud-body">Overlay is alive. Wire this up as an iframe in your Portals scene.</p>
  </div>
</body>
</html>
`;

    await fs.writeFile(path.join(dirPath, 'index.html'), starterHtml, 'utf8');

    const spaceRecord = {
      id: slug, // for now, id === slug
      slug,
      dirPath,
      quotaMb: Number.isFinite(Number(quotaMb))
        ? Number(quotaMb)
        : 200, // default 200 MB
      createdAt: now,
      updatedAt: now,
      status: 'active',
      ownerEmail: ownerEmail && isValidEmail(ownerEmail)
        ? ownerEmail.trim().toLowerCase()
        : null,
    };

    spaces.push(spaceRecord);
    await saveSpacesMeta(spaces);

    console.log('[admin] space created:', spaceRecord);

    res.status(201).json({
      ok: true,
      space: spaceRecord,
    });
  } catch (err) {
    console.error('[admin] error creating space:', err);
    next(err);
  }
});

// ───────────────── Public space serving (static) ─────────────────

// Serve static files for a space at /p/:slug/... (e.g. /p/demo-hud/index.html)
app.use('/p/:slug', async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;

    if (!isValidSlug(slug)) {
      return res.status(404).send('Not found');
    }

    const spaces = await loadSpacesMeta();
    const space = spaces.find((s) => s.slug === slug && s.status === 'active');

    if (!space) {
      return res.status(404).send('Space not found');
    }

    const staticMiddleware = express.static(space.dirPath, {
      fallthrough: false,
    });

    return staticMiddleware(req, res, (err) => {
      if (err) return next(err);
      if (!res.headersSent) {
        res.status(404).send('File not found in space');
      }
    });
  } catch (err) {
    next(err);
  }
});

// ───────────────── 404 / error handlers ─────────────────

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'not_found' });
});

// Generic error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || 'server_error',
  });
});

// ───────────────── Start server ─────────────────

ensureSpacesRoot()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `[portals-iframes] listening on port ${PORT} (${NODE_ENV})`
      );
      console.log(`[portals-iframes] spaces root: ${SPACES_ROOT}`);
      console.log(
        `[portals-iframes] admin routes ${
          ADMIN_TOKEN ? 'enabled' : 'DISABLED (no ADMIN_TOKEN)'
        }`
      );
      console.log(`[portals-iframes] APP_BASE_URL: ${APP_BASE_URL}`);
    });
  })
  .catch((err) => {
    console.error('[fatal] failed to initialize spaces root', err);
    process.exit(1);
  });
