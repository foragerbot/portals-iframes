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
import OpenAI from 'openai';
import multer from 'multer';
import rateLimit from 'express-rate-limit';


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

// OpenAI client
const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
  : null;

// Cheap-but-capable default model
const DEFAULT_GPT_MODEL = process.env.OPENAI_DEFAULT_MODEL || 'gpt-4.1-mini';

// Limit to a small safe set so someone can't accidentally slam GPT-5.2 pro
const ALLOWED_GPT_MODELS = [
  'gpt-4.1-mini',
  'gpt-4.1-nano',
  'gpt-4o-mini'
];

// Upload limits
const MAX_ASSET_FILE_SIZE = 10 * 1024 * 1024; // 10 MB per file
const MAX_ASSET_FILES = 10;                   // max files per upload

// Multer setup for in-memory uploads (we write to disk ourselves)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_ASSET_FILE_SIZE,
    files: MAX_ASSET_FILES,
  },
});

const GPT_MAX_CALLS_PER_DAY = Number(process.env.GPT_MAX_CALLS_PER_DAY || 200);
const GPT_RATE_WINDOW_MS = Number(process.env.GPT_RATE_WINDOW_MS || 60_000);
const GPT_RATE_MAX_PER_WINDOW = Number(
  process.env.GPT_RATE_MAX_PER_WINDOW || 10
);

// Basic per-IP rate limiter for GPT endpoint
const gptRateLimiter = rateLimit({
  windowMs: GPT_RATE_WINDOW_MS,
  max: GPT_RATE_MAX_PER_WINDOW,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res /*, next*/) => {
    return res.status(429).json({
      error: 'rate_limited',
      message: 'Too many GPT requests, slow down a bit.',
    });
  },
});

const app = express();

function pickModel(requested) {
  if (requested && ALLOWED_GPT_MODELS.includes(requested)) {
    return requested;
  }
  return DEFAULT_GPT_MODEL;
}

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
function todayIsoDate() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

async function checkAndIncrementUserGptUsage(userId, amount = 1) {
  const users = await loadUsersMeta();
  const idx = users.findIndex((u) => u.id === userId);
  if (idx === -1) {
    throw Object.assign(new Error('user_not_found'), { status: 500 });
  }

  const user = users[idx];
  const today = todayIsoDate();

  const usage = user.gptUsage || {
    day: today,
    calls: 0,
  };

  // Reset counter if day changed
  if (usage.day !== today) {
    usage.day = today;
    usage.calls = 0;
  }

  if (usage.calls + amount > GPT_MAX_CALLS_PER_DAY) {
    return { ok: false, usage };
  }

  usage.calls += amount;
  users[idx] = {
    ...user,
    gptUsage: usage,
  };
  await saveUsersMeta(users);

  return { ok: true, usage };
}

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

function isAllowedAssetFile(filename) {
  const ext = (path.extname(filename) || '').toLowerCase();
  const allowed = [
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.webp',
    '.svg',
    '.ico',
    '.bmp',
    '.apng',

    '.woff',
    '.woff2',
    '.ttf',
    '.otf',

    '.json',
    '.txt',
  ];
  return allowed.includes(ext);
}

// Recursively compute directory size (bytes). Fine for small spaces.
async function getDirSizeBytes(dirPath) {
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  let total = 0;

  for (const entry of entries) {
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      total += await getDirSizeBytes(full);
    } else if (entry.isFile()) {
      const stat = await fs.stat(full);
      total += stat.size;
    }
  }

  return total;
}

async function updateSpaceSizeBytes(space, newSizeBytes) {
  const spaces = await loadSpacesMeta();
  const idx = spaces.findIndex((s) => s.slug === space.slug);
  if (idx === -1) return;
  spaces[idx] = {
    ...spaces[idx],
    currentSizeBytes: newSizeBytes,
    updatedAt: new Date().toISOString(),
  };
  await saveSpacesMeta(spaces);
}

async function getSpaceUsage(space) {
  let usedBytes = 0;
  try {
    usedBytes = await getDirSizeBytes(space.dirPath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    usedBytes = 0;
  }

  const quotaMb = Number.isFinite(Number(space.quotaMb))
    ? Number(space.quotaMb)
    : 200;

  const usedMb = +(usedBytes / (1024 * 1024)).toFixed(2);

  return { usedBytes, usedMb, quotaMb };
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

async function getUserGptUsage(userId) {
  const users = await loadUsersMeta();
  const user = users.find((u) => u.id === userId);
  if (!user) return null;

  const usage = user.gptUsage || null;
  return usage;
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

// ───────────────── GPT helper for a user space ─────────────────

// POST /api/spaces/:slug/gpt/chat
// body: {
//   prompt: string,
//   filePath?: string,           // relative to space root
//   model?: string,              // optional: gpt-4.1-mini, gpt-4.1-nano, gpt-4o-mini
//   messages?: [{role,content}]  // optional prior chat history
// }
app.post('/api/spaces/:slug/gpt/chat', requireUser, gptRateLimiter, async (req, res, next) => {
  try {
    if (!openai) {
      return res.status(503).json({
        error: 'gpt_disabled',
        message: 'OPENAI_API_KEY is not configured on the server',
      });
    }

    await ensureSpacesRoot();
    const { slug } = req.params;
    const { prompt, filePath, model: requestedModel, messages } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }
    if (!prompt || typeof prompt !== 'string') {
      return res.status(400).json({ error: 'missing_prompt' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

          // Per-user daily GPT quota
      const quotaCheck = await checkAndIncrementUserGptUsage(req.user.id, 1);
      if (!quotaCheck.ok) {
        return res.status(429).json({
          error: 'gpt_quota_exceeded',
          message: `Daily GPT limit reached (${GPT_MAX_CALLS_PER_DAY} calls).`,
          usage: quotaCheck.usage,
        });
      }

    const model = pickModel(requestedModel);

    // Optional: load current file content for context
    let fileContext = null;
    let fileLang = 'text';
    if (filePath) {
      try {
        const fullPath = resolveSpacePath(space, filePath);
        if (isEditableTextFile(fullPath)) {
          const content = await fs.readFile(fullPath, 'utf8');
          const MAX_FILE_CHARS = 20000;
          const snippet =
            content.length > MAX_FILE_CHARS
              ? content.slice(0, MAX_FILE_CHARS) + '\n<!-- [truncated for GPT] -->'
              : content;

          const ext = (path.extname(filePath) || '').toLowerCase();
          if (ext === '.html' || ext === '.htm') fileLang = 'html';
          else if (ext === '.css') fileLang = 'css';
          else if (ext === '.js' || ext === '.mjs') fileLang = 'javascript';
          else if (ext === '.json') fileLang = 'json';

          fileContext = { path: filePath, snippet, lang: fileLang };
        }
      } catch (err) {
        console.warn('[gpt] failed to load file context', filePath, err.message);
      }
    }

    // Build messages for the chat completion
    const chatMessages = [];

    chatMessages.push({
      role: 'system',
      content: [
        'You are a coding assistant helping a developer build HTML/CSS/JS overlays that run as iframes in a Unity/Portals-based game.',
        'All code you generate must be client-side only (no Node.js, no server frameworks).',
        'Prefer small, focused changes and clearly labeled code blocks.',
        'When modifying a file, either provide the full updated file OR clear, copy-pastable snippets.',
      ].join(' '),
    });

    if (fileContext) {
      chatMessages.push({
        role: 'system',
        content: `Here is the current file ${fileContext.path}. Respond with updated code that fits this structure.\n\n\`\`\`${fileContext.lang}\n${fileContext.snippet}\n\`\`\``,
      });
    }

    // Include any prior chat history the frontend wants to send
    if (Array.isArray(messages)) {
      for (const m of messages) {
        if (
          m &&
          typeof m.role === 'string' &&
          typeof m.content === 'string' &&
          ['user', 'assistant', 'system'].includes(m.role)
        ) {
          chatMessages.push({ role: m.role, content: m.content });
        }
      }
    }

    // Finally, the new user prompt
    chatMessages.push({
      role: 'user',
      content: prompt,
    });

    const completion = await openai.chat.completions.create({
      model,
      messages: chatMessages,
      temperature: 0.3,
    });

    const answer = completion.choices[0]?.message || { role: 'assistant', content: '' };

    res.json({
      ok: true,
      model,
      message: answer,
    });
  } catch (err) {
    console.error('[gpt] error in /api/spaces/:slug/gpt/chat', err);
    next(err);
  }
});

// ───────────────── Asset upload for a user space ─────────────────

// POST /api/spaces/:slug/upload
// multipart/form-data
// fields:
//   files[]  -> file inputs
//   subdir   -> optional subdirectory inside the space (e.g. "assets" or "assets/icons")
app.post(
  '/api/spaces/:slug/upload',
  requireUser,
  upload.array('files', MAX_ASSET_FILES),
  async (req, res, next) => {
    try {
      await ensureSpacesRoot();
      const { slug } = req.params;
      const subdirRaw = (req.body?.subdir || '').trim();

      if (!isValidSlug(slug)) {
        return res.status(400).json({ error: 'bad_slug' });
      }

      const space = await getUserSpaceBySlug(slug, req.user);
      if (!space) {
        return res.status(404).json({ error: 'space_not_found' });
      }

      const quotaMb = Number.isFinite(Number(space.quotaMb))
        ? Number(space.quotaMb)
        : 200;
      const quotaBytes = quotaMb * 1024 * 1024;

      const files = req.files || [];
      if (!files.length) {
        return res.status(400).json({ error: 'no_files' });
      }

      // Clean up subdir (POSIX style, no ..)
      let subdir = subdirRaw || '';
      if (subdir) {
        subdir = subdir.replace(/\\/g, '/'); // normalize slashes
        if (subdir.startsWith('/')) subdir = subdir.slice(1);
        // We will rely on resolveSpacePath to block '..', but let's be extra cautious:
        if (subdir.includes('..')) {
          return res.status(400).json({ error: 'bad_subdir' });
        }
      }

      // Validate extensions and total incoming size
      let incomingBytes = 0;
      for (const f of files) {
        if (!isAllowedAssetFile(f.originalname)) {
          return res.status(400).json({
            error: 'unsupported_type',
            file: f.originalname,
          });
        }
        incomingBytes += f.size;
      }

      // Compute current directory size
      let currentBytes = 0;
      try {
        currentBytes = await getDirSizeBytes(space.dirPath);
      } catch (err) {
        // If directory is new/empty, dir might not exist yet
        if (err.code !== 'ENOENT') throw err;
        currentBytes = 0;
      }

      const projectedBytes = currentBytes + incomingBytes;
      if (projectedBytes > quotaBytes) {
        return res.status(413).json({
          error: 'quota_exceeded',
          message: `Upload would exceed quota of ${quotaMb} MB`,
          quotaMb,
          currentMb: +(currentBytes / (1024 * 1024)).toFixed(2),
          incomingMb: +(incomingBytes / (1024 * 1024)).toFixed(2),
        });
      }

      const saved = [];

      // Actually write the files
      for (const f of files) {
        const filename = f.originalname;
        const relPath = subdir ? `${subdir}/${filename}` : filename;
        const destPath = resolveSpacePath(space, relPath);

        // Ensure parent directory exists
        const destDir = path.dirname(destPath);
        await fs.mkdir(destDir, { recursive: true });

        // Write file from memory buffer
        await fs.writeFile(destPath, f.buffer);

        saved.push({
          name: filename,
          path: relPath,
          size: f.size,
        });
      }

      // Update stored size
      await updateSpaceSizeBytes(space, projectedBytes);

      res.status(201).json({
        ok: true,
        quotaMb,
        usedMb: +(projectedBytes / (1024 * 1024)).toFixed(2),
        files: saved,
      });
    } catch (err) {
      // Multer can throw specific errors (like file too large)
      if (err && err.code === 'LIMIT_FILE_SIZE') {
        return res
          .status(413)
          .json({ error: 'file_too_large', message: 'File exceeds max size' });
      }
      if (err && err.code === 'LIMIT_FILE_COUNT') {
        return res.status(413).json({
          error: 'too_many_files',
          message: 'Too many files in a single upload',
        });
      }
      next(err);
    }
  }
);

// ───────────────── Space usage endpoint ─────────────────

// GET /api/spaces/:slug/usage
// Returns disk usage + GPT usage for the current user + space
app.get('/api/spaces/:slug/usage', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    const spaceUsage = await getSpaceUsage(space);
    const gptUsage = await getUserGptUsage(req.user.id);

    res.json({
      ok: true,
      slug: space.slug,
      quotaMb: spaceUsage.quotaMb,
      usedMb: spaceUsage.usedMb,
      usedBytes: spaceUsage.usedBytes,
      gptUsage: gptUsage
        ? {
            day: gptUsage.day,
            calls: gptUsage.calls,
            dailyLimit: GPT_MAX_CALLS_PER_DAY,
          }
        : {
            day: null,
            calls: 0,
            dailyLimit: GPT_MAX_CALLS_PER_DAY,
          },
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
