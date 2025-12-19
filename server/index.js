// server/index.js
import express from 'express';
import path from 'path';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import fs from 'fs/promises';
import fsSync from 'fs';
import crypto from 'crypto';
import OpenAI from 'openai';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import sgMail from '@sendgrid/mail';
import {
  PORT,
  LISTEN_HOST,
  NODE_ENV,
  IS_PROD,
  ADMIN_TOKEN,
  APP_BASE_URL,
  PUBLIC_IFRAME_BASE_URL,
  SPACES_ROOT,
  SPACES_META_PATH,
  USERS_META_PATH,
  TOKENS_META_PATH,
  SESSIONS_META_PATH,
  APPROVED_USERS_PATH,
  WORKSPACE_REQUESTS_PATH,
  PORTALS_NOTES_PATH,
  PORTALS_SDK_SOURCE_PATH,
  SENDGRID_API_KEY,
  SENDGRID_FROM,
  WORKSPACE_ADMIN_EMAIL,
  OPENAI_API_KEY,
  DEFAULT_GPT_MODEL,
  ALLOWED_GPT_MODELS,
  MAX_ASSET_FILE_SIZE,
  MAX_ASSET_FILES,
  GPT_MAX_CALLS_PER_DAY,
  GPT_RATE_WINDOW_MS,
  GPT_RATE_MAX_PER_WINDOW,
  TRUST_PROXY,
  PORTALS_FRAME_ANCESTORS,
} from './config.js';

import { readJsonArray, writeJsonArray } from './stores/jsonStore.js';


const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// Multer setup for in-memory uploads (we write to disk ourselves)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_ASSET_FILE_SIZE,
    files: MAX_ASSET_FILES,
  },
});

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

const magicLinkRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 4,                   // per IP per window (tune as desired)
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    return res.status(429).json({
      error: 'rate_limited',
      message: 'Too many login links requested. Please wait and try again.',
    });
  },
});

if (SENDGRID_API_KEY && SENDGRID_FROM) {
  sgMail.setApiKey(SENDGRID_API_KEY);
  console.log('[mail] SendGrid configured, from:', SENDGRID_FROM);
} else {
  console.log('[mail] SendGrid not fully configured (missing key or from address)');
}

let portalsMarkdownCache = null;

async function getPortalsMarkdown() {
  if (portalsMarkdownCache !== null) {
    return portalsMarkdownCache;
  }
  try {
    const raw = await fs.readFile(PORTALS_NOTES_PATH, 'utf8');
    portalsMarkdownCache = raw;
    console.log('[gpt] loaded portals-sdk-notes.md (length:', raw.length, ')');
  } catch (err) {
    console.warn('[gpt] could not load portals-sdk-notes.md at', PORTALS_NOTES_PATH, err.message);
    portalsMarkdownCache = '';
  }
  return portalsMarkdownCache;
}

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

function redactMagicTokenFromUrl(url) {
  try {
    const u = new URL(url);
    if (u.searchParams.has('token')) u.searchParams.set('token', '[redacted]');
    return u.toString();
  } catch {
    // fallback: cheap redaction
    return String(url).replace(/token=([^&]+)/, 'token=[redacted]');
  }
}

// ───────────────── Spaces helpers ─────────────────
function todayIsoDate() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

async function checkAndIncrementUserGptUsage(userId, amount = 1, opts = {}) {
  const commit = opts.commit !== false; // default true

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

  // Check limit BEFORE increment
  if (usage.calls + amount > GPT_MAX_CALLS_PER_DAY) {
    return { ok: false, usage };
  }

  // If we're just checking, don't persist anything
  if (!commit) {
    return { ok: true, usage };
  }

  // Commit increment
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
    : 100;

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

async function loadApprovedUsers() {
  return readJsonArray(APPROVED_USERS_PATH);
}

async function saveApprovedUsers(list) {
  return writeJsonArray(APPROVED_USERS_PATH, list);
}

async function loadWorkspaceRequests() {
  return readJsonArray(WORKSPACE_REQUESTS_PATH);
}

async function saveWorkspaceRequests(reqs) {
  return writeJsonArray(WORKSPACE_REQUESTS_PATH, reqs);
}

async function isEmailApproved(email) {
  const list = await loadApprovedUsers();
  const normalized = (email || '').trim().toLowerCase();
  return list.some((u) => (u.email || '').trim().toLowerCase() === normalized);
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

function portalsEmbedHeaders(req, res, next) {
  // Helmet sets this; remove it for iframe content
  res.removeHeader('X-Frame-Options');

  // Configure via env so you can tune without code deploy
const ancestors = PORTALS_FRAME_ANCESTORS;

  // If you don't know the Portals hostnames yet, start permissive, tighten later
  const frameAncestors = ancestors || '*';

  // Important: CSP is per-response. This is the modern replacement for XFO.
  res.setHeader('Content-Security-Policy', `frame-ancestors ${frameAncestors};`);
  res.setHeader('Cross-Origin-Resource-Policy', 'same-site');

  next();
}

async function sendMagicLinkEmail(email, url) {
  // If SendGrid isn't configured, fall back to dev-mode logging
  if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
console.log(
  `[magic-link] dev mode: would send to ${email}: ${NODE_ENV === 'development' ? url : redactMagicTokenFromUrl(url)}`
);

    return;
  }

  const subject = 'Sign in to Portals iFrame Builder';
  const escapedUrl = url.replace(/"/g, '&quot;'); // minimal safety

  const html = `
  <div style="font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#020617; color:#e5e7eb; padding:24px;">
    <table width="100%" cellspacing="0" cellpadding="0" style="max-width:520px; margin:0 auto; background:#0b1120; border-radius:14px; border:1px solid #1f2937;">
      <tr>
        <td style="padding:18px 20px 12px; border-bottom:1px solid #1f2937;">
          <div style="font-size:11px; letter-spacing:0.18em; text-transform:uppercase; color:#22d3ee; margin-bottom:4px;">
            Portals iFrames - 
          </div>
          <div style="font-size:16px; font-weight:600; color:#e5e7eb;">
            Sign in to access your Portals iFrame Builder!
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 20px 8px; font-size:14px; color:#cbd5f5;">
          <p style="margin:0 0 10px;">Hi,</p>
          <p style="margin:0 0 14px;">
            Click the button below to sign in to your account and access your Portals iFrame Builder.
          </p>
          <p style="margin:0 0 18px; font-size:12px; color:#9ca3af;">
            This link expires in about <strong>15 minutes</strong> or after it&apos;s used once.
          </p>
        </td>
      </tr>
      <tr>
        <td style="padding:0 20px 18px;">
          <table cellspacing="0" cellpadding="0" style="margin:0 auto;">
            <tr>
              <td align="center" style="border-radius:999px; background:linear-gradient(to right,#22d3ee,#a855f7);">
                <a href="${escapedUrl}" 
                   style="display:inline-block; padding:10px 24px; font-size:13px; color:#020617; text-decoration:none; font-weight:600;">
                  Sign in to Portals iFrame Builder
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:0 20px 18px;">
          <p style="margin:0 0 8px; font-size:12px; color:#9ca3af;">
            If the button doesn&apos;t work, copy and paste this URL into your browser:
          </p>
          <p style="margin:0; font-size:11px; color:#22d3ee;">
            <a href="${escapedUrl}" style="color:#22d3ee; text-decoration:none;">${escapedUrl}</a>
          </p>
        </td>
      </tr>
      <tr>
        <td style="padding:12px 20px 16px; border-top:1px solid #1f2937;">
          <p style="margin:0; font-size:11px; color:#6b7280;">
            You&apos;re receiving this email because someone attempted to log in with the email <strong>${email}</strong>.
            If this wasn&apos;t you, you can ignore this message.
          </p>
        </td>
      </tr>
    </table>
  </div>
  `;

  const text = [
    'Sign in to Portals iFrame Builder',
    '',
    `Click this link to sign in: ${url}`,
    '',
    'This link expires in 15 minutes or after it’s used once.',
    '',
    `If you didn’t request this, you can ignore this email.`
  ].join('\n');

  const msg = {
    to: email,
    from: SENDGRID_FROM,
    subject,
    text,
    html
  };

  await sgMail.send(msg);
  console.log('[magic-link] sent email to', email);
}

async function sendWorkspaceRequestNotificationToAdmin(request) {
  if (!SENDGRID_API_KEY || !SENDGRID_FROM || !WORKSPACE_ADMIN_EMAIL) {
    console.log('[workspace-email] dev mode: would notify admin of workspace request:', {
      admin: WORKSPACE_ADMIN_EMAIL,
      request,
    });
    return;
  }

  const appBase = APP_BASE_URL.replace(/\/+$/, '');
  const adminUrl = `${appBase}/admin`;

  const subject = `New workspace request from ${request.email}`;
  const textLines = [
    `A new workspace request has been submitted.`,
    ``,
    `User: ${request.email}`,
    `User ID: ${request.userId}`,
    `Suggested slug: ${request.suggestedSlug || '(none)'}`,
    `Note: ${request.note || '(none)'}`,
    `Requested at: ${request.createdAt}`,
    ``,
    `Review and approve this request at: ${adminUrl}`,
  ];

  const text = textLines.join('\n');

  const html = `
    <div style="font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#020617; color:#e5e7eb; padding:24px;">
      <table width="100%" cellspacing="0" cellpadding="0" style="max-width:520px; margin:0 auto; background:#0b1120; border-radius:14px; border:1px solid #1f2937;">
        <tr>
          <td style="padding:18px 20px 12px; border-bottom:1px solid #1f2937;">
            <div style="font-size:11px; letter-spacing:0.18em; text-transform:uppercase; color:#22d3ee; margin-bottom:4px;">
              Portals iFrame Builder · Workspace Request
            </div>
            <div style="font-size:16px; font-weight:600; color:#e5e7eb;">
              New workspace request from ${request.email}
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 20px 10px; font-size:13px; color:#cbd5f5;">
            <p style="margin:0 0 8px;">Details:</p>
            <ul style="margin:0 0 10px; padding-left:18px;">
              <li><strong>User:</strong> ${request.email}</li>
              <li><strong>User ID:</strong> ${request.userId}</li>
              <li><strong>Suggested slug:</strong> ${request.suggestedSlug || '(none)'}</li>
              <li><strong>Note:</strong> ${request.note || '(none)'}</li>
              <li><strong>Requested at:</strong> ${request.createdAt}</li>
            </ul>
          </td>
        </tr>
        <tr>
          <td style="padding:0 20px 18px;">
            <table cellspacing="0" cellpadding="0">
              <tr>
                <td style="border-radius:999px; background:linear-gradient(to right,#22d3ee,#a855f7);">
                  <a href="${adminUrl}"
                     style="display:inline-block; padding:8px 20px; font-size:13px; color:#020617; text-decoration:none; font-weight:600;">
                    Open admin workspace requests
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
  `;

  const msg = {
    to: WORKSPACE_ADMIN_EMAIL,
    from: SENDGRID_FROM,
    subject,
    text,
    html,
  };

  try {
    await sgMail.send(msg);
    console.log('[workspace-email] sent admin workspace request notification for', request.id);
  } catch (err) {
    console.error('[workspace-email] failed to send admin notification', err);
  }
}

async function sendWorkspaceApprovalEmailToUser(user, spaceRecord, requestRecord) {
  if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
    console.log('[workspace-email] dev mode: would email user about approval:', {
      to: user.email,
      space: spaceRecord.slug,
    });
    return;
  }
  const appBase = APP_BASE_URL.replace(/\/+$/, '');
  const appUrl = `${appBase}/`;

  const publicBase = PUBLIC_IFRAME_BASE_URL.replace(/\/+$/, '');
  const iframeUrl = `${publicBase}/p/${encodeURIComponent(spaceRecord.slug)}/index.html`;

  const subject = `Your Portals iFrame workspace "${spaceRecord.slug}" is ready`;
  const textLines = [
    `Your workspace request has been approved.`,
    ``,
    `Space slug: ${spaceRecord.slug}`,
    `Quota: ${spaceRecord.quotaMb} MB`,
    ``,
    `You can sign in and start editing your overlay at:`,
    `${appUrl}`,
    ``,
    `Default iframe URL for your Portals space:`,
    `${iframeUrl}`,
  ];

  const text = textLines.join('\n');

  const html = `
    <div style="font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#020617; color:#e5e7eb; padding:24px;">
      <table width="100%" cellspacing="0" cellpadding="0" style="max-width:520px; margin:0 auto; background:#0b1120; border-radius:14px; border:1px solid #1f2937;">
        <tr>
          <td style="padding:18px 20px 12px; border-bottom:1px solid #1f2937;">
            <div style="font-size:11px; letter-spacing:0.18em; text-transform:uppercase; color:#22d3ee; margin-bottom:4px;">
              Portals iFrame Builder · Workspace Approved
            </div>
            <div style="font-size:16px; font-weight:600; color:#e5e7eb;">
              Your workspace "${spaceRecord.slug}" is ready
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 20px 10px; font-size:13px; color:#cbd5f5;">
            <p style="margin:0 0 10px;">You can now sign in and start building your HUD overlays.</p>
            <p style="margin:0 0 6px;">
              <strong>Space slug:</strong> ${spaceRecord.slug}<br/>
              <strong>Quota:</strong> ${spaceRecord.quotaMb} MB
            </p>
            <p style="margin:10px 0 6px; font-size:12px; color:#9ca3af;">
              Default iFrame URL for your Portals space:
            </p>
            <p style="margin:0 0 12px; font-size:12px; color:#22d3ee; word-break:break-all;">
              <a href="${iframeUrl}" style="color:#22d3ee; text-decoration:none;">${iframeUrl}</a>
            </p>
          </td>
        </tr>
        <tr>
          <td style="padding:0 20px 18px;">
            <table cellspacing="0" cellpadding="0">
              <tr>
                <td style="border-radius:999px; background:linear-gradient(to right,#22d3ee,#a855f7);">
                  <a href="${appUrl}"
                     style="display:inline-block; padding:8px 20px; font-size:13px; color:#020617; text-decoration:none; font-weight:600;">
                    Open Portals iFrame Builder
                  </a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
  `;

  const msg = {
    to: user.email,
    from: SENDGRID_FROM,
    subject,
    text,
    html,
  };

  try {
    await sgMail.send(msg);
    console.log('[workspace-email] sent approval email to', user.email, 'for space', spaceRecord.slug);
  } catch (err) {
    console.error('[workspace-email] failed to send approval email', err);
  }
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
    console.log('[admin] bad admin token:');
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
if (TRUST_PROXY) {
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

const EDITOR_ORIGINS = new Set([
  'https://iframes.jawn.bot',
  // Dev origins:
  'http://localhost:4100',
  'http://localhost:5173',
]);

const ALLOWED_ORIGINS = [
  'https://iframes.jawn.bot',
  'http://localhost:4100', // dev UI
  'http://localhost:5173', // if you’re running Vite locally
];

app.use(
  '/api',
  cors({
    origin(origin, cb) {
      // Allow non-browser / same-origin calls (curl, health checks, etc.)
      if (!origin) return cb(null, true);

      if (ALLOWED_ORIGINS.includes(origin)) {
        return cb(null, true);
      }

      console.warn('[cors] blocked origin:', origin);
      return cb(new Error('Not allowed by CORS'));
    },
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
app.post('/api/auth/magic/start', magicLinkRateLimiter, async (req, res, next) => {
  try {
    const { email } = req.body || {};
    const normalizedEmail = (email || '').trim().toLowerCase();

    if (!isValidEmail(normalizedEmail)) {
      return res
        .status(400)
        .json({ error: 'bad_email', message: 'Invalid email address' });
    }
    
    // Invite-only gate: only approved emails can receive magic links
    const approved = await isEmailApproved(normalizedEmail);
    if (!approved) {
      return res.status(403).json({
        error: 'not_approved',
        message: 'This project is invite-only. Your email is not approved for access.',
      });
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

    const base = APP_BASE_URL.replace(/\/+$/, '');
    const verifyUrl = `${base}/api/auth/magic/verify?token=${encodeURIComponent(
      token
    )}&redirect=1`;


    await sendMagicLinkEmail(normalizedEmail, verifyUrl);

    console.log(`[auth] magic link created for ${normalizedEmail}`);

    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// Verify magic link: GET /api/auth/magic/verify?token=...
app.get('/api/auth/magic/verify', async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { token, redirect } = req.query || {};
    const wantsRedirect = redirect === '1';

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
    const appBase = APP_BASE_URL.replace(/\/+$/, '');

    if (wantsRedirect) {
      // After verification, send user to the app UI rather than showing JSON
      return res.redirect(302, `${appBase}/`);
    }

    // Fallback: JSON response (useful for curl / debugging)
    res.json({ ok: true, user });
  } catch (err) {
    next(err);
  }
});

// Logout: POST /api/auth/logout
app.post('/api/auth/logout', async (req, res, next) => {
  try {
    const sid = req.cookies?.sid || null;

    if (sid) {
      const sessions = await loadSessionsMeta();
      const nextSessions = sessions.filter((s) => s.id !== sid);

      if (nextSessions.length !== sessions.length) {
        await saveSessionsMeta(nextSessions);
        console.log('[auth] logout session', sid);
      }
    }

    // Clear the cookie (must match the options used when setting it)
    res.clearCookie('sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
    });

    res.json({ ok: true });
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

function requireEditorOrigin(req, res, next) {
  const origin = req.get('origin');

  // Non-browser clients (curl, internal scripts) often send no Origin; allow them.
  if (!origin) return next();

  if (!EDITOR_ORIGINS.has(origin)) {
    console.warn('[origin] blocked write from origin:', origin, 'to', req.method, req.originalUrl);
    return res.status(403).json({
      error: 'bad_origin',
      message: 'This action is only allowed from the editor.',
    });
  }

  next();
}

// List files in a space directory
// GET /api/spaces/:slug/files?path=subdir/
app.get('/api/spaces/:slug/files', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const slug = String(req.params.slug || '');
    const relPath =
      typeof req.query.path === 'string' && req.query.path.trim()
        ? req.query.path.trim()
        : '.';

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    const dirPath = resolveSpacePath(space, relPath);

    let dirents;
    try {
      dirents = await fs.readdir(dirPath, { withFileTypes: true });
    } catch (err) {
      // Directory doesn't exist yet? Treat as empty (nice UX for assets/)
      if (err.code === 'ENOENT') {
        return res.json({ ok: true, path: relPath, items: [] });
      }
      // Path exists but isn't a directory
      if (err.code === 'ENOTDIR') {
        return res.status(400).json({ error: 'not_a_directory' });
      }
      throw err;
    }

    const itemsRaw = await Promise.all(
      dirents.map(async (d) => {
        const full = path.join(dirPath, d.name);

        // File might vanish between readdir and stat; skip if so
        try {
          const stat = await fs.stat(full);
          return {
            name: d.name,
            isDir: d.isDirectory(),
            size: stat.size,
            mtime: stat.mtime,
          };
        } catch (err) {
          if (err.code === 'ENOENT') return null;
          throw err;
        }
      })
    );

    const items = itemsRaw.filter(Boolean);

    // Optional: stable sort (dirs first, then alphabetical)
    items.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ ok: true, path: relPath, items });
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
app.post('/api/spaces/:slug/file', requireUser, requireEditorOrigin, async (req, res, next) => {
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
    // ── Enforce quota on editor saves too (not just uploads)
    const quotaMb = Number.isFinite(Number(space.quotaMb))
      ? Number(space.quotaMb)
      : 100;
    const quotaBytes = quotaMb * 1024 * 1024;

    // Current usage on disk
    let currentBytes = 0;
    try {
      currentBytes = await getDirSizeBytes(space.dirPath);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      currentBytes = 0;
    }

    // If overwriting an existing file, subtract its current size
    let existingBytes = 0;
    try {
      existingBytes = (await fs.stat(filePath)).size;
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      existingBytes = 0;
    }

    const newBytes = Buffer.byteLength(content, 'utf8');
    const projectedBytes = Math.max(0, currentBytes - existingBytes) + newBytes;

    if (projectedBytes > quotaBytes) {
      const deltaBytes = newBytes - existingBytes;

      return res.status(413).json({
        error: 'quota_exceeded',
        message: `Save would exceed quota of ${quotaMb} MB`,
        quotaMb,
        currentMb: +(currentBytes / (1024 * 1024)).toFixed(2),
        deltaMb: +(deltaBytes / (1024 * 1024)).toFixed(2),
      });
    }

    await fs.writeFile(filePath, content, 'utf8');

    // Keep meta in sync (best-effort)
    try {
      await updateSpaceSizeBytes(space, projectedBytes);
    } catch (err) {
      console.warn('[spaces] failed to update size meta after save:', err.message);
    }

    res.json({
      ok: true,
      path: relPath,
    });
  } catch (err) {
    next(err);
  }
});

// Delete a file in a space
// DELETE /api/spaces/:slug/file
// body: { path }
app.delete('/api/spaces/:slug/file', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const { path: relPath } = req.body || {};

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

    // optional: only allow deleting editable text files
    if (!isEditableTextFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    await fs.unlink(filePath).catch((err) => {
      if (err.code === 'ENOENT') {
        throw Object.assign(new Error('file_not_found'), { status: 404 });
      }
      throw err;
    });

    // You could update stored quota here, but we recompute on demand via usage,
    // so it's fine to skip.

    res.json({ ok: true, path: relPath });
  } catch (err) {
    if (err.message === 'file_not_found') {
      return res.status(404).json({ error: 'file_not_found' });
    }
    next(err);
  }
});

// Rename a file in a space
// POST /api/spaces/:slug/file/rename
// body: { from, to }
app.post('/api/spaces/:slug/file/rename', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const { from, to } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }
    if (!from || !to) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    // Normalize names (no subdirs for now, just simple filenames)
    const fromName = from.trim();
    const toName = to.trim();
    if (!fromName || !toName) {
      return res.status(400).json({ error: 'bad_name' });
    }

    // Optional: enforce basic extension sanity
    const ext = (toName.split('.').pop() || '').toLowerCase();
    const allowedExts = ['html', 'htm', 'css', 'js', 'mjs', 'json', 'txt'];
    if (!allowedExts.includes(ext)) {
      return res.status(400).json({
        error: 'unsupported_type',
        message: 'Please use one of: .html, .css, .js, .json, .txt'
      });
    }

    const srcPath = resolveSpacePath(space, fromName);
    const destPath = resolveSpacePath(space, toName);

    // Ensure source exists
    const srcStat = await fs.stat(srcPath).catch((err) => {
      if (err.code === 'ENOENT') {
        return null;
      }
      throw err;
    });
    if (!srcStat || !srcStat.isFile()) {
      return res.status(404).json({ error: 'file_not_found' });
    }

    // Prevent overwriting an existing file
    const destExists = await fs
      .stat(destPath)
      .then((s) => s && s.isFile())
      .catch((err) => {
        if (err.code === 'ENOENT') return false;
        throw err;
      });
    if (destExists) {
      return res.status(409).json({ error: 'target_exists' });
    }

    // Restrict to editable text files
    if (!isEditableTextFile(srcPath) || !isEditableTextFile(destPath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    await fs.rename(srcPath, destPath);

    res.json({
      ok: true,
      from: fromName,
      to: toName
    });
  } catch (err) {
    console.error('[files] error renaming file', err);
    next(err);
  }
});

let portalsSdkSourceCache = { text: '', mtimeMs: 0 };

async function loadPortalsSdkSource() {
  try {
    const stat = await fs.stat(PORTALS_SDK_SOURCE_PATH);

    if (portalsSdkSourceCache.text && portalsSdkSourceCache.mtimeMs === stat.mtimeMs) {
      return portalsSdkSourceCache.text;
    }

    const raw = await fs.readFile(PORTALS_SDK_SOURCE_PATH, 'utf8');
    portalsSdkSourceCache = { text: raw, mtimeMs: stat.mtimeMs };

    console.log('[gpt] loaded Portals SDK source (len:', raw.length, ')');
    return raw;
  } catch (err) {
    console.warn('[gpt] could not load Portals SDK source:', err.message);
    portalsSdkSourceCache = { text: '', mtimeMs: 0 };
    return '';
  }
}

function shouldIncludePortalsSdk({ prompt, fileText, messages }) {
  const msgHay = [
    prompt || '',
    ...(Array.isArray(messages) ? messages.map((m) => m?.content || '') : []),
  ].join('\n').toLowerCase();

  const fileHay = (fileText || '').toLowerCase();

  // "Strong" SDK / Unity integration identifiers
  const strong = [
    'portalssdk',          // matches "PortalsSdk" when lowercased
    'uniwebview://',
    'requestpublicid',
    'requestpublickey',
    'getinventorydata',
    'getuserquests',
    'startquest',
    'getzones',
    'claimzone',
    'sessionset',
    'sessionget',
    'startspeechtotext',
    'stopspeechtotext',
    'starttexttospeech',
    'texttospeech',
    'closeiframe',
    'openauthmodal',
    'openbackpack',
    'sendmessagetounity',
    'setmessagelistener',
    'oncloseiframemessage',
  ];

  // "Weak" integration words that are too common on their own
  const weak = [
    'postmessage',
    'window.parent',
    'parent.postmessage',
    'targetorigin',
    'messageevent',
  ];

  const env = ['portals', 'unity'];

  const msgHasStrong = strong.some((t) => msgHay.includes(t));
  const msgHasEnv = env.some((t) => msgHay.includes(t));
  const msgHasWeak = weak.some((t) => msgHay.includes(t));

  // File-only triggers must be explicit SDK fingerprints (NOT generic)
  const fileHasSdkFingerprint =
    fileHay.includes('portalssdk') ||
    fileHay.includes('uniwebview://') ||
    fileHay.includes('portalsSdk'.toLowerCase()); // redundant but clear

  // Include SDK if:
  // - user/messages mention strong SDK terms, OR
  // - file clearly uses SDK, OR
  // - user mentions Portals/Unity AND integration mechanics (postMessage etc.)
  return msgHasStrong || fileHasSdkFingerprint || (msgHasEnv && msgHasWeak);
}


const PORTALS_SDK_PROD_CHEATSHEET = [
  'You are using the official Portals SDK (global object: PortalsSdk). This tool is ONLY for the Portals production environment.',
  'When a method requires originUrl, use: PortalsSdk.Origin.Prod',
  '',
  'Important SDK behavior:',
  '- Many SDK methods set: PortalsSdk.PortalsWindow.onmessage = PortalsSdk.OnMessage (overwrites onmessage).',
  '- Do NOT recommend overriding window.onmessage in user code. Prefer SDK callbacks + PortalsSdk.setMessageListener(cb) when appropriate.',
  '- Set the callback BEFORE calling the SDK method; OnMessage may invoke callbacks immediately.',
  '',
  'Common calls:',
  '- PortalsSdk.requestPublicKey(PortalsSdk.Origin.Prod, cb)',
  '- PortalsSdk.requestPublicId(PortalsSdk.Origin.Prod, cb)',
  '- PortalsSdk.getInventoryData(PortalsSdk.Origin.Prod, itemGeneratorKeys, itemGeneratorIds, cb, extraItems?)',
  '- PortalsSdk.sessionSet(key, value) / PortalsSdk.sessionGet(key, cb)',
  '- PortalsSdk.startSpeechToText(prompt, liveTranscription, speechTime, onTranscript, onVolume)',
  '- PortalsSdk.startTextToSpeech(text, story?, passage?)',
  '- PortalsSdk.closeIframe(), PortalsSdk.openAuthModal(), PortalsSdk.openBackpack()',
].join('\n');

// ───────────────── GPT helper for a user space ─────────────────
// POST /api/spaces/:slug/gpt/chat
// body: {
//   prompt: string,
//   filePath?: string,           // relative to space root
//   model?: string,              // optional: gpt-4.1-mini, gpt-4.1-nano, gpt-4o-mini
//   messages?: [{role,content}]  // optional prior chat history
// }
app.post(
  '/api/spaces/:slug/gpt/chat',
  requireUser,
  requireEditorOrigin,
  gptRateLimiter,
  async (req, res, next) => {
    try {
      if (!openai) {
        return res.status(503).json({
          error: 'gpt_disabled',
          message: 'OPENAI_API_KEY is not configured on the server',
        });
      }

      await ensureSpacesRoot();
      const { slug } = req.params;
      const { prompt, filePath, fileContent, model: requestedModel, messages } = req.body || {};

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
      // Per-user daily GPT quota (PRECHECK only — don't burn quota on OpenAI failure)
      const quotaCheck = await checkAndIncrementUserGptUsage(req.user.id, 1, { commit: false });
      if (!quotaCheck.ok) {
        return res.status(429).json({
          error: 'gpt_quota_exceeded',
          message: `Daily GPT limit reached (${GPT_MAX_CALLS_PER_DAY} calls).`,
          usage: quotaCheck.usage,
        });
      }

      const model = pickModel(requestedModel);


let fileContext = null;
let fileLang = 'text';

if (filePath) {
  try {
    let content = null;

    if (typeof fileContent === 'string' && fileContent.length) {
      content = fileContent;
    } else {
      const fullPath = resolveSpacePath(space, filePath);
      if (isEditableTextFile(fullPath)) {
        content = await fs.readFile(fullPath, 'utf8');
      }
    }

    if (typeof content === 'string') {
      const ext = (path.extname(filePath) || '').toLowerCase();
      if (ext === '.html' || ext === '.htm') fileLang = 'html';
      else if (ext === '.css') fileLang = 'css';
      else if (ext === '.js' || ext === '.mjs') fileLang = 'javascript';
      else if (ext === '.json') fileLang = 'json';

      const MAX_FILE_CHARS = 20_000;
      const isTruncated = content.length > MAX_FILE_CHARS;

      // Show head+tail when truncated (better than only head)
      const HEAD_CHARS = 12_000;
      const TAIL_CHARS = MAX_FILE_CHARS - HEAD_CHARS; // keeps total <= MAX_FILE_CHARS

      let snippet = content;
      let headChars = content.length;
      let tailChars = 0;

      if (isTruncated) {
        const head = content.slice(0, HEAD_CHARS);
        const tail = content.slice(Math.max(0, content.length - TAIL_CHARS));
        snippet = head + '\n' + tail;

        headChars = HEAD_CHARS;
        tailChars = TAIL_CHARS;
      }

      fileContext = {
        path: filePath,
        snippet,
        lang: fileLang,
        truncated: isTruncated,
        totalChars: content.length,
        headChars,
        tailChars,
      };
    }
  } catch (err) {
    console.warn('[gpt] failed to load file context', filePath, err.message);
  }
}


const includeSdk = shouldIncludePortalsSdk({
  prompt,
  fileText: fileContext?.snippet || '',
  messages,
});
const portalsSdkContext = [
  'Context:',
  '- The overlay runs inside an <iframe> embedded in the Portals Unity environment.',
  '- A global PortalsSdk object exists in the iframe (official production SDK).',
  '- This tool targets production only. When an SDK method requires originUrl, use PortalsSdk.Origin.Prod.',
  '- Avoid setting window.onmessage directly; the SDK overwrites PortalsSdk.PortalsWindow.onmessage in many methods.',
  '- Prefer the SDK callback pattern (e.g. requestPublicId(originUrl, cb), sessionGet(key, cb)).',
].join('\n');

// Optional (small) markdown hints, only when the question looks Portals/Unity-related
const portalsDocs = includeSdk ? await getPortalsMarkdown() : '';


      // Build messages for the chat completion
      const chatMessages = [];

      // General overlay / iframe system prompt
chatMessages.push({
  role: 'system',
  content: [
    'You are a coding assistant helping a developer build HTML/CSS/JS overlays that run as iframes in a Unity/Portals-based game.',
    'All code you generate must be client-side only (no Node.js, no server frameworks).',
    'Prefer small, focused changes and clearly labeled code blocks.',
    'Always format your response as Markdown.',
    'Wrap code in fenced blocks with a correct language tag (```html, ```css, ```js, ```json, etc.) so that a Markdown renderer can pretty-print it.',
'If a current file is provided: your FIRST fenced code block must be the FULL updated file content. Output exactly one code block for the file.'
  ].join(' '),
});

if (includeSdk) {
  chatMessages.push({
    role: 'system',
    content: PORTALS_SDK_PROD_CHEATSHEET,
  });

  const sdkSource = await loadPortalsSdkSource();
  if (sdkSource) {
    const MAX_SDK_CHARS = 80_000; // usually plenty; adjust if needed
    const sdkText =
      sdkSource.length > MAX_SDK_CHARS
        ? sdkSource.slice(0, MAX_SDK_CHARS) + '\n/* [truncated for prompt size] */\n'
        : sdkSource;

    chatMessages.push({
      role: 'system',
      content:
        'Below is the official Portals SDK source (production). Treat it as the source of truth. ' +
        'Do not invent SDK methods/properties that are not present here.\n\n' +
        '```js\n' +
        sdkText +
        '\n```',
    });
  } else {
    chatMessages.push({
      role: 'system',
      content:
        'PortalsSdk source was expected at sdk/portals-sdk.js but was not found on the server. ' +
        'If you are unsure about an SDK API name, say so and propose a safe postMessage-based fallback.',
    });
  }
}

      chatMessages.push({
        role: 'system',
        content: portalsSdkContext,
      });

      // Optional: inject markdown docs if the prompt looks Portals-related
      if (portalsDocs) {
        chatMessages.push({
          role: 'system',
          content:
            'Here is a curated markdown reference for the Portals iframe SDK and Unity integration. ' +
            'Consult it when generating examples or advising on Portals-related issues:\n\n' +
            portalsDocs,
        });
      }

      // File context, if we have one
if (fileContext) {
  const truncNote = fileContext.truncated
    ? `NOTE: The file was truncated for GPT context (showing first ${fileContext.headChars} chars + last ${fileContext.tailChars} chars of ${fileContext.totalChars}). ` +
      `DO NOT output a full-file replacement. Output only targeted, copy-pastable snippets and say exactly where they go.`
    : '';

  chatMessages.push({
    role: 'system',
    content:
      `${truncNote}\n\n` +
      `Here is the current file ${fileContext.path}:\n\n` +
      `\`\`\`${fileContext.lang}\n${fileContext.snippet}\n\`\`\``,
  });
}


      // Include any prior chat history the frontend wants to send
      if (Array.isArray(messages)) {
        for (const m of messages) {
          if (
            m &&
            typeof m.role === 'string' &&
            typeof m.content === 'string' &&
            ['user', 'assistant'].includes(m.role)
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

      // Commit quota ONLY after OpenAI succeeds
      // (If this write fails, log it, but don't destroy UX by failing the response.)
      try {
        await checkAndIncrementUserGptUsage(req.user.id, 1, { commit: true });
      } catch (e) {
        console.error('[gpt] quota commit failed (non-fatal)', e);
      }

      const answer = completion.choices[0]?.message || { role: 'assistant', content: '' };

      res.json({
        ok: true,
        model,
        sdkIncluded: includeSdk,
        fileContextTruncated: !!fileContext?.truncated,
        message: answer,
      });

    } catch (err) {
      console.error('[gpt] error in /api/spaces/:slug/gpt/chat', err);
      next(err);
    }
  }
);
// ───────────────── GPT helper for a user space ─────────────────


// ───────────────── Asset upload for a user space ─────────────────

// POST /api/spaces/:slug/upload
// multipart/form-data
// fields:
//   files[]  -> file inputs
//   subdir   -> optional subdirectory inside the space (e.g. "assets" or "assets/icons")
app.post(
  '/api/spaces/:slug/upload',
  requireUser, requireEditorOrigin,
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
        : 100;
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
          const rawName = String(f.originalname || '');
          const filename = path.posix.basename(rawName.replace(/\\/g, '/'));

          if (!filename) {
            return res.status(400).json({ error: 'bad_filename' });
          }

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

// DELETE an asset (e.g. image) in a space
// DELETE /api/spaces/:slug/asset
// body: { path } where path starts with "assets/"
app.delete('/api/spaces/:slug/asset', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const { path: relPath } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({ error: 'bad_slug' });
    }
    if (!relPath || typeof relPath !== 'string') {
      return res.status(400).json({ error: 'missing_path' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) {
      return res.status(404).json({ error: 'space_not_found' });
    }

    // Require that assets live under "assets/" (no arbitrary paths)
    let normalized = relPath.trim().replace(/\\/g, '/');
    if (normalized.startsWith('/')) normalized = normalized.slice(1);
    if (!normalized.toLowerCase().startsWith('assets/')) {
      return res.status(400).json({ error: 'bad_asset_path' });
    }

    const filePath = resolveSpacePath(space, normalized);

    // Check it's an allowed asset type
    if (!isAllowedAssetFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    // Try to delete
    await fs.unlink(filePath).catch((err) => {
      if (err.code === 'ENOENT') {
        throw Object.assign(new Error('asset_not_found'), { status: 404 });
      }
      throw err;
    });

    // Recompute usage and store it (optional but nice)
    try {
      const newSize = await getDirSizeBytes(space.dirPath);
      await updateSpaceSizeBytes(space, newSize);
    } catch (err) {
      console.warn('[assets] failed to recompute size after delete:', err.message);
    }

    res.json({ ok: true, path: normalized });
  } catch (err) {
    if (err.message === 'asset_not_found') {
      return res.status(404).json({ error: 'asset_not_found' });
    }
    console.error('[assets] error deleting asset', err);
    next(err);
  }
});


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

// User-facing: request a new workspace / space
// POST /api/spaces/request
// body: { note?: string }
app.post('/api/spaces/request', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const note = (req.body?.note || '').toString().trim();
    const suggestedSlugRaw = (req.body?.suggestedSlug || '').toString().trim();
    const now = new Date();

    const requests = await loadWorkspaceRequests();

    // If there's already a pending request for this user, don't spam
    const existing = requests.find(
      (r) => r.userId === req.user.id && r.status === 'pending'
    );
    if (existing) {
      return res.json({
        ok: true,
        alreadyPending: true,
        request: existing
      });
    }

       let suggestedSlug = null;
    if (suggestedSlugRaw) {
      let normalized = suggestedSlugRaw.trim().toLowerCase();
      normalized = normalized.replace(/[^a-z0-9-]/g, '-');
      normalized = normalized.replace(/-+/g, '-');
      normalized = normalized.replace(/^-+|-+$/g, '');
      if (!normalized || !/^[a-z0-9-]{3,32}$/.test(normalized)) {
        return res.status(400).json({
          error: 'bad_suggested_slug',
          message: 'Slug must be between 3 and 32 characters in length.'
        });
      }
      suggestedSlug = normalized;
    }


    const reqRecord = {
      id: generateId('wr_'),
      userId: req.user.id,
      email: req.user.email,
      status: 'pending', // 'pending' | 'approved' | 'rejected'
      note: note || null,
      suggestedSlug,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString()
    };

    requests.push(reqRecord);
    await saveWorkspaceRequests(requests);

    console.log('[workspace-requests] new request', {
      id: reqRecord.id,
      userId: reqRecord.userId,
      email: reqRecord.email,
      suggestedSlug
    });
     try {
      await sendWorkspaceRequestNotificationToAdmin(reqRecord);
    } catch (mailErr) {
      // already logged inside helper; no-op here
    }

    res.status(201).json({
      ok: true,
      request: reqRecord
    });
  } catch (err) {
    console.error('[workspace-requests] error creating request', err);
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
    <p class="hud-body">Overlay is alive. Wire this up as an iFrame in your Portals space!</p>
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
        : 100, // default 100 MB
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

// Admin: list workspace requests
// GET /api/admin/space-requests?status=pending|approved|rejected
app.get('/api/admin/space-requests', requireAdmin, async (req, res, next) => {
  try {
    const statusFilter = (req.query?.status || '').toString().trim();
    const reqs = await loadWorkspaceRequests();

    const filtered =
      statusFilter && ['pending', 'approved', 'rejected'].includes(statusFilter)
        ? reqs.filter((r) => r.status === statusFilter)
        : reqs;

    res.json({ ok: true, requests: filtered });
  } catch (err) {
    console.error('[workspace-requests] error listing requests', err);
    next(err);
  }
});

// Admin: approve a workspace request and create a space for the user
// POST /api/admin/space-requests/:id/approve
// body: { slug, quotaMb? }
app.post('/api/admin/space-requests/:id/approve', requireAdmin, requireEditorOrigin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const rawSlug = (req.body?.slug || '').toString();

    // Normalize slug: trim, lowercase, replace invalid chars with '-'
    let slug = rawSlug.trim().toLowerCase();
    slug = slug.replace(/[^a-z0-9-]/g, '-');   // anything not a-z,0-9,- => '-'
    slug = slug.replace(/-+/g, '-');           // collapse multiple dashes
    slug = slug.replace(/^-+|-+$/g, '');       // trim leading/trailing dashes

    if (!slug || !/^[a-z0-9-]{3,32}$/.test(slug)) {
      console.warn('[workspace-requests] bad_slug from admin input:', rawSlug, 'normalized to:', slug);
      return res.status(400).json({
        error: 'bad_slug',
        message: 'Slug must be between 3 and 32 characters in length.'
      });
    }

    const quotaMbRaw = req.body?.quotaMb;
    const quotaMb = Number.isFinite(Number(quotaMbRaw)) ? Number(quotaMbRaw) : 100;

    const requests = await loadWorkspaceRequests();
    const idx = requests.findIndex((r) => r.id === id);
    if (idx === -1) {
      return res.status(404).json({ error: 'request_not_found' });
    }

    const reqRecord = requests[idx];
    if (reqRecord.status !== 'pending') {
      return res.status(400).json({
        error: 'bad_status',
        message: `Request is already ${reqRecord.status}`
      });
    }

    const users = await loadUsersMeta();
    const user = users.find((u) => u.id === reqRecord.userId || u.email === reqRecord.email);
    if (!user) {
      return res.status(404).json({
        error: 'user_not_found',
        message: 'User referenced in request could not be found'
      });
    }

    // Make sure we don't already have a space with this slug
    const spaces = await loadSpacesMeta();
    if (spaces.find((s) => s.slug === slug)) {
      return res.status(409).json({
        error: 'space_exists',
        message: 'A space with this slug already exists.'
      });
    }

    const now = new Date().toISOString();
    const dirPath = path.join(SPACES_ROOT, slug);

    if (fsSync.existsSync(dirPath)) {
      return res.status(409).json({
        error: 'dir_exists',
        message: 'Directory for this slug already exists.'
      });
    }

    await fs.mkdir(dirPath, { recursive: true });

    const starterHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${slug} overlay</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>/* ...(same as before)... */</style>
</head>
<body>
  <div class="hud">
    <p class="hud-title">Space: ${slug}</p>
    <p class="hud-body">It's alive! Wire this up as an iFrame in your Portals space.</p>
  </div>
</body>
</html>
`;

    await fs.writeFile(path.join(dirPath, 'index.html'), starterHtml, 'utf8');

    const spaceRecord = {
      id: slug,
      slug,
      dirPath,
      quotaMb,
      createdAt: now,
      updatedAt: now,
      status: 'active',
      ownerEmail: (user.email || '').trim().toLowerCase()
    };

    spaces.push(spaceRecord);
    await saveSpacesMeta(spaces);

    const updatedReq = {
      ...reqRecord,
      status: 'approved',
      updatedAt: now,
      approvedAt: now,
      spaceSlug: slug
    };
    requests[idx] = updatedReq;
    await saveWorkspaceRequests(requests);

    console.log('[workspace-requests] approved', {
      requestId: id,
      userId: user.id,
      email: user.email,
      slug
    });
    try {
      await sendWorkspaceApprovalEmailToUser(user, spaceRecord, updatedReq);
    } catch (mailErr) {
      // helper logs internally; don't block the approval
    }
    res.json({
      ok: true,
      request: updatedReq,
      space: spaceRecord
    });
  } catch (err) {
    console.error('[workspace-requests] error approving request', err);
    next(err);
  }
});


// Admin: reject a workspace request
// POST /api/admin/space-requests/:id/reject
// body: { reason? }
app.post('/api/admin/space-requests/:id/reject', requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    const requests = await loadWorkspaceRequests();
    const idx = requests.findIndex((r) => r.id === id);
    if (idx === -1) {
      return res.status(404).json({ error: 'request_not_found' });
    }

    const reqRecord = requests[idx];
    if (reqRecord.status !== 'pending') {
      return res.status(400).json({
        error: 'bad_status',
        message: `Request is already ${reqRecord.status}`
      });
    }

    const now = new Date().toISOString();
    const updatedReq = {
      ...reqRecord,
      status: 'rejected',
      updatedAt: now,
      rejectedAt: now,
      rejectReason: reason || null
    };

    requests[idx] = updatedReq;
    await saveWorkspaceRequests(requests);

    console.log('[workspace-requests] rejected', {
      requestId: id,
      email: reqRecord.email
    });

    res.json({ ok: true, request: updatedReq });
  } catch (err) {
    console.error('[workspace-requests] error rejecting request', err);
    next(err);
  }
});

// ───────────────── Public space serving (static) ─────────────────

// Serve static files for a space at /p/:slug/... (e.g. /p/demo-hud/index.html)
app.use('/p/:slug', portalsEmbedHeaders, async (req, res, next) => {
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

// Admin: list approved emails (allowlist)
// GET /api/admin/approved-users
app.get('/api/admin/approved-users', requireAdmin, async (req, res, next) => {
  try {
    const users = await loadApprovedUsers();
    res.json({ ok: true, users });
  } catch (err) {
    console.error('[allowlist] error listing approved users', err);
    next(err);
  }
});

// Admin: add an email to the allowlist
// POST /api/admin/approved-users
// body: { email }
app.post('/api/admin/approved-users', requireAdmin, async (req, res, next) => {
  try {
    const rawEmail = (req.body?.email || '').toString().trim().toLowerCase();

    if (!isValidEmail(rawEmail)) {
      return res.status(400).json({
        error: 'bad_email',
        message: 'Invalid email address',
      });
    }

    const list = await loadApprovedUsers();
    const exists = list.some(
      (u) => (u.email || '').trim().toLowerCase() === rawEmail
    );
    if (exists) {
      return res.status(409).json({
        error: 'already_approved',
        message: 'Email is already on the allowlist',
      });
    }

    const entry = {
      email: rawEmail,
      createdAt: new Date().toISOString(),
    };

    list.push(entry);
    await saveApprovedUsers(list);

    console.log('[allowlist] added', rawEmail);

    res.status(201).json({ ok: true, user: entry });
  } catch (err) {
    console.error('[allowlist] error adding approved user', err);
    next(err);
  }
});

// Admin: remove an email from the allowlist
// DELETE /api/admin/approved-users
// body: { email }
app.delete('/api/admin/approved-users', requireAdmin, async (req, res, next) => {
  try {
    const rawEmail = (req.body?.email || '').toString().trim().toLowerCase();

    if (!isValidEmail(rawEmail)) {
      return res.status(400).json({
        error: 'bad_email',
        message: 'Invalid email address',
      });
    }

    const list = await loadApprovedUsers();
    const next = list.filter(
      (u) => (u.email || '').trim().toLowerCase() !== rawEmail
    );

    if (next.length === list.length) {
      return res.status(404).json({
        error: 'not_found',
        message: 'Email not found on allowlist',
      });
    }

    await saveApprovedUsers(next);

    console.log('[allowlist] removed', rawEmail);

    res.json({ ok: true });
  } catch (err) {
    console.error('[allowlist] error removing approved user', err);
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

  // In prod, don't leak internal error strings to clients
  const safeMessage =
    NODE_ENV === 'production'
      ? (status >= 500 ? 'server_error' : (err.message || 'error'))
      : (err.message || 'server_error');

  res.status(status).json({ error: safeMessage });
});

// ───────────────── Start server ─────────────────

ensureSpacesRoot()
  .then(() => {
    app.listen(PORT, LISTEN_HOST, () => {
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
