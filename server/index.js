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
  MAX_PENDING_WORKSPACE_REQUESTS,
  FILES_META_PATH,
  FILE_VERSIONS_META_PATH,
  HISTORY_DIR_NAME,
  HISTORY_BLOBS_DIR_NAME,
  DISCORD_REQUIRED_ROLE_IDS,
  DISCORD_BOT_TOKEN,
  DISCORD_GUILD_ID,
  APP_HOSTNAME,
  PUBLIC_IFRAME_HOSTNAME,
  SESSION_MAX_AGE_DAYS,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_SCOPES,
  EMAIL_VERIFY_TOKENS_META_PATH,
  EMAIL_VERIFY_TOKEN_TTL_HOURS,
} from './config.js';

import { readJsonArray, writeJsonArray } from './stores/jsonStore.js';

// ───────────────── Host isolation (public /p host vs app /api host) ─────────────────

function safeParseUrl(str) {
  try {
    return new URL(String(str || ''));
  } catch {
    return null;
  }
}

function canonicalHost(host) {
  const h = String(host || '').trim().toLowerCase();
  if (!h) return '';
  return h
    .replace('127.0.0.1', 'localhost')
    .replace('[::1]', 'localhost');
}

function firstForwardedHost(v) {
  const raw = String(v || '');
  if (!raw) return '';
  return canonicalHost(raw.split(',')[0].trim());
}

const APP_URL = safeParseUrl(APP_BASE_URL);
const PUBLIC_URL = safeParseUrl(PUBLIC_IFRAME_BASE_URL);

const APP_HOST = canonicalHost(APP_URL?.host || '');
const PUBLIC_HOST = canonicalHost(PUBLIC_URL?.host || '');
const PUBLIC_ORIGIN = PUBLIC_URL?.origin ? String(PUBLIC_URL.origin).replace(/\/+$/, '') : '';

// ✅ Only enforce host isolation in production.
// In dev, Vite proxy + localhost/127.0.0.1 host normalization will otherwise trip the block.
const HOST_ISOLATION_ENABLED = Boolean(
  IS_PROD && APP_HOST && PUBLIC_HOST && APP_HOST !== PUBLIC_HOST
);

function getEffectiveHost(req) {
  const host = canonicalHost(req.get('host'));

  // Only trust x-forwarded-host if you explicitly enabled TRUST_PROXY
  if (TRUST_PROXY) {
    const xfHost = firstForwardedHost(req.get('x-forwarded-host'));
    return xfHost || host;
  }

  return host;
}

// ✅ Block ALL /api traffic on the public host (defense-in-depth)
function enforceApiOnAppHost(req, res, next) {
  if (!HOST_ISOLATION_ENABLED) return next();

  const h = getEffectiveHost(req);
  if (h === PUBLIC_HOST) {
    // stealthy: pretend API doesn't exist here
    return res.status(404).json({ error: 'not_found' });
  }

  next();
}

// ✅ Redirect /p/* accessed on the app host over to the public host
function enforcePublicHostForP(req, res, next) {
  if (!HOST_ISOLATION_ENABLED) return next();
  if (!PUBLIC_ORIGIN || !PUBLIC_HOST) return next();

  const h = getEffectiveHost(req);
  if (h === PUBLIC_HOST) return next();

  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(302, `${PUBLIC_ORIGIN}${req.originalUrl}`);
}


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
// Cookies
app.use(cookieParser());

function pickModel(requested) {
  if (requested && ALLOWED_GPT_MODELS.includes(requested)) {
    return requested;
  }
  return DEFAULT_GPT_MODEL;
}

// ───────────────── Billing / entitlement helpers ─────────────────

const PUBLIC_UNPAID_MODE = String(process.env.PUBLIC_UNPAID_MODE || 'paywall').toLowerCase();
// 'paywall' | '404'

const PAYWALL_CONTACT_EMAIL =
  process.env.PAYWALL_CONTACT_EMAIL ||
  WORKSPACE_ADMIN_EMAIL ||
  SENDGRID_FROM ||
  null;

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function getUserEmails(user) {
  const u = user || {};
  const out = [];

  // legacy fields
  if (u.email) out.push({ email: normalizeEmail(u.email), verifiedAt: u.emailVerifiedAt || null, source: 'legacy' });
  if (u.pendingEmail) out.push({ email: normalizeEmail(u.pendingEmail), verifiedAt: null, source: 'pending' });

  // new multi-email field (preferred)
  if (Array.isArray(u.emails)) {
    for (const e of u.emails) {
      const em = normalizeEmail(e?.email);
      if (!em) continue;
      out.push({
        email: em,
        verifiedAt: e?.verifiedAt || e?.verifiedAt === null ? e.verifiedAt : null,
        source: e?.source || 'emails',
      });
    }
  }

  // de-dupe
  const seen = new Set();
  const deduped = [];
  for (const e of out) {
    if (!e.email || seen.has(e.email)) continue;
    seen.add(e.email);
    deduped.push(e);
  }
  return deduped;
}

function userHasEmail(user, email) {
  const needle = normalizeEmail(email);
  if (!needle) return false;
  return getUserEmails(user).some((e) => e.email === needle);
}

function upsertUserEmail(user, email, patch = {}) {
  const u = user || {};
  const em = normalizeEmail(email);
  if (!em) return u;

  const list = Array.isArray(u.emails) ? [...u.emails] : [];

  const idx = list.findIndex((x) => normalizeEmail(x?.email) === em);

  const next = {
    email: em,
    verifiedAt: patch.verifiedAt ?? null,
    source: patch.source || null,
  };

  if (idx === -1) list.push(next);
  else list[idx] = { ...list[idx], ...next };

  return { ...u, emails: list };
}


function withUserDefaults(u) {
  const user = u || {};
  const billing = user.billing || {};
  return {
    ...user,
    status: user.status || 'active',
    lastLoginAt: user.lastLoginAt || null,
    billing: {
      paidUntil: billing.paidUntil || null,   // ISO string or null
      comped: Boolean(billing.comped),        // true/false
      wallet: billing.wallet || null,
      notes: billing.notes || null,
    },
  };
}

function isUserPaid(user) {
  const u = withUserDefaults(user);

  if (u.status !== 'active') return false;
  if (u.billing.comped) return true;

  if (!u.billing.paidUntil) return false;
  const t = new Date(u.billing.paidUntil).getTime();
  if (!Number.isFinite(t)) return false;

  return t > Date.now();
}

function requestWantsHtml(req) {
  const accept = String(req.get('accept') || '').toLowerCase();
  if (accept.includes('text/html')) return true;

  // If extension is empty, treat as html-ish
  const ext = (path.extname(req.path || '') || '').toLowerCase();
  return !ext || ext === '.html' || ext === '.htm';
}

function sendInertPublicResponse(req, res, slug) {
  // If you want stealth, force 404
  if (PUBLIC_UNPAID_MODE === '404' || !requestWantsHtml(req)) {
    return res.status(404).send('Not found');
  }

  const contactLine = PAYWALL_CONTACT_EMAIL
    ? `Contact <a href="mailto:${PAYWALL_CONTACT_EMAIL}" style="color:#22d3ee;text-decoration:none;">${PAYWALL_CONTACT_EMAIL}</a> to reactivate.`
    : `Contact the admin to reactivate.`;

  res.status(402); // Payment Required (works fine in practice)
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  return res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Overlay inactive</title>
  <style>
    html, body { height: 100%; margin: 0; }
    body {
      display: flex;
      align-items: center;
      justify-content: center;
      background: #020617;
      color: #e5e7eb;
      font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      padding: 16px;
      box-sizing: border-box;
    }
    .card {
      width: min(520px, 100%);
      border: 1px solid #1f2937;
      border-radius: 16px;
      background: rgba(15,23,42,0.9);
      padding: 16px;
    }
    .kicker {
      font-size: 11px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: #22d3ee;
      margin-bottom: 8px;
    }
    h1 { font-size: 16px; margin: 0 0 8px; }
    p { margin: 0 0 10px; color: #cbd5f5; font-size: 13px; line-height: 1.35; }
    code { color: #93c5fd; }
  </style>
</head>
<body>
  <div class="card">
    <div class="kicker">Portals iFrame Builder</div>
    <h1>Oh no! This page is inactive!</h1>
    <p>If you are the owner of this page, please contact the admin immediately.</p>
    <p>${contactLine}</p>
    <p style="opacity:.75;font-size:12px;margin-top:12px;">
      Space: <code>${String(slug || '')}</code>
    </p>
  </div>
</body>
</html>`);
}

async function findUserByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;

  const users = await loadUsersMeta();

  // 1) match in emails[] (new)
  for (const u of users) {
    if (!u) continue;
    if (Array.isArray(u.emails) && u.emails.some((e) => normalizeEmail(e?.email) === normalized)) {
      return u;
    }
  }

  // 2) fallback legacy match
  return users.find((x) => normalizeEmail(x?.email) === normalized) || null;
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
      (
        (s.ownerUserId && s.ownerUserId === user.id) ||
        (s.ownerEmail && s.ownerEmail.trim().toLowerCase() === normalizedEmail)
      )
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

// ───────────────── Per-file history + content-addressed blobs ─────────────────

function normalizeRelPosix(input) {
  const raw = String(input || '').replace(/\\/g, '/');
  const normalized = path.posix.normalize('/' + raw);
  const rel = normalized.replace(/^\/+/, '').replace(/\/+$/, '');
  return rel || '.'; // '.' means "space root"
}

function isHistoryRelPath(relPosix) {
  const rel = normalizeRelPosix(relPosix);
  return (
    rel === HISTORY_DIR_NAME ||
    rel.startsWith(HISTORY_DIR_NAME + '/') ||
    rel.includes('/' + HISTORY_DIR_NAME + '/')
  );
}

function assertNotHistoryPath(relPosix) {
  if (isHistoryRelPath(relPosix)) {
    throw Object.assign(new Error('reserved_path'), { status: 404 });
  }
}

function resolveLiveSpacePath(space, relPath) {
  const rel = normalizeRelPosix(relPath);
  assertNotHistoryPath(rel);
  return resolveSpacePath(space, rel);
}

function sha256Text(text) {
  return crypto.createHash('sha256').update(String(text || ''), 'utf8').digest('hex');
}

async function ensureHistoryDirs(space) {
  const blobsDir = resolveSpacePath(
    space,
    `${HISTORY_DIR_NAME}/${HISTORY_BLOBS_DIR_NAME}`
  );
  await fs.mkdir(blobsDir, { recursive: true });
  return blobsDir;
}

async function ensureBlobForText(space, sha256, text) {
  await ensureHistoryDirs(space);

  const blobPath = resolveSpacePath(
    space,
    `${HISTORY_DIR_NAME}/${HISTORY_BLOBS_DIR_NAME}/${sha256}`
  );

  try {
    // 'wx' => create if missing, fail if exists (prevents overwriting)
    await fs.writeFile(blobPath, String(text || ''), { encoding: 'utf8', flag: 'wx' });
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }

  return blobPath;
}

async function loadFilesMeta() {
  return readJsonArray(FILES_META_PATH);
}

async function saveFilesMeta(arr) {
  return writeJsonArray(FILES_META_PATH, arr);
}

async function loadFileVersionsMeta() {
  return readJsonArray(FILE_VERSIONS_META_PATH);
}

async function saveFileVersionsMeta(arr) {
  return writeJsonArray(FILE_VERSIONS_META_PATH, arr);
}

function findActiveFileRecordByPath(filesMeta, spaceSlug, relPath) {
  const p = normalizeRelPosix(relPath);
  return filesMeta.find(
    (f) =>
      f &&
      f.spaceSlug === spaceSlug &&
      f.deletedAt == null &&
      f.currentPath === p
  );
}

function findLatestVersionForFileAndSha(versionsMeta, spaceSlug, fileId, sha256) {
  // newest-last in the array means scan from end (cheaper)
  for (let i = versionsMeta.length - 1; i >= 0; i -= 1) {
    const v = versionsMeta[i];
    if (
      v &&
      v.spaceSlug === spaceSlug &&
      v.fileId === fileId &&
      v.sha256 === sha256
    ) {
      return v;
    }
  }
  return null;
}

/**
 * Core save pipeline:
 * - resolve/create fileId record
 * - (if needed) snapshot existing disk content as baseline "import" version
 * - ensure blob exists for new content
 * - write live file
 * - append version record ("save")
 * - update file record pointer to latest
 *
 * ✅ NEW: quota enforcement for BOTH live file and history blobs (preflight)
 */
async function saveTextFileWithHistory({ space, spaceSlug, relPath, content, userId }) {
  const nowIso = new Date().toISOString();
  const liveRel = normalizeRelPosix(relPath);

  // Block internal history writes via the normal file API
  assertNotHistoryPath(liveRel);

  const liveFullPath = resolveLiveSpacePath(space, liveRel);

  // Load both meta stores once
  const [filesMeta, versionsMeta] = await Promise.all([
    loadFilesMeta(),
    loadFileVersionsMeta(),
  ]);

  // Find or create file record (fileId)
  let fileRec = findActiveFileRecordByPath(filesMeta, spaceSlug, liveRel);
  if (!fileRec) {
    fileRec = {
      id: generateId('f_'),
      spaceSlug,
      currentPath: liveRel,
      createdAt: nowIso,
      updatedAt: nowIso,
      createdByUserId: userId || null,

      deletedAt: null,
      deletedByUserId: null,

      currentSha256: null,
      currentVersionId: null,
    };
    filesMeta.push(fileRec);
  }

  // Compute new sha
  const newText = String(content || '');
  const newSha = sha256Text(newText);

  // Read disk (if exists) so we can snapshot baseline before overwriting
  let diskText = null;
  let diskSha = null;
  try {
    diskText = await fs.readFile(liveFullPath, 'utf8');
    diskSha = sha256Text(diskText);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  const oldBytes = typeof diskText === 'string' ? Buffer.byteLength(diskText, 'utf8') : 0;
  const newBytes = Buffer.byteLength(newText, 'utf8');

  // Determine "current" sha if we have it (meta > disk)
  const effectiveCurrentSha = fileRec.currentSha256 || diskSha;

  // ✅ QUOTA PREFLIGHT (prevents bypass via text saves / history blobs)
  {
    const quotaMb = Number.isFinite(Number(space.quotaMb)) ? Number(space.quotaMb) : 100;
    const quotaBytes = quotaMb * 1024 * 1024;

    let currentBytes = 0;
    try {
      currentBytes = await getDirSizeBytes(space.dirPath);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      currentBytes = 0;
    }

    // Delta for the live file write
    // - if file exists: overwrite => delta = new - old
    // - if missing: create => delta = new
    const deltaLive = diskSha ? (newBytes - oldBytes) : newBytes;

    // Which blob SHAs might be written by the pipeline?
    // Important edge case: baseline SHA can equal new SHA (no double count).
    const blobCandidates = new Map(); // sha -> bytes

    const unchanged = effectiveCurrentSha && effectiveCurrentSha === newSha;

    if (unchanged) {
      // Only "adoption baseline" case writes a blob when meta is empty
      if (!fileRec.currentSha256) {
        // blob content equals the file content
        blobCandidates.set(newSha, newBytes);
      }
    } else {
      // Baseline blob (import) only when meta has no sha yet and disk exists
      if (!fileRec.currentSha256 && diskSha) {
        blobCandidates.set(diskSha, oldBytes);
      }
      // New content blob always
      blobCandidates.set(newSha, newBytes);
    }

    // Check which blobs already exist on disk
    let blobAdds = 0;
    for (const [sha, bytes] of blobCandidates.entries()) {
      const blobPath = resolveSpacePath(
        space,
        `${HISTORY_DIR_NAME}/${HISTORY_BLOBS_DIR_NAME}/${sha}`
      );

      const exists = await fs
        .stat(blobPath)
        .then((s) => !!s && s.isFile())
        .catch((err) => {
          if (err.code === 'ENOENT') return false;
          throw err;
        });

      if (!exists) blobAdds += bytes;
    }

    const projectedBytes = currentBytes + deltaLive + blobAdds;

    if (projectedBytes > quotaBytes) {
      const currentMb = +(currentBytes / (1024 * 1024)).toFixed(2);
      const projectedMb = +(projectedBytes / (1024 * 1024)).toFixed(2);

      throw Object.assign(new Error(`Save would exceed quota of ${quotaMb} MB.`), {
        status: 413,
        error: 'quota_exceeded',
        quotaMb,
        currentMb,
        projectedMb,
      });
    }
  }

  // If nothing changed, we usually don't create a new version
  if (effectiveCurrentSha && effectiveCurrentSha === newSha) {
    // If meta was empty (legacy adoption), finalize it with a baseline version record.
    if (!fileRec.currentSha256) {
      await ensureBlobForText(space, newSha, diskText ?? newText);

      const existing = findLatestVersionForFileAndSha(
        versionsMeta,
        spaceSlug,
        fileRec.id,
        newSha
      );

      const baseline = existing || {
        id: generateId('fv_'),
        fileId: fileRec.id,
        spaceSlug,
        sha256: newSha,
        action: diskSha ? 'import' : 'save',
        path: liveRel,
        createdAt: nowIso,
        createdByUserId: userId || null,
        sizeBytes: Buffer.byteLength(diskText ?? newText, 'utf8'),
      };

      if (!existing) versionsMeta.push(baseline);

      fileRec.currentSha256 = newSha;
      fileRec.currentVersionId = baseline.id;
      fileRec.updatedAt = nowIso;

      await Promise.all([saveFilesMeta(filesMeta), saveFileVersionsMeta(versionsMeta)]);
    }

    // Ensure the live file exists (edge case: meta says it exists but disk file missing)
    if (diskSha == null) {
      await fs.mkdir(path.dirname(liveFullPath), { recursive: true });
      await fs.writeFile(liveFullPath, newText, 'utf8');
    }

    return { ok: true, changed: false, fileId: fileRec.id, sha256: newSha, versionId: fileRec.currentVersionId };
  }

  // If we have disk content but no recorded sha yet, snapshot it as baseline ("import")
  if (!fileRec.currentSha256 && diskSha) {
    await ensureBlobForText(space, diskSha, diskText);

    const existingBaseline = findLatestVersionForFileAndSha(
      versionsMeta,
      spaceSlug,
      fileRec.id,
      diskSha
    );

    const baselineVer = existingBaseline || {
      id: generateId('fv_'),
      fileId: fileRec.id,
      spaceSlug,
      sha256: diskSha,
      action: 'import',
      path: liveRel,
      createdAt: nowIso,
      createdByUserId: userId || null,
      sizeBytes: Buffer.byteLength(diskText, 'utf8'),
    };

    if (!existingBaseline) versionsMeta.push(baselineVer);

    fileRec.currentSha256 = diskSha;
    fileRec.currentVersionId = baselineVer.id;
  }

  // Ensure blob exists for new content
  await ensureBlobForText(space, newSha, newText);

  // Write live file
  await fs.mkdir(path.dirname(liveFullPath), { recursive: true });
  await fs.writeFile(liveFullPath, newText, 'utf8');

  // Append version record
  const versionId = generateId('fv_');
  versionsMeta.push({
    id: versionId,
    fileId: fileRec.id,
    spaceSlug,
    sha256: newSha,
    action: 'save',
    path: liveRel,
    createdAt: nowIso,
    createdByUserId: userId || null,
    sizeBytes: Buffer.byteLength(newText, 'utf8'),
  });

  // Update file pointer
  fileRec.currentSha256 = newSha;
  fileRec.currentVersionId = versionId;
  fileRec.updatedAt = nowIso;

  await Promise.all([saveFilesMeta(filesMeta), saveFileVersionsMeta(versionsMeta)]);

  return { ok: true, changed: true, fileId: fileRec.id, sha256: newSha, versionId };
}

async function markFileDeletedInMeta({ spaceSlug, relPath, userId }) {
  const nowIso = new Date().toISOString();
  const p = normalizeRelPosix(relPath);
  assertNotHistoryPath(p);

  const filesMeta = await loadFilesMeta();
  const rec = findActiveFileRecordByPath(filesMeta, spaceSlug, p);
  if (!rec) return { ok: true, found: false };

  rec.deletedAt = nowIso;
  rec.deletedByUserId = userId || null;
  rec.updatedAt = nowIso;

  await saveFilesMeta(filesMeta);
  return { ok: true, found: true, fileId: rec.id };
}

async function renameFilePathInMeta({ spaceSlug, fromPath, toPath, userId }) {
  const nowIso = new Date().toISOString();
  const from = normalizeRelPosix(fromPath);
  const to = normalizeRelPosix(toPath);

  assertNotHistoryPath(from);
  assertNotHistoryPath(to);

  const filesMeta = await loadFilesMeta();

  // Find existing active record; if missing, create a new one so the renamed file has a fileId
  let rec = findActiveFileRecordByPath(filesMeta, spaceSlug, from);
  if (!rec) {
    rec = {
      id: generateId('f_'),
      spaceSlug,
      currentPath: from,
      createdAt: nowIso,
      updatedAt: nowIso,
      createdByUserId: userId || null,

      deletedAt: null,
      deletedByUserId: null,

      currentSha256: null,
      currentVersionId: null,
    };
    filesMeta.push(rec);
  }

  // Prevent path collision in meta (should be rare; disk check already prevents overwriting)
  const collision = findActiveFileRecordByPath(filesMeta, spaceSlug, to);
  if (collision && collision.id !== rec.id) {
    throw Object.assign(new Error('target_exists'), { status: 409 });
  }

  rec.currentPath = to;
  rec.updatedAt = nowIso;

  await saveFilesMeta(filesMeta);
  return { ok: true, fileId: rec.id };
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

  const ancestors = PORTALS_FRAME_ANCESTORS;
  const frameAncestors = ancestors || '*';

  // ✅ Keep ONLY what we need:
  // - allow embedding where you want (Unity / Portals / etc.)
  // - do NOT sandbox the whole document (breaks localStorage/fetch)
  res.setHeader('Content-Security-Policy', `frame-ancestors ${frameAncestors};`);

  // ✅ Don’t leak URLs (helps token/referrer hygiene generally)
  res.setHeader('Referrer-Policy', 'no-referrer');

  // ✅ Allow cross-site embedding (Unity host is a different site)
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  next();
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function makeOauthState() {
  return base64Url(crypto.randomBytes(24));
}

function buildDiscordAuthorizeUrl({ state }) {
  const p = new URLSearchParams();
  p.set('client_id', DISCORD_CLIENT_ID);
  p.set('redirect_uri', DISCORD_REDIRECT_URI);
  p.set('response_type', 'code');
  p.set('scope', DISCORD_SCOPES || 'identify email');
  p.set('state', state);
  // optional: forces the consent screen and avoids “silent weirdness” in dev
  p.set('prompt', 'consent');

  return `https://discord.com/oauth2/authorize?${p.toString()}`;
}


async function exchangeDiscordCodeForToken(code) {
  const body = new URLSearchParams();
  body.set('client_id', DISCORD_CLIENT_ID);
  body.set('client_secret', DISCORD_CLIENT_SECRET);
  body.set('grant_type', 'authorization_code');
  body.set('code', code);
  body.set('redirect_uri', DISCORD_REDIRECT_URI);

  const r = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const msg = data?.error_description || data?.error || 'discord_token_exchange_failed';
    throw Object.assign(new Error(msg), { status: 400, payload: data });
  }
  return data; // { access_token, token_type, expires_in, refresh_token?, scope }
}

async function fetchDiscordMe(accessToken) {
  const r = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  const data = await r.json().catch(() => null);
  if (!r.ok) {
    throw Object.assign(new Error('discord_me_failed'), { status: 400, payload: data });
  }
  return data; // {id, username, global_name, avatar, email?, verified? ...}
}

async function fetchDiscordGuildMember(discordUserId) {
  if (!DISCORD_BOT_TOKEN || !DISCORD_GUILD_ID) {
    throw Object.assign(new Error('discord_guild_check_misconfigured'), { status: 503 });
  }

  const r = await fetch(
    `https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`,
    { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
  );

  if (r.status === 404) return null;
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    throw Object.assign(new Error('discord_guild_member_fetch_failed'), { status: 400, payload: data });
  }
  return data;
}

function hasRequiredRole(member) {
  if (!Array.isArray(DISCORD_REQUIRED_ROLE_IDS) || DISCORD_REQUIRED_ROLE_IDS.length === 0) return true;
  const roles = Array.isArray(member?.roles) ? member.roles : [];
  return DISCORD_REQUIRED_ROLE_IDS.some((rid) => roles.includes(rid));
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
// ───────────────── Email verification meta ─────────────────

async function loadEmailVerifyTokens() {
  return readJsonArray(EMAIL_VERIFY_TOKENS_META_PATH);
}

async function saveEmailVerifyTokens(arr) {
  return writeJsonArray(EMAIL_VERIFY_TOKENS_META_PATH, arr);
}

function requireVerifiedEmail(req, res, next) {
  const email = String(req.user?.email || '').trim().toLowerCase();
  const verifiedAt = req.user?.emailVerifiedAt || null;

  if (!email || !isValidEmail(email) || !verifiedAt) {
    return res.status(403).json({
      error: 'email_not_verified',
      message: 'Please verify your email before continuing.',
    });
  }
  next();
}

function buildAppUrl(pathname = '/') {
  const base = String(APP_BASE_URL || '').replace(/\/+$/, '');
  return base + (pathname.startsWith('/') ? pathname : `/${pathname}`);
}

function buildVerifyEmailUrl(tokenId) {
  // This link should point to your API (in dev it’s localhost:5173 via proxy, which is fine)
  // Use APP_BASE_URL origin since that’s the browser-visible origin in your setup.
  const base = String(APP_BASE_URL || '').replace(/\/+$/, '');
  return `${base}/api/auth/email/verify?token=${encodeURIComponent(tokenId)}`;
}

async function sendVerifyEmailToUser({ toEmail, verifyUrl, isWelcome }) {
  if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
    console.log('[email-verify] dev mode: would send verify email to', toEmail, verifyUrl);
    return;
  }

  const subject = isWelcome
    ? 'Welcome to Portals iFrame Builder — verify your email'
    : 'Verify your email for Portals iFrame Builder';

  const html = `
  <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#020617; color:#e5e7eb; padding:24px;">
    <table width="100%" cellspacing="0" cellpadding="0" style="max-width:560px; margin:0 auto; background:#0b1120; border-radius:14px; border:1px solid #1f2937;">
      <tr>
        <td style="padding:18px 20px 12px; border-bottom:1px solid #1f2937;">
          <div style="font-size:11px; letter-spacing:0.18em; text-transform:uppercase; color:#22d3ee; margin-bottom:4px;">
            Portals iFrame Builder
          </div>
          <div style="font-size:16px; font-weight:600; color:#e5e7eb;">
            ${isWelcome ? 'Welcome — verify your email' : 'Verify your email'}
          </div>
        </td>
      </tr>
      <tr>
        <td style="padding:18px 20px 10px; font-size:13px; color:#cbd5f5;">
          <p style="margin:0 0 10px;">
            Click the button below to verify this email address so we can send workspace approvals and updates.
          </p>
        </td>
      </tr>
      <tr>
        <td style="padding:0 20px 18px;">
          <table cellspacing="0" cellpadding="0" style="margin:0 auto;">
            <tr>
              <td align="center" style="border-radius:999px; background:linear-gradient(to right,#22d3ee,#a855f7);">
                <a href="${verifyUrl}" style="display:inline-block; padding:10px 24px; font-size:13px; color:#020617; text-decoration:none; font-weight:600;">
                  Verify email
                </a>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:0 20px 18px;">
          <p style="margin:0 0 8px; font-size:12px; color:#9ca3af;">
            If the button doesn’t work, copy/paste:
          </p>
          <p style="margin:0; font-size:11px; color:#22d3ee; word-break:break-all;">
            <a href="${verifyUrl}" style="color:#22d3ee; text-decoration:none;">${verifyUrl}</a>
          </p>
        </td>
      </tr>
    </table>
  </div>`;

  const text = [
    'Verify your email for Portals iFrame Builder',
    '',
    `Verify: ${verifyUrl}`,
  ].join('\n');

  await sgMail.send({ to: toEmail, from: SENDGRID_FROM, subject, text, html });
  console.log('[email-verify] sent verify email to', toEmail);
}

//history helpers
function isValidSha256Hex(s) {
  return typeof s === 'string' && /^[a-f0-9]{64}$/.test(s);
}

function findFileRecordByIdAnyStatus(filesMeta, spaceSlug, fileId) {
  return filesMeta.find((f) => f && f.spaceSlug === spaceSlug && f.id === fileId) || null;
}

function findFileRecordByPathAnyStatus(filesMeta, spaceSlug, relPath) {
  const p = normalizeRelPosix(relPath);
  return filesMeta.find((f) => f && f.spaceSlug === spaceSlug && f.currentPath === p) || null;
}

function findActiveFileRecordByPathAnyStatusAllowed(filesMeta, spaceSlug, relPath) {
  // “active record” here means: the record exists (even if deleted) but path matches.
  // We still block internal history paths at the caller level.
  return findFileRecordByPathAnyStatus(filesMeta, spaceSlug, relPath);
}

function findVersionById(versionsMeta, spaceSlug, versionId) {
  return versionsMeta.find((v) => v && v.spaceSlug === spaceSlug && v.id === versionId) || null;
}

function listVersionsForFile(versionsMeta, spaceSlug, fileId) {
  const out = versionsMeta
    .filter((v) => v && v.spaceSlug === spaceSlug && v.fileId === fileId)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  return out;
}

async function readHistoryBlobText(space, sha256) {
  if (!isValidSha256Hex(sha256)) {
    throw Object.assign(new Error('bad_sha'), { status: 400 });
  }

  const blobPath = resolveSpacePath(
    space,
    `${HISTORY_DIR_NAME}/${HISTORY_BLOBS_DIR_NAME}/${sha256}`
  );

  const text = await fs.readFile(blobPath, 'utf8').catch((err) => {
    if (err.code === 'ENOENT') {
      throw Object.assign(new Error('blob_missing'), { status: 404 });
    }
    throw err;
  });

  return text;
}

/** DISCORD OAUTH LOGIN */
// ───────────────── Discord OAuth ─────────────────

app.get('/api/auth/discord/start', (req, res) => {
  if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
    return res.status(503).json({ error: 'discord_auth_disabled' });
  }

  // ✅ if an oauth_state already exists, don't generate a new one
  const existing = String(req.cookies?.oauth_state || '').trim();
  if (existing) {
    return res.redirect(302, buildDiscordAuthorizeUrl({ state: existing }));
  }

  const state = makeOauthState();
  res.cookie('oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 1000 * 60 * 10,
  });

  res.setHeader('Cache-Control', 'no-store');
  return res.redirect(302, buildDiscordAuthorizeUrl({ state }));
});

// /api/auth/discord/callback
app.get('/api/auth/discord/callback', async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');

  const appBase = String(APP_BASE_URL || '').replace(/\/+$/, '');
  const bounce = (code) => {
    if (!appBase) {
      return res
        .status(500)
        .json({ error: 'misconfigured', message: 'APP_BASE_URL is not set' });
    }
    return res.redirect(302, `${appBase}/login?error=${encodeURIComponent(code)}`);
  };

  try {
    const code = String(req.query?.code || '');
    const state = String(req.query?.state || '');
    const expected = String(req.cookies?.oauth_state || '');

    // Clear state cookie regardless
    res.clearCookie('oauth_state', {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
    });

    if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_REDIRECT_URI) {
      return bounce('discord_auth_disabled');
    }

    if (!code) return bounce('missing_code');
    if (!state || !expected || state !== expected) return bounce('bad_state');

    // Exchange code -> access token, then fetch /users/@me
    const token = await exchangeDiscordCodeForToken(code);
    const me = await fetchDiscordMe(token.access_token);

    const discordId = String(me.id || '');
    if (!discordId) return bounce('discord_no_id');

    // ✅ REQUIRED: guild membership + required role gate
    const member = await fetchDiscordGuildMember(discordId);
    if (!member) return bounce('not_in_guild');
    if (!hasRequiredRole(member)) return bounce('missing_required_role');

    // Optional email from Discord (may be null depending on scopes/user)
    const discordEmail = normalizeEmail(me.email || '');
    const discordEmailOk = !!discordEmail && isValidEmail(discordEmail);

    // Build a stable avatar URL for UI
    const avatarHash = me.avatar ? String(me.avatar) : '';
    const isAnimated = avatarHash.startsWith('a_');
    const avatarExt = isAnimated ? 'gif' : 'png';
    const discordAvatarUrl = avatarHash
      ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(
          discordId
        )}/${encodeURIComponent(avatarHash)}.${avatarExt}?size=128`
      : null;

    // Create or update user (Discord-first identity)
    const users = await loadUsersMeta();
    let user = users.find((u) => u && String(u.discordId || '') === discordId) || null;

    const nowIso = new Date().toISOString();

    if (!user) {
      user = {
        id: generateId('u_'),
        roles: ['user'],
        createdAt: nowIso,

        // legacy email fields remain supported
        email: null,
        emailVerifiedAt: null,
        pendingEmail: null,
        pendingEmailSetAt: null,

        // multi-email (new)
        emails: [],
        primaryEmail: null,
      };
      users.push(user);
    }

    // Update Discord identity snapshot
    user.discordId = discordId;
    user.discordUsername = me.username || null;
    user.discordGlobalName = me.global_name || null;
    user.discordAvatar = avatarHash || null;
    user.discordAvatarUrl = discordAvatarUrl;
    user.lastLoginAt = nowIso;

    user.discordGuildId = DISCORD_GUILD_ID || null;
    user.discordRoleIds = Array.isArray(member.roles) ? member.roles : [];

    user.billing = user.billing || {};
    user.status = user.status || 'active';
    user.updatedAt = nowIso;

    // ✅ Record Discord-linked email as an additional VERIFIED contact method.
    // Important: this does NOT force primary email; primary can be set via onboarding.
    if (discordEmailOk) {
      user = upsertUserEmail(user, discordEmail, {
        verifiedAt: nowIso,
        source: 'discord',
      });

      // If user has no primary email set at all, default primary to Discord email.
      // (If you want to force onboarding even in that case, delete this block.)
      const hasPrimary = !!String(user.email || user.primaryEmail || '').trim();
      if (!hasPrimary) {
        user.email = discordEmail;
        user.emailVerifiedAt = user.emailVerifiedAt || nowIso;
        user.primaryEmail = discordEmail;
      }
    }

    // Determine if the user has a verified primary email already
    const hasVerifiedEmail =
      !!user.emailVerifiedAt && isValidEmail(normalizeEmail(user.email));

    // ✅ Onboarding: if they don't have a verified primary, we can prefill pendingEmail
    // with the Discord email (optional convenience).
    if (!hasVerifiedEmail) {
      if (discordEmailOk) {
        user.pendingEmail = discordEmail;
        user.pendingEmailSetAt = user.pendingEmailSetAt || nowIso;
      } else {
        user.pendingEmail = user.pendingEmail || null;
        user.pendingEmailSetAt = user.pendingEmailSetAt || null;
      }
    }

    // Persist updated user record (important: user may have been reassigned by upsertUserEmail)
    // Because `user` is a reference to an object inside `users`, the array already sees updates.
    // Still, we ensure the object in the array is the same reference by re-finding and replacing if needed.
    const uIdx = users.findIndex((u) => u && u.id === user.id);
    if (uIdx !== -1) users[uIdx] = user;

    await saveUsersMeta(users);

    // Create session + set sid cookie
    const sessions = await loadSessionsMeta();
    const sid = generateId('sid_');

    sessions.push({
      id: sid,
      userId: user.id,
      // session email = primary email (legacy field)
      email: user.email || null,
      createdAt: nowIso,
      userAgent: req.get('user-agent') || null,
      ip: req.ip || null,
    });
    await saveSessionsMeta(sessions);

    res.cookie('sid', sid, {
      httpOnly: true,
      sameSite: 'lax',
      secure: IS_PROD,
      maxAge: 1000 * 60 * 60 * 24 * 30,
    });

    if (!appBase) {
      return res
        .status(500)
        .json({ error: 'misconfigured', message: 'APP_BASE_URL is not set' });
    }

    if (hasVerifiedEmail) {
      return res.redirect(302, `${appBase}/`);
    }

    return res.redirect(302, `${appBase}/login?step=onboarding`);
  } catch (err) {
    console.error('[discord] callback failed', err);
    return bounce('discord_oauth_failed');
  }
});

/**
 * Restore a historical version into a live file path.
 * - Keeps the same fileId (even if the file was deleted)
 * - Overwrites ONLY if restoring into the same file record’s currentPath
 * - Creates a new version record with action: "restore"
 *
 * ✅ NEW: quota enforcement for the live file write
 */
async function restoreFileVersionToLive({ space, spaceSlug, versionId, toPath, userId }) {
  const nowIso = new Date().toISOString();

  const [filesMeta, versionsMeta] = await Promise.all([
    loadFilesMeta(),
    loadFileVersionsMeta(),
  ]);

  const ver = findVersionById(versionsMeta, spaceSlug, versionId);
  if (!ver) throw Object.assign(new Error('version_not_found'), { status: 404 });

  const sha = ver.sha256;
  if (!isValidSha256Hex(sha)) throw Object.assign(new Error('bad_sha'), { status: 400 });

  // Read content from blob (source of truth)
  const content = await readHistoryBlobText(space, sha);
  const restoredBytes = Buffer.byteLength(String(content || ''), 'utf8');

  // Find or create file record by fileId (KEEP SAME FILEID)
  let fileRec = findFileRecordByIdAnyStatus(filesMeta, spaceSlug, ver.fileId);
  if (!fileRec) {
    fileRec = {
      id: ver.fileId,
      spaceSlug,
      currentPath: normalizeRelPosix(ver.path || 'restored.txt'),
      createdAt: nowIso,
      updatedAt: nowIso,
      createdByUserId: userId || null,
      deletedAt: null,
      deletedByUserId: null,
      currentSha256: null,
      currentVersionId: null,
    };
    filesMeta.push(fileRec);
  }

  // Pick destination path
  const destRel = normalizeRelPosix(
    toPath ? String(toPath) : (fileRec.currentPath || ver.path || 'restored.txt')
  );

  // Never allow restoring into history
  assertNotHistoryPath(destRel);

  // Block meta collision with a DIFFERENT active file record
  const collision = filesMeta.find(
    (f) =>
      f &&
      f.spaceSlug === spaceSlug &&
      f.deletedAt == null &&
      f.currentPath === destRel &&
      f.id !== fileRec.id
  );
  if (collision) throw Object.assign(new Error('target_exists'), { status: 409 });

  const destFullPath = resolveLiveSpacePath(space, destRel);

  // Disk overwrite rules:
  // - If the live file exists AND it’s the same file record’s currentPath (and not deleted), allow overwrite.
  // - Otherwise, block overwrite.
  const destStat = await fs
    .stat(destFullPath)
    .then((s) => (s && s.isFile() ? s : null))
    .catch((err) => {
      if (err.code === 'ENOENT') return null;
      throw err;
    });

  const diskExists = !!destStat;
  const isOverwritingSameLiveFile =
    diskExists && fileRec.deletedAt == null && fileRec.currentPath === destRel;

  if (diskExists && !isOverwritingSameLiveFile) {
    throw Object.assign(new Error('target_exists'), { status: 409 });
  }

  // ✅ QUOTA PREFLIGHT (restore only affects live file size; blob already exists)
  {
    const quotaMb = Number.isFinite(Number(space.quotaMb)) ? Number(space.quotaMb) : 100;
    const quotaBytes = quotaMb * 1024 * 1024;

    let currentBytes = 0;
    try {
      currentBytes = await getDirSizeBytes(space.dirPath);
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
      currentBytes = 0;
    }

    const oldBytes = destStat ? Number(destStat.size || 0) : 0;
    const deltaLive = diskExists ? (restoredBytes - oldBytes) : restoredBytes;

    const projectedBytes = currentBytes + deltaLive;

    if (projectedBytes > quotaBytes) {
      const currentMb = +(currentBytes / (1024 * 1024)).toFixed(2);
      const projectedMb = +(projectedBytes / (1024 * 1024)).toFixed(2);

      throw Object.assign(new Error(`Restore would exceed quota of ${quotaMb} MB.`), {
        status: 413,
        error: 'quota_exceeded',
        quotaMb,
        currentMb,
        projectedMb,
      });
    }
  }

  // Ensure blob exists (safe no-op if already there)
  await ensureBlobForText(space, sha, content);

  // Write live file
  await fs.mkdir(path.dirname(destFullPath), { recursive: true });
  await fs.writeFile(destFullPath, content, 'utf8');

  // Create restore version record (so restore itself is part of history)
  const newVersionId = generateId('fv_');
  versionsMeta.push({
    id: newVersionId,
    fileId: fileRec.id,
    spaceSlug,
    sha256: sha,
    action: 'restore',
    path: destRel,
    createdAt: nowIso,
    createdByUserId: userId || null,
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    restoredFromVersionId: ver.id,
  });

  // Update file pointer + undelete if needed
  fileRec.currentPath = destRel;
  fileRec.deletedAt = null;
  fileRec.deletedByUserId = null;
  fileRec.currentSha256 = sha;
  fileRec.currentVersionId = newVersionId;
  fileRec.updatedAt = nowIso;

  await Promise.all([saveFilesMeta(filesMeta), saveFileVersionsMeta(versionsMeta)]);

  return {
    ok: true,
    fileId: fileRec.id,
    path: destRel,
    sha256: sha,
    versionId: newVersionId,
    restoredFromVersionId: ver.id,
  };
}

// Attach req.user + req.session if sid cookie exists (with server-side expiry + allowlist enforcement)
async function sessionMiddleware(req, res, next) {
  try {
    const sid = req.cookies?.sid || null;
    if (!sid) return next();

    const sessions = await loadSessionsMeta();
    const session = sessions.find((s) => s.id === sid);
    if (!session) return next();

    // ✅ Server-side TTL (prevents stolen sid from working forever)
    const maxDaysRaw = Number(SESSION_MAX_AGE_DAYS);
    const maxDays = Number.isFinite(maxDaysRaw) && maxDaysRaw > 0 ? maxDaysRaw : 30;
    const ttlMs = maxDays * 24 * 60 * 60 * 1000;

    const createdAtMs = Date.parse(session.createdAt);
    const expired =
      !Number.isFinite(createdAtMs) || (Date.now() - createdAtMs) > ttlMs;

    // helper: revoke session + clear cookie
    const revoke = async (why) => {
      const nextSessions = sessions.filter((s) => s.id !== sid);
      if (nextSessions.length !== sessions.length) {
        await saveSessionsMeta(nextSessions);
      }
      res.clearCookie('sid', {
        httpOnly: true,
        sameSite: 'lax',
        secure: IS_PROD,
      });

      if (NODE_ENV === 'development') {
        console.log('[session] revoked', sid, 'reason=', why);
      }
    };

    if (expired) {
      await revoke('expired');
      return next();
    }

    const users = await loadUsersMeta();
    const user = users.find((u) => u.id === session.userId);
    if (!user) {
      await revoke('user_missing');
      return next();
    }

    const emailCandidate = String(user.email || user.pendingEmail || '').trim().toLowerCase();
if (!emailCandidate || !isValidEmail(emailCandidate)) {
  await revoke('missing_email');
  return next();
}

const status = String(user.status || 'active').toLowerCase();
if (status !== 'active') { await revoke('inactive_user'); return next(); }


    req.session = session;
    req.user = user;
    return next();
  } catch (err) {
    console.error('[session] error loading session', err);
    return next();
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

import { ADMIN_DISCORD_IDS } from './config.js';

function isAdminDiscordId(discordId) {
  const id = String(discordId || '').trim();
  if (!id) return false;
  return Array.isArray(ADMIN_DISCORD_IDS) && ADMIN_DISCORD_IDS.includes(id);
}

function requireAdminUser(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'not_logged_in' });

  const discordId = String(req.user?.discordId || '').trim();
  if (!discordId) return res.status(403).json({ error: 'forbidden' });

  // ADMIN_DISCORD_IDS must be an array of strings
  const ok = Array.isArray(ADMIN_DISCORD_IDS) && ADMIN_DISCORD_IDS.includes(discordId);
  if (!ok) return res.status(403).json({ error: 'forbidden' });

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

// Sessions (loads req.user if sid cookie present)
app.use(sessionMiddleware);

// Basic security headers
app.use(
  helmet({
    contentSecurityPolicy: false, // we’ll tune CSP later per domain
  })
);

// ───────────────── Host gating (production) ─────────────────
// Prevent the public iframe hostname from ever serving /api,
// and prevent the editor hostname from ever serving /p.
// This matters even if both hostnames hit the same Express server.

function hostEquals(req, expectedHostname) {
  if (!expectedHostname) return true;
  return String(req.hostname || '').toLowerCase() === String(expectedHostname).toLowerCase();
}

if (IS_PROD && APP_HOSTNAME && PUBLIC_IFRAME_HOSTNAME && APP_HOSTNAME !== PUBLIC_IFRAME_HOSTNAME) {
  app.use('/api', (req, res, next) => {
    if (!hostEquals(req, APP_HOSTNAME)) {
      return res.status(404).json({ error: 'not_found' });
    }
    next();
  });

  app.use('/p', (req, res, next) => {
    if (!hostEquals(req, PUBLIC_IFRAME_HOSTNAME)) {
      return res.status(404).send('Not found');
    }
    next();
  });

  console.log('[host-gate] /api allowed only on', APP_HOSTNAME);
  console.log('[host-gate] /p allowed only on', PUBLIC_IFRAME_HOSTNAME);
}

// ───────────────── Origin allowlists ─────────────────
// ───────────────── CORS (API only) ─────────────────

// Origins allowed to perform *write* actions (enforced separately by requireEditorOrigin)
const EDITOR_ORIGINS = new Set([
  'https://iframes.jawn.bot',
  'http://localhost:4100',
  'http://localhost:5173',
  'http://127.0.0.1:4100',
  'http://127.0.0.1:5173',
]);

// Origins allowed to call the API in PROD
const PROD_API_ORIGINS = new Set([
  'https://iframes.jawn.bot',
]);

function apiCorsOrigin(origin, cb) {
  // Allow non-browser / curl / health checks (no Origin header)
  if (!origin) return cb(null, true);

  // DEV: be permissive so Vite<->API split ports always works
  if (NODE_ENV !== 'production') return cb(null, true);

  // PROD: strict allowlist
  if (PROD_API_ORIGINS.has(origin)) return cb(null, true);

  console.warn('[cors] blocked origin:', origin);
  return cb(null, false);
}

const apiCors = cors({
  origin: apiCorsOrigin,
  credentials: true,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-token', 'Authorization'],
  maxAge: 86400,
});

// Apply to all /api routes
app.use('/api', enforceApiOnAppHost, apiCors);

// ✅ Express 5-safe preflight handler (no path-to-regexp parsing)
app.options(/^\/api\/.*$/, apiCors);


// ───────────────── Logs ─────────────────

// Redact magic token from any logged URL or Referer.
// This protects legacy links that still hit /api/auth/magic/verify?token=...
morgan.token('safe-url', (req) => redactMagicTokenFromUrl(req.originalUrl));
morgan.token('safe-ref', (req) => redactMagicTokenFromUrl(req.get('referer') || '-'));

if (NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  const combinedSafe =
    ':remote-addr - :remote-user [:date[clf]] ' +
    '":method :safe-url HTTP/:http-version" :status :res[content-length] ' +
    '":safe-ref" ":user-agent"';

  app.use(morgan(combinedSafe));
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


// In-process lock queue (single Node process)
// Prevents races like "same token consumed twice" under concurrent requests.
const __locks = new Map();

async function withInProcessLock(key, fn) {
  const prev = __locks.get(key) || Promise.resolve();

  let release;
  const current = new Promise((resolve) => (release = resolve));

  // Queue: next waits for prev, then waits for current to release
  const next = prev.then(() => current);
  __locks.set(key, next);

  await prev;

  try {
    return await fn();
  } finally {
    release();
    // Only delete if nobody queued after us
    if (__locks.get(key) === next) {
      __locks.delete(key);
    }
  }
}

// Shared helper: consumes a magic token, creates user+session, sets sid cookie.
async function consumeMagicTokenAndSetSessionCookie({ token, req, res }) {
  if (!token || typeof token !== 'string') {
    return { ok: false, status: 400, payload: { error: 'bad_token', message: 'Invalid token' } };
  }

  const tokens = await loadTokensMeta();
  const idx = tokens.findIndex((t) => t.id === token);
  if (idx === -1) {
    return { ok: false, status: 400, payload: { error: 'invalid_token', message: 'Token not found' } };
  }

  const t = tokens[idx];

  if (t.usedAt) {
    return { ok: false, status: 400, payload: { error: 'used_token', message: 'Token already used' } };
  }

  const now = new Date();
  if (new Date(t.expiresAt).getTime() < now.getTime()) {
    return { ok: false, status: 400, payload: { error: 'expired_token', message: 'Token expired' } };
  }

  // Find or create user
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
    secure: IS_PROD,
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  });

  return { ok: true, user };
}

app.all(/^\/api\/auth\/magic(\/.*)?$/, (req, res) => {
  return res.status(410).json({
    error: 'magic_link_disabled',
    message: 'Magic link login has been retired. Please sign in with Discord.',
  });
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
    const normalizedEmail = String(req.user.email || '').trim().toLowerCase();

    const mySpaces = spaces.filter((s) => {
      if (!s || s.status !== 'active') return false;
      if (s.ownerUserId && s.ownerUserId === req.user.id) return true;
      if (normalizedEmail && s.ownerEmail && String(s.ownerEmail).trim().toLowerCase() === normalizedEmail) return true;
      return false;
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      user: {
        id: req.user.id,

        // email + verification gate
        email: req.user.email || null,
        pendingEmail: req.user.pendingEmail || null,
        emailVerifiedAt: req.user.emailVerifiedAt || null,

        // discord identity for header pill
        discordId: req.user.discordId || null,
        discordUsername: req.user.discordUsername || null,
        discordGlobalName: req.user.discordGlobalName || null,
        discordAvatar: req.user.discordAvatar || null,
        discordAvatarUrl: req.user.discordAvatarUrl || null,

        roles: req.user.roles || [],
        status: req.user.status || 'active',
        lastLoginAt: req.user.lastLoginAt || null,
      },
      spaces: mySpaces,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/user/email/start
// body: { email }
app.post('/api/user/email/start', requireUser, requireEditorOrigin, async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const emailRaw = String(req.body?.email || '').trim().toLowerCase();
    if (!emailRaw || !isValidEmail(emailRaw)) {
      return res.status(400).json({ error: 'bad_email', message: 'Provide a valid email.' });
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const expiresAt = new Date(now.getTime() + EMAIL_VERIFY_TOKEN_TTL_HOURS * 60 * 60 * 1000).toISOString();

    const users = await loadUsersMeta();
    const idx = users.findIndex((u) => u && u.id === req.user.id);
    if (idx === -1) return res.status(404).json({ error: 'user_not_found' });

    // If they already verified this exact email, no-op.
    const currentEmail = String(users[idx].email || '').trim().toLowerCase();
    const alreadyVerified = !!users[idx].emailVerifiedAt && currentEmail === emailRaw;
    if (alreadyVerified) {
      return res.json({ ok: true, alreadyVerified: true });
    }

    // Set pending email (or if no email yet, still treat as pending until verified)
    users[idx] = {
      ...users[idx],
      pendingEmail: emailRaw,
      pendingEmailSetAt: nowIso,
      emailVerifySentAt: nowIso,
      updatedAt: nowIso,
    };

    // Revoke any old unused tokens for this user (keeps store clean)
    const tokens = await loadEmailVerifyTokens();
    for (const t of tokens) {
      if (t && t.userId === req.user.id && !t.usedAt && !t.revokedAt) {
        t.revokedAt = nowIso;
      }
    }

    const tokenId = generateId('ev_');
    tokens.push({
      id: tokenId,
      userId: req.user.id,
      email: emailRaw,
      createdAt: nowIso,
      expiresAt,
      usedAt: null,
      revokedAt: null,
    });

    await Promise.all([saveUsersMeta(users), saveEmailVerifyTokens(tokens)]);

    const isWelcome = !users[idx].welcomeEmailSentAt;
    const verifyUrl = buildVerifyEmailUrl(tokenId);

    await sendVerifyEmailToUser({ toEmail: emailRaw, verifyUrl, isWelcome });

    // Mark welcome sent the first time we ever send this “welcome/verify” email
    if (isWelcome) {
      const users2 = await loadUsersMeta();
      const idx2 = users2.findIndex((u) => u && u.id === req.user.id);
      if (idx2 !== -1 && !users2[idx2].welcomeEmailSentAt) {
        users2[idx2] = { ...users2[idx2], welcomeEmailSentAt: nowIso, updatedAt: nowIso };
        await saveUsersMeta(users2);
      }
    }

    return res.json({ ok: true, email: emailRaw, sent: true });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/email/verify?token=ev_...
app.get('/api/auth/email/verify', async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const tokenId = String(req.query?.token || '').trim();
    if (!tokenId || !tokenId.startsWith('ev_')) {
      return res.status(400).send('Bad token');
    }

    const tokens = await loadEmailVerifyTokens();
    const t = tokens.find((x) => x && x.id === tokenId) || null;
    if (!t || t.usedAt || t.revokedAt) {
      return res.status(400).send('Token invalid or already used.');
    }

    const now = new Date();
    if (Date.parse(t.expiresAt) < now.getTime()) {
      return res.status(400).send('Token expired.');
    }

    const users = await loadUsersMeta();
    const idx = users.findIndex((u) => u && u.id === t.userId);
    if (idx === -1) {
      return res.status(400).send('User not found.');
    }

    const nowIso = now.toISOString();
    const normalizedEmail = normalizeEmail(t.email);

    if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
      return res.status(400).send('Bad email.');
    }

    // ✅ Collision check: no OTHER user may already have this email verified
    for (const u of users) {
      if (!u || u.id === t.userId) continue;

      // Search in multi-email store first
      if (Array.isArray(u.emails)) {
        const hit = u.emails.find(
          (e) =>
            normalizeEmail(e?.email) === normalizedEmail &&
            !!e?.verifiedAt
        );
        if (hit) {
          return res
            .status(409)
            .send('This email is already verified on another account. Contact admin.');
        }
      }

      // Fallback legacy check
      const legacyEmail = normalizeEmail(u.email);
      if (
        legacyEmail === normalizedEmail &&
        !!u.emailVerifiedAt
      ) {
        return res
          .status(409)
          .send('This email is already verified on another account. Contact admin.');
      }
    }

    // ✅ Promote verified email to primary (admin comms) + store in emails[]
    let user = users[idx];

    user = {
      ...user,
      email: normalizedEmail,          // primary comms email (legacy field)
      primaryEmail: normalizedEmail,   // preferred future field
      emailVerifiedAt: nowIso,
      pendingEmail: null,
      pendingEmailSetAt: null,
      updatedAt: nowIso,
    };

    // Upsert into multi-email list as verified
    user = upsertUserEmail(user, normalizedEmail, {
      verifiedAt: nowIso,
      source: 'manual',
    });

    users[idx] = user;

    // Mark token as used
    const tidx = tokens.findIndex((x) => x && x.id === tokenId);
    tokens[tidx] = { ...tokens[tidx], usedAt: nowIso };

    await Promise.all([saveUsersMeta(users), saveEmailVerifyTokens(tokens)]);

    // Redirect back to app (you can style a “verified!” toast on this query param)
    return res.redirect(302, buildAppUrl('/login?verified=1'));
  } catch (err) {
    next(err);
  }
});


// POST /api/user/email/resend
app.post('/api/user/email/resend', requireUser, requireEditorOrigin, async (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const email = String(req.user?.pendingEmail || req.user?.email || '').trim().toLowerCase();
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'missing_email', message: 'No email on file to verify.' });
    }

    // If already verified, no-op
    if (req.user?.emailVerifiedAt && String(req.user.email || '').trim().toLowerCase() === email) {
      return res.json({ ok: true, alreadyVerified: true });
    }

    // Reuse /start logic by creating a fresh token + sending “verify” (not welcome)
    const now = new Date();
    const nowIso = now.toISOString();
    const expiresAt = new Date(now.getTime() + EMAIL_VERIFY_TOKEN_TTL_HOURS * 60 * 60 * 1000).toISOString();

    const tokens = await loadEmailVerifyTokens();
    for (const t of tokens) {
      if (t && t.userId === req.user.id && !t.usedAt && !t.revokedAt) t.revokedAt = nowIso;
    }

    const tokenId = generateId('ev_');
    tokens.push({ id: tokenId, userId: req.user.id, email, createdAt: nowIso, expiresAt, usedAt: null, revokedAt: null });
    await saveEmailVerifyTokens(tokens);

    const verifyUrl = buildVerifyEmailUrl(tokenId);
    await sendVerifyEmailToUser({ toEmail: email, verifyUrl, isWelcome: false });

    return res.json({ ok: true, sent: true });
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

// List history versions for a file (by fileId OR current path)
// GET /api/spaces/:slug/file/history?fileId=...&limit=...
// GET /api/spaces/:slug/file/history?path=...&limit=...
app.get('/api/spaces/:slug/file/history', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug } = req.params;
    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const fileId = (req.query?.fileId || '').toString().trim();
    const pathRaw = (req.query?.path || '').toString().trim();

    const limitRaw = Number(req.query?.limit || 100);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 100;

    const filesMeta = await loadFilesMeta();
    let fileRec = null;

    if (fileId) {
      fileRec = findFileRecordByIdAnyStatus(filesMeta, slug, fileId);
    } else if (pathRaw) {
      const p = normalizeRelPosix(pathRaw);
      if (isHistoryRelPath(p)) return res.status(404).json({ error: 'not_found' });
      fileRec = findActiveFileRecordByPathAnyStatusAllowed(filesMeta, slug, p);
    } else {
      return res.status(400).json({ error: 'missing_fileId_or_path' });
    }

    if (!fileRec) {
      return res.json({
        ok: true,
        tracked: false,
        file: null,
        versions: [],
        message: 'No history yet for this file (save it once to start tracking).',
      });
    }

    const versionsMeta = await loadFileVersionsMeta();
    const versions = listVersionsForFile(versionsMeta, slug, fileRec.id)
      .slice(0, limit)
      .map((v) => ({
        id: v.id,
        createdAt: v.createdAt,
        action: v.action,
        sha256: v.sha256,
        sizeBytes: v.sizeBytes,
        path: v.path,
        createdByUserId: v.createdByUserId || null,
        restoredFromVersionId: v.restoredFromVersionId || null,
      }));

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      ok: true,
      tracked: true,
      file: {
        id: fileRec.id,
        currentPath: fileRec.currentPath,
        deletedAt: fileRec.deletedAt || null,
        currentSha256: fileRec.currentSha256 || null,
        currentVersionId: fileRec.currentVersionId || null,
        createdAt: fileRec.createdAt,
        updatedAt: fileRec.updatedAt,
      },
      versions,
    });
  } catch (err) {
    next(err);
  }
});

// Fetch a single version’s content (from blob)
// GET /api/spaces/:slug/file/version?versionId=...
app.get('/api/spaces/:slug/file/version', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug } = req.params;
    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const versionId = (req.query?.versionId || '').toString().trim();
    if (!versionId) return res.status(400).json({ error: 'missing_versionId' });

    const versionsMeta = await loadFileVersionsMeta();
    const ver = findVersionById(versionsMeta, slug, versionId);
    if (!ver) return res.status(404).json({ error: 'version_not_found' });

    const content = await readHistoryBlobText(space, ver.sha256);

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      ok: true,
      version: {
        id: ver.id,
        fileId: ver.fileId,
        createdAt: ver.createdAt,
        action: ver.action,
        sha256: ver.sha256,
        sizeBytes: ver.sizeBytes,
        path: ver.path,
        createdByUserId: ver.createdByUserId || null,
        restoredFromVersionId: ver.restoredFromVersionId || null,
      },
      content,
    });
  } catch (err) {
    next(err);
  }
});

// Restore a version into the live file
// POST /api/spaces/:slug/file/restore
// body: { versionId, toPath? }
app.post('/api/spaces/:slug/file/restore', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug } = req.params;
    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });

    const { versionId, toPath } = req.body || {};
    if (!versionId || typeof versionId !== 'string') {
      return res.status(400).json({ error: 'missing_versionId' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const result = await restoreFileVersionToLive({
      space,
      spaceSlug: slug,
      versionId: versionId.trim(),
      toPath: toPath ? String(toPath) : null,
      userId: req.user?.id || null,
    });

    res.setHeader('Cache-Control', 'no-store');
    res.json(result);
  } catch (err) {
    if (err && err.status === 413 && err.error === 'quota_exceeded') {
      return res.status(413).json({
        error: 'quota_exceeded',
        message: err.message || 'Restore would exceed quota.',
        quotaMb: err.quotaMb,
        currentMb: err.currentMb,
        projectedMb: err.projectedMb,
      });
    }
    if (err.message === 'version_not_found') return res.status(404).json({ error: 'version_not_found' });
    if (err.message === 'blob_missing') return res.status(404).json({ error: 'blob_missing' });
    if (err.message === 'target_exists') return res.status(409).json({ error: 'target_exists' });
    next(err);
  }
});

// List files in a space directory
// GET /api/spaces/:slug/files?path=subdir/
app.get('/api/spaces/:slug/files', requireUser, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const slug = String(req.params.slug || '');
    const relPathRaw =
      typeof req.query.path === 'string' && req.query.path.trim()
        ? req.query.path.trim()
        : '.';

    const relPath = normalizeRelPosix(relPathRaw);

    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });

    // Never allow browsing internal history
    if (isHistoryRelPath(relPath)) {
      return res.status(404).json({ error: 'not_found' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const dirPath = resolveLiveSpacePath(space, relPath);

    let dirents;
    try {
      dirents = await fs.readdir(dirPath, { withFileTypes: true });
    } catch (err) {
      if (err.code === 'ENOENT') return res.json({ ok: true, path: relPathRaw, items: [] });
      if (err.code === 'ENOTDIR') return res.status(400).json({ error: 'not_a_directory' });
      throw err;
    }

    const itemsRaw = await Promise.all(
      dirents.map(async (d) => {
        // hide .history always (should only appear at root, but belt+suspenders)
        if (d.name === HISTORY_DIR_NAME) return null;

        const full = path.join(dirPath, d.name);
        try {
          const stat = await fs.stat(full);
          return { name: d.name, isDir: d.isDirectory(), size: stat.size, mtime: stat.mtime };
        } catch (err) {
          if (err.code === 'ENOENT') return null;
          throw err;
        }
      })
    );

    const items = itemsRaw.filter(Boolean);
    items.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ ok: true, path: relPathRaw, items });
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
    const relPathRaw = req.query.path;

    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });
    if (!relPathRaw) return res.status(400).json({ error: 'missing_path' });

    const relPath = normalizeRelPosix(relPathRaw);

    if (isHistoryRelPath(relPath)) {
      return res.status(404).json({ error: 'not_found' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const filePath = resolveLiveSpacePath(space, relPath);

    if (!isEditableTextFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    const content = await fs.readFile(filePath, 'utf8');
    res.json({ ok: true, path: relPathRaw, content });
  } catch (err) {
    if (err.code === 'ENOENT') return res.status(404).json({ error: 'file_not_found' });
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
    const { path: relPathRaw, content } = req.body || {};

    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });
    if (!relPathRaw || typeof content !== 'string') {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const relPath = normalizeRelPosix(relPathRaw);
    if (isHistoryRelPath(relPath)) {
      return res.status(404).json({ error: 'not_found' });
    }

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const livePath = resolveLiveSpacePath(space, relPath);

    if (!isEditableTextFile(livePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    const result = await saveTextFileWithHistory({
      space,
      spaceSlug: slug,
      relPath,
      content,
      userId: req.user?.id || null,
    });

    res.json({
      ok: true,
      path: relPathRaw,
      fileId: result.fileId,
      sha256: result.sha256,
      versionId: result.versionId,
      changed: result.changed,
    });
  } catch (err) {
    if (err && err.status === 413 && err.error === 'quota_exceeded') {
      return res.status(413).json({
        error: 'quota_exceeded',
        message: err.message || 'Save would exceed quota.',
        quotaMb: err.quotaMb,
        currentMb: err.currentMb,
        projectedMb: err.projectedMb,
      });
    }
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
    const { path: relPathRaw } = req.body || {};

    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });
    if (!relPathRaw) return res.status(400).json({ error: 'missing_path' });

    const relPath = normalizeRelPosix(relPathRaw);
    if (isHistoryRelPath(relPath)) return res.status(404).json({ error: 'not_found' });

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    const filePath = resolveLiveSpacePath(space, relPath);

    if (!isEditableTextFile(filePath)) {
      return res.status(400).json({ error: 'unsupported_type' });
    }

    await fs.unlink(filePath).catch((err) => {
      if (err.code === 'ENOENT') throw Object.assign(new Error('file_not_found'), { status: 404 });
      throw err;
    });

    await markFileDeletedInMeta({
      spaceSlug: slug,
      relPath,
      userId: req.user?.id || null,
    });

    res.json({ ok: true, path: relPathRaw });
  } catch (err) {
    if (err.message === 'file_not_found') return res.status(404).json({ error: 'file_not_found' });
    next(err);
  }
});

// Rename a file in a space
// POST /api/spaces/:slug/file/rename
// body: { from, to }
// Rename a file in a space
// POST /api/spaces/:slug/file/rename
// body: { from, to }
app.post('/api/spaces/:slug/file/rename', requireUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();
    const { slug } = req.params;
    const { from, to } = req.body || {};

    if (!isValidSlug(slug)) return res.status(400).json({ error: 'bad_slug' });
    if (!from || !to) return res.status(400).json({ error: 'missing_fields' });

    const space = await getUserSpaceBySlug(slug, req.user);
    if (!space) return res.status(404).json({ error: 'space_not_found' });

    // Treat these as relative POSIX paths (can include subdirs)
    const fromRel = normalizeRelPosix(String(from).trim());
    const toRel = normalizeRelPosix(String(to).trim());

    if (!fromRel || !toRel || fromRel === '.' || toRel === '.') {
      return res.status(400).json({ error: 'bad_name' });
    }

    // Hard block internal history
    if (isHistoryRelPath(fromRel) || isHistoryRelPath(toRel)) {
      return res.status(404).json({ error: 'not_found' });
    }

    // Extension sanity (still applies even with subdirs)
    const toBase = path.posix.basename(toRel);
    const ext = (toBase.split('.').pop() || '').toLowerCase();
    const allowedExts = ['html', 'htm', 'css', 'js', 'mjs', 'json', 'txt'];
    if (!allowedExts.includes(ext)) {
      return res.status(400).json({
        error: 'unsupported_type',
        message: 'Please use one of: .html, .css, .js, .json, .txt',
      });
    }

    const srcPath = resolveLiveSpacePath(space, fromRel);
    const destPath = resolveLiveSpacePath(space, toRel);

    // Ensure source exists
    const srcStat = await fs.stat(srcPath).catch((err) => {
      if (err.code === 'ENOENT') return null;
      throw err;
    });
    if (!srcStat || !srcStat.isFile()) {
      return res.status(404).json({ error: 'file_not_found' });
    }

    // Prevent overwriting
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

    // Ensure parent directory exists for dest
    await fs.mkdir(path.dirname(destPath), { recursive: true });

    // Rename on disk first (now safe because we already blocked .history)
    await fs.rename(srcPath, destPath);

    // Update meta path (fileId stays the same)
    await renameFilePathInMeta({
      spaceSlug: slug,
      fromPath: fromRel,
      toPath: toRel,
      userId: req.user?.id || null,
    });

    res.json({ ok: true, from: fromRel, to: toRel });
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
      const fullPath = resolveLiveSpacePath(space, filePath);
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

// ───────────────── Asset upload for a user space ─────────────────

// POST /api/spaces/:slug/upload
// multipart/form-data
// fields:
//   files[]  -> file inputs
//   subdir   -> optional subdirectory inside the space (e.g. "assets" or "assets/icons")
app.post('/api/spaces/:slug/upload', 
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
            // Never allow writing into internal history via uploads
      if (subdir && isHistoryRelPath(subdir)) {
        return res.status(400).json({ error: 'bad_subdir' });
      }

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
// body: { note?: string, suggestedSlug?: string, email?: string }
app.post('/api/spaces/request', requireUser, requireEditorOrigin, requireVerifiedEmail, async (req, res, next) => {
  try {
    const note = (req.body?.note || '').toString().trim();
    const suggestedSlugRaw = (req.body?.suggestedSlug || '').toString().trim();
    const emailFromBody = (req.body?.email || '').toString().trim().toLowerCase();

    // ✅ Enforce that we have an email on first request (for approvals/comms)
    // - Prefer stored user email
    // - Allow frontend to supply email once (stored to user record)
    const existingEmail = String(req.user?.email || '').trim().toLowerCase();
    const effectiveEmail = existingEmail || emailFromBody;

    if (!effectiveEmail || !isValidEmail(effectiveEmail)) {
      return res.status(400).json({
        error: 'missing_email',
        message: 'Email is required to request a workspace. Please provide a valid email address.',
      });
    }

    const now = new Date();
    const nowIso = now.toISOString();

    const requests = await loadWorkspaceRequests();
    const pending = requests.filter((r) => r.userId === req.user.id && r.status === 'pending');

    if (pending.length >= MAX_PENDING_WORKSPACE_REQUESTS) {
      return res.status(429).json({
        ok: false,
        error: 'too_many_pending_requests',
        message: `You already have ${pending.length} pending request(s).`,
        pending,
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
          message: 'Slug must be between 3 and 32 characters in length.',
        });
      }
      suggestedSlug = normalized;
    }

    // ✅ If user record is missing email, persist it now (first-time capture)
    if (!existingEmail) {
      const users = await loadUsersMeta();
      const idx = users.findIndex((u) => u && u.id === req.user.id);
      if (idx !== -1) {
        users[idx] = {
          ...users[idx],
          email: effectiveEmail,
          updatedAt: nowIso,
        };
        await saveUsersMeta(users);
        // keep req.user in sync for this request
        req.user.email = effectiveEmail;
      }
    }

    const reqRecord = {
      id: generateId('wr_'),
      userId: req.user.id,
      email: effectiveEmail,

      // ✅ Helpful Discord identity for admin review (even though email is required)
      discordId: req.user.discordId || null,
      discordUsername: req.user.discordUsername || null,
      discordGlobalName: req.user.discordGlobalName || null,

      status: 'pending', // 'pending' | 'approved' | 'rejected'
      note: note || null,
      suggestedSlug,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    requests.push(reqRecord);
    await saveWorkspaceRequests(requests);

    console.log('[workspace-requests] new request', {
      id: reqRecord.id,
      userId: reqRecord.userId,
      email: reqRecord.email,
      discordId: reqRecord.discordId,
      suggestedSlug,
    });

    try {
      await sendWorkspaceRequestNotificationToAdmin(reqRecord);
    } catch {
      // already logged inside helper; no-op here
    }

    return res.status(201).json({ ok: true, request: reqRecord });
  } catch (err) {
    console.error('[workspace-requests] error creating request', err);
    next(err);
  }
});


app.post('/api/admin/spaces', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug, quotaMb, ownerEmail, ownerUserId } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({
        error: 'bad_slug',
        message: 'Slug must be 3-32 chars of lowercase letters, digits, or hyphens.',
      });
    }

    const users = await loadUsersMeta();

    let resolvedOwnerUserId = null;
    let resolvedOwnerEmail = null;

    if (ownerUserId && String(ownerUserId).trim()) {
      const uid = String(ownerUserId).trim();
      const u = users.find((x) => x && x.id === uid) || null;
      if (!u) {
        return res.status(400).json({ error: 'bad_owner_user', message: 'ownerUserId does not match any user.' });
      }
      resolvedOwnerUserId = u.id;

      const em = String(u.email || '').trim().toLowerCase();
      const isVerified = !!u.emailVerifiedAt;
      resolvedOwnerEmail = (isVerified && em && isValidEmail(em)) ? em : null;
    } else if (ownerEmail != null && String(ownerEmail).trim() !== '') {
      const raw = String(ownerEmail).trim().toLowerCase();
      if (!isValidEmail(raw)) {
        return res.status(400).json({ error: 'bad_owner_email', message: 'ownerEmail must be a valid email address.' });
      }

      resolvedOwnerEmail = raw;
      const u = users.find((x) => String(x?.email || '').trim().toLowerCase() === resolvedOwnerEmail) || null;
      resolvedOwnerUserId = u ? u.id : null;
    }

    const spaces = await loadSpacesMeta();
    if (spaces.find((s) => s.slug === slug)) {
      return res.status(409).json({ error: 'space_exists', slug, message: 'slug already in use' });
    }

    const nowIso = new Date().toISOString();
    const dirPath = path.join(SPACES_ROOT, slug);

    if (fsSync.existsSync(dirPath)) {
      return res.status(409).json({ error: 'dir_exists', slug, message: 'directory already exists on disk' });
    }

    await fs.mkdir(dirPath, { recursive: true });

    const starterHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${slug} overlay</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html, body { margin:0; padding:0; height:100%; width:100%; background:transparent; font-family:system-ui,-apple-system,"Segoe UI",sans-serif; }
    body { display:flex; align-items:center; justify-content:center; background:rgba(15,23,42,.6); color:#e5e7eb; }
    .hud { padding:12px 16px; border-radius:10px; border:1px solid rgba(148,163,184,.7); background:rgba(15,23,42,.9); box-shadow:0 0 24px rgba(59,130,246,.35); }
    .hud-title { font-size:14px; letter-spacing:.12em; text-transform:uppercase; color:#93c5fd; margin:0 0 4px; }
    .hud-body { font-size:13px; margin:0; color:#e5e7eb; }
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
      id: slug,
      slug,
      dirPath,
      quotaMb: Number.isFinite(Number(quotaMb)) ? Number(quotaMb) : 100,
      createdAt: nowIso,
      updatedAt: nowIso,
      status: 'active',
      ownerEmail: resolvedOwnerEmail,
      ownerUserId: resolvedOwnerUserId,
    };

    spaces.push(spaceRecord);
    await saveSpacesMeta(spaces);

    // ✅ AUDIT
    await appendAdminAudit(req, {
      action: 'space_created',
      target: { type: 'space', slug, userId: resolvedOwnerUserId || null, email: resolvedOwnerEmail || null },
      detail: { quotaMb: spaceRecord.quotaMb },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.status(201).json({ ok: true, space: spaceRecord });
  } catch (err) {
    next(err);
  }
});


app.post('/api/admin/space-requests/:id/approve', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const rawSlug = (req.body?.slug || '').toString();

    let slug = rawSlug.trim().toLowerCase();
    slug = slug.replace(/[^a-z0-9-]/g, '-');
    slug = slug.replace(/-+/g, '-');
    slug = slug.replace(/^-+|-+$/g, '');

    if (!slug || !/^[a-z0-9-]{3,32}$/.test(slug)) {
      return res.status(400).json({ error: 'bad_slug', message: 'Slug must be between 3 and 32 characters in length.' });
    }

    const quotaMbRaw = req.body?.quotaMb;
    const quotaMb = Number.isFinite(Number(quotaMbRaw)) ? Number(quotaMbRaw) : 100;

    const requests = await loadWorkspaceRequests();
    const idx = requests.findIndex((r) => r.id === id);
    if (idx === -1) return res.status(404).json({ error: 'request_not_found' });

    const reqRecord = requests[idx];
    if (reqRecord.status !== 'pending') {
      return res.status(400).json({ error: 'bad_status', message: `Request is already ${reqRecord.status}` });
    }

    const users = await loadUsersMeta();
    const normReqEmail = String(reqRecord.email || '').trim().toLowerCase();

    const user =
      users.find((u) => u && u.id === reqRecord.userId) ||
      users.find((u) => u && String(u.email || '').trim().toLowerCase() === normReqEmail) ||
      users.find((u) => u && String(u.pendingEmail || '').trim().toLowerCase() === normReqEmail) ||
      null;

    if (!user) {
      return res.status(404).json({ error: 'user_not_found', message: 'User referenced in request could not be found' });
    }

    // Optional billing patch on approve
    const billingIn = req.body?.billing || null;
    if (billingIn && typeof billingIn === 'object') {
      user.billing = user.billing || {};
      if ('comped' in billingIn) user.billing.comped = Boolean(billingIn.comped);
      if ('paidUntil' in billingIn) user.billing.paidUntil = billingIn.paidUntil ? String(billingIn.paidUntil) : null;
      if ('tier' in billingIn) user.billing.tier = billingIn.tier ? String(billingIn.tier) : null;
      if ('notes' in billingIn) user.billing.notes = billingIn.notes ? String(billingIn.notes) : null;
    }

    user.status = 'active';
    user.updatedAt = new Date().toISOString();
    await saveUsersMeta(users);

    const spaces = await loadSpacesMeta();
    if (spaces.find((s) => s.slug === slug)) {
      return res.status(409).json({ error: 'space_exists', message: 'A space with this slug already exists.' });
    }

    const now = new Date().toISOString();
    const dirPath = path.join(SPACES_ROOT, slug);

    if (fsSync.existsSync(dirPath)) {
      return res.status(409).json({ error: 'dir_exists', message: 'Directory for this slug already exists.' });
    }

    await fs.mkdir(dirPath, { recursive: true });

    const starterHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${slug} overlay</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    html, body { margin:0; padding:0; height:100%; width:100%; background:transparent; font-family:system-ui,-apple-system,"Segoe UI",sans-serif; }
    body { display:flex; align-items:center; justify-content:center; background:rgba(15,23,42,.6); color:#e5e7eb; }
    .hud { padding:12px 16px; border-radius:10px; border:1px solid rgba(148,163,184,.7); background:rgba(15,23,42,.9); box-shadow:0 0 24px rgba(59,130,246,.35); }
    .hud-title { font-size:14px; letter-spacing:.12em; text-transform:uppercase; color:#93c5fd; margin:0 0 4px; }
    .hud-body { font-size:13px; margin:0; color:#e5e7eb; }
  </style>
</head>
<body>
  <div class="hud">
    <p class="hud-title">Space: ${slug}</p>
    <p class="hud-body">Your overlay is alive. Wire this up as an iFrame in your Portals space!</p>
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
      ownerEmail: (user.email || '').trim().toLowerCase() || null,
      ownerUserId: user.id,
    };

    spaces.push(spaceRecord);
    await saveSpacesMeta(spaces);

    const updatedReq = {
      ...reqRecord,
      status: 'approved',
      updatedAt: now,
      approvedAt: now,
      spaceSlug: slug,
    };
    requests[idx] = updatedReq;
    await saveWorkspaceRequests(requests);

    // ✅ AUDIT
    await appendAdminAudit(req, {
      action: 'space_request_approved',
      target: { type: 'workspace_request', id, userId: user.id, email: reqRecord.email || null, slug },
      detail: { quotaMb, billingPatch: billingIn || null },
    });

    try {
      await sendWorkspaceApprovalEmailToUser(user, spaceRecord, updatedReq);
    } catch {}

    return res.json({ ok: true, request: updatedReq, space: spaceRecord });
  } catch (err) {
    console.error('[workspace-requests] error approving request', err);
    next(err);
  }
});

app.post('/api/admin/space-requests/:id/reject', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const reason = (req.body?.reason || '').toString().trim();

    const requests = await loadWorkspaceRequests();
    const idx = requests.findIndex((r) => r.id === id);
    if (idx === -1) return res.status(404).json({ error: 'request_not_found' });

    const reqRecord = requests[idx];
    if (reqRecord.status !== 'pending') {
      return res.status(400).json({ error: 'bad_status', message: `Request is already ${reqRecord.status}` });
    }

    const nowIso = new Date().toISOString();
    const updatedReq = {
      ...reqRecord,
      status: 'rejected',
      updatedAt: nowIso,
      rejectedAt: nowIso,
      rejectReason: reason || null,
    };

    requests[idx] = updatedReq;
    await saveWorkspaceRequests(requests);

    // ✅ AUDIT
    await appendAdminAudit(req, {
      action: 'space_request_rejected',
      target: { type: 'workspace_request', id, userId: updatedReq.userId || null, email: updatedReq.email || null },
      detail: { reason: updatedReq.rejectReason || null },
    });

    // Best-effort email
    try {
      const users = await loadUsersMeta();
      const byId = users.find((u) => u && u.id === updatedReq.userId) || null;

      const normReqEmail = String(updatedReq.email || '').trim().toLowerCase();
      const byEmail =
        !byId && normReqEmail
          ? users.find((u) => (u?.email || '').trim().toLowerCase() === normReqEmail) || null
          : null;

      const user = byId || byEmail;

      if (user) {
        await sendWorkspaceRejectionEmailToUser(user, updatedReq);
      }
    } catch (mailErr) {
      console.error('[workspace-email] failed to send rejection email (non-fatal)', mailErr);
    }

    return res.json({ ok: true, request: updatedReq });
  } catch (err) {
    console.error('[workspace-requests] error rejecting request', err);
    next(err);
  }
});

function deepReplaceExactString(value, replaceMap) {
  if (value == null) return value;

  if (typeof value === 'string') {
    return replaceMap.has(value) ? replaceMap.get(value) : value;
  }

  if (Array.isArray(value)) {
    return value.map((v) => deepReplaceExactString(v, replaceMap));
  }

  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = deepReplaceExactString(v, replaceMap);
    }
    return out;
  }

  return value;
}


// Admin: list workspace requests
// GET /api/admin/space-requests?status=pending|approved|rejected|all
app.get('/api/admin/space-requests', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const statusRaw = String(req.query?.status || 'pending').trim().toLowerCase();

    const allowed = new Set(['pending', 'approved', 'rejected', 'all']);
    const status = allowed.has(statusRaw) ? statusRaw : 'pending';

    const requests = await loadWorkspaceRequests();

    const filtered =
      status === 'all'
        ? requests
        : requests.filter((r) => String(r?.status || '').toLowerCase() === status);

    // newest first (helps the admin UI)
    filtered.sort((a, b) => {
      const ta = Date.parse(a?.createdAt || '') || 0;
      const tb = Date.parse(b?.createdAt || '') || 0;
      return tb - ta;
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      status,
      requests: filtered,
    });
  } catch (err) {
    next(err);
  }
});

// Admin: search users (for creating spaces + emailing)
// GET /api/admin/users/search?q=...&limit=...
app.get('/api/admin/users/search', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const qRaw = String(req.query?.q || '').trim().toLowerCase();
    const limitRaw = Number(req.query?.limit || 25);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(100, limitRaw)) : 25;

    const users = await loadUsersMeta();
    const arr = Array.isArray(users) ? users.filter(Boolean) : [];

    const hayFor = (u) => {
      const parts = [
        u.id,
        u.email,
        u.pendingEmail,
        u.discordId,
        u.discordUsername,
        u.discordGlobalName,
      ].filter(Boolean);
      return parts.join(' ').toLowerCase();
    };

    let matches = arr;

    if (qRaw) {
      matches = arr.filter((u) => hayFor(u).includes(qRaw));
      // simple scoring: startsWith on username/globalName/id first
      matches.sort((a, b) => {
        const aU = String(a.discordUsername || '').toLowerCase();
        const bU = String(b.discordUsername || '').toLowerCase();
        const aG = String(a.discordGlobalName || '').toLowerCase();
        const bG = String(b.discordGlobalName || '').toLowerCase();
        const aId = String(a.id || '').toLowerCase();
        const bId = String(b.id || '').toLowerCase();

        const score = (u, U, G, Id) => {
          let s = 0;
          if (U && U.startsWith(qRaw)) s += 6;
          if (G && G.startsWith(qRaw)) s += 5;
          if (Id && Id.startsWith(qRaw)) s += 4;
          if (String(u.discordId || '').toLowerCase().startsWith(qRaw)) s += 3;
          if (String(u.email || '').toLowerCase().startsWith(qRaw)) s += 2;
          if (String(u.pendingEmail || '').toLowerCase().startsWith(qRaw)) s += 2;
          return s;
        };

        const sa = score(a, aU, aG, aId);
        const sb = score(b, bU, bG, bId);
        if (sb !== sa) return sb - sa;

        // newest login-ish first
        const ta = Date.parse(a.lastLoginAt || a.updatedAt || a.createdAt || '') || 0;
        const tb = Date.parse(b.lastLoginAt || b.updatedAt || b.createdAt || '') || 0;
        return tb - ta;
      });
    } else {
      // empty query: most recent first
      matches.sort((a, b) => {
        const ta = Date.parse(a.lastLoginAt || a.updatedAt || a.createdAt || '') || 0;
        const tb = Date.parse(b.lastLoginAt || b.updatedAt || b.createdAt || '') || 0;
        return tb - ta;
      });
    }

    const out = matches.slice(0, limit).map((u) => ({
      id: u.id,
      discordId: u.discordId || null,
      discordUsername: u.discordUsername || null,
      discordGlobalName: u.discordGlobalName || null,
      discordAvatarUrl: u.discordAvatarUrl || null,
      email: u.email || null,
      pendingEmail: u.pendingEmail || null,
      emailVerifiedAt: u.emailVerifiedAt || null,
      status: u.status || 'active',
      lastLoginAt: u.lastLoginAt || null,
      createdAt: u.createdAt || null,
    }));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, q: qRaw, users: out });
  } catch (err) {
    next(err);
  }
});

// ───────────────── Admin: Email Templates And Comms ─────────────────
app.post('/api/admin/users/:id/email', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
      return res.status(503).json({
        error: 'mail_disabled',
        message: 'SendGrid is not configured (missing SENDGRID_API_KEY or SENDGRID_FROM).',
      });
    }

    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const subject = String(req.body?.subject || '').trim();
    const text = req.body?.text != null ? String(req.body.text) : '';
    const html = req.body?.html != null ? String(req.body.html) : '';
    const from = String(req.body?.from || SENDGRID_FROM).trim();

    if (!subject) return res.status(400).json({ error: 'missing_subject' });
    if (!text && !html) {
      return res.status(400).json({ error: 'missing_body', message: 'Provide at least one of: text, html' });
    }

    const users = await loadUsersMeta();
    const user = users.find((u) => u && u.id === userId) || null;
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const to = String(user.email || user.pendingEmail || '').trim().toLowerCase();
    if (!to || !isValidEmail(to)) {
      return res.status(400).json({
        error: 'user_missing_email',
        message: 'User does not have a valid email on file.',
        user: {
          id: user.id,
          discordId: user.discordId || null,
          discordUsername: user.discordUsername || null,
          discordGlobalName: user.discordGlobalName || null,
          email: user.email || null,
          pendingEmail: user.pendingEmail || null,
        },
      });
    }

    await sgMail.send({
      to,
      from,
      subject,
      ...(text ? { text } : {}),
      ...(html ? { html } : {}),
    });

    // ✅ AUDIT (don’t store full body; store a safe preview + flags)
    await appendAdminAudit(req, {
      action: 'admin_email_sent',
      target: { type: 'user', id: userId, email: to },
      detail: {
        subject,
        from,
        mode: html ? 'html' : 'text',
        textPreview: text ? safeStr(text, 280) : null,
        htmlPreview: html ? safeStr(html, 280) : null,
      },
    });

    console.log('[admin-email] sent', { to, userId, subject });
    return res.json({ ok: true, to, userId });
  } catch (err) {
    console.error('[admin-email] failed', err);
    next(err);
  }
});

async function sendWelcomeEmailToUser(user) {
  if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
    console.log('[welcome-email] dev mode: would send welcome email to', user?.email);
    return;
  }

  const to = String(user?.email || '').trim().toLowerCase();
  if (!to || !isValidEmail(to)) {
    console.warn('[welcome-email] skipped (missing/invalid email)', { userId: user?.id, to });
    return;
  }

  const appBase = String(APP_BASE_URL || '').replace(/\/+$/, '');
  const subject = 'Welcome to Portals iFrame Builder';

  const text = [
    'Welcome to Portals iFrame Builder!',
    '',
    'You’re in.',
    'Next: request a workspace, then an admin will approve it.',
    '',
    `Open the app: ${appBase}/`,
    '',
    '— Portals iFrame Builder',
  ].join('\n');

  const html = `
    <div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#020617; color:#e5e7eb; padding:24px;">
      <table width="100%" cellspacing="0" cellpadding="0" style="max-width:520px;margin:0 auto;background:#0b1120;border-radius:14px;border:1px solid #1f2937;">
        <tr>
          <td style="padding:18px 20px 12px;border-bottom:1px solid #1f2937;">
            <div style="font-size:11px;letter-spacing:.18em;text-transform:uppercase;color:#22d3ee;margin-bottom:6px;">
              Portals iFrame Builder
            </div>
            <div style="font-size:16px;font-weight:600;color:#e5e7eb;">
              Welcome aboard
            </div>
          </td>
        </tr>
        <tr>
          <td style="padding:18px 20px;color:#cbd5f5;font-size:13px;line-height:1.4;">
            <p style="margin:0 0 10px;">You’ve successfully signed in.</p>
            <p style="margin:0 0 10px;">Next step: request a workspace. An admin will approve it and you’ll see it in your Spaces list.</p>
            <p style="margin:0;">
              <a href="${appBase}/" style="color:#22d3ee;text-decoration:none;">Open the app →</a>
            </p>
          </td>
        </tr>
      </table>
    </div>
  `;

  await sgMail.send({ to, from: SENDGRID_FROM, subject, text, html });
  console.log('[welcome-email] sent welcome email to', to);
}

const EMAIL_TEMPLATES_META_PATH =
  process.env.EMAIL_TEMPLATES_META_PATH ||
  path.join(path.dirname(USERS_META_PATH), 'emailTemplates.meta.json');

async function loadEmailTemplates() {
  return readJsonArray(EMAIL_TEMPLATES_META_PATH);
}
async function saveEmailTemplates(arr) {
  return writeJsonArray(EMAIL_TEMPLATES_META_PATH, arr);
}

function safeStr(x, max = 8000) {
  const s = x == null ? '' : String(x);
  return s.length > max ? s.slice(0, max) + '…' : s;
}

// Very small template renderer: replaces {{key}} with vars[key]
function renderTemplate(str, vars) {
  const s = String(str || '');
  return s.replace(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g, (_, key) => {
    const v = vars && Object.prototype.hasOwnProperty.call(vars, key) ? vars[key] : '';
    return v == null ? '' : String(v);
  });
}

function buildTemplateVars({ user, space, appBaseUrl, iframeBaseUrl }) {
  const u = user || {};
  const s = space || null;

  const handle =
    (u.discordUsername ? `@${u.discordUsername}` : '') ||
    (u.discordGlobalName ? String(u.discordGlobalName) : '') ||
    (u.email ? String(u.email) : '') ||
    (u.pendingEmail ? String(u.pendingEmail) : '') ||
    (u.id ? String(u.id) : '');

  const slug = s?.slug ? String(s.slug) : '';
  const iframeUrl = slug && iframeBaseUrl
    ? `${iframeBaseUrl}/p/${encodeURIComponent(slug)}/index.html`
    : (slug ? `/p/${encodeURIComponent(slug)}/index.html` : '');

  const paywallPreviewUrl = iframeUrl
    ? (iframeUrl.includes('?') ? `${iframeUrl}&paywallPreview=1` : `${iframeUrl}?paywallPreview=1`)
    : '';

  return {
    // user
    userId: u.id || '',
    email: u.email || '',
    pendingEmail: u.pendingEmail || '',
    discordId: u.discordId || '',
    discordUsername: u.discordUsername || '',
    discordGlobalName: u.discordGlobalName || '',
    handle,

    // app + iframe
    appUrl: appBaseUrl || '',
    iframeBase: iframeBaseUrl || '',
    slug,
    iframeUrl,
    paywallPreviewUrl,

    // misc
    nowIso: new Date().toISOString(),
  };
}

// GET list
app.get('/api/admin/email-templates', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const templates = await loadEmailTemplates().catch(() => []);
    const list = Array.isArray(templates) ? templates.filter(Boolean) : [];

    // newest first
    list.sort((a, b) => (Date.parse(b.updatedAt || b.createdAt || '') || 0) - (Date.parse(a.updatedAt || a.createdAt || '') || 0));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, templates: list });
  } catch (err) {
    next(err);
  }
});

// POST create
app.post('/api/admin/email-templates', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const name = String(req.body?.name || '').trim();
    const subject = String(req.body?.subject || '').trim();
    const modeRaw = String(req.body?.mode || 'text').trim().toLowerCase(); // text|html|both
    const text = req.body?.text != null ? String(req.body.text) : '';
    const html = req.body?.html != null ? String(req.body.html) : '';

    if (!name) return res.status(400).json({ error: 'missing_name' });
    if (!subject) return res.status(400).json({ error: 'missing_subject' });

    const mode = (modeRaw === 'html' || modeRaw === 'both') ? modeRaw : 'text';

    if (mode === 'text' && !text.trim()) return res.status(400).json({ error: 'missing_text' });
    if (mode === 'html' && !html.trim()) return res.status(400).json({ error: 'missing_html' });
    if (mode === 'both' && !text.trim() && !html.trim()) return res.status(400).json({ error: 'missing_body' });

    const nowIso = new Date().toISOString();

    const templates = await loadEmailTemplates().catch(() => []);
    const arr = Array.isArray(templates) ? templates : [];

    const rec = {
      id: generateId('et_'),
      name,
      subject,
      mode,
      text,
      html,
      createdAt: nowIso,
      updatedAt: nowIso,
      createdByUserId: req.user?.id || null,
      updatedByUserId: req.user?.id || null,
    };

    arr.push(rec);
    await saveEmailTemplates(arr);

    await appendAdminAudit(req, {
      action: 'email_template_created',
      target: { type: 'email_template', id: rec.id },
      detail: { name: rec.name, mode: rec.mode },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.status(201).json({ ok: true, template: rec });
  } catch (err) {
    next(err);
  }
});

// POST update
app.post('/api/admin/email-templates/:id', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ error: 'bad_id' });

    const templates = await loadEmailTemplates().catch(() => []);
    const arr = Array.isArray(templates) ? templates : [];

    const idx = arr.findIndex((t) => t && t.id === id);
    if (idx === -1) return res.status(404).json({ error: 'template_not_found' });

    const prev = arr[idx];

    const name = ('name' in (req.body || {})) ? String(req.body.name || '').trim() : prev.name;
    const subject = ('subject' in (req.body || {})) ? String(req.body.subject || '').trim() : prev.subject;
    const modeRaw = ('mode' in (req.body || {})) ? String(req.body.mode || '').trim().toLowerCase() : prev.mode;
    const text = ('text' in (req.body || {})) ? String(req.body.text || '') : prev.text;
    const html = ('html' in (req.body || {})) ? String(req.body.html || '') : prev.html;

    if (!name) return res.status(400).json({ error: 'missing_name' });
    if (!subject) return res.status(400).json({ error: 'missing_subject' });

    const mode = (modeRaw === 'html' || modeRaw === 'both') ? modeRaw : 'text';

    if (mode === 'text' && !text.trim()) return res.status(400).json({ error: 'missing_text' });
    if (mode === 'html' && !html.trim()) return res.status(400).json({ error: 'missing_html' });
    if (mode === 'both' && !text.trim() && !html.trim()) return res.status(400).json({ error: 'missing_body' });

    const nowIso = new Date().toISOString();

    const nextRec = {
      ...prev,
      name,
      subject,
      mode,
      text,
      html,
      updatedAt: nowIso,
      updatedByUserId: req.user?.id || null,
    };

    arr[idx] = nextRec;
    await saveEmailTemplates(arr);

    await appendAdminAudit(req, {
      action: 'email_template_updated',
      target: { type: 'email_template', id },
      detail: { name: nextRec.name, mode: nextRec.mode },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, template: nextRec });
  } catch (err) {
    next(err);
  }
});

// DELETE
app.delete('/api/admin/email-templates/:id', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ error: 'bad_id' });

    const templates = await loadEmailTemplates().catch(() => []);
    const arr = Array.isArray(templates) ? templates : [];

    const idx = arr.findIndex((t) => t && t.id === id);
    if (idx === -1) return res.status(404).json({ error: 'template_not_found' });

    const removed = arr[idx];
    const nextArr = arr.filter((t) => t && t.id !== id);

    await saveEmailTemplates(nextArr);

    await appendAdminAudit(req, {
      action: 'email_template_deleted',
      target: { type: 'email_template', id },
      detail: { name: removed?.name || null },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, deleted: id });
  } catch (err) {
    next(err);
  }
});

// POST send using template
// body: { userId, spaceSlug? }
// - picks recipient from user.email or user.pendingEmail
// - renders {{vars}} into subject/text/html
app.post('/api/admin/email-templates/:id/send', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    if (!SENDGRID_API_KEY || !SENDGRID_FROM) {
      return res.status(503).json({
        error: 'mail_disabled',
        message: 'SendGrid is not configured (missing SENDGRID_API_KEY or SENDGRID_FROM).',
      });
    }

    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ error: 'bad_id' });

    const userId = String(req.body?.userId || '').trim();
    if (!userId) return res.status(400).json({ error: 'missing_userId' });

    const spaceSlug = req.body?.spaceSlug != null ? String(req.body.spaceSlug).trim() : '';

    const templates = await loadEmailTemplates().catch(() => []);
    const tpl = (Array.isArray(templates) ? templates : []).find((t) => t && t.id === id) || null;
    if (!tpl) return res.status(404).json({ error: 'template_not_found' });

    const users = await loadUsersMeta();
    const user = (Array.isArray(users) ? users : []).find((u) => u && u.id === userId) || null;
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    const to = String(user.email || user.pendingEmail || '').trim().toLowerCase();
    if (!to || !isValidEmail(to)) {
      return res.status(400).json({
        error: 'user_missing_email',
        message: 'User does not have a valid email on file.',
      });
    }

    let space = null;
    if (spaceSlug) {
      const spaces = await loadSpacesMeta();
      space = (Array.isArray(spaces) ? spaces : []).find((s) => s && s.slug === spaceSlug && s.status === 'active') || null;
    }

    const appBaseUrl = String(APP_BASE_URL || '').replace(/\/+$/, '');
    const iframeBaseUrl = String(PUBLIC_IFRAME_BASE_URL || '').replace(/\/+$/, '');

    const vars = buildTemplateVars({ user, space, appBaseUrl, iframeBaseUrl });

    const subject = renderTemplate(tpl.subject, vars);
    const text = tpl.mode === 'text' || tpl.mode === 'both' ? renderTemplate(tpl.text, vars) : '';
    const html = tpl.mode === 'html' || tpl.mode === 'both' ? renderTemplate(tpl.html, vars) : '';

    if (!subject.trim()) return res.status(400).json({ error: 'rendered_subject_empty' });
    if (tpl.mode === 'text' && !text.trim()) return res.status(400).json({ error: 'rendered_text_empty' });
    if (tpl.mode === 'html' && !html.trim()) return res.status(400).json({ error: 'rendered_html_empty' });

    await sgMail.send({
      to,
      from: SENDGRID_FROM,
      subject,
      ...(text ? { text } : {}),
      ...(html ? { html } : {}),
    });

    await appendAdminAudit(req, {
      action: 'email_template_sent',
      target: { type: 'user', id: userId, email: to },
      detail: {
        templateId: id,
        templateName: tpl.name || null,
        mode: tpl.mode,
        spaceSlug: spaceSlug || null,
        subject: safeStr(subject, 200),
        textPreview: text ? safeStr(text, 280) : null,
        htmlPreview: html ? safeStr(html, 280) : null,
      },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, to, userId, templateId: id, mode: tpl.mode });
  } catch (err) {
    next(err);
  }
});


// ───────────────── Public space serving (static) ─────────────────

// Serve static files for a space at /p/:slug/... (e.g. /p/demo-hud/index.html)
app.use('/p/:slug', enforcePublicHostForP, portalsEmbedHeaders, async (req, res, next) => {
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

// ✅ If this space belongs to a user, enforce billing here.
// If ownerEmail is null (admin-created “public marketing space”), we skip gating.
if (space.ownerEmail) {
  // ✅ Paywall preview mode (admin UX) — shows what unpaid users see.
  // Safe to expose publicly; it doesn’t change data, it just renders the inert page for this request.
  const paywallPreview =
    String(req.query?.paywallPreview || '').trim() === '1' ||
    String(req.query?.paywallPreview || '').trim().toLowerCase() === 'true';

  if (paywallPreview) {
    return sendInertPublicResponse(req, res, slug);
  }

  const ownerUser = await findUserByEmail(space.ownerEmail);

  // If we can’t find the owner user record, treat it as inactive (safer)
  if (!ownerUser || !isUserPaid(ownerUser)) {
    return sendInertPublicResponse(req, res, slug);
  }
}

    // Never serve internal history, even if it exists on disk
    const reqRel = normalizeRelPosix(req.path || '');
    if (isHistoryRelPath(reqRel)) {
      return res.status(404).send('Not found');
    }

    // Serve the actual files
    const staticMiddleware = express.static(space.dirPath, {
      fallthrough: false,
      setHeaders(res /*, filePath */) {
        // Avoid stale overlays while you’re iterating
        res.setHeader('Cache-Control', 'no-store');
      },
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

app.use('/api/auth/status', (req, res, next) => {
  console.log('[debug] hit /api/auth/status', {
    host: req.get('host'),
    origin: req.get('origin'),
    hasUser: !!req.user,
    env: NODE_ENV,
  });
  next();
});

// Admin: search users (for admin UI pickers)
// GET /api/admin/users?q=...&limit=...
app.get('/api/admin/users', requireAdmin, async (req, res, next) => {
  try {
    const q = String(req.query?.q || '').trim().toLowerCase();
    const limitRaw = Number(req.query?.limit || 25);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(100, limitRaw)) : 25;

    const users = await loadUsersMeta();

    const matches = (users || [])
      .filter(Boolean)
      .filter((u) => {
        if (!q) return true;
        const email = String(u.email || '').toLowerCase();
        const pending = String(u.pendingEmail || '').toLowerCase();
        const du = String(u.discordUsername || '').toLowerCase();
        const dg = String(u.discordGlobalName || '').toLowerCase();
        const did = String(u.discordId || '').toLowerCase();
        return (
          email.includes(q) ||
          pending.includes(q) ||
          du.includes(q) ||
          dg.includes(q) ||
          did.includes(q)
        );
      })
      .slice(0, limit)
      .map((u) => ({
        id: u.id,
        email: u.email || null,
        pendingEmail: u.pendingEmail || null,
        emailVerifiedAt: u.emailVerifiedAt || null,
        discordId: u.discordId || null,
        discordUsername: u.discordUsername || null,
        discordGlobalName: u.discordGlobalName || null,
        discordAvatar: u.discordAvatar || null,
        discordAvatarUrl: u.discordAvatarUrl || null,
        status: u.status || 'active',
        lastLoginAt: u.lastLoginAt || null,
        createdAt: u.createdAt || null,
      }));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, users: matches });
  } catch (err) {
    next(err);
  }
});


// ───────────────── Admin Billing / Entitlements ─────────────────

function safeIsoOrNull(v) {
  if (v == null) return null;
  const s = String(v).trim();
  if (!s) return null;
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}

function daysBetween(nowMs, futureMs) {
  const d = (futureMs - nowMs) / (24 * 60 * 60 * 1000);
  return Math.ceil(d);
}

function computeEntitlement(user) {
  const u = withUserDefaults(user);
  const now = Date.now();

  const paidUntilMs = u.billing?.paidUntil ? Date.parse(u.billing.paidUntil) : NaN;
  const hasValidPaidUntil = Number.isFinite(paidUntilMs);

  const isComped = !!u.billing?.comped;
  const isActive = String(u.status || 'active').toLowerCase() === 'active';

  const isPaid = isActive && (isComped || (hasValidPaidUntil && paidUntilMs > now));
  const daysLeft = hasValidPaidUntil ? daysBetween(now, paidUntilMs) : null;

  const expiringSoon =
    isActive &&
    !isComped &&
    hasValidPaidUntil &&
    paidUntilMs > now &&
    daysLeft != null &&
    daysLeft <= 7;

  const expired =
    isActive &&
    !isComped &&
    hasValidPaidUntil &&
    paidUntilMs <= now;

  return {
    isActive,
    isComped,
    isPaid,
    paidUntil: u.billing?.paidUntil || null,
    daysLeft,
    expiringSoon,
    expired,
    tier: u.billing?.tier || null,
    notes: u.billing?.notes || null,
  };
}

// GET /api/admin/billing/overview
// Returns users + entitlement classification + their spaces + preview URLs
app.get('/api/admin/billing/overview', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const users = await loadUsersMeta();
    const spaces = await loadSpacesMeta();

    const publicBase = String(PUBLIC_IFRAME_BASE_URL || '').replace(/\/+$/, '');
    const appBase = String(APP_BASE_URL || '').replace(/\/+$/, '');

    const byUserIdSpaces = new Map();
    for (const s of (spaces || [])) {
      if (!s || s.status !== 'active') continue;
      const ownerId = s.ownerUserId || null;
      if (!ownerId) continue;
      if (!byUserIdSpaces.has(ownerId)) byUserIdSpaces.set(ownerId, []);
      byUserIdSpaces.get(ownerId).push(s);
    }

    const outUsers = (users || []).filter(Boolean).map((u) => {
      const ent = computeEntitlement(u);
      const mySpaces = byUserIdSpaces.get(u.id) || [];

      const spacesOut = mySpaces.map((s) => {
        const iframeUrl = publicBase
          ? `${publicBase}/p/${encodeURIComponent(s.slug)}/index.html`
          : `/p/${encodeURIComponent(s.slug)}/index.html`;

        const paywallPreviewUrl = iframeUrl.includes('?')
          ? `${iframeUrl}&paywallPreview=1`
          : `${iframeUrl}?paywallPreview=1`;

        return {
          slug: s.slug,
          quotaMb: s.quotaMb ?? null,
          iframeUrl,
          paywallPreviewUrl,
        };
      });

      return {
        id: u.id,
        status: u.status || 'active',
        lastLoginAt: u.lastLoginAt || null,

        discordId: u.discordId || null,
        discordUsername: u.discordUsername || null,
        discordGlobalName: u.discordGlobalName || null,
        discordAvatarUrl: u.discordAvatarUrl || null,

        email: u.email || null,
        pendingEmail: u.pendingEmail || null,
        emailVerifiedAt: u.emailVerifiedAt || null,

        billing: {
          comped: !!u.billing?.comped,
          paidUntil: u.billing?.paidUntil || null,
          tier: u.billing?.tier || null,
          notes: u.billing?.notes || null,
        },

        entitlement: ent,
        spaces: spacesOut,

        // convenience links
        adminAppUrl: appBase ? `${appBase}/admin` : '/admin',
      };
    });

    // Useful server-side buckets
    const comped = outUsers.filter((u) => u.entitlement.isComped && u.entitlement.isActive);
    const paid = outUsers.filter((u) => !u.entitlement.isComped && u.entitlement.isPaid);
    const unpaid = outUsers.filter((u) => !u.entitlement.isPaid && u.entitlement.isActive);
    const expiringSoon = outUsers.filter((u) => u.entitlement.expiringSoon);
    const inactive = outUsers.filter((u) => !u.entitlement.isActive);

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      counts: {
        total: outUsers.length,
        comped: comped.length,
        paid: paid.length,
        unpaid: unpaid.length,
        expiringSoon: expiringSoon.length,
        inactive: inactive.length,
      },
      users: outUsers,
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/billing', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const users = await loadUsersMeta();
    const idx = users.findIndex((u) => u && u.id === userId);
    if (idx === -1) return res.status(404).json({ error: 'user_not_found' });

    const nowIso = new Date().toISOString();
    const u = users[idx];
    const before = withUserDefaults(u);

    const patch = req.body && typeof req.body === 'object' ? req.body : {};
    const nextBilling = { ...(u.billing || {}) };

    if ('comped' in patch) nextBilling.comped = Boolean(patch.comped);

    if ('paidUntil' in patch) {
      const v = patch.paidUntil == null ? null : String(patch.paidUntil).trim();
      nextBilling.paidUntil = v || null;
    }

    if ('tier' in patch) {
      const v = patch.tier == null ? null : String(patch.tier).trim();
      nextBilling.tier = v || null;
    }

    if ('notes' in patch) {
      const v = patch.notes == null ? null : String(patch.notes);
      nextBilling.notes = v || null;
    }

    let nextStatus = u.status || 'active';
    if ('status' in patch) {
      const s = String(patch.status || '').trim().toLowerCase();
      if (s !== 'active' && s !== 'inactive') {
        return res.status(400).json({ error: 'bad_status', message: 'status must be active or inactive' });
      }
      nextStatus = s;
    }

    users[idx] = {
      ...u,
      billing: nextBilling,
      status: nextStatus,
      updatedAt: nowIso,
    };

    await saveUsersMeta(users);

    const after = withUserDefaults(users[idx]);

    // ✅ AUDIT (store before/after billing + status only)
    await appendAdminAudit(req, {
      action: 'user_billing_updated',
      target: { type: 'user', id: userId, email: after.email || after.pendingEmail || null },
      detail: {
        before: { status: before.status || 'active', billing: before.billing || {} },
        after: { status: after.status || 'active', billing: after.billing || {} },
      },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      user: {
        id: users[idx].id,
        status: users[idx].status || 'active',
        billing: {
          comped: !!users[idx].billing?.comped,
          paidUntil: users[idx].billing?.paidUntil || null,
          tier: users[idx].billing?.tier || null,
          notes: users[idx].billing?.notes || null,
        },
      },
    });
  } catch (err) {
    next(err);
  }
});

app.post('/api/admin/users/:id/billing/extend', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const daysRaw = Number(req.body?.days ?? 30);
    const days = Number.isFinite(daysRaw) ? Math.max(1, Math.min(365, Math.floor(daysRaw))) : 30;

    const users = await loadUsersMeta();
    const idx = users.findIndex((u) => u && u.id === userId);
    if (idx === -1) return res.status(404).json({ error: 'user_not_found' });

    const nowIso = new Date().toISOString();
    const u = users[idx];
    const beforePaidUntil = u.billing?.paidUntil || null;

    const billing = { ...(u.billing || {}) };

    // If comped, extending is a no-op (log as such)
    if (billing.comped) {
      await appendAdminAudit(req, {
        action: 'user_billing_extend_noop_comped',
        target: { type: 'user', id: userId, email: u.email || u.pendingEmail || null },
        detail: { days },
      });

      return res.json({ ok: true, unchanged: true, userId });
    }

    const nowMs = Date.now();
    const curMs = billing.paidUntil ? Date.parse(billing.paidUntil) : NaN;
    const baseMs = Number.isFinite(curMs) && curMs > nowMs ? curMs : nowMs;
    const nextMs = baseMs + days * 24 * 60 * 60 * 1000;
    billing.paidUntil = new Date(nextMs).toISOString();

    users[idx] = {
      ...u,
      billing,
      updatedAt: nowIso,
      status: u.status || 'active',
    };

    await saveUsersMeta(users);

    await appendAdminAudit(req, {
      action: 'user_billing_extended',
      target: { type: 'user', id: userId, email: users[idx].email || users[idx].pendingEmail || null },
      detail: { days, beforePaidUntil, afterPaidUntil: users[idx].billing?.paidUntil || null },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      user: {
        id: users[idx].id,
        billing: {
          comped: !!users[idx].billing?.comped,
          paidUntil: users[idx].billing?.paidUntil || null,
          tier: users[idx].billing?.tier || null,
          notes: users[idx].billing?.notes || null,
        },
      },
    });
  } catch (err) {
    next(err);
  }
});

const GODMODE_DISCORD_ID = String(process.env.GODMODE_DISCORD_ID || '').trim() || null;

function isGodmodeUser(user) {
  const did = String(user?.discordId || '').trim();
  return !!GODMODE_DISCORD_ID && !!did && did === GODMODE_DISCORD_ID;
}

function requireGodmode(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'not_logged_in' });
  if (!isGodmodeUser(req.user)) return res.status(403).json({ error: 'forbidden' });
  next();
}

// GET /api/admin/users/duplicates
// Finds emails that appear on 2+ user records (across email/pendingEmail/emails[])
app.get('/api/admin/users/duplicates', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const users = await loadUsersMeta();
    const arr = Array.isArray(users) ? users.filter(Boolean) : [];

    const emailMap = new Map(); // email -> [{user summary, verifiedAt, source}]
    for (const u of arr) {
      const emails = getUserEmails(u); // from Step 8A
      for (const e of emails) {
        const em = normalizeEmail(e.email);
        if (!em) continue;
        if (!emailMap.has(em)) emailMap.set(em, []);
        emailMap.get(em).push({
          userId: u.id,
          discordId: u.discordId || null,
          discordUsername: u.discordUsername || null,
          email: u.email || null,
          pendingEmail: u.pendingEmail || null,
          emailVerifiedAt: u.emailVerifiedAt || null,
          lastLoginAt: u.lastLoginAt || null,
          status: u.status || 'active',
          billing: u.billing || {},
          hit: {
            email: em,
            verifiedAt: e.verifiedAt || null,
            source: e.source || null,
          },
        });
      }
    }

    // Keep only duplicates
    const groups = [];
    for (const [email, hits] of emailMap.entries()) {
      if (!hits || hits.length < 2) continue;

      // recommend target: prefer discordId; otherwise most recent login; otherwise first
      const scored = hits.map((h) => {
        const hasDiscord = !!String(h.discordId || '').trim();
        const last = Date.parse(h.lastLoginAt || '') || 0;
        const verified = !!(h.hit?.verifiedAt);
        const score = (hasDiscord ? 1000 : 0) + (verified ? 100 : 0) + Math.min(99, Math.floor(last / 1e9));
        return { ...h, _score: score };
      });

      scored.sort((a, b) => b._score - a._score);
      const recommendedTargetUserId = scored[0]?.userId || null;

      groups.push({
        email,
        count: hits.length,
        recommendedTargetUserId,
        users: scored.map(({ _score, ...rest }) => rest),
      });
    }

    // stable sort: biggest dup groups first
    groups.sort((a, b) => b.count - a.count || a.email.localeCompare(b.email));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, groups });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users/duplicates
// Finds emails that appear on 2+ user records (across email/pendingEmail/emails[])
app.get('/api/admin/users/duplicates', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const users = await loadUsersMeta();
    const arr = Array.isArray(users) ? users.filter(Boolean) : [];

    const emailMap = new Map(); // email -> [{user summary, verifiedAt, source}]
    for (const u of arr) {
      const emails = getUserEmails(u); // from Step 8A
      for (const e of emails) {
        const em = normalizeEmail(e.email);
        if (!em) continue;
        if (!emailMap.has(em)) emailMap.set(em, []);
        emailMap.get(em).push({
          userId: u.id,
          discordId: u.discordId || null,
          discordUsername: u.discordUsername || null,
          email: u.email || null,
          pendingEmail: u.pendingEmail || null,
          emailVerifiedAt: u.emailVerifiedAt || null,
          lastLoginAt: u.lastLoginAt || null,
          status: u.status || 'active',
          billing: u.billing || {},
          hit: {
            email: em,
            verifiedAt: e.verifiedAt || null,
            source: e.source || null,
          },
        });
      }
    }

    // Keep only duplicates
    const groups = [];
    for (const [email, hits] of emailMap.entries()) {
      if (!hits || hits.length < 2) continue;

      // recommend target: prefer discordId; otherwise most recent login; otherwise first
      const scored = hits.map((h) => {
        const hasDiscord = !!String(h.discordId || '').trim();
        const last = Date.parse(h.lastLoginAt || '') || 0;
        const verified = !!(h.hit?.verifiedAt);
        const score = (hasDiscord ? 1000 : 0) + (verified ? 100 : 0) + Math.min(99, Math.floor(last / 1e9));
        return { ...h, _score: score };
      });

      scored.sort((a, b) => b._score - a._score);
      const recommendedTargetUserId = scored[0]?.userId || null;

      groups.push({
        email,
        count: hits.length,
        recommendedTargetUserId,
        users: scored.map(({ _score, ...rest }) => rest),
      });
    }

    // stable sort: biggest dup groups first
    groups.sort((a, b) => b.count - a.count || a.email.localeCompare(b.email));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, groups });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/delete
// body: { reason? }
// Godmode only
app.post('/api/admin/users/:id/delete', requireUser, requireGodmode, requireEditorOrigin, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const reason = req.body?.reason != null ? String(req.body.reason) : null;

    const users = await loadUsersMeta();
    const idx = users.findIndex((u) => u && u.id === userId);
    if (idx === -1) return res.status(404).json({ error: 'user_not_found' });

    // Prevent deleting space owners (force transfer first)
    const spaces = await loadSpacesMeta();
    const owned = (Array.isArray(spaces) ? spaces : []).filter((s) => s && s.status === 'active' && String(s.ownerUserId || '') === userId);

    if (owned.length) {
      return res.status(409).json({
        error: 'user_owns_spaces',
        message: 'Transfer ownership of these spaces before deleting the user.',
        spaces: owned.map((s) => s.slug),
      });
    }

    const nowIso = new Date().toISOString();

    // Revoke all sessions for this user (delete session records)
    try {
      const sessions = await loadSessionsMeta();
      const nextSessions = (Array.isArray(sessions) ? sessions : []).filter((s) => !(s && String(s.userId || '') === userId));
      await saveSessionsMeta(nextSessions);
    } catch {}

    // Remove from any space members[] lists (if you’ve started adding ACL)
    try {
      const nextSpaces = (Array.isArray(spaces) ? spaces : []).map((s) => {
        if (!s) return s;
        if (!Array.isArray(s.members)) return s;
        const members = s.members.filter((m) => String(m?.userId || '') !== userId);
        return { ...s, members };
      });
      await saveSpacesMeta(nextSpaces);
    } catch {}

    // Soft-delete user record
    users[idx] = {
      ...users[idx],
      status: 'deleted',
      deletedAt: nowIso,
      deletedReason: reason || null,
      updatedAt: nowIso,
      // Optional: remove emails from being used for login/verification
      pendingEmail: null,
      pendingEmailSetAt: null,
    };

    await saveUsersMeta(users);

    await appendAdminAudit(req, {
      action: 'user_deleted_soft',
      target: { type: 'user', id: userId },
      detail: { reason: reason || null },
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, userId, status: 'deleted' });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/merge
// body: { sourceUserId, targetUserId, primaryEmail? }
// Godmode only (safest)
app.post(
  '/api/admin/users/merge',
  requireUser,
  requireGodmode,
  requireEditorOrigin,
  async (req, res, next) => {
    try {
      const sourceUserId = String(req.body?.sourceUserId || '').trim();
      const targetUserId = String(req.body?.targetUserId || '').trim();
      const primaryEmailIn =
        req.body?.primaryEmail != null ? normalizeEmail(req.body.primaryEmail) : null;

      if (!sourceUserId || !targetUserId) {
        return res.status(400).json({ error: 'missing_fields' });
      }
      if (sourceUserId === targetUserId) {
        return res.status(400).json({ error: 'same_user' });
      }

      const lockKey = `merge:${sourceUserId}->${targetUserId}`;
      return withInProcessLock(lockKey, async () => {
        const users = await loadUsersMeta();
        const arr = Array.isArray(users) ? users : [];

        const sIdx = arr.findIndex((u) => u && u.id === sourceUserId);
        const tIdx = arr.findIndex((u) => u && u.id === targetUserId);

        if (sIdx === -1) return res.status(404).json({ error: 'source_not_found' });
        if (tIdx === -1) return res.status(404).json({ error: 'target_not_found' });

        const source = arr[sIdx];
        let target = arr[tIdx];

        // Guard: avoid merging *into* a deleted user
        const tStatus = String(target.status || 'active').toLowerCase();
        if (tStatus === 'deleted') {
          return res.status(400).json({ error: 'target_deleted' });
        }

        const nowIso = new Date().toISOString();

        // Choose primary email: explicit param > target primary > target email > source email
        const targetPrimary = normalizeEmail(target.primaryEmail || target.email);
        const primaryEmail =
          primaryEmailIn || targetPrimary || normalizeEmail(source.email) || null;

        // Merge emails (policy A: treat legacy emails as verified if emailVerifiedAt exists)
        const mergedEmailObjs = [];
        for (const u of [target, source]) {
          const emails = getUserEmails(u); // Step 8A helper
          for (const e of emails) {
            const em = normalizeEmail(e.email);
            if (!em) continue;

            const verifiedAt =
              e.verifiedAt ||
              (normalizeEmail(u.email) === em && u.emailVerifiedAt ? u.emailVerifiedAt : null) ||
              null;

            mergedEmailObjs.push({
              email: em,
              verifiedAt: verifiedAt || null,
              source: e.source || 'merge',
            });
          }
        }

        if (primaryEmail) {
          mergedEmailObjs.push({ email: primaryEmail, verifiedAt: nowIso, source: 'primary' });
        }

        // De-dupe email entries by keeping the latest verifiedAt
        const byEmail = new Map();
        for (const e of mergedEmailObjs) {
          const em = normalizeEmail(e.email);
          if (!em) continue;

          const cur = byEmail.get(em);
          const curMs = cur?.verifiedAt ? Date.parse(cur.verifiedAt) : 0;
          const nxtMs = e.verifiedAt ? Date.parse(e.verifiedAt) : 0;

          if (!cur || nxtMs > curMs) {
            byEmail.set(em, {
              email: em,
              verifiedAt: e.verifiedAt || null,
              source: e.source || null,
            });
          }
        }

        const emailsOut = Array.from(byEmail.values());

        // Merge billing conservatively
        const billing = target.billing || {};
        const comped = !!(target.billing?.comped || source.billing?.comped);
        if (comped) billing.comped = true;

        const paidUntilMs = [target, source]
          .map((u) => Date.parse(u?.billing?.paidUntil || ''))
          .filter((ms) => Number.isFinite(ms));
        if (paidUntilMs.length) {
          billing.paidUntil = new Date(Math.max(...paidUntilMs)).toISOString();
        }

        const notes = [billing.notes, source.billing?.notes]
          .filter(Boolean)
          .map(String);
        if (notes.length) billing.notes = Array.from(new Set(notes)).join(' | ');

        // Apply to target
        target = {
          ...target,
          billing,
          emails: emailsOut,
          primaryEmail: primaryEmail || target.primaryEmail || target.email || null,
          email: primaryEmail || target.email || null, // legacy primary stays in sync
          emailVerifiedAt:
            target.emailVerifiedAt || (primaryEmail ? nowIso : null),
          pendingEmail: null,
          pendingEmailSetAt: null,
          updatedAt: nowIso,
          mergedFromUserIds: Array.from(
            new Set([...(target.mergedFromUserIds || []), sourceUserId])
          ),
        };

        // Rewrite meta stores: replace sourceUserId -> targetUserId anywhere it appears
        const replaceMap = new Map([[sourceUserId, targetUserId]]);
        const rewrite = (obj) => deepReplaceExactString(obj, replaceMap);

        // sessions
        try {
          const sessions = await loadSessionsMeta();
          await saveSessionsMeta(rewrite(sessions));
        } catch {}

        // spaces
        try {
          const spaces = await loadSpacesMeta();
          const nextSpaces = rewrite(spaces);

          // If any space.ownerEmail matches source email, update to primary
          const sEmail = normalizeEmail(source.email);
          if (sEmail && primaryEmail) {
            for (const sp of nextSpaces) {
              if (!sp) continue;
              if (normalizeEmail(sp.ownerEmail) === sEmail) sp.ownerEmail = primaryEmail;
            }
          }

          await saveSpacesMeta(nextSpaces);
        } catch {}

        // workspace requests
        try {
          const reqs = await loadWorkspaceRequests();
          await saveWorkspaceRequests(rewrite(reqs));
        } catch {}

        // file meta + versions
        try {
          const fm = await loadFilesMeta();
          await saveFilesMeta(rewrite(fm));
        } catch {}
        try {
          const fv = await loadFileVersionsMeta();
          await saveFileVersionsMeta(rewrite(fv));
        } catch {}

        // email verify tokens
        try {
          const ev = await loadEmailVerifyTokens();
          await saveEmailVerifyTokens(rewrite(ev));
        } catch {}

        // Persist users: replace target, remove source
        arr[tIdx] = target;
        const nextUsers = arr.filter((u) => !(u && u.id === sourceUserId));
        await saveUsersMeta(nextUsers);

        await appendAdminAudit(req, {
          action: 'user_merged',
          target: { type: 'user', id: targetUserId },
          detail: {
            sourceUserId,
            targetUserId,
            primaryEmail: target.primaryEmail || target.email || null,
            verifiedEmails: (target.emails || [])
              .filter((e) => e?.verifiedAt)
              .map((e) => e.email),
          },
        });

        res.setHeader('Cache-Control', 'no-store');
        return res.json({ ok: true, targetUserId, removedUserId: sourceUserId });
      });
    } catch (err) {
      next(err);
    }
  }
);

// ───────────────── Admin Audit Log (append-only) ─────────────────

// Store audit log next to your other meta files by default.
// You can override via ADMIN_AUDIT_META_PATH env var.
const ADMIN_AUDIT_META_PATH =
  process.env.ADMIN_AUDIT_META_PATH ||
  path.join(path.dirname(USERS_META_PATH), 'adminAudit.meta.json');

const ADMIN_AUDIT_MAX = (() => {
  const n = Number(process.env.ADMIN_AUDIT_MAX || 5000);
  return Number.isFinite(n) ? Math.max(500, Math.min(50_000, n)) : 5000;
})();

async function loadAdminAuditLog() {
  return readJsonArray(ADMIN_AUDIT_META_PATH);
}

async function saveAdminAuditLog(arr) {
  return writeJsonArray(ADMIN_AUDIT_META_PATH, arr);
}

function auditActorFromReq(req) {
  const u = req.user || {};
  return {
    userId: u.id || null,
    discordId: u.discordId || null,
    discordUsername: u.discordUsername || null,
    discordGlobalName: u.discordGlobalName || null,
    email: u.email || u.pendingEmail || null,
    ip: req.ip || null,
    userAgent: req.get('user-agent') || null,
  };
}

// Append-only. Trims to ADMIN_AUDIT_MAX newest entries.
async function appendAdminAudit(req, entry) {
  const nowIso = new Date().toISOString();

  const base = {
    id: generateId('aa_'),
    at: nowIso,
    action: safeStr(entry?.action || 'unknown', 120),
    actor: auditActorFromReq(req),
    target: entry?.target || null, // {type,id,slug,email,...}
    meta: {
      method: req.method,
      path: req.originalUrl,
    },
    detail: entry?.detail || null, // any JSON-safe data
  };

  let arr = [];
  try {
    arr = await loadAdminAuditLog();
  } catch (err) {
    // If missing/corrupt, start fresh (don’t block admin actions)
    console.warn('[audit] failed to load audit log; starting new', err.message);
    arr = [];
  }

  arr.push(base);

  // Trim (keep newest)
  if (arr.length > ADMIN_AUDIT_MAX) {
    arr = arr.slice(arr.length - ADMIN_AUDIT_MAX);
  }

  try {
    await saveAdminAuditLog(arr);
  } catch (err) {
    console.error('[audit] failed to append audit log (non-fatal)', err);
  }
}

// GET /api/admin/audit?limit=200&q=...&action=...&actor=...
// Returns newest-first
app.get('/api/admin/audit', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const limitRaw = Number(req.query?.limit || 200);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(2000, limitRaw)) : 200;

    const q = String(req.query?.q || '').trim().toLowerCase();
    const action = String(req.query?.action || '').trim().toLowerCase();
    const actor = String(req.query?.actor || '').trim().toLowerCase();

    const arr = await loadAdminAuditLog();
    const list = Array.isArray(arr) ? arr.filter(Boolean) : [];

    const haystack = (e) => {
      const a = e?.actor || {};
      const t = e?.target || {};
      return [
        e?.id,
        e?.action,
        e?.at,
        a.userId,
        a.discordId,
        a.discordUsername,
        a.discordGlobalName,
        a.email,
        t.type,
        t.id,
        t.slug,
        t.email,
        t.userId,
        JSON.stringify(e?.detail || {}),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
    };

    let out = list;

    if (action) out = out.filter((e) => String(e?.action || '').toLowerCase() === action);

    if (actor) {
      out = out.filter((e) => {
        const a = e?.actor || {};
        return (
          String(a.userId || '').toLowerCase().includes(actor) ||
          String(a.discordId || '').toLowerCase().includes(actor) ||
          String(a.discordUsername || '').toLowerCase().includes(actor) ||
          String(a.discordGlobalName || '').toLowerCase().includes(actor) ||
          String(a.email || '').toLowerCase().includes(actor)
        );
      });
    }

    if (q) out = out.filter((e) => haystack(e).includes(q));

    // newest first
    out.sort((a, b) => (Date.parse(b?.at || '') || 0) - (Date.parse(a?.at || '') || 0));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, total: out.length, entries: out.slice(0, limit) });
  } catch (err) {
    next(err);
  }
});

// ───────────────── Admin Activity Feed ─────────────────
// GET /api/admin/activity?limit=200
// Merges: audit log + recent sessions + workspace requests + spaces created
app.get('/api/admin/activity', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const limitRaw = Number(req.query?.limit || 200);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(2000, limitRaw)) : 200;

    const toMs = (iso) => {
      const ms = Date.parse(String(iso || ''));
      return Number.isFinite(ms) ? ms : 0;
    };

    const [audit, sessions, requests, spaces] = await Promise.all([
      loadAdminAuditLog().catch(() => []),
      loadSessionsMeta().catch(() => []),
      loadWorkspaceRequests().catch(() => []),
      loadSpacesMeta().catch(() => []),
    ]);

    const items = [];

    // Audit entries → activity items
    for (const e of (Array.isArray(audit) ? audit : [])) {
      if (!e) continue;
      items.push({
        kind: 'audit',
        at: e.at || null,
        atMs: toMs(e.at),
        action: e.action || 'unknown',
        actor: e.actor || null,
        target: e.target || null,
        detail: e.detail || null,
        id: e.id || null,
      });
    }

    // Sessions → logins (recent sign-ins)
    for (const s of (Array.isArray(sessions) ? sessions : [])) {
      if (!s) continue;
      items.push({
        kind: 'login',
        at: s.createdAt || null,
        atMs: toMs(s.createdAt),
        action: 'login',
        actor: null,
        target: { type: 'session', id: s.id, userId: s.userId || null, email: s.email || null },
        detail: {
          userId: s.userId || null,
          email: s.email || null,
          ip: s.ip || null,
          userAgent: s.userAgent || null,
        },
        id: s.id || null,
      });
    }

    // Workspace requests
    for (const r of (Array.isArray(requests) ? requests : [])) {
      if (!r) continue;
      items.push({
        kind: 'workspace_request',
        at: r.createdAt || null,
        atMs: toMs(r.createdAt),
        action: `workspace_request_${String(r.status || 'unknown').toLowerCase()}`,
        actor: null,
        target: { type: 'workspace_request', id: r.id || null, userId: r.userId || null, email: r.email || null, slug: r.suggestedSlug || null },
        detail: {
          status: r.status || null,
          note: r.note || null,
          suggestedSlug: r.suggestedSlug || null,
        },
        id: r.id || null,
      });
    }

    // Spaces created (from spaces meta)
    for (const sp of (Array.isArray(spaces) ? spaces : [])) {
      if (!sp) continue;
      items.push({
        kind: 'space',
        at: sp.createdAt || null,
        atMs: toMs(sp.createdAt),
        action: 'space_created',
        actor: null,
        target: { type: 'space', slug: sp.slug || null, userId: sp.ownerUserId || null, email: sp.ownerEmail || null },
        detail: {
          quotaMb: sp.quotaMb ?? null,
          status: sp.status || null,
        },
        id: sp.slug || null,
      });
    }

    // Sort newest-first
    items.sort((a, b) => (b.atMs || 0) - (a.atMs || 0));

    // Return trimmed
    const out = items.slice(0, limit).map((x) => {
      const { atMs, ...rest } = x;
      return rest;
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, total: items.length, items: out });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users/:id/sessions?limit=50
app.get('/api/admin/users/:id/sessions', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const limitRaw = Number(req.query?.limit || 50);
    const limit = Number.isFinite(limitRaw) ? Math.max(1, Math.min(500, limitRaw)) : 50;

    const sessions = await loadSessionsMeta();
    const list = (Array.isArray(sessions) ? sessions : [])
      .filter((s) => s && String(s.userId || '') === userId)
      .sort((a, b) => (Date.parse(b.createdAt || '') || 0) - (Date.parse(a.createdAt || '') || 0))
      .slice(0, limit)
      .map((s) => ({
        id: s.id,
        createdAt: s.createdAt || null,
        email: s.email || null,
        ip: s.ip || null,
        userAgent: s.userAgent || null,
      }));

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, userId, sessions: list });
  } catch (err) {
    next(err);
  }
});

// POST /api/admin/users/:id/sessions/revoke
// body: { sid?: string }  -> if sid present: revoke that session only; else revoke all for user
app.post('/api/admin/users/:id/sessions/revoke', requireUser, requireAdminUser, requireEditorOrigin, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const sid = req.body?.sid != null ? String(req.body.sid).trim() : '';

    const sessions = await loadSessionsMeta();
    const beforeCount = Array.isArray(sessions) ? sessions.length : 0;

    let nextSessions = Array.isArray(sessions) ? sessions : [];
    let revokedCount = 0;

    if (sid) {
      const had = nextSessions.some((s) => s && s.id === sid && String(s.userId || '') === userId);
      nextSessions = nextSessions.filter((s) => !(s && s.id === sid && String(s.userId || '') === userId));
      revokedCount = had ? 1 : 0;

      await appendAdminAudit(req, {
        action: 'session_revoked_one',
        target: { type: 'user', id: userId },
        detail: { sid, revoked: revokedCount === 1 },
      });
    } else {
      const beforeUser = nextSessions.filter((s) => s && String(s.userId || '') === userId).length;
      nextSessions = nextSessions.filter((s) => !(s && String(s.userId || '') === userId));
      revokedCount = beforeUser;

      await appendAdminAudit(req, {
        action: 'session_revoked_all',
        target: { type: 'user', id: userId },
        detail: { revokedCount },
      });
    }

    if (nextSessions.length !== beforeCount) {
      await saveSessionsMeta(nextSessions);
    }

    res.setHeader('Cache-Control', 'no-store');
    return res.json({ ok: true, userId, revokedCount });
  } catch (err) {
    next(err);
  }
});

// ───────────────── Admin: user detail (for drawer) ─────────────────
// GET /api/admin/users/:id/detail
app.get('/api/admin/users/:id/detail', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const userId = String(req.params.id || '').trim();
    if (!userId) return res.status(400).json({ error: 'bad_user_id' });

    const users = await loadUsersMeta();
    const u0 = (Array.isArray(users) ? users : []).find((u) => u && u.id === userId) || null;
    if (!u0) return res.status(404).json({ error: 'user_not_found' });

    // Compute entitlement inline (self-contained)
    const u = withUserDefaults(u0);
    const now = Date.now();
    const status = String(u.status || 'active').toLowerCase();

    const paidUntilMs = u.billing?.paidUntil ? Date.parse(u.billing.paidUntil) : NaN;
    const hasValidPaidUntil = Number.isFinite(paidUntilMs);

    const isActive = status === 'active';
    const isComped = !!u.billing?.comped;
    const isPaid = isActive && (isComped || (hasValidPaidUntil && paidUntilMs > now));

    const daysLeft = hasValidPaidUntil ? Math.ceil((paidUntilMs - now) / (24 * 60 * 60 * 1000)) : null;
    const expiringSoon = isActive && !isComped && hasValidPaidUntil && paidUntilMs > now && daysLeft != null && daysLeft <= 7;

    const spaces = await loadSpacesMeta();
    const mySpaces = (Array.isArray(spaces) ? spaces : [])
      .filter((s) => s && s.status === 'active' && String(s.ownerUserId || '') === userId);

    const publicBase = String(PUBLIC_IFRAME_BASE_URL || '').replace(/\/+$/, '');
    const spacesOut = mySpaces.map((s) => {
      const iframeUrl = publicBase
        ? `${publicBase}/p/${encodeURIComponent(s.slug)}/index.html`
        : `/p/${encodeURIComponent(s.slug)}/index.html`;

      const paywallPreviewUrl = iframeUrl.includes('?')
        ? `${iframeUrl}&paywallPreview=1`
        : `${iframeUrl}?paywallPreview=1`;

      return {
        slug: s.slug,
        quotaMb: s.quotaMb ?? null,
        iframeUrl,
        paywallPreviewUrl,
      };
    });

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      user: {
        id: u.id,
        status: u.status || 'active',
        lastLoginAt: u.lastLoginAt || null,

        discordId: u.discordId || null,
        discordUsername: u.discordUsername || null,
        discordGlobalName: u.discordGlobalName || null,
        discordAvatarUrl: u.discordAvatarUrl || null,

        email: u.email || null,
        pendingEmail: u.pendingEmail || null,
        emailVerifiedAt: u.emailVerifiedAt || null,

        billing: {
          comped: !!u.billing?.comped,
          paidUntil: u.billing?.paidUntil || null,
          tier: u.billing?.tier || null,
          notes: u.billing?.notes || null,
        },

        entitlement: {
          isActive,
          isComped,
          isPaid,
          paidUntil: u.billing?.paidUntil || null,
          daysLeft,
          expiringSoon,
          tier: u.billing?.tier || null,
          notes: u.billing?.notes || null,
        },

        spaces: spacesOut,
      },
    });
  } catch (err) {
    next(err);
  }
});

// ───────────────── Admin: System Doctor ─────────────────
// GET /api/admin/doctor
app.get('/api/admin/doctor', requireUser, requireAdminUser, async (req, res, next) => {
  try {
    const nowIso = new Date().toISOString();

    // Helper checks
    const canAccess = async (p) => {
      if (!p) return { ok: false, path: p || null, exists: false, readable: false, writable: false, error: 'missing_path' };
      try {
        await fs.access(p, fsSync.constants.F_OK);
      } catch {
        return { ok: false, path: p, exists: false, readable: false, writable: false, error: 'missing' };
      }

      let readable = false;
      let writable = false;

      try { await fs.access(p, fsSync.constants.R_OK); readable = true; } catch {}
      try { await fs.access(p, fsSync.constants.W_OK); writable = true; } catch {}

      return {
        ok: readable && writable,
        path: p,
        exists: true,
        readable,
        writable,
        error: readable && writable ? null : 'permission',
      };
    };

    const statfs = async (p) => {
      // Node 18+ has fs.promises.statfs on linux; if missing, skip gracefully
      const statfsFn = fs.statfs ? fs.statfs : null;
      if (!statfsFn) return { ok: false, supported: false };

      try {
        const s = await statfsFn(p);
        // bytes
        const block = Number(s.bsize || 0);
        const free = Number(s.bfree || 0);
        const avail = Number(s.bavail || 0);
        const total = Number(s.blocks || 0);

        const totalBytes = block * total;
        const freeBytes = block * free;
        const availBytes = block * avail;

        return { ok: true, supported: true, totalBytes, freeBytes, availBytes };
      } catch (err) {
        return { ok: false, supported: true, error: err.message || 'statfs_failed' };
      }
    };

    const fmtMb = (bytes) => {
      const n = Number(bytes);
      if (!Number.isFinite(n) || n < 0) return null;
      return +(n / (1024 * 1024)).toFixed(2);
    };

    // Meta store health
    const metaChecks = await Promise.all([
      canAccess(USERS_META_PATH),
      canAccess(SPACES_META_PATH),
      canAccess(WORKSPACE_REQUESTS_PATH),
      canAccess(SESSIONS_META_PATH),
      canAccess(TOKENS_META_PATH),
      canAccess(FILES_META_PATH),
      canAccess(FILE_VERSIONS_META_PATH),
      canAccess(EMAIL_VERIFY_TOKENS_META_PATH),
    ]);

    const meta = {
      users: metaChecks[0],
      spaces: metaChecks[1],
      workspaceRequests: metaChecks[2],
      sessions: metaChecks[3],
      tokens: metaChecks[4],
      filesMeta: metaChecks[5],
      fileVersionsMeta: metaChecks[6],
      emailVerifyTokens: metaChecks[7],
    };

    // Root checks
    const spacesRootCheck = await (async () => {
      try {
        await fs.mkdir(SPACES_ROOT, { recursive: true });
        const s = await statfs(SPACES_ROOT);
        return { ok: true, path: SPACES_ROOT, statfs: s };
      } catch (err) {
        return { ok: false, path: SPACES_ROOT, error: err.message || 'spaces_root_failed' };
      }
    })();

    // Config / host gating snapshot
    const appBase = String(APP_BASE_URL || '').replace(/\/+$/, '');
    const publicBase = String(PUBLIC_IFRAME_BASE_URL || '').replace(/\/+$/, '');

    const config = {
      env: NODE_ENV,
      isProd: !!IS_PROD,
      trustProxy: !!TRUST_PROXY,
      appBaseUrl: appBase || null,
      publicIframeBaseUrl: publicBase || null,
      appHostname: APP_HOSTNAME || null,
      publicIframeHostname: PUBLIC_IFRAME_HOSTNAME || null,
      frameAncestors: PORTALS_FRAME_ANCESTORS || null,
    };

    // Service config sanity
    const services = {
      sendgrid: {
        configured: !!(SENDGRID_API_KEY && SENDGRID_FROM),
        from: SENDGRID_FROM || null,
        adminEmail: WORKSPACE_ADMIN_EMAIL || null,
      },
      openai: {
        configured: !!OPENAI_API_KEY,
        defaultModel: DEFAULT_GPT_MODEL || null,
        allowedModels: Array.isArray(ALLOWED_GPT_MODELS) ? ALLOWED_GPT_MODELS : [],
        rate: {
          windowMs: GPT_RATE_WINDOW_MS,
          maxPerWindow: GPT_RATE_MAX_PER_WINDOW,
          dailyLimit: GPT_MAX_CALLS_PER_DAY,
        },
      },
      discord: {
        configured: !!(DISCORD_CLIENT_ID && DISCORD_CLIENT_SECRET && DISCORD_REDIRECT_URI),
        guildConfigured: !!(DISCORD_BOT_TOKEN && DISCORD_GUILD_ID),
        requiredRoleIds: Array.isArray(DISCORD_REQUIRED_ROLE_IDS) ? DISCORD_REQUIRED_ROLE_IDS : [],
        redirectUri: DISCORD_REDIRECT_URI || null,
      },
    };

    // Storage: largest spaces (best-effort, bounded)
    let largestSpaces = [];
    try {
      const spaces = await loadSpacesMeta();
      const active = (Array.isArray(spaces) ? spaces : []).filter((s) => s && s.status === 'active');

      // sample cap to avoid heavy scans
      const cap = Math.min(active.length, 30);

      // naive “pick first cap”; if you store currentSizeBytes it’ll still be useful
      const subset = active.slice(0, cap);

      // Compute sizes with limited concurrency
      const concurrency = 4;
      const queue = [...subset];
      const results = [];

      const worker = async () => {
        while (queue.length) {
          const s = queue.shift();
          if (!s?.dirPath) continue;

          let usedBytes = null;
          try {
            usedBytes = await getDirSizeBytes(s.dirPath);
          } catch (err) {
            usedBytes = null;
          }

          results.push({
            slug: s.slug,
            quotaMb: s.quotaMb ?? null,
            usedMb: usedBytes != null ? fmtMb(usedBytes) : null,
            usedBytes,
            ownerUserId: s.ownerUserId || null,
            ownerEmail: s.ownerEmail || null,
          });
        }
      };

      await Promise.all(Array.from({ length: concurrency }, worker));

      results.sort((a, b) => (b.usedBytes || 0) - (a.usedBytes || 0));
      largestSpaces = results.slice(0, 10);
    } catch {
      largestSpaces = [];
    }

    const checks = [
      { key: 'spaces_root', label: 'Spaces root accessible', ok: !!spacesRootCheck.ok },
      { key: 'meta_users', label: 'Users meta readable+writable', ok: !!meta.users.ok },
      { key: 'meta_spaces', label: 'Spaces meta readable+writable', ok: !!meta.spaces.ok },
      { key: 'meta_sessions', label: 'Sessions meta readable+writable', ok: !!meta.sessions.ok },
      { key: 'sendgrid', label: 'SendGrid configured', ok: !!services.sendgrid.configured },
      { key: 'discord_oauth', label: 'Discord OAuth configured', ok: !!services.discord.configured },
      { key: 'discord_guild', label: 'Discord guild check configured', ok: !!services.discord.guildConfigured },
      { key: 'openai', label: 'OpenAI configured', ok: !!services.openai.configured },
    ];

    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      at: nowIso,
      config,
      services,
      meta,
      storage: {
        spacesRoot: spacesRootCheck,
        largestSpaces,
      },
      checks,
      request: {
        host: req.get('host') || null,
        origin: req.get('origin') || null,
        ip: req.ip || null,
      },
    });
  } catch (err) {
    next(err);
  }
});


// ───────────────── auth status (lightweight) ─────────────────
// GET /api/auth/status
// Returns whether the current request has a valid session, plus a tiny user snapshot.
app.get('/api/auth/status', async (req, res, next) => {
  try {
    if (!req.user) {
      return res.json({
        ok: true,
        loggedIn: false,
        user: null,
        spacesCount: 0,
      });
    }

    const spaces = await loadSpacesMeta();
    const normalizedEmail = String(req.user.email || '').trim().toLowerCase();

    const spacesCount = spaces.filter((s) => {
      if (!s || s.status !== 'active') return false;
      if (s.ownerUserId && s.ownerUserId === req.user.id) return true;
      if (normalizedEmail && s.ownerEmail && String(s.ownerEmail).trim().toLowerCase() === normalizedEmail) return true;
      return false;
    }).length;

    return res.json({
      ok: true,
      loggedIn: true,
      user: {
        id: req.user.id,

        // email verification gate
        email: req.user.email || null,
        pendingEmail: req.user.pendingEmail || null,
        emailVerifiedAt: req.user.emailVerifiedAt || null,

        // discord snapshot for onboarding UI
        discordId: req.user.discordId || null,
        discordUsername: req.user.discordUsername || null,
        discordGlobalName: req.user.discordGlobalName || null,
        discordAvatar: req.user.discordAvatar || null,

        status: req.user.status || 'active',
      },
      spacesCount,
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
