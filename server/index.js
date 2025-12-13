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

// Load env vars from .env (if present)
dotenv.config();

// __dirname shim for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Basic config
const PORT = process.env.PORT || 4100;
const NODE_ENV = process.env.NODE_ENV || 'development';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

// Root of repo
const ROOT_DIR = path.join(__dirname, '..');
// Where user spaces (per-tenant dirs) will live
const SPACES_ROOT = path.join(ROOT_DIR, 'spaces');
// Simple metadata file to track spaces
const SPACES_META_PATH = path.join(ROOT_DIR, 'spaces.meta.json');

const app = express();

// ───────────────── Helpers ─────────────────

async function ensureSpacesRoot() {
  try {
    await fs.mkdir(SPACES_ROOT, { recursive: true });
  } catch (err) {
    console.error('[spaces] failed to ensure spaces root', err);
    throw err;
  }
}

// Load spaces metadata from JSON file
async function loadSpacesMeta() {
  try {
    if (!fsSync.existsSync(SPACES_META_PATH)) {
      return [];
    }
    const raw = await fs.readFile(SPACES_META_PATH, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch (err) {
    console.error('[spaces] failed to load metadata', err);
    return [];
  }
}

// Save spaces metadata back to disk
async function saveSpacesMeta(spaces) {
  try {
    const json = JSON.stringify(spaces, null, 2);
    await fs.writeFile(SPACES_META_PATH, json, 'utf8');
  } catch (err) {
    console.error('[spaces] failed to save metadata', err);
    throw err;
  }
}

// Very simple slug validator for space names
function isValidSlug(slug) {
  return typeof slug === 'string' && /^[a-z0-9-]{3,32}$/.test(slug);
}

// Admin auth middleware using x-admin-token header
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) {
    return res
      .status(503)
      .json({ error: 'admin_disabled', reason: 'missing ADMIN_TOKEN' });
  }
  const token = req.get('x-admin-token');
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
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

// ───────────────── Routes: health/version ─────────────────

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
// Body: { slug, quotaMb? }
app.post('/api/admin/spaces', requireAdmin, async (req, res, next) => {
  try {
    await ensureSpacesRoot();

    const { slug, quotaMb } = req.body || {};

    if (!isValidSlug(slug)) {
      return res.status(400).json({
        error: 'bad_slug',
        message:
          'Slug must be 3-32 chars of lowercase letters, digits, or hyphens.',
      });
    }

    const spaces = await loadSpacesMeta();
    if (spaces.find((s) => s.slug === slug)) {
      return res
        .status(409)
        .json({ error: 'space_exists', slug, message: 'slug already in use' });
    }

    const now = new Date().toISOString();
    const dirPath = path.join(SPACES_ROOT, slug);

    // Ensure the directory does not already exist
    if (fsSync.existsSync(dirPath)) {
      return res.status(409).json({
        error: 'dir_exists',
        slug,
        message: 'directory already exists on disk',
      });
    }

    // Create directory
    await fs.mkdir(dirPath, { recursive: true });

    // Seed starter index.html
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
    };

    spaces.push(spaceRecord);
    await saveSpacesMeta(spaces);

    res.status(201).json({
      ok: true,
      space: spaceRecord,
    });
  } catch (err) {
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

    // Use express.static with the space directory as the root.
    // Because this handler is mounted at /p/:slug, Express strips that part
    // from req.url before it reaches this function, so /p/demo-hud/index.html
    // becomes /index.html here.
    const staticMiddleware = express.static(space.dirPath, {
      fallthrough: false, // if file is missing, throw 404 instead of calling next()
    });

    return staticMiddleware(req, res, (err) => {
      if (err) return next(err);
      // If nothing handled it, send 404
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
      console.log(`[portals-iframes] admin routes ${
        ADMIN_TOKEN ? 'enabled' : 'DISABLED (no ADMIN_TOKEN)'
      }`);
    });
  })
  .catch((err) => {
    console.error('[fatal] failed to initialize spaces root', err);
    process.exit(1);
  });

