// server/index.js
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

// Load env vars from .env (if present)
dotenv.config();

// __dirname shim for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Basic config
const PORT = process.env.PORT || 4100;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Root of repo
const ROOT_DIR = path.join(__dirname, '..');
// Where user spaces (per-tenant dirs) will live
const SPACES_ROOT = path.join(ROOT_DIR, 'spaces');

const app = express();

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

// ───────────────── Routes ─────────────────

// Simple healthcheck
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    time: new Date().toISOString(),
  });
});

// Version info – handy for debugging deployments
app.get('/api/version', (req, res) => {
  res.json({
    name: 'portals-iframes',
    version: '0.1.0',
    env: NODE_ENV,
  });
});

// Placeholder: basic listing of spaces dir (for now just for you)
// Later this becomes authenticated + per-user.
app.get('/api/debug/spaces', (req, res) => {
  res.json({
    root: SPACES_ROOT,
    note: 'This will eventually list user spaces. For now it is just a placeholder.',
  });
});

// ───────────────── 404 / error handlers ─────────────────

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({ error: 'not_found' });
});

// Generic error handler
// (eslint-disable-next-line no-unused-vars)
app.use((err, req, res, next) => {
  console.error('[error]', err);
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || 'server_error',
  });
});

// ───────────────── Start server ─────────────────

app.listen(PORT, () => {
  console.log(
    `[portals-iframes] listening on port ${PORT} (${NODE_ENV})`
  );
  console.log(`[portals-iframes] spaces root: ${SPACES_ROOT}`);
});
