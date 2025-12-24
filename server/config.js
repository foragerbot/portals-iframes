// server/config.js
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function stripTrailingSlashes(s) {
  return String(s || '').replace(/\/+$/, '');
}

function safeUrlOrigin(u) {
  try {
    return new URL(String(u)).origin;
  } catch {
    return null;
  }
}

function safeUrlHostname(u) {
  try {
    return new URL(String(u)).hostname;
  } catch {
    return null;
  }
}

export const ROOT_DIR = path.join(__dirname, '..');

export const NODE_ENV = process.env.NODE_ENV || 'development';
export const IS_PROD = NODE_ENV === 'production';

export const PORT = Number(process.env.PORT || 4100);

// Bind host (security hardening). Default: local-only.
// Set LISTEN_HOST=0.0.0.0 if you intentionally want to expose it.
export const LISTEN_HOST = process.env.LISTEN_HOST || '127.0.0.1';

// Legacy (keep for now; not used by Discord-admin flow)
export const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

// Optional: allow multiple pending workspace requests per user
export const MAX_PENDING_WORKSPACE_REQUESTS = Number(
  process.env.MAX_PENDING_WORKSPACE_REQUESTS || 1
);

// Where the editor/app lives (used for email links + redirects)
export const APP_BASE_URL = stripTrailingSlashes(
  process.env.APP_BASE_URL || `http://localhost:${PORT}`
);

// Where public iframes are served (used for iframe links in emails)
// IMPORTANT: in production this should be a DIFFERENT origin than APP_BASE_URL.
export const PUBLIC_IFRAME_BASE_URL = stripTrailingSlashes(
  process.env.PUBLIC_IFRAME_BASE_URL || APP_BASE_URL
);

// Derived origins/hostnames (used to enforce separation)
export const APP_ORIGIN = safeUrlOrigin(APP_BASE_URL);
export const PUBLIC_IFRAME_ORIGIN = safeUrlOrigin(PUBLIC_IFRAME_BASE_URL);

export const APP_HOSTNAME = safeUrlHostname(APP_BASE_URL);
export const PUBLIC_IFRAME_HOSTNAME = safeUrlHostname(PUBLIC_IFRAME_BASE_URL);

// ✅ Production guard: refuse to start if public overlays share the editor origin
if (IS_PROD) {
  if (!APP_ORIGIN) {
    throw new Error(`APP_BASE_URL must be a valid absolute URL in production. Got: ${APP_BASE_URL}`);
  }
  if (!PUBLIC_IFRAME_ORIGIN) {
    throw new Error(
      `PUBLIC_IFRAME_BASE_URL must be a valid absolute URL in production. Got: ${PUBLIC_IFRAME_BASE_URL}`
    );
  }
  if (APP_ORIGIN === PUBLIC_IFRAME_ORIGIN) {
    throw new Error(
      `Misconfig: PUBLIC_IFRAME_BASE_URL must be a DIFFERENT origin than APP_BASE_URL in production.\n` +
      `APP_BASE_URL=${APP_BASE_URL}\nPUBLIC_IFRAME_BASE_URL=${PUBLIC_IFRAME_BASE_URL}`
    );
  }
}

// Workspace root on disk
export const SPACES_ROOT = path.join(ROOT_DIR, 'spaces');

// JSON metadata file paths
export const SPACES_META_PATH = path.join(ROOT_DIR, 'spaces.meta.json');
export const USERS_META_PATH = path.join(ROOT_DIR, 'users.meta.json');
export const TOKENS_META_PATH = path.join(ROOT_DIR, 'magicTokens.meta.json');
export const SESSIONS_META_PATH = path.join(ROOT_DIR, 'sessions.meta.json');
export const APPROVED_USERS_PATH = path.join(ROOT_DIR, 'approvedUsers.meta.json');
export const WORKSPACE_REQUESTS_PATH = path.join(ROOT_DIR, 'workspaceRequests.meta.json');

// Portals context files
export const PORTALS_NOTES_PATH = path.join(ROOT_DIR, 'docs', 'portals-sdk-notes.md');
export const PORTALS_SDK_SOURCE_PATH =
  process.env.PORTALS_SDK_SOURCE_PATH || path.join(ROOT_DIR, 'sdk', 'portals-sdk.js');

// Email
export const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY || null;
export const SENDGRID_FROM = process.env.SENDGRID_FROM || null;
export const WORKSPACE_ADMIN_EMAIL = process.env.WORKSPACE_ADMIN_EMAIL || null;

// OpenAI
export const OPENAI_API_KEY = process.env.OPENAI_API_KEY || null;
export const DEFAULT_GPT_MODEL = process.env.OPENAI_DEFAULT_MODEL || 'gpt-4.1-mini';
export const ALLOWED_GPT_MODELS = ['gpt-4.1-mini', 'gpt-4.1-nano', 'gpt-4o-mini'];

// Upload limits
export const MAX_ASSET_FILE_SIZE = 10 * 1024 * 1024; // 10MB
export const MAX_ASSET_FILES = 10;

// GPT throttles/quotas
export const GPT_MAX_CALLS_PER_DAY = Number(process.env.GPT_MAX_CALLS_PER_DAY || 200);
export const GPT_RATE_WINDOW_MS = Number(process.env.GPT_RATE_WINDOW_MS || 60_000);
export const GPT_RATE_MAX_PER_WINDOW = Number(process.env.GPT_RATE_MAX_PER_WINDOW || 10);

// Session cleanup default (used by cleanup.js)
export const SESSION_MAX_AGE_DAYS = Number(process.env.SESSION_MAX_AGE_DAYS || 30);

// Reverse proxy (Nginx) support
export const TRUST_PROXY = process.env.TRUST_PROXY === '1';

// CSP frame-ancestors for /p/* responses (space-separated list, or leave blank for "*")
export const PORTALS_FRAME_ANCESTORS = (process.env.PORTALS_FRAME_ANCESTORS || '').trim();

// Per-file history + content-addressed blob store (disk-first)
export const FILES_META_PATH = path.join(ROOT_DIR, 'files.meta.json');
export const FILE_VERSIONS_META_PATH = path.join(ROOT_DIR, 'fileVersions.meta.json');
export const HISTORY_DIR_NAME = '.history';
export const HISTORY_BLOBS_DIR_NAME = 'blobs';

export const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || null;
export const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || null;
export const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || null;
export const DISCORD_SCOPES = (process.env.DISCORD_SCOPES || 'identify email').trim();
export const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || null;
export const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID || null;

export const DISCORD_REQUIRED_ROLE_IDS = (process.env.DISCORD_REQUIRED_ROLE_IDS || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

export const EMAIL_VERIFY_TOKENS_META_PATH = path.join(ROOT_DIR, 'emailVerifyTokens.meta.json');
export const EMAIL_VERIFY_TOKEN_TTL_HOURS = Number(process.env.EMAIL_VERIFY_TOKEN_TTL_HOURS || 48);

export const ADMIN_DISCORD_IDS = (process.env.ADMIN_DISCORD_IDS || '')
  .split(',')
  .map((s) => String(s || '').trim())
  .filter(Boolean);
