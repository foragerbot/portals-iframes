// server/cleanup.js
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import fsSync from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, '..');

const TOKENS_META_PATH = path.join(ROOT_DIR, 'magicTokens.meta.json');
const SESSIONS_META_PATH = path.join(ROOT_DIR, 'sessions.meta.json');

function daysAgo(num) {
  const d = new Date();
  d.setDate(d.getDate() - num);
  return d;
}

async function readJsonArray(filePath) {
  try {
    if (!fsSync.existsSync(filePath)) return [];
    const raw = await fs.readFile(filePath, 'utf8');
    if (!raw.trim()) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('[cleanup] failed to read', filePath, err);
    return [];
  }
}

async function writeJsonArray(filePath, arr) {
  try {
    const json = JSON.stringify(arr, null, 2);
    await fs.writeFile(filePath, json, 'utf8');
  } catch (err) {
    console.error('[cleanup] failed to write', filePath, err);
    throw err;
  }
}

async function cleanupTokens() {
  const now = new Date();
  const tokens = await readJsonArray(TOKENS_META_PATH);

  const beforeCount = tokens.length;

  const kept = tokens.filter((t) => {
    const expiresAt = t.expiresAt ? new Date(t.expiresAt) : null;
    const usedAt = t.usedAt ? new Date(t.usedAt) : null;

    // If no expiresAt, keep (be conservative)
    if (!expiresAt) return true;

    // Drop tokens that expired more than 1 day ago
    const expiredCutoff = daysAgo(1);
    if (expiresAt < expiredCutoff) return false;

    // Drop tokens used more than 1 day ago
    if (usedAt && usedAt < expiredCutoff) return false;

    return true;
  });

  await writeJsonArray(TOKENS_META_PATH, kept);

  console.log(
    `[cleanup] tokens: kept ${kept.length}, removed ${beforeCount - kept.length}`
  );
}

async function cleanupSessions() {
  const sessions = await readJsonArray(SESSIONS_META_PATH);
  const beforeCount = sessions.length;

  const cutoff = daysAgo(
    Number(process.env.SESSION_MAX_AGE_DAYS || 30)
  );

  const kept = sessions.filter((s) => {
    const createdAt = s.createdAt ? new Date(s.createdAt) : null;
    if (!createdAt) return false; // drop weird ones
    return createdAt >= cutoff;
  });

  await writeJsonArray(SESSIONS_META_PATH, kept);

  console.log(
    `[cleanup] sessions: kept ${kept.length}, removed ${beforeCount - kept.length}`
  );
}

async function main() {
  console.log('[cleanup] starting cleanup tasks...');
  await cleanupTokens();
  await cleanupSessions();
  console.log('[cleanup] done.');
}

main().catch((err) => {
  console.error('[cleanup] fatal error', err);
  process.exit(1);
});
