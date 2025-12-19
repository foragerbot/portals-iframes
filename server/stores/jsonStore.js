// server/stores/jsonStore.js
import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import crypto from 'crypto';

export async function readJsonArray(filePath) {
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

async function atomicWriteFile(filePath, data) {
  // Ensure parent directory exists
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  // Write to a temp file in the same directory, then rename (atomic on most filesystems)
  const tmp = `${filePath}.tmp.${process.pid}.${crypto.randomBytes(6).toString('hex')}`;
  await fs.writeFile(tmp, data, 'utf8');
  await fs.rename(tmp, filePath);
}

export async function writeJsonArray(filePath, arr) {
  try {
    const json = JSON.stringify(arr, null, 2);
    await atomicWriteFile(filePath, json);
  } catch (err) {
    console.error('[meta] failed to write', filePath, err);
    throw err;
  }
}
