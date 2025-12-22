import fs from 'fs/promises';
import path from 'path';
import { readJsonArray, writeJsonArray } from '../stores/jsonStore.js';
import {
  SPACES_META_PATH,
  FILES_META_PATH,
  FILE_VERSIONS_META_PATH,
  HISTORY_DIR_NAME,
  HISTORY_BLOBS_DIR_NAME,
} from '../config.js';

function safeNum(n, fallback) {
  const x = Number(n);
  return Number.isFinite(x) ? x : fallback;
}

function parseIsoMs(iso) {
  const t = new Date(iso).getTime();
  return Number.isFinite(t) ? t : 0;
}

function isShaFilename(name) {
  return typeof name === 'string' && /^[a-f0-9]{64}$/.test(name);
}

function pickKeepSetForFile(versionsAsc, keepLast, keepFirst) {
  const keep = new Set();
  if (!versionsAsc.length) return keep;

  if (keepFirst) {
    keep.add(versionsAsc[0].id);
  }

  const start = Math.max(0, versionsAsc.length - keepLast);
  for (let i = start; i < versionsAsc.length; i += 1) {
    keep.add(versionsAsc[i].id);
  }

  return keep;
}

/**
 * Prune rules:
 * - Active files: keep FIRST version (optional) + last N versions
 * - Deleted files:
 *    - if deleted older than retentionDays: drop ALL versions
 *    - else keep last N_deleted (and optionally first)
 * - After pruning version records: delete unreferenced blobs in .history/blobs
 */
export async function pruneHistoryForSpaceSlug(spaceSlug, opts = {}) {
  const nowIso = new Date().toISOString();

  const keepLast = safeNum(opts.keepLast, safeNum(process.env.HISTORY_PRUNE_KEEP_LAST, 50));
  const keepFirst = String(opts.keepFirst ?? process.env.HISTORY_PRUNE_KEEP_FIRST ?? '1') !== '0';

  const deletedRetentionDays = safeNum(
    opts.deletedRetentionDays,
    safeNum(process.env.HISTORY_PRUNE_DELETED_RETENTION_DAYS, 30)
  );
  const keepLastDeleted = safeNum(
    opts.keepLastDeleted,
    safeNum(process.env.HISTORY_PRUNE_KEEP_LAST_DELETED, 10)
  );

  const dryRun = Boolean(opts.dryRun);

  const spaces = await readJsonArray(SPACES_META_PATH);
  const space = spaces.find((s) => s && s.slug === spaceSlug && s.status === 'active');
  if (!space) {
    return { ok: false, spaceSlug, error: 'space_not_found' };
  }

  const [filesMeta, versionsMeta] = await Promise.all([
    readJsonArray(FILES_META_PATH),
    readJsonArray(FILE_VERSIONS_META_PATH),
  ]);

  const files = filesMeta.filter((f) => f && f.spaceSlug === spaceSlug);
  const versions = versionsMeta.filter((v) => v && v.spaceSlug === spaceSlug);

  const versionsByFile = new Map();
  for (const v of versions) {
    const arr = versionsByFile.get(v.fileId) || [];
    arr.push(v);
    versionsByFile.set(v.fileId, arr);
  }

  // Decide which version IDs to keep
  const keepVersionIds = new Set();
  const purgePointerFileIds = new Set(); // long-deleted files whose pointers we should clear

  const nowMs = Date.now();
  const retentionMs = deletedRetentionDays * 24 * 60 * 60 * 1000;

  for (const f of files) {
    const fileVers = (versionsByFile.get(f.id) || []).slice().sort((a, b) => parseIsoMs(a.createdAt) - parseIsoMs(b.createdAt));
    if (!fileVers.length) continue;

    const isDeleted = f.deletedAt != null;
    const deletedOld =
      isDeleted && parseIsoMs(f.deletedAt) > 0 && (nowMs - parseIsoMs(f.deletedAt)) > retentionMs;

    if (deletedOld) {
      // drop everything for long-deleted files
     purgePointerFileIds.add(f.id);

      continue;
    }

    const keepN = isDeleted ? keepLastDeleted : keepLast;
    const keepSet = pickKeepSetForFile(fileVers, keepN, keepFirst);

    for (const id of keepSet) keepVersionIds.add(id);
  }

  const versionsBefore = versionsMeta.length;
  const spaceVersionsBefore = versions.length;

  const nextVersionsMeta = versionsMeta.filter((v) => {
    if (!v || v.spaceSlug !== spaceSlug) return true;
    return keepVersionIds.has(v.id);
  });

  const spaceVersionsAfter = nextVersionsMeta.filter((v) => v && v.spaceSlug === spaceSlug).length;

  // Clear file pointers for long-deleted files so their blobs can be GC'ed
  let filePointersCleared = 0;
  const nextFilesMeta = filesMeta.map((f) => {
    if (!f || f.spaceSlug !== spaceSlug) return f;
    if (!purgePointerFileIds.has(f.id)) return f;

    if (f.currentSha256 == null && f.currentVersionId == null) return f;

    filePointersCleared += 1;
    return {
      ...f,
      currentSha256: null,
      currentVersionId: null,
      updatedAt: nowIso,
    };
  });

  // Compute referenced SHAs within this space from kept versions (+ file pointers as belt+suspenders)
  const referencedShas = new Set();

  for (const v of nextVersionsMeta) {
    if (v && v.spaceSlug === spaceSlug && v.sha256) referencedShas.add(v.sha256);
  }
  // Use post-prune file meta (so purged files don't keep blobs alive)
  for (const f of nextFilesMeta) {
    if (f && f.spaceSlug === spaceSlug && f.currentSha256) referencedShas.add(f.currentSha256);
  }

  // GC blobs
  const blobsDir = path.join(space.dirPath, HISTORY_DIR_NAME, HISTORY_BLOBS_DIR_NAME);

  let blobEntries = [];
  try {
    blobEntries = await fs.readdir(blobsDir, { withFileTypes: true });
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    blobEntries = [];
  }

  let blobsRemoved = 0;
  let bytesRemoved = 0;

  for (const ent of blobEntries) {
    if (!ent.isFile()) continue;
    if (!isShaFilename(ent.name)) continue;

    const sha = ent.name;
    if (referencedShas.has(sha)) continue;

    const full = path.join(blobsDir, ent.name);

    if (!dryRun) {
      const st = await fs.stat(full).catch(() => null);
      if (st && st.size) bytesRemoved += st.size;

      await fs.unlink(full).catch(() => {});
    }

    blobsRemoved += 1;
  }

  const versionsRemovedInSpace = spaceVersionsBefore - spaceVersionsAfter;

  if (!dryRun) {
    await writeJsonArray(FILE_VERSIONS_META_PATH, nextVersionsMeta);
    if (filePointersCleared > 0) {
      await writeJsonArray(FILES_META_PATH, nextFilesMeta);
    }
  }

  return {
    ok: true,
    dryRun,
    spaceSlug,
    keepLast,
    keepFirst,
    deletedRetentionDays,
    keepLastDeleted,
    versionsBefore,
    versionsAfter: nextVersionsMeta.length,
    spaceVersionsBefore,
    spaceVersionsAfter,
    versionsRemovedInSpace,
    blobsRemoved,
    bytesRemoved,
    filePointersCleared,
  };
}

export async function pruneHistoryAllSpaces(opts = {}) {
  const spaces = await readJsonArray(SPACES_META_PATH);
  const active = spaces.filter((s) => s && s.status === 'active');

  const results = [];
  for (const s of active) {
    // eslint-disable-next-line no-await-in-loop
    const r = await pruneHistoryForSpaceSlug(s.slug, opts);
    results.push(r);
  }

  return { ok: true, count: results.length, results };
}
