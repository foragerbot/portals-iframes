// server/cleanup.js
import { TOKENS_META_PATH, SESSIONS_META_PATH, SESSION_MAX_AGE_DAYS } from './config.js';
import { readJsonArray, writeJsonArray } from './stores/jsonStore.js';
import { pruneHistoryAllSpaces } from './history/pruneHistory.js';

async function runHistoryPrune() {
  const dryRun = String(process.env.HISTORY_PRUNE_DRY_RUN || '0') === '1';

  const result = await pruneHistoryAllSpaces({
    dryRun,
    // optional overrides:
    // keepLast: 50,
    // keepFirst: true,
    // deletedRetentionDays: 30,
    // keepLastDeleted: 10,
  });

  console.log('[history-prune]', JSON.stringify(result, null, 2));
}

await runHistoryPrune();
function daysAgo(num) {
  const d = new Date();
  d.setDate(d.getDate() - num);
  return d;
}

async function cleanupTokens() {
  const tokens = await readJsonArray(TOKENS_META_PATH);
  const beforeCount = tokens.length;

  const expiredCutoff = daysAgo(1);

  const kept = tokens.filter((t) => {
    const expiresAt = t.expiresAt ? new Date(t.expiresAt) : null;
    const usedAt = t.usedAt ? new Date(t.usedAt) : null;

    // If no expiresAt, keep (be conservative)
    if (!expiresAt) return true;

    // Drop tokens that expired more than 1 day ago
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

  const cutoff = daysAgo(SESSION_MAX_AGE_DAYS);

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
