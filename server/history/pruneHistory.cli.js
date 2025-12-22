#!/usr/bin/env node
import { pruneHistoryAllSpaces, pruneHistoryForSpaceSlug } from './pruneHistory.js';

function parseArgs(argv) {
  const out = { dryRun: false, spaceSlug: null, opts: {} };

  for (const raw of argv) {
    if (raw === '--dry-run' || raw === '--dryRun') out.dryRun = true;
    else if (raw.startsWith('--space=')) out.spaceSlug = raw.split('=')[1] || null;
    else if (raw.startsWith('--keepLast=')) out.opts.keepLast = Number(raw.split('=')[1]);
    else if (raw.startsWith('--keepFirst=')) out.opts.keepFirst = raw.split('=')[1];
    else if (raw.startsWith('--deletedRetentionDays=')) out.opts.deletedRetentionDays = Number(raw.split('=')[1]);
    else if (raw.startsWith('--keepLastDeleted=')) out.opts.keepLastDeleted = Number(raw.split('=')[1]);
  }

  out.opts.dryRun = out.dryRun;
  return out;
}

async function main() {
  const { dryRun, spaceSlug, opts } = parseArgs(process.argv.slice(2));

  const started = new Date().toISOString();
  console.log(`[history-prune] start ${started} dryRun=${dryRun} space=${spaceSlug || 'ALL'}`);

  let result;
  if (spaceSlug) {
    result = await pruneHistoryForSpaceSlug(spaceSlug, opts);
  } else {
    result = await pruneHistoryAllSpaces(opts);
  }

  console.log(`[history-prune] result:\n${JSON.stringify(result, null, 2)}`);

  // If any per-space failed, return non-zero (so systemd alerts you)
  if (result && result.results && Array.isArray(result.results)) {
    const anyFailed = result.results.some((r) => !r || r.ok !== true);
    if (anyFailed) process.exitCode = 2;
  } else if (result && result.ok !== true) {
    process.exitCode = 2;
  }

  const ended = new Date().toISOString();
  console.log(`[history-prune] end ${ended}`);
}

main().catch((err) => {
  console.error('[history-prune] fatal', err);
  process.exit(1);
});
