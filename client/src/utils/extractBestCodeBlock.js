// src/utils/extractBestCodeBlock.js

const LANG_ALIASES = {
  js: 'javascript',
  mjs: 'javascript',
  jsx: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  htm: 'html',
};

function normalizeLang(lang) {
  const key = String(lang || '').trim().toLowerCase();
  return LANG_ALIASES[key] || key;
}

/**
 * Returns the first fenced code block's inner content if present,
 * otherwise returns the original string.
 *
 * Examples it strips:
 * ```html\n ... \n```
 * ```\n ... \n```
 */
export function stripCodeFences(text) {
  const src = String(text ?? '');

  // First fenced block (most common case)
  const m = src.match(/```([a-zA-Z0-9_-]*)\s*\n([\s\S]*?)```/);
  if (m && typeof m[2] === 'string') {
    return m[2].replace(/\s+$/g, ''); // trim only the end
  }

  // Fallback: if someone gave only fences without newline patterns
  // (rare, but cheap to handle)
  const stripped = src
    .replace(/^```[a-zA-Z0-9_-]*\s*\n?/, '')
    .replace(/```$/, '');

  return stripped;
}

/**
 * Extracts fenced code blocks (```lang ... ```) from a markdown string and picks the best match.
 * - If preferredLang is provided, picks the first matching language (with common aliases).
 * - Otherwise picks the first fenced block.
 *
 * Returns: { lang, code } or null
 */
export function extractBestCodeBlock(markdown, preferredLang) {
  const text = String(markdown || '');
  const pref = normalizeLang(preferredLang);

  const blocks = [];
  const re = /```([a-zA-Z0-9_-]*)\s*\n([\s\S]*?)```/g;

  let m;
  while ((m = re.exec(text)) !== null) {
    const lang = normalizeLang(m[1] || '');
    const code = String(m[2] || '').replace(/\s+$/g, ''); // trim only the end
    blocks.push({ lang, code });
  }

  if (!blocks.length) return null;

  if (pref) {
    const hit = blocks.find((b) => b.lang === pref);
    if (hit) return hit;

    // If caller says "text", accept first block
    if (pref === 'text') return blocks[0];
  }

  return blocks[0];
}
