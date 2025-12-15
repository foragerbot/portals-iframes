// client/src/slugUtils.js
export function normalizeSlug(raw) {
  if (!raw) return '';
  let slug = raw.toString().trim().toLowerCase();
  slug = slug.replace(/[^a-z0-9-]/g, '-'); // anything not a-z,0-9,- => '-'
  slug = slug.replace(/-+/g, '-');        // collapse multiple dashes
  slug = slug.replace(/^-+|-+$/g, '');    // trim leading/trailing dashes
  return slug;
}

export function isValidSlug(slug) {
  return typeof slug === 'string' && /^[a-z0-9-]{3,32}$/.test(slug);
}
