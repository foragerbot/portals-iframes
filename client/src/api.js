// client/src/api.js

const API_BASE =
  String(import.meta?.env?.VITE_API_BASE || '').replace(/\/+$/, '') ||
  window.location.origin;

function previewText(s, max = 220) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  if (!t) return '';
  return t.length > max ? t.slice(0, max) + '…' : t;
}

async function request(path, options = {}) {
  const { headers: customHeaders, ...rest } = options;
  const headers = { ...(customHeaders || {}) };

  const hasBody = rest.body != null;
  const isFormData =
    typeof FormData !== 'undefined' && rest.body instanceof FormData;

  const hasContentTypeHeader =
    Object.keys(headers).some((k) => k.toLowerCase() === 'content-type');

  if (hasBody && !isFormData && !hasContentTypeHeader) {
    headers['Content-Type'] = 'application/json';
  }

  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    credentials: 'include',
    ...rest,
    headers,
  });

  const text = await res.text();

  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const msg =
      data && typeof data === 'object' && data.error
        ? String(data.error)
        : previewText(typeof data === 'string' ? data : text) || 'Request failed';

    const err = new Error(msg);
    err.status = res.status;
    err.payload = data;
    err.url = url;
    throw err;
  }

  return data;
}

/** ───────────────── Auth ───────────────── */

export function getMe() {
  return request('/api/me');
}

export function getAuthStatus() {
  return request('/api/auth/status');
}

export function startDiscordLogin() {
  window.location.href = `${API_BASE}/api/auth/discord/start`;
}

export function logout() {
  return request('/api/auth/logout', { method: 'POST' });
}

/** ───────────────── Spaces/files ───────────────── */

export function getSpaceFiles(slug, path = '.') {
  const params = new URLSearchParams({ path });
  return request(`/api/spaces/${encodeURIComponent(slug)}/files?${params.toString()}`);
}

export function getSpaceFile(slug, path) {
  const params = new URLSearchParams({ path });
  return request(`/api/spaces/${encodeURIComponent(slug)}/file?${params.toString()}`);
}

export function saveSpaceFile(slug, path, content) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file`, {
    method: 'POST',
    body: JSON.stringify({ path, content }),
  });
}

export function deleteSpaceFile(slug, path) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file`, {
    method: 'DELETE',
    body: JSON.stringify({ path }),
  });
}

export function renameSpaceFile(slug, from, to) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file/rename`, {
    method: 'POST',
    body: JSON.stringify({ from, to }),
  });
}

export function getSpaceFileHistory(slug, { path, fileId, limit = 200 } = {}) {
  const params = new URLSearchParams();
  if (path) params.set('path', path);
  if (fileId) params.set('fileId', fileId);
  if (limit != null) params.set('limit', String(limit));
  return request(`/api/spaces/${encodeURIComponent(slug)}/file/history?${params.toString()}`);
}

export function getSpaceFileVersion(slug, versionId) {
  const params = new URLSearchParams({ versionId });
  return request(`/api/spaces/${encodeURIComponent(slug)}/file/version?${params.toString()}`);
}

export function restoreSpaceFileVersion(slug, versionId, toPath = null) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file/restore`, {
    method: 'POST',
    body: JSON.stringify({ versionId, ...(toPath ? { toPath } : {}) }),
  });
}

export function getSpaceUsage(slug) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/usage`);
}

/** ───────────────── GPT ───────────────── */

export function callSpaceGpt(slug, { prompt, filePath, fileContent, model = 'gpt-4.1-mini', messages = [] }) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/gpt/chat`, {
    method: 'POST',
    body: JSON.stringify({ prompt, filePath, fileContent, model, messages }),
  });
}

/** ───────────────── Assets ───────────────── */

export async function uploadSpaceAssets(slug, files, subdir = 'assets') {
  const formData = new FormData();
  for (const f of files) formData.append('files', f);
  formData.append('subdir', subdir);

  const url = `${API_BASE}/api/spaces/${encodeURIComponent(slug)}/upload`;
  const res = await fetch(url, { method: 'POST', body: formData, credentials: 'include' });

  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }

  if (!res.ok) {
    const msg =
      data && typeof data === 'object' && data.error
        ? String(data.error)
        : previewText(typeof data === 'string' ? data : text) || 'Upload failed';

    const err = new Error(msg);
    err.status = res.status;
    err.payload = data;
    err.url = url;
    throw err;
  }

  return data;
}

export function deleteSpaceAsset(slug, relPath) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/asset`, {
    method: 'DELETE',
    body: JSON.stringify({ path: relPath }),
  });
}

/** ───────────────── Workspace requests ───────────────── */

export function requestWorkspace(note, suggestedSlug, email = null) {
  const body = {
    ...(note != null ? { note } : {}),
    ...(suggestedSlug != null ? { suggestedSlug } : {}),
    ...(email ? { email } : {}),
  };
  return request('/api/spaces/request', { method: 'POST', body: JSON.stringify(body) });
}

/** ───────────────── Email verification ───────────────── */

export function startEmailVerification(email) {
  return request('/api/user/email/start', { method: 'POST', body: JSON.stringify({ email }) });
}

export function resendEmailVerification() {
  return request('/api/user/email/resend', { method: 'POST' });
}

/** ───────────────── Admin ───────────────── */

export function adminGetSpaceRequests(status = 'pending') {
  const params = new URLSearchParams();
  if (status) params.set('status', status);
  return request(`/api/admin/space-requests?${params.toString()}`, { method: 'GET' });
}

export function adminApproveSpaceRequest(id, { slug, quotaMb, billing } = {}) {
  return request(`/api/admin/space-requests/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    body: JSON.stringify({ slug, quotaMb, ...(billing ? { billing } : {}) }),
  });
}

export function adminRejectSpaceRequest(id, reason) {
  return request(`/api/admin/space-requests/${encodeURIComponent(id)}/reject`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  });
}

export function adminSearchUsers(q, limit = 25) {
  const params = new URLSearchParams();
  if (q != null) params.set('q', String(q));
  params.set('limit', String(limit));
  return request(`/api/admin/users/search?${params.toString()}`, { method: 'GET' });
}

export function adminCreateSpace({ slug, quotaMb = 100, ownerEmail = null, ownerUserId = null } = {}) {
  return request('/api/admin/spaces', {
    method: 'POST',
    body: JSON.stringify({
      slug,
      quotaMb,
      ...(ownerEmail ? { ownerEmail } : {}),
      ...(ownerUserId ? { ownerUserId } : {}),
    }),
  });
}

export function adminSendUserEmail(userId, { subject, text = '', html = '', from = null } = {}) {
  return request(`/api/admin/users/${encodeURIComponent(userId)}/email`, {
    method: 'POST',
    body: JSON.stringify({
      subject,
      ...(text ? { text } : {}),
      ...(html ? { html } : {}),
      ...(from ? { from } : {}),
    }),
  });
}

// Billing endpoints (if you’re using the billing console)
export function adminBillingOverview() {
  return request('/api/admin/billing/overview', { method: 'GET' });
}

export function adminUpdateUserBilling(userId, patch = {}) {
  return request(`/api/admin/users/${encodeURIComponent(userId)}/billing`, {
    method: 'POST',
    body: JSON.stringify(patch),
  });
}

export function adminExtendUserBilling(userId, days = 30) {
  return request(`/api/admin/users/${encodeURIComponent(userId)}/billing/extend`, {
    method: 'POST',
    body: JSON.stringify({ days }),
  });
}

// Audit log
export function adminGetAudit({ limit = 200, q = '', action = '', actor = '' } = {}) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  if (q) params.set('q', q);
  if (action) params.set('action', action);
  if (actor) params.set('actor', actor);
  return request(`/api/admin/audit?${params.toString()}`, { method: 'GET' });
}

// Activity feed
export function adminGetActivity({ limit = 200 } = {}) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  return request(`/api/admin/activity?${params.toString()}`, { method: 'GET' });
}

// Sessions
export function adminGetUserSessions(userId, { limit = 50 } = {}) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  return request(`/api/admin/users/${encodeURIComponent(userId)}/sessions?${params.toString()}`, { method: 'GET' });
}

export function adminRevokeUserSessions(userId, { sid = null } = {}) {
  return request(`/api/admin/users/${encodeURIComponent(userId)}/sessions/revoke`, {
    method: 'POST',
    body: JSON.stringify(sid ? { sid } : {}),
  });
}

export function adminGetUserDetail(userId) {
  return request(`/api/admin/users/${encodeURIComponent(userId)}/detail`, { method: 'GET' });
}

export function adminDoctor() {
  return request('/api/admin/doctor', { method: 'GET' });
}

export function adminListEmailTemplates() {
  return request('/api/admin/email-templates', { method: 'GET' });
}

export function adminCreateEmailTemplate({ name, subject, mode = 'text', text = '', html = '' } = {}) {
  return request('/api/admin/email-templates', {
    method: 'POST',
    body: JSON.stringify({ name, subject, mode, text, html }),
  });
}

export function adminUpdateEmailTemplate(id, patch = {}) {
  return request(`/api/admin/email-templates/${encodeURIComponent(id)}`, {
    method: 'POST',
    body: JSON.stringify(patch),
  });
}

export function adminDeleteEmailTemplate(id) {
  return request(`/api/admin/email-templates/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export function adminSendEmailTemplate(id, { userId, spaceSlug = null } = {}) {
  return request(`/api/admin/email-templates/${encodeURIComponent(id)}/send`, {
    method: 'POST',
    body: JSON.stringify({ userId, ...(spaceSlug ? { spaceSlug } : {}) }),
  });
}
