const API_BASE = '';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const err = new Error(data?.error || 'Request failed');
    err.status = res.status;
    err.payload = data;
    throw err;
  }

  return data;
}

export function getMe() {
  return request('/api/me');
}

export function startMagicLink(email) {
  return request('/api/auth/magic/start', {
    method: 'POST',
    body: JSON.stringify({ email })
  });
}

export function getSpacesForUser() {
  // wrapper around /api/me; could be extended later
  return getMe();
}

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
    body: JSON.stringify({ path, content })
  });
}

export function deleteSpaceFile(slug, path) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file`, {
    method: 'DELETE',
    body: JSON.stringify({ path })
  });
}

export function renameSpaceFile(slug, from, to) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/file/rename`, {
    method: 'POST',
    body: JSON.stringify({ from, to })
  });
}

export function getSpaceUsage(slug) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/usage`);
}

export function callSpaceGpt(slug, { prompt, filePath, model = 'gpt-4.1-mini', messages = [] }) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/gpt/chat`, {
    method: 'POST',
    body: JSON.stringify({ prompt, filePath, model, messages })
  });
}

export async function uploadSpaceAssets(slug, files, subdir = 'assets') {
  const formData = new FormData();
  for (const f of files) {
    formData.append('files', f);
  }
  formData.append('subdir', subdir);

  const res = await fetch(`/api/spaces/${encodeURIComponent(slug)}/upload`, {
    method: 'POST',
    body: formData,
    credentials: 'include'
  });

  const text = await res.text();
  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!res.ok) {
    const err = new Error(data?.error || 'Upload failed');
    err.status = res.status;
    err.payload = data;
    throw err;
  }

  return data;
}

export function deleteSpaceAsset(slug, relPath) {
  return request(`/api/spaces/${encodeURIComponent(slug)}/asset`, {
    method: 'DELETE',
    body: JSON.stringify({ path: relPath })
  });
}

export function requestWorkspace(note) {
  return request('/api/spaces/request', {
    method: 'POST',
    body: JSON.stringify({ note })
  });
}
