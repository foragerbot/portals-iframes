import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import {
  getMe,
  getSpaceFiles,
  getSpaceFile,
  saveSpaceFile,
  getSpaceUsage,
  callSpaceGpt,
  startMagicLink,
  deleteSpaceFile,
  renameSpaceFile,
  uploadSpaceAssets,
  deleteSpaceAsset,
  requestWorkspace,
  adminGetSpaceRequests,
  adminApproveSpaceRequest,
  adminRejectSpaceRequest
} from './api.js';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

function useMe() {
  const [me, setMe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getMe();
      setMe(data);
    } catch (err) {
      if (err.status === 401) {
        setMe(null);
      } else {
        console.error(err);
        setError(err);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { me, loading, error, refresh };
}

function LoginPage() {
  const [email, setEmail] = useState('');
  const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e) => {
    e.preventDefault();
    if (!email) return;
    setBusy(true);
    setStatus('');
    try {
      await startMagicLink(email);
      setStatus('Magic link sent. Check your email and click the link to sign in.');
    } catch (err) {
      console.error(err);
      setStatus(err.payload?.message || 'Failed to send magic link.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card">
        <h1>Sign in to Portals iFrames @ Jawn.Bot</h1>
        <p>
          Enter your email where we can send a login link. Click the link in the email to open your iFrame builder workspace.
        </p>
        <form onSubmit={onSubmit}>
          <input
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            required
          />
          <button className="button primary" type="submit" disabled={busy}>
            {busy ? 'Sending…' : 'Send magic link'}
          </button>
        </form>
        <div className="login-status">{status}</div>
      </div>
    </div>
  );
}

function LayoutShell({ me, usage, children }) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header-title">
          <h1>Portals iFrames @ Jawn.Bot</h1>
          <span>Custom Portals iFrame Builder</span>
        </div>
        <div className="app-header-right">
          {usage && (
            <div className="badge-pill">
              Space: {usage.slug} · {usage.usedMb.toFixed(2)} / {usage.quotaMb} MB
            </div>
          )}
          {me ? (
            <div className="badge-pill ok">{me.user.email}</div>
          ) : (
            <div className="badge-pill">Not signed in</div>
          )}
        </div>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}

function Sidebar({
  spaces,
  activeSlug,
  onSelect,
  usage,
  showFiles,
  showEditor,
  showGpt,
  onToggleFiles,
  onToggleEditor,
  onToggleGpt,
  onUsageRefresh
}) {
  const [assets, setAssets] = useState([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [assetCopyStatus, setAssetCopyStatus] = useState('');

  const fileInputRef = useRef(null);

  const loadAssets = useCallback(
    async (slug) => {
      if (!slug) {
        setAssets([]);
        return;
      }
      setAssetsLoading(true);
      try {
        // list files under "assets" subdir
        const data = await getSpaceFiles(slug, 'assets');
        const items = (data.items || []).filter((i) => !i.isDir);
        setAssets(items);
      } catch (err) {
        if (err.status === 404) {
          // assets directory may not exist yet
          setAssets([]);
        } else {
          console.error(err);
        }
      } finally {
        setAssetsLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (activeSlug) {
      loadAssets(activeSlug);
    } else {
      setAssets([]);
    }
  }, [activeSlug, loadAssets]);

  const handleUploadClick = () => {
    if (!activeSlug) {
      window.alert('Select a space first.');
      return;
    }
    fileInputRef.current?.click();
  };

  const handleFilesSelected = async (e) => {
    const fileList = Array.from(e.target.files || []);
    if (!fileList.length || !activeSlug) {
      e.target.value = '';
      return;
    }

    setUploading(true);
    try {
      await uploadSpaceAssets(activeSlug, fileList, 'assets');
      await loadAssets(activeSlug);
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to upload assets. Check console for details.');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleDeleteAsset = async (relPath) => {
    if (!activeSlug) return;
    if (!window.confirm(`Delete asset "${relPath}"? This cannot be undone.`)) return;

    try {
      await deleteSpaceAsset(activeSlug, relPath);
      await loadAssets(activeSlug);
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to delete asset. Check console for details.');
    }
  };

  const handleCopyAssetPath = async (relPath) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(relPath);
        setAssetCopyStatus('Copied!');
        setTimeout(() => setAssetCopyStatus(''), 1500);
      } else {
        window.prompt('Copy asset path:', relPath);
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to copy asset path. Here it is:\n\n' + relPath);
    }
  };

  return (
    <aside className="app-sidebar">
      {/* SPACES */}
      <div className="sidebar-section">
        <h2>Spaces</h2>
        {spaces.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            No spaces yet. Ask admin.
          </div>
        ) : (
          <ul className="space-list">
            {spaces.map((s) => (
              <li
                key={s.slug}
                className={
                  'space-item' + (s.slug === activeSlug ? ' active' : '')
                }
                onClick={() => onSelect(s.slug)}
              >
                <div className="space-item-name">{s.slug}</div>
                <div className="space-item-meta">
                  {s.quotaMb ?? '—'} MB quota
                  {s.slug === usage?.slug ? ` · ${usage.usedMb.toFixed(2)} MB used` : ''}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* USAGE */}
      <div className="sidebar-section">
        <h2>Usage</h2>
        {usage ? (
          <>
            <div className="usage-chip">
              <span>
                Disk {usage.usedMb.toFixed(2)} / {usage.quotaMb} MB
              </span>
              <div className="usage-bar">
                <div
                  className="usage-bar-fill"
                  style={{
                    width: `${Math.min(100, (usage.usedMb / usage.quotaMb) * 100)}%`
                  }}
                />
              </div>
            </div>
            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
              GPT {usage.gptUsage.calls} / {usage.gptUsage.dailyLimit} calls today
            </div>
          </>
        ) : (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Select a space to view.
          </div>
        )}
      </div>

      {/* LAYOUT */}
      <div className="sidebar-section">
        <h2>Layout</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <button
            type="button"
            className="panel-toggle"
            onClick={onToggleFiles}
          >
            {showFiles ? '« Hide files panel' : 'Show files panel »'}
          </button>
          <button
            type="button"
            className="panel-toggle"
            onClick={onToggleEditor}
          >
            {showEditor ? '« Hide editor' : 'Show editor »'}
          </button>
          <button
            type="button"
            className="panel-toggle"
            onClick={onToggleGpt}
          >
            {showGpt ? '« Hide GPT helper' : 'Show GPT helper »'}
          </button>
        </div>
      </div>

      {/* ASSETS */}
      <div className="sidebar-section">
        <h2>Assets</h2>
        <input
          type="file"
          multiple
          ref={fileInputRef}
          style={{ display: 'none' }}
          onChange={handleFilesSelected}
        />
        <button
          type="button"
          className="button small full-width"
          onClick={handleUploadClick}
          disabled={uploading || !activeSlug}
        >
          {uploading ? 'Uploading…' : 'Upload assets'}
        </button>

        <div style={{ marginTop: 8, maxHeight: 140, overflowY: 'auto' }}>
          {assetsLoading ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Loading assets…
            </div>
          ) : assets.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              No assets yet. Upload images/fonts into <code>assets/</code>.
            </div>
          ) : (
            <ul
              style={{
                listStyle: 'none',
                padding: 0,
                margin: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: 4
              }}
            >
              {assets.map((a) => {
                const relPath = `assets/${a.name}`;
                return (
                  <li key={a.name} style={{ fontSize: 11 }}>
                    <div style={{ color: 'var(--text-main)' }}>{a.name}</div>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 4
                      }}
                    >
                      <code
                        style={{
                          fontFamily:
                            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
                          fontSize: 10,
                          color: 'var(--text-muted)'
                        }}
                      >
                        {relPath}
                      </code>
                      <button
                        type="button"
                        className="asset-copy-btn"
                        onClick={() => handleCopyAssetPath(relPath)}
                        title="Copy asset path"
                      >
                        Copy
                      </button>
                      <button
            type="button"
            className="asset-delete-btn"
            onClick={() => handleDeleteAsset(relPath)}
            title="Delete asset"
          >
            ✕
          </button>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        {assetCopyStatus && (
          <div style={{ marginTop: 4, fontSize: 10, color: 'var(--text-muted)' }}>
            {assetCopyStatus}
          </div>
        )}
      </div>
    </aside>
  );
}


// NOTE: SpaceEditor now accepts onUsageRefresh, and does NOT own usage state itself.
// It calls onUsageRefresh() after save and GPT so the parent can re-fetch usage.
function SpaceEditor({ slug, showFiles, showEditor, showGpt, onUsageRefresh }) {
  const [files, setFiles] = useState([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [selectedPath, setSelectedPath] = useState('index.html');
  const [fileContent, setFileContent] = useState('');
  const [fileLoading, setFileLoading] = useState(false);
  const [saving, setSaving] = useState(false);

  const [gptPrompt, setGptPrompt] = useState('');
  const [gptResponse, setGptResponse] = useState('');
  const [gptBusy, setGptBusy] = useState(false);

  const [creatingFile, setCreatingFile] = useState(false);
  const [deletingFile, setDeletingFile] = useState(false);
  const [renamingFile, setRenamingFile] = useState(false);

  const [copyingUrl, setCopyingUrl] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');

  const loadFiles = useCallback(async () => {
    setFilesLoading(true);
    try {
      const data = await getSpaceFiles(slug, '.');
      setFiles(data.items.filter((i) => !i.isDir));
    } catch (err) {
      console.error(err);
    } finally {
      setFilesLoading(false);
    }
  }, [slug]);

  const loadFile = useCallback(
    async (path) => {
      setFileLoading(true);
      try {
        const data = await getSpaceFile(slug, path);
        setFileContent(data.content || '');
      } catch (err) {
        console.error(err);
        setFileContent('');
      } finally {
        setFileLoading(false);
      }
    },
    [slug]
  );

  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  useEffect(() => {
    if (selectedPath) {
      loadFile(selectedPath);
    }
  }, [selectedPath, loadFile]);

  const onSave = async () => {
    if (!selectedPath) return;
    setSaving(true);
    try {
      await saveSpaceFile(slug, selectedPath, fileContent);
      await loadFiles();
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setSaving(false);
    }
  };

  const onNewFile = async () => {
    const name = window.prompt('New file name (e.g. hud.html)');
    if (!name) return;

    const trimmed = name.trim();
    if (!trimmed) return;

    const ext = (trimmed.split('.').pop() || '').toLowerCase();
    const allowedExts = ['html', 'htm', 'css', 'js', 'mjs', 'json', 'txt'];
    if (!allowedExts.includes(ext)) {
      window.alert('Please use one of: .html, .css, .js, .json, .txt');
      return;
    }

    if (files.some((f) => f.name === trimmed)) {
      window.alert('A file with that name already exists.');
      return;
    }

    let defaultContent = '';
    if (ext === 'html' || ext === 'htm') {
      defaultContent = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${trimmed}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <!-- ${trimmed} -->
</body>
</html>
`;
    } else if (ext === 'css') {
      defaultContent = `/* ${trimmed} */\n`;
    } else if (ext === 'js' || ext === 'mjs') {
      defaultContent = `// ${trimmed}\n`;
    } else if (ext === 'json') {
      defaultContent = `{\n  \n}\n`;
    } else {
      defaultContent = '';
    }

    setCreatingFile(true);
    try {
      await saveSpaceFile(slug, trimmed, defaultContent);
      await loadFiles();
      setSelectedPath(trimmed);
      await loadFile(trimmed);
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to create file. Check console for details.');
    } finally {
      setCreatingFile(false);
    }
  };

  const onDeleteFile = async (name) => {
    if (!window.confirm(`Delete "${name}"? This cannot be undone.`)) return;

    setDeletingFile(true);
    try {
      await deleteSpaceFile(slug, name);
      const updatedFiles = files.filter((f) => f.name !== name);
      setFiles(updatedFiles);

      if (selectedPath === name) {
        const next = updatedFiles[0]?.name || null;
        setSelectedPath(next);
        if (next) {
          await loadFile(next);
        } else {
          setFileContent('');
        }
      }

      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to delete file. Check console for details.');
    } finally {
      setDeletingFile(false);
    }
  };

  const onRenameFile = async (oldName) => {
    const input = window.prompt('Rename file', oldName);
    if (!input) return;

    const trimmed = input.trim();
    if (!trimmed || trimmed === oldName) return;

    const ext = (trimmed.split('.').pop() || '').toLowerCase();
    const allowedExts = ['html', 'htm', 'css', 'js', 'mjs', 'json', 'txt'];
    if (!allowedExts.includes(ext)) {
      window.alert('Please use one of: .html, .css, .js, .json, .txt');
      return;
    }

    if (files.some((f) => f.name === trimmed)) {
      window.alert('A file with that name already exists.');
      return;
    }

    setRenamingFile(true);
    try {
      await renameSpaceFile(slug, oldName, trimmed);
      await loadFiles();
      if (selectedPath === oldName) {
        setSelectedPath(trimmed);
        await loadFile(trimmed);
      }
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      window.alert('Failed to rename file. Check console for details.');
    } finally {
      setRenamingFile(false);
    }
  };

  const onRunGpt = async () => {
    if (!gptPrompt.trim()) return;
    setGptBusy(true);
    setGptResponse('');
    try {
      const data = await callSpaceGpt(slug, {
        prompt: gptPrompt,
        filePath: selectedPath || undefined
      });
      setGptResponse(data.message?.content || '');
      if (onUsageRefresh) {
        onUsageRefresh();
      }
    } catch (err) {
      console.error(err);
      setGptResponse(err.payload?.message || 'GPT request failed.');
    } finally {
      setGptBusy(false);
    }
  };

  const onCopyIframeUrl = async () => {
    if (!selectedPath) return;

    const origin = window.location.origin.replace(/\/+$/, '');
    const url = `${origin}/p/${encodeURIComponent(slug)}/${encodeURIComponent(selectedPath)}`;

    try {
      setCopyingUrl(true);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(url);
      } else {
        window.prompt('Copy iframe URL:', url);
      }
      setCopyStatus('Copied!');
      setTimeout(() => setCopyStatus(''), 2000);
    } catch (err) {
      console.error(err);
      window.alert('Failed to copy URL. Here it is:\n\n' + url);
    } finally {
      setCopyingUrl(false);
    }
  };

  return (
    <div className="app-content">
      <div className="editor-shell">
        {/* Files panel */}
        {showFiles && (
          <div className="panel panel--files">
            <div className="panel-header">
              <div className="panel-header-left">
                <div className="panel-title">Files</div>
                <div className="panel-subtitle">
                  {filesLoading ? 'Loading…' : `${files.length} files`}
                </div>
              </div>
            </div>

            <div className="panel-body-files">
              <ul className="file-list">
                {files.map((f) => (
                  <li
                    key={f.name}
                    className={
                      'file-item' + (selectedPath === f.name ? ' active' : '')
                    }
                    onClick={() => setSelectedPath(f.name)}
                  >
                    <span className="file-item-name">{f.name}</span>
                    <span className="file-item-actions">
                      <button
                        type="button"
                        className="file-item-rename"
                        title="Rename file"
                        onClick={(e) => {
                          e.stopPropagation();
                          onRenameFile(f.name);
                        }}
                        disabled={renamingFile}
                      >
                        ✎
                      </button>
                      <button
                        type="button"
                        className="file-item-delete"
                        title="Delete file"
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteFile(f.name);
                        }}
                        disabled={deletingFile}
                      >
                        ✕
                      </button>
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            <div style={{ marginTop: 8 }}>
              <button
                type="button"
                className="button small full-width"
                onClick={onNewFile}
                disabled={creatingFile}
              >
                {creatingFile ? 'Creating…' : '+ New file'}
              </button>
            </div>
          </div>
        )}

        {/* Editor panel */}
        {showEditor && (
          <div className="panel panel--editor">
            <div className="panel-header">
              <div className="panel-header-left">
                <div className="panel-title">Editor</div>
                <div className="panel-subtitle">{selectedPath || 'Select a file'}</div>
              </div>
            </div>
            {fileLoading ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Loading file…</div>
            ) : (
              <>
                <textarea
                  className="editor-textarea"
                  value={fileContent}
                  onChange={(e) => setFileContent(e.target.value)}
                  spellCheck={false}
                />
                <div className="editor-actions">
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className="button primary"
                      onClick={onSave}
                      disabled={saving}
                    >
                      {saving ? 'Saving…' : 'Save file'}
                    </button>
                    <button
                      className="button small"
                      type="button"
                      onClick={onCopyIframeUrl}
                      disabled={!selectedPath || copyingUrl}
                    >
                      {copyingUrl ? 'Copying…' : 'Copy iframe URL'}
                    </button>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'right' }}>
                    {copyStatus
                      ? copyStatus
                      : (
                        <>
                          Changes live at <code>/p/{slug}/{selectedPath}</code>
                        </>
                      )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* GPT panel */}
        {showGpt && (
          <div className="panel panel--gpt">
            <div className="panel-header">
              <div className="panel-header-left">
                <div className="panel-title">GPT helper</div>
                <div className="panel-subtitle">
                  Model: gpt-4.1-mini · File: {selectedPath || 'none'}
                </div>
              </div>
            </div>
            <div className="gpt-messages">
              {gptResponse ? (
                <ReactMarkdown
                  className="gpt-markdown"
                  remarkPlugins={[remarkGfm]}
                  components={{
                    code({ node, inline, className, children, ...props }) {
                      if (inline) {
                        return (
                          <code className={className} {...props}>
                            {children}
                          </code>
                        );
                      }
                      return (
                        <pre className="gpt-code">
                          <code className={className} {...props}>
                            {children}
                          </code>
                        </pre>
                      );
                    },
                    p({ node, children, ...props }) {
                      return (
                        <p style={{ margin: '0 0 6px', fontSize: 12 }} {...props}>
                          {children}
                        </p>
                      );
                    },
                    li({ node, children, ...props }) {
                      return (
                        <li style={{ marginBottom: 4 }} {...props}>
                          {children}
                        </li>
                      );
                    }
                  }}
                >
                  {gptResponse}
                </ReactMarkdown>
              ) : (
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Ask GPT to help refactor your HUD or generate snippets. It will see the current file
                  when a path is selected.
                </div>
              )}
            </div>
            <div className="gpt-input">
              <textarea
                placeholder="e.g. “Add a pulsing border around the HUD”"
                value={gptPrompt}
                onChange={(e) => setGptPrompt(e.target.value)}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <button
                  className="button primary"
                  onClick={onRunGpt}
                  disabled={gptBusy || !gptPrompt.trim()}
                >
                  {gptBusy ? 'Thinking…' : 'Ask GPT'}
                </button>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Uses your daily GPT quota.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DashboardPage() {
  const { me, loading } = useMe();
  const navigate = useNavigate();
  const location = useLocation();

  const [activeSlug, setActiveSlug] = useState(null);
  const [usage, setUsage] = useState(null);

  // panel visibility lives here so sidebar controls it
  const [showFiles, setShowFiles] = useState(true);
  const [showEditor, setShowEditor] = useState(true);
  const [showGpt, setShowGpt] = useState(true);

  // workspace request UX
  const [requestingWorkspace, setRequestingWorkspace] = useState(false);
  const [workspaceRequestStatus, setWorkspaceRequestStatus] = useState('');

  // Redirect to /login if not logged in
  useEffect(() => {
    if (!loading && !me) {
      navigate('/login', { replace: true, state: { from: location.pathname } });
    }
  }, [me, loading, navigate, location.pathname]);

  // Auto-select first space
  useEffect(() => {
    if (me && me.spaces?.length && !activeSlug) {
      setActiveSlug(me.spaces[0].slug);
    }
  }, [me, activeSlug]);

  // Fetch usage when activeSlug changes
  const refreshUsage = useCallback(
    async (slugOverride) => {
      const slug = slugOverride || activeSlug;
      if (!slug) return;
      try {
        const data = await getSpaceUsage(slug);
        setUsage(data);
      } catch (err) {
        console.error(err);
        setUsage(null);
      }
    },
    [activeSlug]
  );

  useEffect(() => {
    if (activeSlug) {
      refreshUsage(activeSlug);
    }
  }, [activeSlug, refreshUsage]);

  if (loading) {
    return (
      <div className="login-shell">
        <div className="login-card">
          <h1>Loading…</h1>
          <p>Checking your session.</p>
        </div>
      </div>
    );
  }

  if (!me) {
    return null;
  }

    const handleRequestWorkspace = async () => {
    setWorkspaceRequestStatus('');
    setRequestingWorkspace(true);
    try {
      const data = await requestWorkspace(null);
      if (data.alreadyPending) {
        setWorkspaceRequestStatus('You already have a pending workspace request.');
      } else {
        setWorkspaceRequestStatus('Request sent. An admin will review it soon.');
      }
    } catch (err) {
      console.error(err);
      setWorkspaceRequestStatus(
        err.payload?.message || 'Failed to submit workspace request.'
      );
    } finally {
      setRequestingWorkspace(false);
    }
  };

  const spaces = me.spaces || [];

return (
  <LayoutShell me={me} usage={usage}>
    <Sidebar
      spaces={spaces}
      activeSlug={activeSlug}
      onSelect={(slug) => {
        setActiveSlug(slug);
      }}
      usage={usage}
      showFiles={showFiles}
      showEditor={showEditor}
      showGpt={showGpt}
      onToggleFiles={() => setShowFiles((v) => !v)}
      onToggleEditor={() => setShowEditor((v) => !v)}
      onToggleGpt={() => setShowGpt((v) => !v)}
      onUsageRefresh={() => refreshUsage(activeSlug)}

    />
    {activeSlug ? (
      <SpaceEditor
        slug={activeSlug}
        showFiles={showFiles}
        showEditor={showEditor}
        showGpt={showGpt}
        onUsageRefresh={() => refreshUsage(activeSlug)}
      />
      ) : (
        <div className="app-content" style={{ alignItems: 'center', justifyContent: 'center' }}>
          <div
            style={{
              fontSize: 14,
              color: 'var(--text-muted)',
              maxWidth: 360,
              textAlign: 'center',
              padding: '16px'
            }}
          >
            <div style={{ marginBottom: 8 }}>
              No spaces assigned to you yet.
            </div>
            <div style={{ marginBottom: 12 }}>
              Please request a new workspace to continue building your Portals iFrames!
            </div>
            <button
              className="button primary"
              type="button"
              onClick={handleRequestWorkspace}
              disabled={requestingWorkspace}
            >
              {requestingWorkspace ? 'Requesting…' : 'Request workspace'}
            </button>
            {workspaceRequestStatus && (
              <div
                style={{
                  marginTop: 8,
                  fontSize: 12,
                  color: 'var(--text-muted)'
                }}
              >
                {workspaceRequestStatus}
              </div>
            )}
          </div>
        </div>
      )}

  </LayoutShell>
);

}

function AdminDashboard() {
  const [adminToken, setAdminToken] = useState(() => {
    if (typeof window === 'undefined') return '';
    return localStorage.getItem('adminToken') || '';
  });
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const loadRequests = useCallback(
    async (token) => {
      if (!token) {
        setRequests([]);
        return;
      }
      setLoading(true);
      setErrorMsg('');
      try {
        const data = await adminGetSpaceRequests(token, 'pending');
        setRequests(data.requests || []);
        setStatusMsg(`Loaded ${data.requests?.length || 0} pending request(s).`);
      } catch (err) {
        console.error(err);
        setErrorMsg(err.payload?.error || 'Failed to load requests.');
      } finally {
        setLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (adminToken) {
      loadRequests(adminToken);
    }
  }, [adminToken, loadRequests]);

  const handleSaveToken = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const token = (formData.get('adminToken') || '').toString().trim();
    if (!token) return;
    setAdminToken(token);
    localStorage.setItem('adminToken', token);
    loadRequests(token);
  };

  const handleApprove = async (reqId) => {
    const req = requests.find((r) => r.id === reqId);
    if (!req) return;

    const slugInput = window.prompt(
      'Enter space slug (lowercase letters, digits, hyphens).',
      (req.email || '').split('@')[0].replace(/[^a-z0-9-]/g, '-') || ''
    );
    if (!slugInput) return;

    const slug = slugInput.trim();
    const quotaInput = window.prompt('Quota in MB (default 200):', '200');
    const quotaMb = quotaInput ? Number(quotaInput) : 200;

    try {
      setStatusMsg('Approving request...');
      await adminApproveSpaceRequest(adminToken, reqId, { slug, quotaMb });
      // Remove from local list
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg(`Approved request for ${req.email} with space "${slug}".`);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.payload?.message || 'Failed to approve request.');
    }
  };

  const handleReject = async (reqId) => {
    const req = requests.find((r) => r.id === reqId);
    if (!req) return;

    const reason = window.prompt(
      'Optional reason for rejection (shown only in logs for now):',
      ''
    );

    try {
      setStatusMsg('Rejecting request...');
      await adminRejectSpaceRequest(adminToken, reqId, reason || null);
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg(`Rejected request from ${req.email}.`);
    } catch (err) {
      console.error(err);
      setErrorMsg(err.payload?.message || 'Failed to reject request.');
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card" style={{ maxWidth: 640 }}>
        <h1>Admin · Workspace Requests</h1>
        <p style={{ marginBottom: 8 }}>
          Manage workspace requests for approved users. This view uses the same <code>ADMIN_TOKEN</code>{' '}
          that the API expects in the <code>x-admin-token</code> header.
        </p>

        <form onSubmit={handleSaveToken} style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Admin token
            <input
              name="adminToken"
              type="password"
              defaultValue={adminToken}
              style={{
                marginTop: 4,
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: '#020617',
                color: 'var(--text-main)',
                padding: '6px 10px',
                fontSize: 13
              }}
            />
          </label>
          <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', gap: 8 }}>
            <button className="button primary" type="submit">
              Save & load requests
            </button>
            <button
              className="button small"
              type="button"
              onClick={() => {
                setAdminToken('');
                localStorage.removeItem('adminToken');
                setRequests([]);
              }}
            >
              Clear token
            </button>
          </div>
        </form>

        {loading && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
            Loading pending requests…
          </div>
        )}
        {statusMsg && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 4 }}>
            {statusMsg}
          </div>
        )}
        {errorMsg && (
          <div style={{ fontSize: 12, color: '#f97373', marginBottom: 8 }}>
            {errorMsg}
          </div>
        )}

        {requests.length === 0 && !loading ? (
          <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
            No pending requests.
          </div>
        ) : (
          <div
            style={{
              marginTop: 6,
              maxHeight: 360,
              overflowY: 'auto',
              borderRadius: 8,
              border: '1px solid var(--panel-border)',
              padding: 8,
              background: 'rgba(15,23,42,0.9)'
            }}
          >
            {requests.map((r) => (
              <div
                key={r.id}
                style={{
                  padding: 8,
                  borderRadius: 6,
                  border: '1px solid var(--panel-border)',
                  marginBottom: 6,
                  fontSize: 12
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <div>
                    <strong>{r.email}</strong>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      userId: {r.userId}
                    </div>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {r.createdAt}
                  </div>
                </div>
                {r.note && (
                  <div style={{ fontSize: 12, marginBottom: 4 }}>
                    Request note: <span style={{ color: 'var(--text-main)' }}>{r.note}</span>
                  </div>
                )}
                <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                  <button
                    className="button small"
                    type="button"
                    onClick={() => handleApprove(r.id)}
                  >
                    Approve & create space
                  </button>
                  <button
                    className="button small"
                    type="button"
                    onClick={() => handleReject(r.id)}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/admin" element={<AdminDashboard />} />
      <Route path="/*" element={<DashboardPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
