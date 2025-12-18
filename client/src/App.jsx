//client/src/App.jsx

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
  adminRejectSpaceRequest,
  logout,
  adminGetApprovedUsers,
  adminAddApprovedUser,
  adminRemoveApprovedUser,
} from './api.js';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { normalizeSlug, isValidSlug } from './slugUtils'; // ⬅️ ADD THIS
import { extractBestCodeBlock, stripCodeFences } from './utils/extractBestCodeBlock';

// at the top of App.jsx (or a separate file imported into it)
import hljs from 'highlight.js/lib/core';
import javascript from 'highlight.js/lib/languages/javascript';
import xml from 'highlight.js/lib/languages/xml'; // html
import cssLang from 'highlight.js/lib/languages/css';
import jsonLang from 'highlight.js/lib/languages/json';

hljs.registerLanguage('javascript', javascript);
hljs.registerLanguage('js', javascript);
hljs.registerLanguage('html', xml);
hljs.registerLanguage('xml', xml);
hljs.registerLanguage('css', cssLang);
hljs.registerLanguage('json', jsonLang);


const IFRAME_ORIGIN =
  import.meta.env.VITE_IFRAME_ORIGIN ||
  window.location.origin.replace(/\/+$/, '');

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
        <h1>Sign in to Portals iFrame Builder</h1>
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

function LayoutShell({ me, usage, onLogout, children }) {
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header-title">
          <h1>Portals iFrame Builder</h1>
          <span>Custom Builds & Page Hosting</span>
        </div>
        <div className="app-header-right">
          {usage && (
            <div className="badge-pill">
              Space: {usage.slug} · {usage.usedMb.toFixed(2)} / {usage.quotaMb} MB
            </div>
          )}

          {me ? (
            <div className="app-header-user">
              <button
                type="button"
                className="badge-pill ok badge-pill--clickable"
                onClick={() => setUserMenuOpen((open) => !open)}
              >
                <span className="badge-pill-label">{me.user.email}</span>
                <span className="badge-pill-caret">▾</span>
              </button>

              {userMenuOpen && (
                <div className="user-menu">
                  <button
                    type="button"
                    className="user-menu-item"
                    onClick={() => {
                      setUserMenuOpen(false);
                      onLogout && onLogout();
                    }}
                  >
                    Logout
                  </button>
                </div>
              )}
            </div>
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
}) {
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
                  {s.slug === usage?.slug
                    ? ` · ${usage.usedMb.toFixed(2)} MB used`
                    : ''}
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
                    width: `${Math.min(
                      100,
                      (usage.usedMb / usage.quotaMb) * 100
                    )}%`,
                  }}
                />
              </div>
            </div>
            <div
              style={{
                marginTop: 6,
                fontSize: 11,
                color: 'var(--text-muted)',
              }}
            >
              GPT {usage.gptUsage.calls} / {usage.gptUsage.dailyLimit} calls
              today
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
    </aside>
  );
}

function AssetsPanel({ slug, onUsageRefresh, onAssetCountChange }) {
  const [assets, setAssets] = useState([]);
  const [assetsLoading, setAssetsLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState('');
  const [assetCopyStatus, setAssetCopyStatus] = useState('');

  const [assetPreviewOpen, setAssetPreviewOpen] = useState(false);
  const [assetPreviewUrl, setAssetPreviewUrl] = useState('');
  const [assetPreviewName, setAssetPreviewName] = useState('');
  const [assetPreviewKey, setAssetPreviewKey] = useState(0);

  const [activeIndex, setActiveIndex] = useState(0); // for keyboard nav

  const fileInputRef = useRef(null);

  const loadAssets = useCallback(async () => {
    if (!slug) {
      setAssets([]);
      onAssetCountChange?.(0);
      setActiveIndex(0);
      return;
    }
    setAssetsLoading(true);
    try {
      const data = await getSpaceFiles(slug, 'assets');
      const items = (data.items || []).filter((i) => !i.isDir);
      setAssets(items);
      onAssetCountChange?.(items.length);

      setActiveIndex((prev) => {
        if (!items.length) return 0;
        if (prev < 0) return 0;
        if (prev >= items.length) return items.length - 1;
        return prev;
      });
    } catch (err) {
      if (err.status === 404) {
        setAssets([]);
        onAssetCountChange?.(0);
        setActiveIndex(0);
      } else {
        console.error(err);
      }
    } finally {
      setAssetsLoading(false);
    }
  }, [slug, onAssetCountChange]);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const handleUploadClick = () => {
    if (!slug) {
      window.alert('Select a space first.');
      return;
    }
    fileInputRef.current?.click();
  };

  const handleFilesSelected = async (e) => {
    const fileList = Array.from(e.target.files || []);
    if (!fileList.length || !slug) {
      e.target.value = '';
      return;
    }

    const count = fileList.length;
    setUploading(true);
    setUploadStatus(`Uploading ${count} file${count !== 1 ? 's' : ''}…`);
    try {
      await uploadSpaceAssets(slug, fileList, 'assets');
      await loadAssets();
      onUsageRefresh?.();
      setUploadStatus(`Uploaded ${count} file${count !== 1 ? 's' : ''}.`);
      setTimeout(() => setUploadStatus(''), 3000);
    } catch (err) {
      console.error(err);
      setUploadStatus('Failed to upload assets.');
      window.alert('Failed to upload assets. Check console for details.');
    } finally {
      setUploading(false);
      e.target.value = '';
    }
  };

  const handleDeleteAsset = async (relPath) => {
    if (!slug) return;
    if (!window.confirm(`Delete asset "${relPath}"? This cannot be undone.`)) return;

    try {
      await deleteSpaceAsset(slug, relPath);
      await loadAssets();
      onUsageRefresh?.();
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

  const getAssetKind = (name) => {
    const ext = (name.split('.').pop() || '').toLowerCase();
    const imgExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'avif'];
    const videoExts = ['mp4', 'webm', 'mov', 'm4v'];
    const audioExts = ['mp3', 'wav', 'ogg', 'm4a'];
    if (imgExts.includes(ext)) return 'image';
    if (videoExts.includes(ext)) return 'video';
    if (audioExts.includes(ext)) return 'audio';
    return 'other';
  };

  const openPreview = (relPath, name) => {
    if (!slug) return;
    const url = `${IFRAME_ORIGIN}/p/${encodeURIComponent(
      slug
    )}/${encodeURIComponent(relPath)}`;
    setAssetPreviewUrl(url);
    setAssetPreviewName(name);
    setAssetPreviewKey((k) => k + 1);
    setAssetPreviewOpen(true);
  };

  const closePreview = () => {
    setAssetPreviewOpen(false);
  };

  const handleAssetListKeyDown = (e) => {
    if (!assets.length) return;

    let idx = activeIndex;
    if (idx < 0 || idx >= assets.length) idx = 0;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const next = Math.min(assets.length - 1, idx + 1);
      setActiveIndex(next);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const next = Math.max(0, idx - 1);
      setActiveIndex(next);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      const asset = assets[idx];
      if (!asset) return;
      const relPath = `assets/${asset.name}`;
      openPreview(relPath, asset.name);
    }
  };

  return (
    <>
      <div className="files-assets">
        <div className="files-assets-header">Assets</div>

        <input
          type="file"
          multiple
          ref={fileInputRef}
          style={{ display: 'none' }}
          onChange={handleFilesSelected}
        />

      <div className="files-assets-list">
          {assetsLoading ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              Loading assets…
            </div>
          ) : assets.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              No assets yet. Upload into <code>assets/</code>.
            </div>
          ) : (
            <ul
              style={{
                listStyle: 'none',
                padding: 0,
                margin: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
              }}
              tabIndex={0}
              onKeyDown={handleAssetListKeyDown}
            >
              {assets.map((a, index) => {
                const relPath = `assets/${a.name}`;
                const isActive = index === activeIndex;
                return (
                  <li
                    key={a.name}
                    className={`asset-item${isActive ? ' active' : ''}`}
                    style={{ fontSize: 11 }}
                    onClick={() => setActiveIndex(index)}
                  >
                    <div style={{ color: 'var(--text-main)' }}>{a.name}</div>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 4,
                      }}
                    >
                      <code
                        style={{
                          fontFamily:
                            "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace",
                          fontSize: 10,
                          color: 'var(--text-muted)',
                          flex: '1 1 auto',
                          minWidth: 0,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
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
                        className="asset-preview-btn"
                        onClick={() => openPreview(relPath, a.name)}
                        title="Preview asset"
                      >
                        Preview
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
          <div
            style={{ marginTop: 4, fontSize: 10, color: 'var(--text-muted)' }}
          >
            {assetCopyStatus}
          </div>
        )}

      <div className="files-assets-footer">
          <button
            type="button"
            className="button small full-width"
            onClick={handleUploadClick}
            disabled={uploading || !slug}
          >
            {uploading ? 'Uploading…' : 'Upload assets'}
          </button>
        </div>

        {uploadStatus && (
          <div
            style={{
              marginTop: 4,
              fontSize: 11,
              color: 'var(--text-muted)',
            }}
          >
            {uploadStatus}
          </div>
        )}
      </div>

      {assetPreviewOpen && assetPreviewUrl && (
        <div className="preview-modal-backdrop" onClick={closePreview}>
          <div
            className="preview-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="preview-modal-header">
              <div>
                <div className="preview-modal-title">Asset preview</div>
                <div className="preview-modal-subtitle">
                  /p/{slug}/{assetPreviewName}
                </div>
              </div>
              <button
                type="button"
                className="preview-modal-close"
                onClick={closePreview}
                aria-label="Close asset preview"
              >
                ×
              </button>
            </div>
            <div className="preview-modal-body">
              {(() => {
                const kind = getAssetKind(assetPreviewName);
                if (kind === 'image') {
                  return (
                    <img
                      key={assetPreviewKey}
                      src={assetPreviewUrl}
                      alt={assetPreviewName}
                      className="preview-modal-media"
                    />
                  );
                }
                if (kind === 'video') {
                  return (
                    <video
                      key={assetPreviewKey}
                      src={assetPreviewUrl}
                      controls
                      className="preview-modal-media"
                    />
                  );
                }
                if (kind === 'audio') {
                  return (
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: '100%',
                        padding: 16,
                      }}
                    >
                      <audio
                        key={assetPreviewKey}
                        src={assetPreviewUrl}
                        controls
                        style={{ width: '100%' }}
                      />
                    </div>
                  );
                }
                return (
                  <iframe
                    key={assetPreviewKey}
                    src={assetPreviewUrl}
                    title={`Preview ${assetPreviewName}`}
                    className="preview-modal-media"
                  />
                );
              })()}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function SpaceEditor({
  slug,
  showFiles,
  showEditor,
  showGpt,
  onUsageRefresh,
  onDirtyChange,
  usage,
}) {
  const [filesView, setFilesView] = useState('files');
  const [assetCount, setAssetCount] = useState(0);
  const [files, setFiles] = useState([]);
  const [filesLoading, setFilesLoading] = useState(false);
  const [selectedPath, setSelectedPath] = useState('index.html');
  const [fileContent, setFileContent] = useState('');
  const [fileLoading, setFileLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  // GPT state
  const [gptPrompt, setGptPrompt] = useState('');
  const [gptBusy, setGptBusy] = useState(false);
  const [gptHistory, setGptHistory] = useState([]); // [{role, content}]
  const [gptError, setGptError] = useState(null);
  const [gptMeta, setGptMeta] = useState({
    model: null,
    sdkIncluded: false,
    truncated: false,
  });

  const [creatingFile, setCreatingFile] = useState(false);
  const [deletingFile, setDeletingFile] = useState(false);
  const [renamingFile, setRenamingFile] = useState(false);

  const [copyingUrl, setCopyingUrl] = useState(false);
  const [copyStatus, setCopyStatus] = useState('');

  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewReloadKey, setPreviewReloadKey] = useState(0);

  const bothCodePanels = showEditor && showGpt;
  const [editorFontSize, setEditorFontSize] = useState(12);
  const [gptFontSize, setGptFontSize] = useState(12);


  // themes
  const [editorTheme, setEditorTheme] = useState(() => {
    if (typeof window === 'undefined') return 'default';
    return localStorage.getItem('editorTheme') || 'default';
  });

  const [gptTheme, setGptTheme] = useState(() => {
    if (typeof window === 'undefined') return 'default';
    return localStorage.getItem('gptTheme') || 'default';
  });

  const gptMessagesRef = useRef(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('editorTheme', editorTheme);
    }
  }, [editorTheme]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('gptTheme', gptTheme);
    }
  }, [gptTheme]);

  // Scroll GPT messages to bottom when history/error changes
  useEffect(() => {
    if (gptMessagesRef.current) {
      gptMessagesRef.current.scrollTop = gptMessagesRef.current.scrollHeight;
    }
  }, [gptHistory, gptError]);

  const loadFiles = useCallback(async () => {
    setFilesLoading(true);
    try {
      const data = await getSpaceFiles(slug, '.');
      setFiles((data.items || []).filter((i) => !i.isDir));
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
        setHasUnsavedChanges(false);
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

  // Warn if trying to close/refresh tab with unsaved changes
  useEffect(() => {
    const handleBeforeUnload = (e) => {
      if (!hasUnsavedChanges) return;
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasUnsavedChanges]);

  // Report dirty state up to DashboardPage
  useEffect(() => {
    onDirtyChange?.(hasUnsavedChanges);
  }, [hasUnsavedChanges, onDirtyChange]);

  const handleSelectFile = (nextPath) => {
    if (nextPath === selectedPath) return;
    if (hasUnsavedChanges) {
      const ok = window.confirm(
        `You have unsaved changes in "${selectedPath}". Switch files and discard them?`
      );
      if (!ok) return;
    }
    setSelectedPath(nextPath);
    // reset GPT context when switching files
    setGptHistory([]);
    setGptError(null);
    setGptMeta({ model: null, sdkIncluded: false, truncated: false });
  };

  const onSave = async () => {
    if (!selectedPath) return;
    setSaving(true);
    try {
      await saveSpaceFile(slug, selectedPath, fileContent);
      await loadFiles();
      setHasUnsavedChanges(false);
      onUsageRefresh?.();
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
      onUsageRefresh?.();
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
          setHasUnsavedChanges(false);
        }
      }

      onUsageRefresh?.();
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
      onUsageRefresh?.();
    } catch (err) {
      console.error(err);
      window.alert('Failed to rename file. Check console for details.');
    } finally {
      setRenamingFile(false);
    }
  };

  // GPT quota info from usage
  const gptUsage = usage?.gptUsage || null;
  const gptCalls = typeof gptUsage?.calls === 'number' ? gptUsage.calls : 0;
  const gptDailyLimit =
    typeof gptUsage?.dailyLimit === 'number' ? gptUsage.dailyLimit : null;
  const gptQuotaReached =
    gptDailyLimit !== null && gptCalls >= gptDailyLimit;

  const onRunGpt = async () => {
  if (!gptPrompt.trim() || gptQuotaReached || gptBusy) return;

  const promptText = gptPrompt.trim();
  const historyToSend = gptHistory.slice(-10); // prior turns only

  setGptBusy(true);
  setGptError(null);
  setGptPrompt(''); // clear textarea immediately

  // Optimistically append the user message to the chat
  setGptHistory((prev) => {
    const next = [...prev, { role: 'user', content: promptText }];
    return next.slice(-50);
  });

  try {
    const data = await callSpaceGpt(slug, {
      prompt: promptText,
      filePath: selectedPath || undefined,
      fileContent: fileContent || '',
      messages: historyToSend,
    });

    const content = data.message?.content || '';

    // Append GPT reply
    setGptHistory((prev) => {
      const next = [...prev, { role: 'assistant', content }];
      return next.slice(-50);
    });

    setGptMeta({
      model: data.model,
      sdkIncluded: !!data.sdkIncluded,
      truncated: !!data.fileContextTruncated,
    });

    setGptError(null);
    onUsageRefresh?.();
  } catch (err) {
    console.error(err);
    const status = err.status;
    const code = err.payload?.error;

    let message =
      err.payload?.message || 'GPT request failed.';

    if (status === 429 && code === 'gpt_quota_exceeded') {
      message =
        err.payload?.message ||
        'Daily GPT limit reached for this account.';
    } else if (status === 429 && code === 'rate_limited') {
      message =
        err.payload?.message ||
        'Too many GPT requests. Try again in a moment.';
    } else if (status === 503 && code === 'gpt_disabled') {
      message =
        'GPT is disabled on this server (no API key configured).';
    }

    setGptError(message);
  } finally {
    setGptBusy(false);
  }
};


const handleGptKeyDown = (e) => {
  if (e.key === 'Enter') {
    if (e.altKey || e.shiftKey || e.metaKey || e.ctrlKey) {
      return; // newline
    }
    e.preventDefault();
    if (!gptBusy && !gptQuotaReached && gptPrompt.trim()) {
      onRunGpt();
    }
  }
};


  function inferPreferredLangFromPath(filePath) {
    const p = String(filePath || '').toLowerCase();
    if (p.endsWith('.html') || p.endsWith('.htm')) return 'html';
    if (p.endsWith('.css')) return 'css';
    if (p.endsWith('.json')) return 'json';
    if (p.endsWith('.js') || p.endsWith('.mjs')) return 'javascript';
    return 'text';
  }

  const getLastAssistantContent = useCallback(() => {
    for (let i = gptHistory.length - 1; i >= 0; i -= 1) {
      const msg = gptHistory[i];
      if (msg && msg.role === 'assistant' && typeof msg.content === 'string') {
        return msg.content;
      }
    }
    return '';
  }, [gptHistory]);

  const onCopyGptText = async () => {
    const content = getLastAssistantContent();
    if (!content) return;

    try {
      const preferredLang = inferPreferredLangFromPath(selectedPath);
      const best = extractBestCodeBlock(content, preferredLang);

      const textToCopy =
        best?.code?.length ? best.code : stripCodeFences(content || '');

      await navigator.clipboard.writeText(textToCopy);
    } catch (err) {
      console.error(err);
    }
  };

  const onReplaceWithGpt = () => {
    const content = getLastAssistantContent();
    if (!content || !selectedPath) return;

    if (gptMeta.truncated) {
      const ok = window.confirm(
        'The file sent to GPT was truncated for context size. Its suggestion may be incomplete. Replace the entire file anyway?'
      );
      if (!ok) return;
    }

    const best = extractBestCodeBlock(content, selectedPath);
    const newContent =
      best?.code?.length ? best.code : stripCodeFences(content || '');

    if (!newContent) return;

    setFileContent(newContent);
    setHasUnsavedChanges(true);
  };

  const handleFileListKeyDown = (e) => {
    if (!files.length) return;

    const currentIndex = files.findIndex((f) => f.name === selectedPath);
    const idx = currentIndex === -1 ? 0 : currentIndex;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const nextIndex = Math.min(files.length - 1, idx + 1);
      const nextName = files[nextIndex].name;
      handleSelectFile(nextName);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      const nextIndex = Math.max(0, idx - 1);
      const nextName = files[nextIndex].name;
      handleSelectFile(nextName);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (idx >= 0 && idx < files.length) {
        const name = files[idx].name;
        handleSelectFile(name);
      }
    }
  };

  const onCopyIframeUrl = async () => {
    if (!selectedPath) return;

    const url = `${IFRAME_ORIGIN}/p/${encodeURIComponent(
      slug
    )}/${encodeURIComponent(selectedPath)}`;

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

  const handleOpenPreview = () => {
    if (!selectedPath) return;
    if (hasUnsavedChanges) {
      const ok = window.confirm(
        'You have unsaved changes. Preview will show the last saved version. Open preview anyway?'
      );
      if (!ok) return;
    }
    setPreviewReloadKey((k) => k + 1);
    setPreviewOpen(true);
  };

  const handleClosePreview = () => {
    setPreviewOpen(false);
  };

  // ───────────────── render ─────────────────
  return (
    <>
      <div className="app-content">
        <div className="editor-shell">
          {/* Files panel */}
          {showFiles && (
            <div className="panel panel--files">
              <div className="panel-header">
                <div className="panel-header-left">
                  <div className="panel-title">Files</div>
                  <div className="panel-subtitle">
                    {filesView === 'files'
                      ? filesLoading
                        ? 'Loading…'
                        : `${files.length} file${
                            files.length === 1 ? '' : 's'
                          }`
                      : `${assetCount} asset${
                          assetCount === 1 ? '' : 's'
                        }`}
                  </div>
                </div>

                <div className="panel-header-right">
                  <div className="files-toggle">
                    <button
                      type="button"
                      className={
                        'files-toggle-button' +
                        (filesView === 'files' ? ' active' : '')
                      }
                      onClick={() => setFilesView('files')}
                    >
                      Files
                    </button>
                    <button
                      type="button"
                      className={
                        'files-toggle-button' +
                        (filesView === 'assets' ? ' active' : '')
                      }
                      onClick={() => setFilesView('assets')}
                    >
                      Assets
                    </button>
                  </div>

                </div>
              </div>

              {filesView === 'files' ? (
                <>
                  <div className="panel-body-files">
                    <ul
                      className="file-list"
                      tabIndex={0}
                      onKeyDown={handleFileListKeyDown}
                    >
                      {files.map((f) => (
                        <li
                          key={f.name}
                          className={
                            'file-item' +
                            (selectedPath === f.name ? ' active' : '')
                          }
                          onClick={() => handleSelectFile(f.name)}
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
                </>
              ) : (
                <AssetsPanel
                  slug={slug}
                  onUsageRefresh={onUsageRefresh}
                  onAssetCountChange={setAssetCount}
                />
              )}
            </div>
          )}

          {/* Editor panel */}
          {showEditor && (
            <div
              className={`panel panel--editor theme-${editorTheme} ${
                bothCodePanels ? 'panel--editor-half' : ''
              }`}
               style={{ '--editor-code-font-size': `${editorFontSize}px` }}
            >
              <div className="panel-header">
                <div className="panel-header-left">
                  <div className="panel-title">Editor</div>
                  <div className="panel-subtitle">
                    {selectedPath ? (
                      <>
                        {selectedPath}
                        {hasUnsavedChanges && (
                          <span
                            style={{
                              marginLeft: 6,
                              fontSize: 11,
                              color: '#f97373',
                            }}
                          >
                            ● unsaved
                          </span>
                        )}
                      </>
                    ) : (
                      'Select a file'
                    )}
                  </div>
                </div>
                <div className="font-size-controls">
    <button
      type="button"
      className="button small"
      onClick={() => setEditorFontSize((s) => Math.max(10, s - 1))}
    >
      A-
    </button>
    <button
      type="button"
      className="button small"
      onClick={() => setEditorFontSize((s) => Math.min(18, s + 1))}
    >
      A+
    </button>
  </div>
                <div>
                  <select
                    className="theme-select"
                    value={editorTheme}
                    onChange={(e) => setEditorTheme(e.target.value)}
                  >
                    <option value="default">Default</option>
                    <option value="midnight">Midnight</option>
                    <option value="paper">Paper</option>
                    <option value="ocean">Ocean</option>
                    <option value="flower">Flower</option>
                  </select>
                </div>
              </div>

              {fileLoading ? (
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  Loading file…
                </div>
              ) : (
                <>
                  <textarea
                    className="editor-textarea"
                    value={fileContent}
                    onChange={(e) => {
                      setFileContent(e.target.value);
                      setHasUnsavedChanges(true);
                    }}
                    spellCheck={false}
                  />
                  <div className="editor-actions">
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button
                        className="button primary"
                        onClick={onSave}
                        disabled={
                          saving || !hasUnsavedChanges || !selectedPath
                        }
                      >
                        {saving
                          ? 'Saving…'
                          : hasUnsavedChanges
                          ? 'Save file'
                          : 'Saved'}
                      </button>
                      <button
                        className="button small"
                        type="button"
                        onClick={onCopyIframeUrl}
                        disabled={!selectedPath || copyingUrl}
                      >
                        {copyingUrl ? 'Copying…' : 'Copy iframe URL'}
                      </button>
                      <button
                        className="button small"
                        type="button"
                        onClick={handleOpenPreview}
                        disabled={!selectedPath}
                      >
                        Preview iFrame
                      </button>
                    </div>
                    <div
                      style={{
                        fontSize: 11,
                        color: 'var(--text-muted)',
                        textAlign: 'right',
                      }}
                    >
                      {copyStatus
                        ? copyStatus
                        : selectedPath && (
                            <>
                              {hasUnsavedChanges ? (
                                <>
                                  Unsaved changes — last published at{' '}
                                  <code>
                                    /p/{slug}/{selectedPath}
                                  </code>
                                </>
                              ) : (
                                <>
                                  Live at{' '}
                                  <code>
                                    /p/{slug}/{selectedPath}
                                  </code>
                                </>
                              )}
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
            <div
              className={`panel panel--gpt theme-${gptTheme} ${
                !showEditor ? 'panel--gpt-full' : bothCodePanels ? 'panel--gpt-half' : '' }`}
                    style={{
                   '--gpt-font-size': `${gptFontSize}px`,
                   '--gpt-code-font-size': `${Math.max(10, gptFontSize - 1)}px`,
               }}
            >
              <div className="panel-header">
                <div className="panel-header-left">
                  <div className="panel-title">GPT helper</div>
                  <div className="panel-subtitle">
                    Model: {gptMeta.model || 'gpt-4.1-mini'} · File:{' '}
                    {selectedPath || 'none'}
                    {gptMeta.sdkIncluded && (
                      <span className="pill pill--tiny">
                        Portals SDK context
                      </span>
                    )}
                    {gptMeta.truncated && (
                      <span className="pill pill--tiny pill--warn">
                        Large file (partial)
                      </span>
                    )}
                  </div>
                </div>
    <div className="font-size-controls">
      <button
        type="button"
        className="button small"
        onClick={() => setGptFontSize((s) => Math.max(10, s - 1))}
      >
        A-
      </button>
      <button
        type="button"
        className="button small"
        onClick={() => setGptFontSize((s) => Math.min(18, s + 1))}
      >
        A+
      </button>
    </div>
                <div>
                  <select
                    className="theme-select"
                    value={gptTheme}
                    onChange={(e) => setGptTheme(e.target.value)}
                  >
                    <option value="default">Default</option>
                    <option value="midnight">Midnight</option>
                    <option value="paper">Paper</option>
                    <option value="ocean">Ocean</option>
                    <option value="flower">Flower</option>
                  </select>
                </div>
              </div>

<div className="gpt-messages" ref={gptMessagesRef}>
  {gptHistory.length === 0 && !gptError && (
    <div style={{ fontSize: 12, color: 'var(--code-text)' }}>
      Ask GPT to help refactor your HUD or generate snippets.
      It will see the current file when a path is selected.
    </div>
  )}

  {gptHistory.map((msg, index) => (
    <div
      key={index}
      className={`gpt-message gpt-message--${msg.role}`}
    >
      <div className="gpt-message-avatar">
        {msg.role === 'user' ? '👤' : '🤖'}
      </div>
      <div className="gpt-message-bubble">
        <div className="gpt-message-meta">
          {msg.role === 'user' ? 'You' : 'GPT'}
        </div>
        <div className="gpt-message-content">
          {msg.role === 'assistant' ? (
            <div className="gpt-markdown">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  p({ children, ...props }) {
                    return (
                      <p
                        style={{ margin: '0 0 6px', fontSize: 12 }}
                        {...props}
                      >
                        {children}
                      </p>
                    );
                  },
                  li({ children, ...props }) {
                    return (
                      <li
                        style={{ marginBottom: 4 }}
                        {...props}
                      >
                        {children}
                      </li>
                    );
                  },
code({ inline, className, children, ...props }) {
  const text = String(children || '');
  const codeText = text.replace(/\n$/, '');

  // language-js → "js" etc
  const match =
    typeof className === 'string'
      ? /language-(\w+)/.exec(className)
      : null;
  const lang = match?.[1]?.toLowerCase();

  const handleCopy = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(codeText);
      } else {
        window.prompt('Copy code:', codeText);
      }
    } catch (err) {
      console.error('Copy failed', err);
    }
  };

  // 🔹 Inline code: no syntax highlighting, just a pill
  if (inline) {
    return (
      <code className="gpt-inline-code" {...props}>
        {children}
      </code>
    );
  }

  // 🔹 Block code: run through highlight.js
  let highlightedHtml = codeText;
  try {
    if (lang && hljs.getLanguage(lang)) {
      highlightedHtml = hljs.highlight(codeText, { language: lang }).value;
    } else {
      highlightedHtml = hljs.highlightAuto(codeText).value;
    }
  } catch (err) {
    console.error('highlight.js error', err);
    highlightedHtml = codeText; // fallback if something explodes
  }

  const codeClass = ['hljs', className].filter(Boolean).join(' ');

  return (
    <div className="gpt-code-block">
      <div className="gpt-code-header">
        <span className="gpt-code-lang">{lang || 'code'}</span>
        <button
          type="button"
          className="gpt-code-copy-btn"
          onClick={handleCopy}
        >
          Copy
        </button>
      </div>
      <pre className="gpt-code">
        <code
          className={codeClass}
          dangerouslySetInnerHTML={{ __html: highlightedHtml }}
          {...props}
        />
      </pre>
    </div>
  );
},

                }}
              >
                {msg.content}
              </ReactMarkdown>
            </div>
          ) : (
            msg.content
          )}
        </div>
      </div>
    </div>
  ))}

  {gptError && (
    <div className="gpt-message gpt-message--error">
      <div className="gpt-message-avatar">!</div>
      <div className="gpt-message-bubble">
        <div className="gpt-message-meta">Error</div>
        <div className="gpt-message-content">{gptError}</div>
      </div>
    </div>
  )}
</div>


              <div className="gpt-input">
                <textarea
                placeholder={
                  gptBusy
                   ? 'Waiting for GPT to respond…'
                    : selectedPath
                   ? 'e.g. “Add a pulsing border around the HUD”'
                   : 'Tip: select a file so GPT can see your overlay code, then ask for changes.'
               }
               value={gptPrompt}
               onChange={(e) => setGptPrompt(e.target.value)}
               onKeyDown={handleGptKeyDown}
               disabled={gptBusy || gptQuotaReached}
              />

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 8,
                    alignItems: 'center',
                    flexWrap: 'wrap',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      gap: 6,
                      flexWrap: 'wrap',
                    }}
                  >
                    <button
                      className="button primary"
                      onClick={onRunGpt}
                      disabled={
                        gptBusy || !gptPrompt.trim() || gptQuotaReached
                      }
                    >
                      {gptBusy
                        ? 'Thinking…'
                        : gptQuotaReached
                        ? 'Daily limit reached'
                        : 'Ask GPT'}
                    </button>
                    <button
                      className="button small"
                      type="button"
                      onClick={onCopyGptText}
                      disabled={!getLastAssistantContent()}
                    >
                      Copy output
                    </button>
                    <button
                      className="button small"
                      type="button"
                      onClick={onReplaceWithGpt}
                      disabled={!getLastAssistantContent() || !selectedPath}
                    >
                      Replace active file
                    </button>
                  </div>
                  <div
                    style={{ fontSize: 11, color: 'var(--text-muted)' }}
                  >
                    {gptDailyLimit !== null ? (
                      gptQuotaReached ? (
                        <>Daily GPT limit reached ({gptCalls} / {gptDailyLimit} calls)</>
                      ) : (
                        <>Uses your daily GPT quota ({gptCalls} / {gptDailyLimit} calls today)</>
                      )
                    ) : (
                      <>Uses your daily GPT quota.</>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Iframe preview modal */}
      {previewOpen && selectedPath && (
        <div
          className="preview-modal-backdrop"
          onClick={handleClosePreview}
        >
          <div
            className="preview-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="preview-modal-header">
              <div>
                <div className="preview-modal-title">iFrame preview</div>
                <div className="preview-modal-subtitle">
                  /p/{slug}/{selectedPath}
                </div>
              </div>
              <button
                type="button"
                className="preview-modal-close"
                onClick={handleClosePreview}
                aria-label="Close preview"
              >
                ×
              </button>
            </div>
            <div className="preview-modal-body preview-modal-body--iframe">
              <iframe
                key={previewReloadKey}
                src={`${IFRAME_ORIGIN}/p/${encodeURIComponent(
                  slug
                )}/${encodeURIComponent(selectedPath)}`}
                title={`Preview ${slug}/${selectedPath}`}
                className="preview-modal-iframe"
              />
            </div>
          </div>
        </div>
      )}
    </>
  );
}



function DashboardPage() {
  const { me, loading, refresh } = useMe();
  const navigate = useNavigate();
  const location = useLocation();

  const [activeSlug, setActiveSlug] = useState(null);
  const [usage, setUsage] = useState(null);
  const [spaceDirty, setSpaceDirty] = useState(false); 
  // panel visibility lives here so sidebar controls it
  const [showFiles, setShowFiles] = useState(true);
  const [showEditor, setShowEditor] = useState(true);
  const [showGpt, setShowGpt] = useState(true);

  // workspace request UX
  const [requestingWorkspace, setRequestingWorkspace] = useState(false);
  const [workspaceRequestStatus, setWorkspaceRequestStatus] = useState('');
  const [workspaceSlugSuggestion, setWorkspaceSlugSuggestion] = useState('');
  const [workspaceNote, setWorkspaceNote] = useState('');

  const [pendingRequest, setPendingRequest] = useState(null);

  // track when we're in "mobile/stacked" mode
  const [isNarrow, setIsNarrow] = useState(
    typeof window !== 'undefined' ? window.innerWidth <= 1024 : false
  );
    useEffect(() => {
    const onResize = () => {
      setIsNarrow(window.innerWidth <= 1024);
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

    // When in narrow mode, ensure only one panel is active at a time
  useEffect(() => {
    if (!isNarrow) return;

    const activeCount = [showFiles, showEditor, showGpt].filter(Boolean).length;
    if (activeCount <= 1) return; // already fine

    // Priority: Editor > GPT > Files
    if (showEditor) {
      setShowFiles(false);
      setShowGpt(false);
    } else if (showGpt) {
      setShowFiles(false);
    } else if (showFiles) {
      setShowEditor(false);
      setShowGpt(false);
    }
  }, [isNarrow, showFiles, showEditor, showGpt]);


  // Redirect to /login if not logged in
  useEffect(() => {
    if (!loading && !me) {
      navigate('/login', { replace: true, state: { from: location.pathname } });
    }
  }, [me, loading, navigate, location.pathname]);

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

  // Auto-select first space
  useEffect(() => {
    if (me && me.spaces?.length && !activeSlug) {
      setActiveSlug(me.spaces[0].slug);
    }
  }, [me, activeSlug]);

  useEffect(() => {
    if (activeSlug) {
      refreshUsage(activeSlug);
    }
  }, [activeSlug, refreshUsage]);

  const handleLogout = useCallback(async () => {
    try {
      await logout(); // POST /api/auth/logout
    } catch (err) {
      console.error(err);
    } finally {
      await refresh?.(); // clear /api/me state
      navigate('/login', { replace: true });
    }
  }, [navigate, refresh]);

    const handleSelectSpace = useCallback(
    (slug) => {
      if (slug === activeSlug) return;

      if (spaceDirty) {
        const ok = window.confirm(
          'You have unsaved changes in this space. Switch spaces and discard them?'
        );
        if (!ok) return;
      }

      setActiveSlug(slug);
    },
    [activeSlug, spaceDirty]
  );

    const handleToggleFiles = useCallback(() => {
    setShowFiles((prev) => {
      const next = !prev;
      if (next && isNarrow) {
        // on narrow screens, Files wins; hide others
        setShowEditor(false);
        setShowGpt(false);
      }
      return next;
    });
  }, [isNarrow]);

  const handleToggleEditor = useCallback(() => {
    setShowEditor((prev) => {
      const next = !prev;
      if (next && isNarrow) {
        setShowFiles(false);
        setShowGpt(false);
      }
      return next;
    });
  }, [isNarrow]);

  const handleToggleGpt = useCallback(() => {
    setShowGpt((prev) => {
      const next = !prev;
      if (next && isNarrow) {
        setShowFiles(false);
        setShowEditor(false);
      }
      return next;
    });
  }, [isNarrow]);

  const handleRequestWorkspace = async () => {
    setWorkspaceRequestStatus('');
    setRequestingWorkspace(true);
    try {
      const data = await requestWorkspace(
        workspaceNote || null,
        workspaceSlugSuggestion || null
      );

      if (data.request) {
        setPendingRequest(data.request);
        setWorkspaceSlugSuggestion(data.request.suggestedSlug || '');
        setWorkspaceNote(data.request.note || '');
      }

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

  // 🔽 early returns AFTER all hooks are declared

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

  const spaces = me.spaces || [];

  return (
    <LayoutShell me={me} usage={usage} onLogout={handleLogout}>
      <Sidebar
        spaces={spaces}
        activeSlug={activeSlug}
        onSelect={handleSelectSpace}
        usage={usage}
        showFiles={showFiles}
        showEditor={showEditor}
        showGpt={showGpt}
        onToggleFiles={handleToggleFiles}
        onToggleEditor={handleToggleEditor}
        onToggleGpt={handleToggleGpt}
        // (you can drop this next prop if you like; Sidebar doesn't use it)
        // onUsageRefresh={() => refreshUsage(activeSlug)}
      />
      {activeSlug ? (
        <SpaceEditor
          key={activeSlug}
          slug={activeSlug}
          showFiles={showFiles}
          showEditor={showEditor}
          showGpt={showGpt}
          onUsageRefresh={() => refreshUsage(activeSlug)}
          onDirtyChange={setSpaceDirty}
        />

      ) : (
        <div
          className="app-content"
          style={{ alignItems: 'center', justifyContent: 'center' }}
        >
          <div
            style={{
              fontSize: 14,
              color: 'var(--text-muted)',
              maxWidth: 420,
              textAlign: 'center',
              padding: '16px',
            }}
          >
            <div style={{ marginBottom: 8 }}>No spaces assigned to you yet.</div>
            <div style={{ marginBottom: 12 }}>
              You can request a new workspace for your Portals overlays. An admin will review and
              create a space for you.
            </div>

            {pendingRequest ? (
              // ... your existing pendingRequest block ...
              <div
                style={{
                  textAlign: 'left',
                  marginBottom: 12,
                  padding: 10,
                  borderRadius: 8,
                  border: '1px solid var(--panel-border)',
                  background: 'rgba(15,23,42,0.9)',
                }}
              >
                {/* unchanged content */}
                {/* ... */}
              </div>
            ) : (
              <>
                {/* workspace request form, unchanged */}
                {/* ... */}
                <button
                  className="button primary"
                  type="button"
                  onClick={handleRequestWorkspace}
                  disabled={requestingWorkspace}
                >
                  {requestingWorkspace ? 'Requesting…' : 'Request workspace'}
                </button>
              </>
            )}

            {workspaceRequestStatus && (
              <div
                style={{
                  marginTop: 8,
                  fontSize: 12,
                  color: 'var(--text-muted)',
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

  // inline slug editing per request
  const [slugEdits, setSlugEdits] = useState({});   // { [requestId]: currentSlug }
  const [slugErrors, setSlugErrors] = useState({}); // { [requestId]: errorMessage | null }

  // allowlist
  const [approvedUsers, setApprovedUsers] = useState([]);
  const [allowlistLoading, setAllowlistLoading] = useState(false);
  const [allowlistError, setAllowlistError] = useState('');
  const [newAllowEmail, setNewAllowEmail] = useState('');

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
        const reqs = data.requests || [];
        setRequests(reqs);
        setStatusMsg(`Loaded ${reqs.length || 0} pending request(s).`);

        // initialize slug inputs for each request
        setSlugEdits((prev) => {
          const next = { ...prev };
          for (const r of reqs) {
            const base =
              (r.suggestedSlug && r.suggestedSlug.toLowerCase()) ||
              ((r.email || '')
                .split('@')[0]
                .replace(/[^a-z0-9-]/g, '-') || '');
            if (!next[r.id]) {
              next[r.id] = normalizeSlug(base);
            }
          }
          return next;
        });

        setSlugErrors({});
      } catch (err) {
        console.error(err);
        setErrorMsg(err.payload?.error || 'Failed to load requests.');
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const loadApproved = useCallback(
    async (token) => {
      if (!token) {
        setApprovedUsers([]);
        return;
      }
      setAllowlistLoading(true);
      setAllowlistError('');
      try {
        const data = await adminGetApprovedUsers(token);
        setApprovedUsers(data.users || []);
      } catch (err) {
        console.error(err);
        setAllowlistError(err.payload?.message || 'Failed to load allowlist.');
      } finally {
        setAllowlistLoading(false);
      }
    },
    []
  );

  useEffect(() => {
    if (adminToken) {
      loadRequests(adminToken);
      loadApproved(adminToken);
    } else {
      setRequests([]);
      setApprovedUsers([]);
    }
  }, [adminToken, loadRequests, loadApproved]);

  const handleAddAllowEmail = async () => {
    const email = newAllowEmail.trim();
    if (!email) return;
    try {
      setAllowlistError('');
      await adminAddApprovedUser(adminToken, email);
      setNewAllowEmail('');
      await loadApproved(adminToken);
    } catch (err) {
      console.error(err);
      setAllowlistError(err.payload?.message || 'Failed to add email.');
    }
  };

  const handleRemoveAllowEmail = async (email) => {
    if (!window.confirm(`Remove "${email}" from allowlist?`)) return;
    try {
      setAllowlistError('');
      await adminRemoveApprovedUser(adminToken, email);
      await loadApproved(adminToken);
    } catch (err) {
      console.error(err);
      setAllowlistError(err.payload?.message || 'Failed to remove email.');
    }
  };

  const handleSaveToken = (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const token = (formData.get('adminToken') || '').toString().trim();
    if (!token) return;
    setAdminToken(token);
    localStorage.setItem('adminToken', token);
    // this will trigger useEffect and load both requests + allowlist,
    // but we can eagerly load requests too:
    loadRequests(token);
  };

  const handleSlugChange = (reqId, rawInput) => {
    const normalized = normalizeSlug(rawInput);
    setSlugEdits((prev) => ({ ...prev, [reqId]: normalized }));

    if (!normalized) {
      setSlugErrors((prev) => ({
        ...prev,
        [reqId]: 'Slug is required.',
      }));
    } else if (!isValidSlug(normalized)) {
      setSlugErrors((prev) => ({
        ...prev,
        [reqId]: 'Slug must be 3–32 chars (a–z, 0–9, hyphen).',
      }));
    } else {
      setSlugErrors((prev) => {
        const next = { ...prev };
        delete next[reqId];
        return next;
      });
    }
  };

  const getSlugForRequest = (req) => {
    const raw = slugEdits[req.id];
    const fromState = typeof raw === 'string' && raw.length > 0 ? raw : null;
    if (fromState) return fromState;

    const base =
      (req.suggestedSlug && req.suggestedSlug.toLowerCase()) ||
      ((req.email || '')
        .split('@')[0]
        .replace(/[^a-z0-9-]/g, '-') || '');
    return normalizeSlug(base);
  };

  const handleApprove = async (reqId) => {
    const req = requests.find((r) => r.id === reqId);
    if (!req) return;

    const slug = getSlugForRequest(req);
    const normalized = normalizeSlug(slug);

    if (!normalized || !isValidSlug(normalized)) {
      setSlugErrors((prev) => ({
        ...prev,
        [reqId]: 'Slug must be 3–32 chars (a–z, 0–9, hyphen).',
      }));
      return;
    }

    const quotaMb = 100;

    try {
      setStatusMsg(`Approving request for ${req.email}…`);
      setErrorMsg('');
      await adminApproveSpaceRequest(adminToken, reqId, {
        slug: normalized,
        quotaMb,
      });
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg(`Approved ${req.email} with space "${normalized}" (${quotaMb} MB).`);
    } catch (err) {
      console.error(err);
      const code = err.payload?.error;
      if (err.status === 409 && (code === 'space_exists' || code === 'dir_exists')) {
        setSlugErrors((prev) => ({
          ...prev,
          [reqId]: err.payload?.message || 'Slug already in use. Choose another.',
        }));
      } else {
        setErrorMsg(err.payload?.message || 'Failed to approve request.');
      }
    }
  };

  const handleApproveCustom = async (reqId) => {
    const req = requests.find((r) => r.id === reqId);
    if (!req) return;

    const slug = getSlugForRequest(req);
    const normalized = normalizeSlug(slug);

    if (!normalized || !isValidSlug(normalized)) {
      setSlugErrors((prev) => ({
        ...prev,
        [reqId]: 'Slug must be 3–32 chars (a–z, 0–9, hyphen).',
      }));
      return;
    }

    const quotaInput = window.prompt('Quota in MB (default 100):', '100');
    const quotaMb = quotaInput ? Number(quotaInput) : 100;

    try {
      setStatusMsg(`Approving request for ${req.email}…`);
      setErrorMsg('');
      await adminApproveSpaceRequest(adminToken, reqId, {
        slug: normalized,
        quotaMb,
      });
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg(`Approved ${req.email} with space "${normalized}" (${quotaMb} MB).`);
    } catch (err) {
      console.error(err);
      const code = err.payload?.error;
      if (err.status === 409 && (code === 'space_exists' || code === 'dir_exists')) {
        setSlugErrors((prev) => ({
          ...prev,
          [reqId]: err.payload?.message || 'Slug already in use. Choose another.',
        }));
      } else {
        setErrorMsg(err.payload?.message || 'Failed to approve request.');
      }
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
      setErrorMsg('');
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

        <form onSubmit={handleSaveToken} style={{ marginBottom: 10, border: '1px solid var(--panel-border)', borderRadius: 8, padding: '6px 10px', background: 'var(--bg-elevated)' }}>
          <label style={{ fontSize: 12, color: 'var(--danger)' }}>
            Admin Password:
            <input
              name="adminToken"
              type="password"
              defaultValue={adminToken}
              style={{
                marginTop: 4,
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '6px 10px',
                fontSize: 13
              }}
            />
          </label>
          <div style={{ marginTop: 8, display: 'flex', justifyContent: 'space-between', gap: 8}}>
            <button className="button small" type="submit">
              Save & load requests
            </button>
            <button
              className="button small"
              type="button"
              onClick={() => {
                setAdminToken('');
                localStorage.removeItem('adminToken');
                setRequests([]);
                setSlugEdits({});
                setSlugErrors({});
              }}
            >
              Clear token
            </button>
          </div>
        </form>
{/* Allowlist panel */}
        <div
          style={{
            marginBottom: 12,
            padding: 8,
            borderRadius: 8,
            border: '1px solid var(--panel-border)',
            background: 'var(--bg-elevated)',
          }}
        >
          <h2 style={{ fontSize: 14, margin: '0 0 6px', color: 'var(--accent-primary)' }}>Approved emails</h2>
          <p style={{ fontSize: 12, color: 'var(--text-light)', margin: '0 0 8px' }}>
            Only emails on this allowlist can receive magic-link logins.
          </p>

          <div
            style={{
              display: 'flex',
              gap: 8,
              marginBottom: 8,
              alignItems: 'center',
              flexWrap: 'wrap',
            }}
          >
            <input
              type="email"
              placeholder="new-user@example.com"
              value={newAllowEmail}
              onChange={(e) => setNewAllowEmail(e.target.value)}
              style={{
                flex: '1 1 200px',
                minWidth: 0,
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '6px 10px',
                fontSize: 13,
              }}
            />
            <button
              type="button"
              className="button small"
              onClick={handleAddAllowEmail}
              disabled={!newAllowEmail.trim()}
            >
              Add email
            </button>
          </div>

          {allowlistLoading ? (
            <div style={{ fontSize: 12, color: 'var(--ok)' }}>
              Loading allowlist…
            </div>
          ) : approvedUsers.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--accent-secondary)' }}>
              No approved emails yet. Add at least one to allow logins.
            </div>
          ) : (
            <ul
              style={{
                listStyle: 'none',
                padding: 0,
                margin: 0,
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
                maxHeight: 160,
                overflowY: 'auto',
              }}
            >
              {approvedUsers.map((u) => (
                <li
                  key={u.email}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: 12,
                  }}
                >
                  <div>
                    <span style={{ color: 'var(--text-light)' }}>{u.email}</span>
                    {u.createdAt && (
                      <span style={{ color: 'var(--text-light)', marginLeft: 6 }}>
                        · {u.createdAt}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    className="button small"
                    onClick={() => handleRemoveAllowEmail(u.email)}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}

          {allowlistError && (
            <div style={{ marginTop: 6, fontSize: 12, color: '#f97373' }}>
              {allowlistError}
            </div>
          )}
        </div>
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
            {requests.map((r) => {
              const slugValue = getSlugForRequest(r);
              const slugError = slugErrors[r.id] || null;
              const slugIsValid = slugValue && isValidSlug(slugValue);

              return (
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
                    <div style={{ fontSize: 12, marginBottom: 6 }}>
                      Request note:{' '}
                      <span style={{ color: 'var(--text-main)' }}>{r.note}</span>
                    </div>
                  )}

                  <div style={{ marginBottom: 6 }}>
                    <label style={{ fontSize: 11, display: 'block' }}>
                      Space slug
                      <input
                        type="text"
                        value={slugValue}
                        onChange={(e) => handleSlugChange(r.id, e.target.value)}
                        placeholder="e.g. scott-hud"
                        style={{
                          marginTop: 4,
                          width: '100%',
                          borderRadius: 999,
                          border: '1px solid var(--panel-border)',
                          background: '#020617',
                          color: 'var(--text-main)',
                          padding: '4px 10px',
                          fontSize: 12
                        }}
                      />
                    </label>
                    <div style={{ fontSize: 10, marginTop: 2 }}>
                      <span style={{ color: 'var(--text-muted)' }}>
                        3–32 chars; lowercase letters, digits, hyphens only.
                      </span>
                      {slugError && (
                        <div style={{ color: '#f97373', marginTop: 2 }}>
                          {slugError}
                        </div>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 4 }}>
                    <button
                      className="button small"
                      type="button"
                      onClick={() => handleApprove(r.id)}
                      title="Approve using current slug and default quota"
                      disabled={!slugIsValid}
                    >
                      Approve
                    </button>
                    <button
                      className="button small"
                      type="button"
                      onClick={() => handleApproveCustom(r.id)}
                      title="Approve with current slug and custom quota"
                      disabled={!slugIsValid}
                    >
                      Approve (custom quota)
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
              );
            })}
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
