import React, { useEffect, useState, useCallback } from 'react';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import {
  getMe,
  getSpaceFiles,
  getSpaceFile,
  saveSpaceFile,
  getSpaceUsage,
  callSpaceGpt,
  startMagicLink
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
        <h1>Sign in to Jawn Overlays</h1>
        <p>
          Enter your email and we&apos;ll send a magic link. No passwords. After clicking the link,
          come back here and refresh.
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
          <h1>Jawn Overlays</h1>
          <span>Portals iframe spaces</span>
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
  onToggleGpt
}) {

  return (
    <aside className="app-sidebar">
      <div className="sidebar-section">
        <h2>Spaces</h2>
        {spaces.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No spaces yet. Ask admin.</div>
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
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Select a space to view.</div>
        )}
      </div>

      {/* NEW: layout / panel toggles */}
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
            <ul className="file-list">
              {files.map((f) => (
                <li
                  key={f.name}
                  className={
                    'file-item' + (selectedPath === f.name ? ' active' : '')
                  }
                  onClick={() => setSelectedPath(f.name)}
                >
                  {f.name}
                </li>
              ))}
            </ul>
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
                  <button
                    className="button primary"
                    onClick={onSave}
                    disabled={saving}
                  >
                    {saving ? 'Saving…' : 'Save file'}
                  </button>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    Changes go live at <code>/p/{slug}/{selectedPath}</code>
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
        // Pretty-print code blocks inside your existing card style
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
        <div style={{ fontSize: 14, color: 'var(--text-muted)' }}>
          No spaces assigned to you yet. Ask the admin to create one.
        </div>
      </div>
    )}
  </LayoutShell>
);

}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/*" element={<DashboardPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
