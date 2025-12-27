//client/src/App.jsx
import React, { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import {
  getMe,
  getSpaceFiles,
  getSpaceFile,
  saveSpaceFile,
  getSpaceFileHistory,
  getSpaceFileVersion,
  restoreSpaceFileVersion,
  getSpaceUsage,
  callSpaceGpt,
  getAuthStatus,
  startDiscordLogin,
  deleteSpaceFile,
  renameSpaceFile,
  uploadSpaceAssets,
  deleteSpaceAsset,
  requestWorkspace,
  adminGetSpaceRequests,
  adminApproveSpaceRequest,
  adminRejectSpaceRequest,
  logout,
  startEmailVerification,
  resendEmailVerification,
  adminCreateSpace,
  adminSendUserEmail,
  adminSearchUsers,
  adminBillingOverview,
  adminUpdateUserBilling,
  adminExtendUserBilling,
  adminGetAudit,
  adminGetActivity,
  adminDoctor,
  adminListEmailTemplates,
  adminGetUserSessions,
  adminGetDuplicateUsers,
  adminMergeUsers
} from './api.js';

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { normalizeSlug, isValidSlug } from './slugUtils'; // ⬅️ ADD THIS
import { extractBestCodeBlock, stripCodeFences } from './utils/extractBestCodeBlock';

// Highlight.js (safe)
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

// Avoid highlight.js throwing on weird input
try {
  hljs.configure({ ignoreUnescapedHTML: true });
} catch {
  // ok on older versions
}

// ✅ Critical: escape fallback for any dangerous innerHTML paths
function escapeHtml(unsafe) {
  return String(unsafe ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ✅ Single safe highlighting function (never returns raw code)
function highlightToHtmlSafe(codeText, lang) {
  const text = String(codeText ?? '');

  try {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(text, { language: lang, ignoreIllegals: true }).value || escapeHtml(text);
    }
    return hljs.highlightAuto(text).value || escapeHtml(text);
  } catch (err) {
    console.error('[hljs] highlight failed', err);
    return escapeHtml(text);
  }
}

const IFRAME_ORIGIN = (() => {
  const raw = import.meta.env.VITE_IFRAME_ORIGIN;
  const cleaned = raw ? String(raw).replace(/\/+$/, '') : '';

  if (import.meta.env.PROD) {
    if (!cleaned) {
      throw new Error(
        'VITE_IFRAME_ORIGIN is required in production (set it to your public iframe host origin).'
      );
    }
    const editorOrigin = window.location.origin.replace(/\/+$/, '');
    if (cleaned === editorOrigin) {
      throw new Error(
        'VITE_IFRAME_ORIGIN must be different from the editor origin in production.'
      );
    }
    return cleaned;
  }

  // Dev fallback
  return cleaned || window.location.origin.replace(/\/+$/, '');
})();

function useEmailVerifiedGate({ me, loading }) {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (loading) return;
    if (!me) return;

    const verified = !!me?.user?.emailVerifiedAt;
    if (!verified) {
      navigate('/login', { replace: true, state: { from: location.pathname } });
    }
  }, [me, loading, navigate, location.pathname]);
}
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
  const navigate = useNavigate();
  const [statusIsError, setStatusIsError] = useState(false);
  const [auth, setAuth] = useState(null); // { loggedIn, user, ... }
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('');

  const [email, setEmail] = useState(() => {
    try {
      return localStorage.getItem('pendingEmail') || '';
    } catch {
      return '';
    }
  });

  const emailTrim = String(email || '').trim().toLowerCase();
  const emailOk = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(emailTrim);

  const refreshStatus = useCallback(async () => {
    const s = await getAuthStatus();
    setAuth(s);
    return s;
  }, []);

  useEffect(() => {
    const run = async () => {
      setBusy(true);
      setStatus('');
      try {
        const s = await refreshStatus();

        // If verified, go straight into the app
        const verified =
          !!s?.loggedIn &&
          !!s?.user?.email &&
          !!s?.user?.emailVerifiedAt; // NOTE: see backend tip below

   if (verified) {
  navigate('/', { replace: true });
  return;
}

        // Prefill email from backend if present
        const backendEmail = String(s?.user?.pendingEmail || s?.user?.email || '').trim().toLowerCase();
        if (backendEmail) {
          setEmail((prev) => prev || backendEmail);
          try {
            localStorage.setItem('pendingEmail', backendEmail);
          } catch {}
        }

        // Nice UX when coming back from verify link
const qp = new URLSearchParams(window.location.search || '');
const err = qp.get('error');

if (err) {
  const msg =
    err === 'not_in_guild'
      ? 'Access denied: you are not in the Portals Discord server.'
      : err === 'missing_required_role'
      ? 'Access denied: you are missing the required role.'
      : err === 'discord_auth_disabled'
      ? 'Discord login is disabled on this server.'
      : err === 'bad_state'
      ? 'Login expired. Please try again.'
      : err === 'discord_oauth_failed'
      ? 'Discord login failed. Please try again.'
      : 'Login blocked. Please try again.';

  setStatus(msg);
  setStatusIsError(true);

  // clean URL (remove ?error=...)
  qp.delete('error');
  const nextQs = qp.toString();
  const nextUrl = nextQs ? `${window.location.pathname}?${nextQs}` : window.location.pathname;
  window.history.replaceState({}, '', nextUrl);
}

if (qp.get('verified') === '1') {
          setStatus('Email verified. Entering the app…');
          // refresh again (in case status was cached)
          const s2 = await refreshStatus();
          const verified2 = !!s2?.loggedIn && !!s2?.user?.email && !!s2?.user?.emailVerifiedAt;
          if (verified2) navigate('/', { replace: true });
        }
      } catch (err) {
        console.error(err);
        // Don’t block UI if status route hiccups
        setAuth({ ok: true, loggedIn: false, user: null });
      } finally {
        setBusy(false);
      }
    };
    run();
  }, [navigate, refreshStatus]);

const onDiscord = () => {
  setStatusIsError(false);
  setBusy(true);
  setStatus('Opening Discord…');
  startDiscordLogin();
};

const onSendVerify = async () => {
  if (!emailOk) {
    setStatusIsError(true);
    setStatus('Please enter a valid email.');
    return;
  }

  setStatusIsError(false);
  setBusy(true);
  setStatus('Sending verification email…');

  try {
    try {
      localStorage.setItem('pendingEmail', emailTrim);
    } catch {}

    await startEmailVerification(emailTrim);
    setStatus('Check your inbox — click the verification link to continue.');
    await refreshStatus();
  } catch (err) {
    console.error(err);
    setStatusIsError(true);
    setStatus(err.payload?.message || 'Failed to send verification email.');
  } finally {
    setBusy(false);
  }
};

const onResend = async () => {
  setStatusIsError(false);
  setBusy(true);
  setStatus('Resending…');

  try {
    await resendEmailVerification();
    setStatus('Sent. Check your inbox.');
  } catch (err) {
    console.error(err);
    setStatusIsError(true);
    setStatus(err.payload?.message || 'Failed to resend.');
  } finally {
    setBusy(false);
  }
};

const onIveVerified = async () => {
  setStatusIsError(false);
  setBusy(true);
  setStatus('Checking verification…');

  try {
    const s = await refreshStatus();
    const verified = !!s?.loggedIn && !!s?.user?.email && !!s?.user?.emailVerifiedAt;

    if (verified) {
      setStatusIsError(false);
      setStatus('Verified. Entering the app…');
      navigate('/', { replace: true });
    } else {
      setStatusIsError(true);
      setStatus('Not verified yet. Open the link in your email, then try again.');
    }
  } catch (err) {
    console.error(err);
    setStatusIsError(true);
    setStatus('Could not confirm verification. Try again in a moment.');
  } finally {
    setBusy(false);
  }
};


  const loggedIn = !!auth?.loggedIn;
  const emailVerified = !!auth?.user?.emailVerifiedAt; // NOTE: see backend tip below

if (!loggedIn) {
  return (
   <div className="login-shell">
      <div className="login-card login-card--with-hero">
        <div className="login-hero login-hero--gradient">
          <div className="login-hero-ring" aria-hidden="true" />
          <div className="login-hero-grain" aria-hidden="true" />
        </div>

        <div className="login-body">
          <div className="login-title-row">
            <h1>Portals iFrame Builder</h1>
            <div className="login-kicker">For Portals Builders</div>
          </div>

          <p className="login-subtext">
            Sign in with Discord. Must be a member of the Portals server with the designated holder role. All concerns must be sent to Professor Quibbly in writing.
          </p>

          <button
            className="button primary login-cta"
            type="button"
            onClick={onDiscord}
            disabled={busy}
          >
            {busy ? 'Checking…' : 'Continue with Discord'}
          </button>

          {!!status && <div className="login-status">{status}</div>}

          <div className="login-fineprint">
            Tip: access the Portals ecosystem at <a href="https://theportal.to">theportal.to</a>!
          </div>
        </div>
      </div>
    </div>
  );
}


  // Logged in but NOT verified → onboarding UI
  if (!emailVerified) {
  const dUser = auth?.user || null;
  const handle = dUser?.discordUsername ? `@${dUser.discordUsername}` : (dUser?.discordId || 'unknown');

  const avatarUrl =
    dUser?.discordAvatarUrl ||
    (dUser?.discordId && dUser?.discordAvatar
      ? (() => {
          const isAnimated = String(dUser.discordAvatar).startsWith('a_');
          const ext = isAnimated ? 'gif' : 'png';
          return `https://cdn.discordapp.com/avatars/${encodeURIComponent(dUser.discordId)}/${encodeURIComponent(dUser.discordAvatar)}.${ext}?size=96`;
        })()
      : null);

  const statusClass =
    status && (status.toLowerCase().includes('failed') || status.toLowerCase().includes('not verified'))
      ? 'verify-status verify-status--error'
      : status && status.toLowerCase().includes('sent')
      ? 'verify-status verify-status--ok'
      : 'verify-status';

  return (
    <div className="login-shell">
      <div className="login-card verify-card">
        <div className="verify-header">
          {avatarUrl ? (
            <img className="verify-avatar" src={avatarUrl} alt="" referrerPolicy="no-referrer" />
          ) : (
            <span className="verify-avatar--fallback" aria-hidden="true">
              {(handle?.[0] || '•').toUpperCase()}
            </span>
          )}

          <div style={{ minWidth: 0 }}>
            <h1 className="verify-title">Verify your email</h1>
            <div className="verify-subtitle">
              Signed in as <strong>{handle}</strong>. Verify an email to unlock the builder.
            </div>
          </div>
        </div>

        <div className="verify-field">
          <div className="verify-label">Email</div>
          <input
            type="email"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              if (status) setStatus('');
            }}
            autoComplete="email"
            disabled={busy}
          />

          {!busy && emailTrim && !emailOk && (
            <div className="verify-status verify-status--error">
              Please enter a valid email.
            </div>
          )}
        </div>

        <div className="verify-actions">
          <button
            className="button primary"
            type="button"
            onClick={onSendVerify}
            disabled={busy || !emailOk}
            style={{ width: '100%' }}
          >
            {busy ? 'Working…' : 'Send verification email'}
          </button>

          <div className="verify-actions-secondary">
            <button className="button small" type="button" onClick={onResend} disabled={busy}>
              Resend
            </button>
            <button className="button small" type="button" onClick={onIveVerified} disabled={busy}>
              I’ve verified — continue
            </button>
          </div>

          <div className={statusClass}>{status}</div>
        </div>
      </div>
    </div>
  );
}


  // Verified but still here (rare) → send them in
  navigate('/', { replace: true });
  return null;
}

function LayoutShell({ me, onLogout, children }) {
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const email = String(me?.user?.email || '').trim();
  const discordUsername = me?.user?.discordUsername || null;
  const discordId = me?.user?.discordId || null;
  const discordAvatarHash = me?.user?.discordAvatar || null;
  const discordAvatarUrlFromApi = me?.user?.discordAvatarUrl || null;

  const emailVerifiedAt = me?.user?.emailVerifiedAt || null;
  const pendingEmail = me?.user?.pendingEmail || null;

  const headerLabel =
    (discordUsername ? `@${discordUsername}` : '') ||
    email ||
    'Signed in';

  const discordAvatarUrl = (() => {
    if (discordAvatarUrlFromApi) return discordAvatarUrlFromApi;
    if (!discordId || !discordAvatarHash) return null;

    const isAnimated = String(discordAvatarHash).startsWith('a_');
    const ext = isAnimated ? 'gif' : 'png';
    return `https://cdn.discordapp.com/avatars/${encodeURIComponent(
      discordId
    )}/${encodeURIComponent(discordAvatarHash)}.${ext}?size=64`;
  })();

  const closeMenus = () => setUserMenuOpen(false);

  // ───────────────── Email UI state (inline verify/change) ─────────────────
  const [emailDraft, setEmailDraft] = useState('');
  const [emailUiStatus, setEmailUiStatus] = useState('');
  const [emailUiBusy, setEmailUiBusy] = useState(false);

  // Local mirrors so modal reflects actions immediately
  const [pendingEmailLocal, setPendingEmailLocal] = useState(null);
  const [emailVerifiedAtLocal, setEmailVerifiedAtLocal] = useState(null);

  useEffect(() => {
  if (!profileOpen) return;

  const onKey = (e) => {
    if (e.key === 'Escape') setProfileOpen(false);
  };

  document.addEventListener('keydown', onKey);
  return () => document.removeEventListener('keydown', onKey);
}, [profileOpen]);

  // Sync inputs when profile opens
  useEffect(() => {
    if (!profileOpen) return;
    const initial = String(pendingEmail || email || '').trim();
    setEmailDraft(initial);
    setPendingEmailLocal(pendingEmail || null);
    setEmailVerifiedAtLocal(emailVerifiedAt || null);
    setEmailUiStatus('');
  }, [profileOpen, email, pendingEmail, emailVerifiedAt]);

  const emailTrim = String(emailDraft || '').trim().toLowerCase();
  const emailOk = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(emailTrim);

  const handleSendVerify = async () => {
    if (!emailOk) {
      setEmailUiStatus('Please enter a valid email.');
      return;
    }
    setEmailUiBusy(true);
    setEmailUiStatus('Sending verification email…');
    try {
      await startEmailVerification(emailTrim);
      setPendingEmailLocal(emailTrim);
      setEmailVerifiedAtLocal(null);
      setEmailUiStatus('Sent. Check your inbox for the verification link.');
    } catch (err) {
      console.error(err);
      setEmailUiStatus(err.payload?.message || 'Failed to send verification email.');
    } finally {
      setEmailUiBusy(false);
    }
  };

  const handleResendVerify = async () => {
    setEmailUiBusy(true);
    setEmailUiStatus('Resending…');
    try {
      await resendEmailVerification();
      setEmailUiStatus('Sent. Check your inbox.');
    } catch (err) {
      console.error(err);
      setEmailUiStatus(err.payload?.message || 'Failed to resend.');
    } finally {
      setEmailUiBusy(false);
    }
  };

  const handleCheckVerified = async () => {
    setEmailUiBusy(true);
    setEmailUiStatus('Checking…');
    try {
      const s = await getAuthStatus();
      const verifiedAt = s?.user?.emailVerifiedAt || null;

      if (verifiedAt) {
        setEmailVerifiedAtLocal(verifiedAt);
        setPendingEmailLocal(null);
        setEmailUiStatus('Verified. You’re good.');
      } else {
        setEmailUiStatus('Not verified yet. Open the link in your email, then try again.');
      }
    } catch (err) {
      console.error(err);
      setEmailUiStatus('Could not confirm verification. Try again.');
    } finally {
      setEmailUiBusy(false);
    }
  };

  // Close dropdown on outside click + Escape
  useEffect(() => {
    if (!userMenuOpen) return;

    const onDown = (e) => {
      const root = document.querySelector('.app-header-user');
      if (root && !root.contains(e.target)) closeMenus();
    };

    const onKey = (e) => {
      if (e.key === 'Escape') closeMenus();
    };

    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [userMenuOpen]);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="app-header-title">
          <h1>Portals iFrame Builder</h1>
          <span>Custom Builds & Page Hosting</span>
        </div>

        <div className="app-header-right">
          {me ? (
            <div className="app-header-user">
              <button
                type="button"
                className="badge-pill ok badge-pill--clickable user-pill"
                onClick={() => setUserMenuOpen((open) => !open)}
                aria-haspopup="menu"
                aria-expanded={userMenuOpen ? 'true' : 'false'}
              >
                {discordAvatarUrl ? (
                  <img
                    className="user-pill-avatar"
                    src={discordAvatarUrl}
                    alt=""
                    referrerPolicy="no-referrer"
                  />
                ) : (
                  <span
                    className="user-pill-avatar user-pill-avatar--fallback"
                    aria-hidden="true"
                  >
                    {(headerLabel?.[0] || '•').toUpperCase()}
                  </span>
                )}

                <span className="user-pill-label">{headerLabel}</span>
                <span className="badge-pill-caret">▾</span>
              </button>

              {userMenuOpen && (
                <div className="user-menu" role="menu">
                  <button
                    type="button"
                    className="user-menu-item"
                    role="menuitem"
                    onClick={() => {
                      closeMenus();
                      setProfileOpen(true);
                    }}
                  >
                    Profile
                  </button>

                  <button
                    type="button"
                    className="user-menu-item"
                    role="menuitem"
                    onClick={() => {
                      closeMenus();
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

      {/* Profile modal */}
      {profileOpen && me && (
        <div
          className="preview-modal-backdrop"
          onClick={() => setProfileOpen(false)}
        >
          <div
            className="preview-modal"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 'min(560px, 92vw)',
              maxWidth: 560,
              height: 'auto',
              minHeight: 0,
            }}
          >
            <div className="preview-modal-header">
              <div>
                <div className="preview-modal-title">Profile</div>
                <div className="preview-modal-subtitle">Account settings</div>
              </div>
              <button
                type="button"
                className="preview-modal-close"
                onClick={() => setProfileOpen(false)}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div className="preview-modal-body" style={{ display: 'block', padding: 16 }}>
              {/* Discord */}
              <div className="profile-section">
                <div className="profile-section-title">Discord</div>

                <div className="profile-row">
                  <div className="profile-avatar-row">
                    {discordAvatarUrl ? (
                      <img
                        className="profile-avatar"
                        src={discordAvatarUrl}
                        alt=""
                        referrerPolicy="no-referrer"
                      />
                    ) : (
                      <span className="profile-avatar-fallback" aria-hidden="true">
                        {(headerLabel?.[0] || '•').toUpperCase()}
                      </span>
                    )}

                    <div className="profile-kv">
                      <div className="profile-value">
                        <strong>Username:</strong>{' '}
                        {discordUsername ? `@${discordUsername}` : '—'}
                      </div>
                      <div
                        className="profile-value"
                        style={{ fontSize: 12, color: 'var(--text-muted)' }}
                      >
                        <strong>ID:</strong> {discordId || '—'}
                      </div>
                    </div>
                  </div>

                  <div className="profile-actions">
                    <button
                      type="button"
                      className="button small"
                      onClick={() => startDiscordLogin()}
                    >
                      Re-auth Discord
                    </button>
                  </div>
                </div>
              </div>

              {/* Email */}
              <div className="profile-section">
                <div className="profile-section-title">Email</div>

                <div className="profile-row">
                  <div className="profile-kv" style={{ flex: '1 1 auto' }}>
                    <div className="profile-value">
                      <strong>Current:</strong> {email || '—'}{' '}
                      <span
                        className={
                          'profile-status-pill ' +
                          ((emailVerifiedAtLocal || emailVerifiedAt)
                            ? 'profile-status-pill--ok'
                            : 'profile-status-pill--warn')
                        }
                      >
                        {(emailVerifiedAtLocal || emailVerifiedAt) ? 'verified' : 'not verified'}
                      </span>
                    </div>

                    {(pendingEmailLocal || pendingEmail) &&
                      !(emailVerifiedAtLocal || emailVerifiedAt) && (
                        <div
                          className="profile-value"
                          style={{ fontSize: 12, color: 'var(--text-muted)' }}
                        >
                          Pending: <code>{pendingEmailLocal || pendingEmail}</code>
                        </div>
                      )}

                    <div style={{ marginTop: 6, fontSize: 12, color: 'var(--text-muted)' }}>
                      Enter a new email and we’ll send a verification link.
                    </div>

                    <div className="profile-inline">
                      <input
                        className="profile-email-input"
                        type="email"
                        value={emailDraft}
                        onChange={(e) => {
                          setEmailDraft(e.target.value);
                          if (emailUiStatus) setEmailUiStatus('');
                        }}
                        placeholder="you@example.com"
                        autoComplete="email"
                        disabled={emailUiBusy}
                      />

                      <button
                        type="button"
                        className="button small primary"
                        onClick={handleSendVerify}
                        disabled={emailUiBusy || !emailOk}
                        title={!emailOk ? 'Enter a valid email' : 'Send verification email'}
                      >
                        {emailUiBusy ? 'Working…' : 'Send verify'}
                      </button>

                      <button
                        type="button"
                        className="button small"
                        onClick={handleResendVerify}
                        disabled={emailUiBusy || (!email && !(pendingEmailLocal || pendingEmail))}
                      >
                        Resend
                      </button>

                      <button
                        type="button"
                        className="button small"
                        onClick={handleCheckVerified}
                        disabled={emailUiBusy}
                      >
                        I’ve verified
                      </button>
                    </div>

                    {emailUiStatus && (
                      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                        {emailUiStatus}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
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
  onRequestAnotherWorkspace,
  requestWorkspaceBusy,
  requestWorkspaceStatus,
  pendingWorkspaceRequest,
}) {
  return (
    <aside className="app-sidebar">
      {/* SPACES */}
      <div className="sidebar-section">
        <h2>Spaces</h2>
<ul className="space-list">
          {spaces.length === 0 ? (
            <li style={{ fontSize: 12, color: 'var(--text-muted)', padding: '8px 10px' }}>
              No spaces yet.
            </li>
          ) : null}

          {spaces.map((s) => (
            <li
              key={s.slug}
              className={'space-item' + (s.slug === activeSlug ? ' active' : '')}
              onClick={() => onSelect(s.slug)}
            >
              <div className="space-item-name">{s.slug}</div>
              <div className="space-item-meta">
                {s.quotaMb ?? '—'} MB quota
                {s.slug === usage?.slug ? ` · ${usage.usedMb.toFixed(2)} MB used` : ''}
              </div>
            </li>
          ))}
 {/* Ghost item: request another workspace */}
          <li
            className="space-item space-item--ghost"
            onClick={() => {
              if (requestWorkspaceBusy) return;
              onRequestAnotherWorkspace?.();
            }}
            style={{
              cursor: requestWorkspaceBusy ? 'not-allowed' : 'pointer',
              opacity: requestWorkspaceBusy ? 0.7 : 1,
            }}
            title="Request an additional workspace"
          >
            <div className="space-item-name">
              {requestWorkspaceBusy ? 'Requesting…' : '+ Request another workspace'}
            </div>
            <div className="space-item-meta">
              {pendingWorkspaceRequest?.status === 'pending'
                ? 'You have a request pending review'
                : 'Ask an admin to provision a new space'}
            </div>
          </li>
        </ul>
        {requestWorkspaceStatus ? (
          <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            {requestWorkspaceStatus}
          </div>
        ) : null}
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
    sandbox="allow-scripts allow-forms"
    referrerPolicy="no-referrer"
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
  // ───────────────── Version history modal state ─────────────────
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historySeeding, setHistorySeeding] = useState(false);
  const [historyRestoring, setHistoryRestoring] = useState(false);
  const [historyError, setHistoryError] = useState('');

  const [historyTracked, setHistoryTracked] = useState(false);
  const [historyFileMeta, setHistoryFileMeta] = useState(null);
  const [historyVersions, setHistoryVersions] = useState([]);

  const [historyActiveId, setHistoryActiveId] = useState(null);
  const [historyActiveMeta, setHistoryActiveMeta] = useState(null);
  const [historyContentLoading, setHistoryContentLoading] = useState(false);
  const [historyContent, setHistoryContent] = useState('');

  const bothCodePanels = showEditor && showGpt;

  // Per-panel font sizes
  const [editorFontSize, setEditorFontSize] = useState(12);
  const [gptFontSize, setGptFontSize] = useState(12);

  // Editor overlay refs
  const editorTextareaRef = useRef(null);
  const editorHighlightRef = useRef(null);

  // Themes
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
    return () =>
      window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [hasUnsavedChanges]);

  // Report dirty state up to DashboardPage
  useEffect(() => {
    onDirtyChange?.(hasUnsavedChanges);
  }, [hasUnsavedChanges, onDirtyChange]);

    const formatWhen = (iso) => {
    if (!iso) return '';
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return String(iso);
    }
  };

  const formatBytes = (n) => {
    const num = Number(n);
    if (!Number.isFinite(num) || num < 0) return '—';
    if (num < 1024) return `${num} B`;
    const kb = num / 1024;
    if (kb < 1024) return `${kb.toFixed(1)} KB`;
    const mb = kb / 1024;
    return `${mb.toFixed(2)} MB`;
  };

  const openHistoryModal = useCallback(() => {
    if (!selectedPath) return;
    setHistoryOpen(true);
  }, [selectedPath]);

  const closeHistoryModal = useCallback(() => {
    if (historyLoading || historySeeding || historyRestoring) return;
    setHistoryOpen(false);
  }, [historyLoading, historySeeding, historyRestoring]);

  const loadHistoryVersion = useCallback(
    async (versionId) => {
      if (!slug || !versionId) return;

      setHistoryActiveId(versionId);
      setHistoryContentLoading(true);
      setHistoryError('');

      try {
        const data = await getSpaceFileVersion(slug, versionId);
        setHistoryActiveMeta(data.version || null);
        setHistoryContent(data.content || '');
      } catch (err) {
        console.error(err);
        setHistoryActiveMeta(null);
        setHistoryContent('');
        setHistoryError(
          err.payload?.message ||
            err.payload?.error ||
            'Failed to load version content.'
        );
      } finally {
        setHistoryContentLoading(false);
      }
    },
    [slug]
  );

  const loadHistoryList = useCallback(
    async ({ autoSelect = true } = {}) => {
      if (!slug || !selectedPath) return;

      setHistoryLoading(true);
      setHistoryError('');

      try {
        const data = await getSpaceFileHistory(slug, {
          path: selectedPath,
          limit: 200,
        });

        const versions = data.versions || [];
        setHistoryTracked(!!data.tracked);
        setHistoryFileMeta(data.file || null);
        setHistoryVersions(versions);

        if (!autoSelect) return;

        const currentId = data.file?.currentVersionId || null;
        const keepExisting =
          historyActiveId && versions.some((v) => v.id === historyActiveId);

        const nextId =
          keepExisting
            ? historyActiveId
            : currentId && versions.some((v) => v.id === currentId)
            ? currentId
            : versions[0]?.id || null;

        if (nextId) {
          await loadHistoryVersion(nextId);
        } else {
          setHistoryActiveId(null);
          setHistoryActiveMeta(null);
          setHistoryContent('');
        }
      } catch (err) {
        console.error(err);
        setHistoryTracked(false);
        setHistoryFileMeta(null);
        setHistoryVersions([]);
        setHistoryActiveId(null);
        setHistoryActiveMeta(null);
        setHistoryContent('');
        setHistoryError(
          err.payload?.message || err.payload?.error || 'Failed to load history.'
        );
      } finally {
        setHistoryLoading(false);
      }
    },
    [slug, selectedPath, historyActiveId, loadHistoryVersion]
  );

  useEffect(() => {
    if (!historyOpen) return;
    loadHistoryList({ autoSelect: true });
  }, [historyOpen, selectedPath, loadHistoryList]);

  const seedHistoryForFile = useCallback(async () => {
    if (!slug || !selectedPath) return;

    if (hasUnsavedChanges) {
      const ok = window.confirm('Start tracking by saving your current unsaved changes?');
      if (!ok) return;
    }

    setHistorySeeding(true);
    setHistoryError('');

    try {
      // This “adopts” the current disk file into history too (backend will create an import baseline).
      await saveSpaceFile(slug, selectedPath, fileContent);

      setHasUnsavedChanges(false);
      onUsageRefresh?.();

      await loadFiles();
      await loadHistoryList({ autoSelect: true });
    } catch (err) {
      console.error(err);
      setHistoryError(
        err.payload?.message || err.payload?.error || 'Failed to start history.'
      );
    } finally {
      setHistorySeeding(false);
    }
  }, [slug, selectedPath, hasUnsavedChanges, fileContent, onUsageRefresh, loadFiles, loadHistoryList]);

  const restoreSelectedVersion = useCallback(async () => {
    if (!slug || !selectedPath || !historyActiveId) return;

    if (hasUnsavedChanges) {
      const ok = window.confirm('You have unsaved changes. Restoring will discard them. Continue?');
      if (!ok) return;
    }

    const meta = historyVersions.find((v) => v.id === historyActiveId) || historyActiveMeta;
    const label = meta ? `${meta.action} @ ${formatWhen(meta.createdAt)}` : 'this version';

    const ok = window.confirm(
      `Restore ${label} to "${selectedPath}"?\n\nThis overwrites the saved file and adds a restore entry to history.`
    );
    if (!ok) return;

    setHistoryRestoring(true);
    setHistoryError('');

    try {
      const result = await restoreSpaceFileVersion(slug, historyActiveId);

      await loadFiles();

      const nextPath = result.path || selectedPath;
      setSelectedPath(nextPath);
      await loadFile(nextPath);

      // Clear GPT thread so it doesn’t refer to old code
      setGptHistory([]);
      setGptError(null);
      setGptMeta({ model: null, sdkIncluded: false, truncated: false });

      onUsageRefresh?.();
      setHistoryOpen(false);
    } catch (err) {
      console.error(err);
      const code = err.payload?.error;

      let msg = err.payload?.message || err.payload?.error || 'Failed to restore version.';
      if (err.status === 409 && code === 'target_exists') {
        msg = 'Restore blocked: destination exists.';
      }
      setHistoryError(msg);
    } finally {
      setHistoryRestoring(false);
    }
  }, [
    slug, selectedPath, historyActiveId, hasUnsavedChanges,
    historyVersions, historyActiveMeta, formatWhen,
    loadFiles, loadFile, onUsageRefresh
  ]);

  const useVersionInEditorBuffer = useCallback(() => {
    if (!historyContent) return;

    if (hasUnsavedChanges) {
      const ok = window.confirm('You have unsaved changes. Replace the editor buffer anyway?');
      if (!ok) return;
    }

    setFileContent(historyContent);
    setHasUnsavedChanges(true);
    setHistoryOpen(false);
  }, [historyContent, hasUnsavedChanges]);

  const copyVersionToClipboard = useCallback(async () => {
    if (!historyContent) return;
    try {
      await navigator.clipboard.writeText(historyContent);
    } catch (err) {
      console.error(err);
      window.prompt('Copy content:', historyContent);
    }
  }, [historyContent]);

  const handleSelectFile = (nextPath) => {
    if (nextPath === selectedPath) return;
    if (hasUnsavedChanges) {
      const ok = window.confirm(
        `You have unsaved changes in "${selectedPath}". Switch files and discard them?`
      );
      if (!ok) return;
    }
    setSelectedPath(nextPath);
    setHistoryOpen(false);
    setHistoryError('');
    setHistoryTracked(false);
    setHistoryFileMeta(null);
    setHistoryVersions([]);
    setHistoryActiveId(null);
    setHistoryActiveMeta(null);
    setHistoryContent('');
    setGptHistory([]);
    setGptError(null);
    setGptMeta({ model: null, sdkIncluded: false, truncated: false });

    // reset editor scroll
    const ta = editorTextareaRef.current;
    const pre = editorHighlightRef.current;
    if (ta && pre) {
      ta.scrollTop = 0;
      ta.scrollLeft = 0;
      pre.scrollTop = 0;
      pre.scrollLeft = 0;
    }
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
  const gptCalls =
    typeof gptUsage?.calls === 'number' ? gptUsage.calls : 0;
  const gptDailyLimit =
    typeof gptUsage?.dailyLimit === 'number' ? gptUsage.dailyLimit : null;
  const gptQuotaReached =
    gptDailyLimit !== null && gptCalls >= gptDailyLimit;

  const onRunGpt = async () => {
    if (!gptPrompt.trim() || gptQuotaReached || gptBusy) return;

    const promptText = gptPrompt.trim();
    const historyToSend = gptHistory.slice(-10);

    setGptBusy(true);
    setGptError(null);
    setGptPrompt(''); // clear input immediately

    // Optimistic user message
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

      let message = err.payload?.message || 'GPT request failed.';

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

  // Editor language + highlighted HTML
  const editorLang = inferPreferredLangFromPath(selectedPath);

const highlightedEditorHtml = useMemo(() => {
  return highlightToHtmlSafe(fileContent || '', editorLang);
}, [fileContent, editorLang]);


  const handleEditorScroll = (e) => {
    const pre = editorHighlightRef.current;
    if (!pre) return;
    pre.scrollTop = e.target.scrollTop;
    pre.scrollLeft = e.target.scrollLeft;
  };

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
                <div className="panel-header-right">
                  <div className="font-size-controls">
                    <button
                      type="button"
                      className="button small"
                      onClick={() =>
                        setEditorFontSize((s) => Math.max(10, s - 1))
                      }
                    >
                      A-
                    </button>
                    <button
                      type="button"
                      className="button small"
                      onClick={() =>
                        setEditorFontSize((s) => Math.min(18, s + 1))
                      }
                    >
                      A+
                    </button>
                  </div>
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
                  <div className="editor-code-shell">
                    <pre
                      className="editor-highlight"
                      ref={editorHighlightRef}
                    >
                      <code
                        className={`hljs language-${editorLang || 'text'}`}
                        dangerouslySetInnerHTML={{
                          __html: highlightedEditorHtml,
                        }}
                      />
                    </pre>

                    <textarea wrap="off"
                      ref={editorTextareaRef}
                      className="editor-textarea"
                      value={fileContent}
                      onChange={(e) => {
                        setFileContent(e.target.value);
                        setHasUnsavedChanges(true);
                      }}
                      onScroll={handleEditorScroll}
                      spellCheck={false}
                    />
                  </div>

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
                      <button
                      className="button small"
                      type="button"
                      onClick={openHistoryModal}
                      disabled={!selectedPath}
                      >
                       History
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
                !showEditor
                  ? 'panel--gpt-full'
                  : bothCodePanels
                  ? 'panel--gpt-half'
                  : ''
              }`}
              style={{
                '--gpt-font-size': `${gptFontSize}px`,
                '--gpt-code-font-size': `${Math.max(
                  10,
                  gptFontSize - 1
                )}px`,
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
                <div className="panel-header-right">
                  <div className="font-size-controls">
                    <button
                      type="button"
                      className="button small"
                      onClick={() =>
                        setGptFontSize((s) => Math.max(10, s - 1))
                      }
                    >
                      A-
                    </button>
                    <button
                      type="button"
                      className="button small"
                      onClick={() =>
                        setGptFontSize((s) => Math.min(18, s + 1))
                      }
                    >
                      A+
                    </button>
                  </div>
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
                  <div
                    style={{ fontSize: 12, color: 'var(--code-text)' }}
                  >
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
                                      style={{
                                        margin: '0 0 6px',
                                        fontSize: 12,
                                      }}
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

  const match =
    typeof className === 'string'
      ? /language-(\w+)/.exec(className)
      : null;
  const lang = match?.[1]?.toLowerCase() || '';

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

  if (inline) {
    return (
      <code className="gpt-inline-code" {...props}>
        {children}
      </code>
    );
  }

  const highlightedHtml = highlightToHtmlSafe(codeText, lang);

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
}
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
                      <div className="gpt-message-content">
                        {gptError}
                      </div>
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
                        gptBusy ||
                        !gptPrompt.trim() ||
                        gptQuotaReached
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
                        <>
                          Daily GPT limit reached ({gptCalls} /{' '}
                          {gptDailyLimit} calls)
                        </>
                      ) : (
                        <>
                          Uses your daily GPT quota ({gptCalls} /{' '}
                          {gptDailyLimit} calls today)
                        </>
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

{/* Version history modal */}
{historyOpen && selectedPath && (
  <div className="preview-modal-backdrop" onClick={closeHistoryModal}>
    <div
      className="preview-modal preview-modal--history"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="preview-modal-header">
        <div>
          <div className="preview-modal-title">Version history</div>
          <div className="preview-modal-subtitle">
            {slug}/{selectedPath}
          </div>
        </div>
        <button
          type="button"
          className="preview-modal-close"
          onClick={closeHistoryModal}
          aria-label="Close history"
        >
          ×
        </button>
      </div>

      <div className="preview-modal-body preview-modal-body--history">
        {/* Left: versions list */}
        <div className="history-sidebar">
          <div className="history-sidebar-actions">
            <button
              type="button"
              className="button small"
              onClick={() => loadHistoryList({ autoSelect: false })}
              disabled={historyLoading}
            >
              {historyLoading ? 'Loading…' : 'Refresh'}
            </button>

            {!historyTracked && (
              <button
                type="button"
                className="button small primary"
                onClick={seedHistoryForFile}
                disabled={historySeeding || !selectedPath}
              >
                {historySeeding ? 'Saving…' : 'Start history'}
              </button>
            )}
          </div>

          {historyError && (
            <div style={{ fontSize: 12, color: '#f97373', marginBottom: 10 }}>
              {historyError}
            </div>
          )}

          {!historyTracked && !historyLoading && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
              No history yet. Click <strong>Start history</strong> to create the baseline snapshot.
            </div>
          )}

          {historyVersions.length === 0 && !historyLoading ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              No versions found.
            </div>
          ) : (
            <div className="history-version-list">
              {historyVersions.map((v) => {
                const isActive = v.id === historyActiveId;
                const isCurrent = historyFileMeta?.currentVersionId === v.id;

                return (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() => loadHistoryVersion(v.id)}
                    className={`history-version-btn${isActive ? ' active' : ''}`}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <div style={{ fontSize: 12, fontWeight: 600 }}>
                        {v.action}
                        {isCurrent ? (
                          <span className="pill pill--tiny" style={{ marginLeft: 6 }}>
                            current
                          </span>
                        ) : null}
                      </div>

                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {formatBytes(v.sizeBytes)}
                      </div>
                    </div>

                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                      {formatWhen(v.createdAt)}
                    </div>

                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>
                      {String(v.sha256 || '').slice(0, 10)}…
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Right: preview + actions */}
        <div className="history-main">
          <div className="history-main-toolbar">
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {historyActiveMeta ? (
                <>
                  Viewing <strong>{historyActiveMeta.action}</strong> · {formatWhen(historyActiveMeta.createdAt)} ·{' '}
                  {formatBytes(historyActiveMeta.sizeBytes)}
                </>
              ) : (
                <>Select a version to preview.</>
              )}
            </div>

            <div className="history-main-toolbar-actions">
              <button
                type="button"
                className="button small"
                onClick={copyVersionToClipboard}
                disabled={!historyContent}
              >
                Copy
              </button>

              <button
                type="button"
                className="button small"
                onClick={useVersionInEditorBuffer}
                disabled={!historyContent}
                title="Loads into your editor buffer (does not save)"
              >
                Use in editor
              </button>

              <button
                type="button"
                className="button small primary"
                onClick={restoreSelectedVersion}
                disabled={!historyActiveId || historyRestoring}
                title="Writes this version to disk as the current saved file"
              >
                {historyRestoring ? 'Restoring…' : 'Restore'}
              </button>
            </div>
          </div>

          <div className="history-preview">
            {historyContentLoading ? (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                Loading version…
              </div>
            ) : !historyContent ? (
              <div style={{ padding: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                No content loaded.
              </div>
            ) : (
              <pre>
                <code>{historyContent}</code>
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  </div>
)}


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
  src={`${IFRAME_ORIGIN}/p/${encodeURIComponent(slug)}/${encodeURIComponent(selectedPath)}`}
  title={`Preview ${slug}/${selectedPath}`}
  className="preview-modal-iframe"
  // ✅ No allow-modals => alert/confirm/prompt are blocked (your “XSS” popup goes away)
  // ✅ No allow-same-origin => even if you accidentally serve /p on same origin in dev,
  //    the iframe can’t read cookies/localStorage of the editor origin.
  sandbox="allow-scripts allow-forms"
  referrerPolicy="no-referrer"
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

  useEmailVerifiedGate({ me, loading });

  const [activeSlug, setActiveSlug] = useState(null);
  const [usage, setUsage] = useState(null);
  const [spaceDirty, setSpaceDirty] = useState(false);

  // panel visibility lives here so sidebar controls it
  const [showFiles, setShowFiles] = useState(true);
  const [showEditor, setShowEditor] = useState(true);
  const [showGpt, setShowGpt] = useState(true);

  // workspace request UX (reused for first + additional workspaces)
  const [requestingWorkspace, setRequestingWorkspace] = useState(false);
  const [workspaceRequestStatus, setWorkspaceRequestStatus] = useState('');
  const [workspaceSlugSuggestion, setWorkspaceSlugSuggestion] = useState('');
  const [workspaceNote, setWorkspaceNote] = useState('');
  const [pendingRequest, setPendingRequest] = useState(null);

  // Request form modal
  const [workspaceRequestOpen, setWorkspaceRequestOpen] = useState(false);

  // NEW: compact “OK” confirmation modal
  const [workspaceRequestOkOpen, setWorkspaceRequestOkOpen] = useState(false);
  const [workspaceRequestOkMessage, setWorkspaceRequestOkMessage] = useState('');

  // track when we're in "mobile/stacked" mode
  const [isNarrow, setIsNarrow] = useState(
    typeof window !== 'undefined' ? window.innerWidth <= 1024 : false
  );

  useEffect(() => {
    const onResize = () => setIsNarrow(window.innerWidth <= 1024);
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // When in narrow mode, ensure only one panel is active at a time
  useEffect(() => {
    if (!isNarrow) return;
    const activeCount = [showFiles, showEditor, showGpt].filter(Boolean).length;
    if (activeCount <= 1) return;

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
    if (activeSlug) refreshUsage(activeSlug);
  }, [activeSlug, refreshUsage]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
    } catch (err) {
      console.error(err);
    } finally {
      await refresh?.();
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

  const closeWorkspaceRequestModal = useCallback(() => {
    if (requestingWorkspace) return;
    setWorkspaceRequestOpen(false);
  }, [requestingWorkspace]);

  const openWorkspaceRequestModal = useCallback(() => {
    // If we already *know* there’s a pending request this session, show the OK modal instead.
    if (pendingRequest?.status === 'pending') {
      const msg = 'You already have a pending request. An admin will review it soon.';
      setWorkspaceRequestStatus(msg);
      setWorkspaceRequestOkMessage(msg);
      setWorkspaceRequestOkOpen(true);
      return;
    }

    setWorkspaceRequestStatus('');
    setWorkspaceRequestOpen(true);
  }, [pendingRequest]);

  const closeWorkspaceRequestOkModal = useCallback(() => {
    setWorkspaceRequestOkOpen(false);
  }, []);

  const showWorkspaceOk = useCallback((message) => {
    setWorkspaceRequestOkMessage(message);
    setWorkspaceRequestOkOpen(true);
  }, []);

const handleRequestWorkspace = async () => {
  setWorkspaceRequestStatus('');
  setRequestingWorkspace(true);

  try {
    const data = await requestWorkspace(
      workspaceNote || null,
      workspaceSlugSuggestion || null
    );

    // Success path (backend returns { ok:true, request })
    if (data?.request) {
      setPendingRequest(data.request);

      setWorkspaceSlugSuggestion(
        data.request.suggestedSlug || workspaceSlugSuggestion
      );
      setWorkspaceNote(data.request.note || workspaceNote);
    }

    const msg = 'Request sent. An admin will review it soon.';
    setWorkspaceRequestStatus(msg);

    // Close the big form modal and show the smaller OK modal
    setWorkspaceRequestOpen(false);
    showWorkspaceOk(msg);
  } catch (err) {
    console.error(err);

    // Backend “already pending” behavior is a 429 with payload.error === 'too_many_pending_requests'
    if (err.status === 429 && err.payload?.error === 'too_many_pending_requests') {
      const pending = Array.isArray(err.payload?.pending) ? err.payload.pending : [];
      const first = pending[0] || null;

      if (first) setPendingRequest(first);

      const msg = 'You already have a pending request. An admin will review it soon.';
      setWorkspaceRequestStatus(msg);

      // Close big modal and show OK modal (same UX as success)
      setWorkspaceRequestOpen(false);
      showWorkspaceOk(msg);
      return;
    }

    // Keep the form open on other errors
    setWorkspaceRequestStatus(
      err.payload?.message || 'Failed to submit workspace request.'
    );
  } finally {
    setRequestingWorkspace(false);
  }
};


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

  if (!me) return null;

  const spaces = me.spaces || [];
  const hasPending = pendingRequest?.status === 'pending';

  return (
    <LayoutShell me={me} onLogout={handleLogout}>
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
        onRequestAnotherWorkspace={openWorkspaceRequestModal}
        requestWorkspaceBusy={requestingWorkspace}
        requestWorkspaceStatus={workspaceRequestStatus}
        pendingWorkspaceRequest={pendingRequest}
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
          usage={usage}
        />
      ) : (
        <div className="app-content" style={{ alignItems: 'center', justifyContent: 'center' }}>
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
              You can request a new workspace. An admin will review and create a space for you.
            </div>

            <div style={{ textAlign: 'left', marginBottom: 12 }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Suggested slug (optional)
                <input
                  type="text"
                  value={workspaceSlugSuggestion}
                  onChange={(e) => setWorkspaceSlugSuggestion(e.target.value)}
                  placeholder="e.g. scott-hud"
                  style={{
                    marginTop: 6,
                    width: '100%',
                    borderRadius: 999,
                    border: '1px solid var(--panel-border)',
                    background: 'var(--bg-main)',
                    color: 'var(--text-main)',
                    padding: '8px 12px',
                    fontSize: 13,
                  }}
                />
              </label>

              <label
                style={{
                  fontSize: 12,
                  color: 'var(--text-muted)',
                  marginTop: 10,
                  display: 'block',
                }}
              >
                Note (optional)
                <textarea
                  value={workspaceNote}
                  onChange={(e) => setWorkspaceNote(e.target.value)}
                  placeholder="What is this workspace for?"
                  rows={4}
                  style={{
                    marginTop: 6,
                    width: '100%',
                    borderRadius: 12,
                    border: '1px solid var(--panel-border)',
                    background: 'var(--bg-main)',
                    color: 'var(--text-main)',
                    padding: '10px 12px',
                    fontSize: 13,
                    resize: 'vertical',
                  }}
                />
              </label>
            </div>

            <button
              className="button primary"
              type="button"
              onClick={handleRequestWorkspace}
              disabled={requestingWorkspace || hasPending}
              title={hasPending ? 'You already have a pending request' : 'Request workspace'}
            >
              {requestingWorkspace
                ? 'Requesting…'
                : hasPending
                ? 'Request pending'
                : 'Request workspace'}
            </button>

            {workspaceRequestStatus && (
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
                {workspaceRequestStatus}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Workspace Request Form Modal (tighter, less “funky”) */}
      {workspaceRequestOpen && (
        <div className="preview-modal-backdrop" onClick={closeWorkspaceRequestModal}>
          <div
            className="preview-modal"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 'min(680px, 92vw)',
              maxWidth: 680,
              height: 'auto',
              minHeight: 0,
            }}
          >
            <div className="preview-modal-header">
              <div>
                <div className="preview-modal-title">Request another workspace</div>
                <div className="preview-modal-subtitle">Your request goes to the admin queue.</div>
              </div>
              <button
                type="button"
                className="preview-modal-close"
                onClick={closeWorkspaceRequestModal}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div
              className="preview-modal-body"
              style={{
                display: 'block',
                padding: 16,
              }}
            >
              <div style={{ width: '100%', maxWidth: 520, margin: '0 auto' }}>
                {hasPending && (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
                    You already have a pending request. You can’t submit another until it’s reviewed.
                  </div>
                )}

                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block' }}>
                  Suggested slug (optional)
                  <input
                    type="text"
                    value={workspaceSlugSuggestion}
                    onChange={(e) => setWorkspaceSlugSuggestion(e.target.value)}
                    placeholder="e.g. scott-hud-v2"
                    style={{
                      marginTop: 6,
                      width: '100%',
                      borderRadius: 999,
                      border: '1px solid var(--panel-border)',
                      background: 'var(--bg-main)',
                      color: 'var(--text-main)',
                      padding: '8px 12px',
                      fontSize: 13,
                    }}
                    disabled={requestingWorkspace}
                  />
                </label>

                <label
                  style={{
                    fontSize: 12,
                    color: 'var(--text-muted)',
                    display: 'block',
                    marginTop: 12,
                  }}
                >
                  Note (optional)
                  <textarea
                    value={workspaceNote}
                    onChange={(e) => setWorkspaceNote(e.target.value)}
                    placeholder="What is this workspace for?"
                    rows={4}
                    style={{
                      marginTop: 6,
                      width: '100%',
                      borderRadius: 12,
                      border: '1px solid var(--panel-border)',
                      background: 'var(--bg-main)',
                      color: 'var(--text-main)',
                      padding: '10px 12px',
                      fontSize: 13,
                      resize: 'vertical',
                    }}
                    disabled={requestingWorkspace}
                  />
                </label>

                {workspaceRequestStatus && (
                  <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>
                    {workspaceRequestStatus}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 14 }}>
                  <button
                    type="button"
                    className="button"
                    onClick={closeWorkspaceRequestModal}
                    disabled={requestingWorkspace}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="button primary"
                    onClick={handleRequestWorkspace}
                    disabled={requestingWorkspace || hasPending}
                  >
                    {requestingWorkspace ? 'Requesting…' : 'Request workspace'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Compact OK Modal (after request is sent / already pending) */}
      {workspaceRequestOkOpen && (
        <div
          className="preview-modal-backdrop"
          onClick={() => {
            // optional: allow click-outside to close
            closeWorkspaceRequestOkModal();
          }}
        >
          <div
            className="preview-modal"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 'min(440px, 92vw)',
              maxWidth: 440,
              height: 'auto',
              minHeight: 0,
            }}
          >
            <div className="preview-modal-header">
              <div>
                <div className="preview-modal-title">Workspace request</div>
                <div className="preview-modal-subtitle">Status</div>
              </div>
              <button
                type="button"
                className="preview-modal-close"
                onClick={closeWorkspaceRequestOkModal}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div
              className="preview-modal-body"
              style={{
                display: 'block',
                padding: 16,
              }}
            >
              <div style={{ fontSize: 13, color: 'var(--text-main)', lineHeight: 1.4 }}>
                {workspaceRequestOkMessage || 'Request sent. An admin will review it soon.'}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
                <button type="button" className="button primary" onClick={closeWorkspaceRequestOkModal}>
                  OK
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </LayoutShell>
  );
}

function AdminDashboard() {
  const navigate = useNavigate();

  // ───────────────── Global ─────────────────
  const [booting, setBooting] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  const [tab, setTab] = useState('activity'); // activity | requests | billing | create | email | audit

  const setAuthErrorFrom = (err) => {
    if (err?.status === 401) {
      navigate('/login', { replace: true, state: { from: '/admin' } });
      return true;
    }
    if (err?.status === 403) {
      setForbidden(true);
      return true;
    }
    return false;
  };

  const bestHandle = (u) => {
    if (!u) return '';
    if (u.discordUsername) return `@${u.discordUsername}`;
    if (u.discordGlobalName) return String(u.discordGlobalName);
    if (u.discordId) return String(u.discordId);
    if (u.email) return String(u.email);
    return u.id || '';
  };

  const fmtWhen = (iso) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return String(iso);
    }
  };

  const fmtDateInput = (iso) => {
    if (!iso) return '';
    try {
      return new Date(iso).toISOString().slice(0, 10);
    } catch {
      return '';
    }
  };

  const dateInputToIsoOrNull = (yyyyMmDd) => {
    const s = String(yyyyMmDd || '').trim();
    if (!s) return null;
    const ms = Date.parse(s);
    if (!Number.isFinite(ms)) return null;
    return new Date(ms).toISOString();
  };

const extractUserId = (obj) => {
  const target = obj?.target || null;
  if (!target) return null;

  const candidate =
    target.userId ||
    (target.type === 'user' ? target.id : null) ||
    (target.type === 'workspace_request' ? target.userId : null) ||
    null;

  return candidate ? String(candidate) : null;
};

  // ───────────────── Activity ─────────────────
  const [activityLoading, setActivityLoading] = useState(false);
  const [activityItems, setActivityItems] = useState([]);
  const [activityLimit, setActivityLimit] = useState(200);
  const [activityQ, setActivityQ] = useState('');

  const loadActivity = useCallback(async () => {
    setActivityLoading(true);
    setErrorMsg('');
    try {
      const data = await adminGetActivity({ limit: activityLimit });
      setActivityItems(Array.isArray(data?.items) ? data.items : []);
      setStatusMsg(`Loaded activity (${Array.isArray(data?.items) ? data.items.length : 0}).`);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to load activity feed.');
    } finally {
      setActivityLoading(false);
    }
  }, [activityLimit]);

  const filteredActivity = useMemo(() => {
    const q = String(activityQ || '').trim().toLowerCase();
    if (!q) return activityItems;

    const hay = (x) => {
      const actor = x.actor || {};
      const target = x.target || {};
      const detail = x.detail || {};
      return [
        x.kind,
        x.action,
        x.at,
        actor.discordUsername,
        actor.discordId,
        actor.userId,
        actor.email,
        target.type,
        target.id,
        target.slug,
        target.userId,
        target.email,
        JSON.stringify(detail),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
    };

    return activityItems.filter((x) => hay(x).includes(q));
  }, [activityItems, activityQ]);

  // ───────────────── Requests ─────────────────
  const [reqStatusFilter, setReqStatusFilter] = useState('pending');
  const [requests, setRequests] = useState([]);
  const [requestsLoading, setRequestsLoading] = useState(false);
  const [slugEdits, setSlugEdits] = useState({});
  const [slugErrors, setSlugErrors] = useState({});

  const loadRequests = useCallback(async () => {
    setRequestsLoading(true);
    setErrorMsg('');
    try {
      const data = await adminGetSpaceRequests(reqStatusFilter);
      const reqs = Array.isArray(data?.requests) ? data.requests : [];
      setRequests(reqs);

      setSlugEdits((prev) => {
        const next = { ...prev };
        for (const r of reqs) {
          if (next[r.id]) continue;

          const fromDiscord =
            r.discordUsername ? normalizeSlug(r.discordUsername) :
            r.discordGlobalName ? normalizeSlug(r.discordGlobalName) : '';

          const fromSuggested = r.suggestedSlug ? normalizeSlug(r.suggestedSlug) : '';
          const fromEmail = r.email ? normalizeSlug(String(r.email).split('@')[0]) : '';

          next[r.id] = fromSuggested || fromDiscord || fromEmail;
        }
        return next;
      });

      setSlugErrors({});
      setStatusMsg(`Loaded requests (${reqs.length}).`);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to load requests.');
    } finally {
      setRequestsLoading(false);
    }
  }, [reqStatusFilter]);

  const handleSlugChange = (reqId, rawInput) => {
    const normalized = normalizeSlug(rawInput);
    setSlugEdits((prev) => ({ ...prev, [reqId]: normalized }));

    if (!normalized) {
      setSlugErrors((prev) => ({ ...prev, [reqId]: 'Slug is required.' }));
    } else if (!isValidSlug(normalized)) {
      setSlugErrors((prev) => ({ ...prev, [reqId]: 'Slug must be 3–32 chars (a–z, 0–9, hyphen).' }));
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

    const fromSuggested = req.suggestedSlug ? normalizeSlug(req.suggestedSlug) : '';
    const fromDiscord =
      req.discordUsername ? normalizeSlug(req.discordUsername) :
      req.discordGlobalName ? normalizeSlug(req.discordGlobalName) : '';
    const fromEmail = req.email ? normalizeSlug(String(req.email).split('@')[0]) : '';
    return fromSuggested || fromDiscord || fromEmail;
  };

  // ───────────────── Billing ─────────────────
  const [billingLoading, setBillingLoading] = useState(false);
  const [billingCounts, setBillingCounts] = useState(null);
  const [billingUsers, setBillingUsers] = useState([]);
  const [billingFilter, setBillingFilter] = useState('all'); // all | comped | paid | unpaid | expiringSoon | inactive
  const [billingEdits, setBillingEdits] = useState({});
  const [billingSaving, setBillingSaving] = useState({}); // userId -> bool

  const loadBilling = useCallback(async () => {
    setBillingLoading(true);
    setErrorMsg('');
    try {
      const data = await adminBillingOverview();
      const users = Array.isArray(data?.users) ? data.users : [];
      setBillingCounts(data?.counts || null);
      setBillingUsers(users);

      setBillingEdits((prev) => {
        const next = { ...prev };
        for (const u of users) {
          if (next[u.id]) continue;
          next[u.id] = {
            comped: !!u?.billing?.comped,
            paidUntil: u?.billing?.paidUntil || null,
            tier: u?.billing?.tier || '',
            notes: u?.billing?.notes || '',
            status: u?.status || 'active',
          };
        }
        return next;
      });

      setStatusMsg('Loaded billing.');
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to load billing.');
    } finally {
      setBillingLoading(false);
    }
  }, []);

  const filteredBillingUsers = useMemo(() => {
    const arr = Array.isArray(billingUsers) ? billingUsers : [];
    if (billingFilter === 'all') return arr;

    return arr.filter((u) => {
      const ent = u.entitlement || {};
      if (billingFilter === 'comped') return !!ent.isComped && !!ent.isActive;
      if (billingFilter === 'paid') return !ent.isComped && !!ent.isPaid;
      if (billingFilter === 'unpaid') return !!ent.isActive && !ent.isPaid;
      if (billingFilter === 'expiringSoon') return !!ent.expiringSoon;
      if (billingFilter === 'inactive') return !ent.isActive;
      return true;
    });
  }, [billingUsers, billingFilter]);

  const setBillingField = (userId, field, value) => {
    setBillingEdits((prev) => ({
      ...prev,
      [userId]: { ...(prev[userId] || {}), [field]: value },
    }));
  };

  const quickCompIndefinitely = async (u) => {
    const ok = window.confirm(`Comp ${bestHandle(u)} indefinitely?`);
    if (!ok) return;

    setBillingSaving((p) => ({ ...p, [u.id]: true }));
    try {
      await adminUpdateUserBilling(u.id, { comped: true, status: 'active' });
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
      setStatusMsg('Comped indefinitely.');
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to comp user.');
    } finally {
      setBillingSaving((p) => ({ ...p, [u.id]: false }));
    }
  };

  const quickExtend30 = async (u) => {
    setBillingSaving((p) => ({ ...p, [u.id]: true }));
    try {
      await adminExtendUserBilling(u.id, 30);
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
      setStatusMsg('Extended 30 days.');
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to extend.');
    } finally {
      setBillingSaving((p) => ({ ...p, [u.id]: false }));
    }
  };

  const saveBillingRow = async (u) => {
    const patch = billingEdits[u.id] || {};
    setBillingSaving((p) => ({ ...p, [u.id]: true }));
    try {
      await adminUpdateUserBilling(u.id, {
        comped: !!patch.comped,
        paidUntil: patch.paidUntil ?? null,
        tier: String(patch.tier || '').trim() || null,
        notes: String(patch.notes || '').trim() || null,
        status: String(patch.status || u.status || 'active').toLowerCase(),
      });
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
      setStatusMsg(`Saved billing for ${bestHandle(u)}.`);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to save billing.');
    } finally {
      setBillingSaving((p) => ({ ...p, [u.id]: false }));
    }
  };

  // ───────────────── Create Space ─────────────────
  const [createSlug, setCreateSlug] = useState('');
  const [createQuotaMb, setCreateQuotaMb] = useState(100);
  const [createOwnerUser, setCreateOwnerUser] = useState(null);
  const [creatingSpace, setCreatingSpace] = useState(false);

  const suggestSlugFromUser = (u) => {
    const raw =
      (u?.discordUsername ? u.discordUsername : '') ||
      (u?.discordGlobalName ? u.discordGlobalName : '') ||
      (u?.email ? String(u.email).split('@')[0] : '') ||
      '';
    return normalizeSlug(raw);
  };

  const handlePickOwnerForCreate = (u) => {
    setCreateOwnerUser(u);
    if (!createSlug) {
      const suggestion = suggestSlugFromUser(u);
      if (suggestion) setCreateSlug(suggestion);
    }
  };

  const handleCreateSpace = async () => {
    const slug = normalizeSlug(createSlug);
    if (!slug || !isValidSlug(slug)) {
      setErrorMsg('Create space: slug must be 3–32 chars (a–z, 0–9, hyphen).');
      return;
    }

    try {
      setCreatingSpace(true);
      setErrorMsg('');
      setStatusMsg('Creating space…');
      const data = await adminCreateSpace({
        slug,
        quotaMb: Number(createQuotaMb) || 100,
        ownerUserId: createOwnerUser?.id || null,
        ownerEmail: null,
      });
      setStatusMsg(`Created space "${data?.space?.slug || slug}".`);
      setCreateSlug('');
      setCreateOwnerUser(null);
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to create space.');
    } finally {
      setCreatingSpace(false);
    }
  };

  // ───────────────── Send Email ─────────────────
  const [emailUser, setEmailUser] = useState(null);
  const [emailSubject, setEmailSubject] = useState('');
  const [emailBody, setEmailBody] = useState('');
  const [emailAsHtml, setEmailAsHtml] = useState(false);
  const [emailFrom, setEmailFrom] = useState('');
  const [sendingEmail, setSendingEmail] = useState(false);

  const handlePickEmailUser = (u) => setEmailUser(u);

  const handleSendEmail = async () => {
    if (!emailUser?.id) {
      setErrorMsg('Send email: pick a user first.');
      return;
    }
    if (!String(emailSubject || '').trim()) {
      setErrorMsg('Send email: subject is required.');
      return;
    }
    if (!String(emailBody || '').trim()) {
      setErrorMsg('Send email: body is required.');
      return;
    }

    try {
      setSendingEmail(true);
      setErrorMsg('');
      setStatusMsg('Sending email…');

      await adminSendUserEmail(emailUser.id, {
        subject: String(emailSubject).trim(),
        text: emailAsHtml ? '' : String(emailBody),
        html: emailAsHtml ? String(emailBody) : '',
        from: String(emailFrom || '').trim() || null,
      });

      setStatusMsg(`Sent email to ${bestHandle(emailUser)}.`);
      await Promise.all([loadAudit(), loadActivity()]);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to send email.');
    } finally {
      setSendingEmail(false);
    }
  };

  // ───────────────── Identity (duplicates + merge + delete) ─────────────────
const [idLoading, setIdLoading] = useState(false);
const [idError, setIdError] = useState('');
const [dupGroups, setDupGroups] = useState([]);

const [idQuery, setIdQuery] = useState(''); // filter by email/userId/discordId
const [mergeBusyKey, setMergeBusyKey] = useState(''); // `${email}:${sourceId}`
const [deleteBusyId, setDeleteBusyId] = useState('');

const loadIdentity = useCallback(async () => {
  setIdLoading(true);
  setIdError('');
  try {
    const data = await adminGetDuplicateUsers();
    const groups = Array.isArray(data?.groups) ? data.groups : [];
    setDupGroups(groups);
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setIdError(err.payload?.message || err.payload?.error || 'Failed to load duplicates.');
  } finally {
    setIdLoading(false);
  }
}, []);

useEffect(() => {
  if (tab !== 'identity') return;
  if (!dupGroups.length && !idLoading) loadIdentity();
}, [tab, dupGroups.length, idLoading, loadIdentity]);

const filteredDupGroups = useMemo(() => {
  const q = String(idQuery || '').trim().toLowerCase();
  if (!q) return dupGroups;

  const hay = (g) => {
    const users = Array.isArray(g?.users) ? g.users : [];
    return [
      g?.email,
      g?.recommendedTargetUserId,
      ...users.flatMap((u) => [u.userId, u.discordId, u.discordUsername, u.email, u.pendingEmail]),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
  };

  return dupGroups.filter((g) => hay(g).includes(q));
}, [dupGroups, idQuery]);

const confirmMerge = async ({ email, sourceUserId, targetUserId }) => {
  if (!sourceUserId || !targetUserId) return;

  const ok = window.confirm(
    `MERGE USERS\n\nEmail: ${email}\nSource: ${sourceUserId}\nTarget: ${targetUserId}\n\n` +
      `This will move ownership/session/history references to the target and remove the source user record.\n\nContinue?`
  );
  if (!ok) return;

  const key = `${email}:${sourceUserId}`;
  setMergeBusyKey(key);
  setIdError('');

  try {
    await adminMergeUsers({ sourceUserId, targetUserId, primaryEmail: null });
    // refresh dup list + other dashboards
    await Promise.allSettled([loadIdentity(), loadBilling?.(), loadAudit?.(), loadActivity?.()]);
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setIdError(err.payload?.message || err.payload?.error || 'Merge failed.');
  } finally {
    setMergeBusyKey('');
  }
};

const confirmDeleteUser = async (userId) => {
  if (!userId) return;

  const reason = window.prompt(
    `SOFT DELETE USER\n\nuserId: ${userId}\n\nOptional reason:`,
    ''
  );

  const ok = window.confirm(
    `Confirm soft delete?\n\nuserId: ${userId}\n\nThis will:\n- revoke sessions\n- remove from space members lists\n- mark status=deleted\n\nProceed?`
  );
  if (!ok) return;

  setDeleteBusyId(userId);
  setIdError('');

  try {
    await adminDeleteUser(userId, reason || null);
    await Promise.allSettled([loadIdentity(), loadBilling?.(), loadAudit?.(), loadActivity?.()]);
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setIdError(err.payload?.message || err.payload?.error || 'Delete failed.');
  } finally {
    setDeleteBusyId('');
  }
};


  // ───────────────── Audit ─────────────────
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditEntries, setAuditEntries] = useState([]);
  const [auditQ, setAuditQ] = useState('');
  const [auditActor, setAuditActor] = useState('');
  const [auditAction, setAuditAction] = useState('');
  const [auditLimit, setAuditLimit] = useState(200);

  const loadAudit = useCallback(async () => {
    setAuditLoading(true);
    setErrorMsg('');
    try {
      const data = await adminGetAudit({
        limit: auditLimit,
        q: auditQ.trim(),
        actor: auditActor.trim(),
        action: auditAction.trim(),
      });
      setAuditEntries(Array.isArray(data?.entries) ? data.entries : []);
      setStatusMsg(`Loaded audit (${Array.isArray(data?.entries) ? data.entries.length : 0}).`);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to load audit log.');
    } finally {
      setAuditLoading(false);
    }
  }, [auditLimit, auditQ, auditActor, auditAction]);

    // ───────────────── Boot ─────────────────
useEffect(() => {
  let alive = true;

  (async () => {
    try {
      // Don’t let one failure block boot completion
      await Promise.allSettled([
        loadActivity(),
        loadRequests(),
        loadBilling(),
        loadAudit(),
      ]);
    } finally {
      if (alive) setBooting(false);
    }
  })();

  return () => {
    alive = false;
  };
}, [loadActivity, loadRequests, loadBilling, loadAudit]);



  // ───────────────── Sessions modal ─────────────────
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [sessionsUser, setSessionsUser] = useState(null);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessionsList, setSessionsList] = useState([]);
  const [sessionsError, setSessionsError] = useState('');
  const [revokingSid, setRevokingSid] = useState(''); // sid or '__all__'

  const openSessionsModal = useCallback(async (userObjOrId) => {
    const u =
      typeof userObjOrId === 'string'
        ? ({ id: userObjOrId })
        : (userObjOrId || null);

    const userId = u?.id ? String(u.id) : null;
    if (!userId) return;

    setSessionsUser(u);
    setSessionsOpen(true);
    setSessionsError('');
    setSessionsList([]);
    setRevokingSid('');
    setSessionsLoading(true);

    try {
      const data = await adminGetUserSessions(userId, { limit: 50 });
      setSessionsList(Array.isArray(data?.sessions) ? data.sessions : []);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setSessionsError(err.payload?.message || err.payload?.error || 'Failed to load sessions.');
    } finally {
      setSessionsLoading(false);
    }
  }, []);

  const closeSessionsModal = useCallback(() => {
    if (sessionsLoading || !!revokingSid) return;
    setSessionsOpen(false);
  }, [sessionsLoading, revokingSid]);

  const refreshSessions = useCallback(async () => {
    const userId = sessionsUser?.id ? String(sessionsUser.id) : null;
    if (!userId) return;

    setSessionsLoading(true);
    setSessionsError('');
    try {
      const data = await adminGetUserSessions(userId, { limit: 50 });
      setSessionsList(Array.isArray(data?.sessions) ? data.sessions : []);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setSessionsError(err.payload?.message || err.payload?.error || 'Failed to load sessions.');
    } finally {
      setSessionsLoading(false);
    }
  }, [sessionsUser]);

  const revokeAllSessions = useCallback(async () => {
    const userId = sessionsUser?.id ? String(sessionsUser.id) : null;
    if (!userId) return;

    const label = bestHandle(sessionsUser) || userId;
    const ok = window.confirm(`Revoke ALL sessions for ${label}? They will be logged out everywhere.`);
    if (!ok) return;

    setRevokingSid('__all__');
    setSessionsError('');
    try {
      await adminRevokeUserSessions(userId, {});
      await Promise.all([refreshSessions(), loadAudit(), loadActivity()]);
      setStatusMsg('Revoked all sessions.');
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setSessionsError(err.payload?.message || err.payload?.error || 'Failed to revoke all sessions.');
    } finally {
      setRevokingSid('');
    }
  }, [sessionsUser, refreshSessions, loadAudit, loadActivity]);

  const revokeOneSession = useCallback(async (sid) => {
    const userId = sessionsUser?.id ? String(sessionsUser.id) : null;
    if (!userId || !sid) return;

    const ok = window.confirm(`Revoke this session?\n\n${sid}`);
    if (!ok) return;

    setRevokingSid(sid);
    setSessionsError('');
    try {
      await adminRevokeUserSessions(userId, { sid });
      await Promise.all([refreshSessions(), loadAudit(), loadActivity()]);
      setStatusMsg('Revoked session.');
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setSessionsError(err.payload?.message || err.payload?.error || 'Failed to revoke session.');
    } finally {
      setRevokingSid('');
    }
  }, [sessionsUser, refreshSessions, loadAudit, loadActivity]);



  // ───────────────── User Drawer ─────────────────
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerUserId, setDrawerUserId] = useState(null);
  const [drawerUser, setDrawerUser] = useState(null);
  const [drawerLoading, setDrawerLoading] = useState(false);
  const [drawerError, setDrawerError] = useState('');

  const findUserInCache = useCallback((userId) => {
    const id = String(userId || '').trim();
    if (!id) return null;
    const arr = Array.isArray(billingUsers) ? billingUsers : [];
    return arr.find((u) => u && String(u.id || '') === id) || null;
  }, [billingUsers]);

  const openUserDrawer = useCallback(async (userId) => {
    const id = String(userId || '').trim();
    if (!id) return;

    setDrawerOpen(true);
    setDrawerUserId(id);
    setDrawerError('');
    setDrawerUser(null);
    setDrawerLoading(true);

    // Try cache first (billing overview)
    const cached = findUserInCache(id);
    if (cached) {
      setDrawerUser(cached);
      setDrawerLoading(false);
      return;
    }

    try {
      const data = await adminGetUserDetail(id);
      setDrawerUser(data?.user || null);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setDrawerError(err.payload?.message || err.payload?.error || 'Failed to load user.');
    } finally {
      setDrawerLoading(false);
    }
  }, [findUserInCache]);

  const closeUserDrawer = useCallback(() => {
    if (drawerLoading) return;
    setDrawerOpen(false);
  }, [drawerLoading]);

  // ───────────────── User search (Create + Email) ─────────────────
  const [userQuery, setUserQuery] = useState('');
  const [userResults, setUserResults] = useState([]);
  const [userSearching, setUserSearching] = useState(false);

  useEffect(() => {
    const shouldSearch = tab === 'create' || tab === 'email';
    if (!shouldSearch) return;

    let alive = true;
    const q = String(userQuery || '').trim();

    const t = setTimeout(async () => {
      if (!q) {
        setUserResults([]);
        return;
      }
      setUserSearching(true);
      try {
        const data = await adminSearchUsers(q, 25);
        if (!alive) return;
        setUserResults(Array.isArray(data?.users) ? data.users : []);
      } catch (err) {
        console.error(err);
        if (setAuthErrorFrom(err)) return;
        if (!alive) return;
        setUserResults([]);
      } finally {
        if (alive) setUserSearching(false);
      }
    }, 250);

    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [userQuery, tab]);

// ───────────────── Doctor ─────────────────
const [doctorLoading, setDoctorLoading] = useState(false);
const [doctorData, setDoctorData] = useState(null);
const [doctorError, setDoctorError] = useState('');

const loadDoctor = useCallback(async () => {
  setDoctorLoading(true);
  setDoctorError('');
  setErrorMsg('');

  try {
    const data = await adminDoctor();
    setDoctorData(data);
    setStatusMsg('Doctor loaded.');
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setDoctorError(err.payload?.message || err.payload?.error || 'Failed to load doctor.');
  } finally {
    setDoctorLoading(false);
  }
}, []);

useEffect(() => {
  if (tab !== 'doctor') return;
  if (!doctorData && !doctorLoading) loadDoctor();
}, [tab, doctorData, doctorLoading, loadDoctor]);

// ───────────────── Email templates ─────────────────
const [tplLoading, setTplLoading] = useState(false);
const [tplError, setTplError] = useState('');
const [templates, setTemplates] = useState([]);
const [tplQuery, setTplQuery] = useState('');
const [activeTplId, setActiveTplId] = useState(null);
const [tplDraft, setTplDraft] = useState({
  id: null,
  name: '',
  subject: '',
  mode: 'text', // text|html|both
  text: '',
  html: '',
});
const [tplDirty, setTplDirty] = useState(false);
const [tplSaving, setTplSaving] = useState(false);
const [tplDeleting, setTplDeleting] = useState(false);

// Sending
const [tplSendQuery, setTplSendQuery] = useState('');
const [tplSendSearching, setTplSendSearching] = useState(false);
const [tplSendResults, setTplSendResults] = useState([]);
const [tplSendUser, setTplSendUser] = useState(null);
const [tplSendSpaceSlug, setTplSendSpaceSlug] = useState('');
const [tplSending, setTplSending] = useState(false);
const [tplSendStatus, setTplSendStatus] = useState('');
const [tplLoadedOnce, setTplLoadedOnce] = useState(false);

const loadTemplates = useCallback(async () => {
  setTplLoading(true);
  // NOTE: don't clear tplError here if you want errors to stay visible during auto-load

  try {
    const data = await adminListEmailTemplates();
    const list = Array.isArray(data?.templates) ? data.templates : [];
    setTemplates(list);

    // Auto-select if nothing selected OR selected template disappeared
    const exists = activeTplId && list.some((t) => t?.id === activeTplId);

    if ((!activeTplId || !exists) && list.length) {
      const first = list[0];
      setActiveTplId(first.id);
      setTplDraft({
        id: first.id,
        name: first.name || '',
        subject: first.subject || '',
        mode: first.mode || 'text',
        text: first.text || '',
        html: first.html || '',
      });
      setTplDirty(false);
    }

    // If list is empty, keep draft as-is (lets you create a new template)
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setTplError(
      err.payload?.message ||
        err.payload?.error ||
        'Failed to load templates.'
    );
  } finally {
    setTplLoading(false);
    setTplLoadedOnce(true); // ✅ prevents infinite retry loops
  }
}, [activeTplId]);

useEffect(() => {
  if (tab !== 'templates') return;
  if (tplLoadedOnce) return;
  if (tplLoading) return;
  loadTemplates();
}, [tab, tplLoadedOnce, tplLoading, loadTemplates]);

const selectTemplate = (tpl) => {
  if (!tpl) return;

  if (tplDirty) {
    const ok = window.confirm(
      'You have unsaved changes. Discard them and switch templates?'
    );
    if (!ok) return;
  }

  setActiveTplId(tpl.id);
  setTplDraft({
    id: tpl.id,
    name: tpl.name || '',
    subject: tpl.subject || '',
    mode: tpl.mode || 'text',
    text: tpl.text || '',
    html: tpl.html || '',
  });
  setTplDirty(false);

  // ✅ Reset “send” state so you don’t accidentally send the new template
  // to the previous recipient.
  setTplSendStatus('');
  setTplSendUser(null);
  setTplSendQuery('');
  setTplSendResults([]);
};

const setDraftField = (k, v) => {
  setTplDraft((prev) => ({ ...prev, [k]: v }));
  setTplDirty(true);
};

const newTemplate = () => {
  if (tplDirty) {
    const ok = window.confirm(
      'Discard unsaved changes and create a new template draft?'
    );
    if (!ok) return;
  }

  setActiveTplId(null);
  setTplDraft({
    id: null,
    name: '',
    subject: '',
    mode: 'text',
    text: '',
    html: '',
  });
  setTplDirty(true);

  // Reset send UI
  setTplSendStatus('');
  setTplSendUser(null);
  setTplSendQuery('');
  setTplSendResults([]);
  setTplSendSpaceSlug('');
};

const saveTemplate = async () => {
  const name = String(tplDraft.name || '').trim();
  const subject = String(tplDraft.subject || '').trim();
  const mode = String(tplDraft.mode || 'text')
    .trim()
    .toLowerCase(); // text|html|both
  const text = String(tplDraft.text || '');
  const html = String(tplDraft.html || '');

  if (!name) return setTplError('Template name is required.');
  if (!subject) return setTplError('Subject is required.');

  if (mode === 'text' && !text.trim()) {
    return setTplError('Text body is required for mode=text.');
  }
  if (mode === 'html' && !html.trim()) {
    return setTplError('HTML body is required for mode=html.');
  }
  if (mode === 'both' && !text.trim() && !html.trim()) {
    return setTplError('Provide at least one body for mode=both.');
  }

  setTplSaving(true);
  setTplError('');

  try {
    if (!tplDraft.id) {
      const data = await adminCreateEmailTemplate({
        name,
        subject,
        mode,
        text,
        html,
      });

      const created = data?.template || null;

      // Reload list and select newly created if returned
      await loadTemplates();

      if (created?.id) {
        setActiveTplId(created.id);
        setTplDraft({
          id: created.id,
          name: created.name || '',
          subject: created.subject || '',
          mode: created.mode || 'text',
          text: created.text || '',
          html: created.html || '',
        });
      }

      setTplDirty(false);
    } else {
      await adminUpdateEmailTemplate(tplDraft.id, {
        name,
        subject,
        mode,
        text,
        html,
      });

      await loadTemplates();
      setTplDirty(false);
    }

    setTplSendStatus('Saved.');

    // Optional: refresh logs if you have these funcs
    try {
      await Promise.all([loadAudit?.(), loadActivity?.()]);
    } catch {}
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setTplError(
      err.payload?.message ||
        err.payload?.error ||
        'Failed to save template.'
    );
  } finally {
    setTplSaving(false);
  }
};

const deleteTemplate = async () => {
  if (!tplDraft.id) return;

  const ok = window.confirm(
    `Delete template "${tplDraft.name}"? This cannot be undone.`
  );
  if (!ok) return;

  setTplDeleting(true);
  setTplError('');

  try {
    await adminDeleteEmailTemplate(tplDraft.id);

    // Clear selection before reload so auto-select works
    setActiveTplId(null);
    setTplDraft({ id: null, name: '', subject: '', mode: 'text', text: '', html: '' });
    setTplDirty(false);

    setTplSendStatus('Deleted.');
    setTplSendUser(null);
    setTplSendQuery('');
    setTplSendResults([]);
    setTplSendSpaceSlug('');

    // Allow auto-select again after delete
    setTplLoadedOnce(false);

    await loadTemplates();

    try {
      await Promise.all([loadAudit?.(), loadActivity?.()]);
    } catch {}
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setTplError(
      err.payload?.message ||
        err.payload?.error ||
        'Failed to delete template.'
    );
  } finally {
    setTplDeleting(false);
  }
};

// Recipient search for "Send using template"
useEffect(() => {
  if (tab !== 'templates') return;

  let alive = true;
  const q = String(tplSendQuery || '').trim();

  const t = setTimeout(async () => {
    if (!q) {
      setTplSendResults([]);
      return;
    }

    setTplSendSearching(true);
    try {
      const data = await adminSearchUsers(q, 25);
      if (!alive) return;
      setTplSendResults(Array.isArray(data?.users) ? data.users : []);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      if (!alive) return;
      setTplSendResults([]);
    } finally {
      if (alive) setTplSendSearching(false);
    }
  }, 250);

  return () => {
    alive = false;
    clearTimeout(t);
  };
}, [tab, tplSendQuery]);

const sendTemplate = async () => {
  if (!tplDraft.id) return setTplError('Save the template before sending.');
  if (!tplSendUser?.id) return setTplError('Pick a recipient user.');

  setTplSending(true);
  setTplError('');

  try {
    await adminSendEmailTemplate(tplDraft.id, {
      userId: tplSendUser.id,
      spaceSlug: String(tplSendSpaceSlug || '').trim() || null,
    });

    setTplSendStatus('Sent.');

    try {
      await Promise.all([loadAudit?.(), loadActivity?.()]);
    } catch {}
  } catch (err) {
    console.error(err);
    if (setAuthErrorFrom(err)) return;
    setTplError(
      err.payload?.message ||
        err.payload?.error ||
        'Failed to send template.'
    );
  } finally {
    setTplSending(false);
  }
};



  // ───────────────── Requests actions (depends on billing/audit/activity) ─────────────────
  const handleApprove = async (reqId, quotaMbOverride = 100) => {
    const req = requests.find((r) => r.id === reqId);
    if (!req) return;

    const slug = normalizeSlug(getSlugForRequest(req));
    if (!slug || !isValidSlug(slug)) {
      setSlugErrors((prev) => ({ ...prev, [reqId]: 'Slug must be 3–32 chars (a–z, 0–9, hyphen).' }));
      return;
    }

    const quotaMb = Number.isFinite(Number(quotaMbOverride)) ? Number(quotaMbOverride) : 100;

    try {
      setErrorMsg('');
      setStatusMsg('Approving…');
      await adminApproveSpaceRequest(reqId, { slug, quotaMb });
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg(`Approved → "${slug}".`);
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;

      const code = err.payload?.error;
      if (err.status === 409 && (code === 'space_exists' || code === 'dir_exists')) {
        setSlugErrors((prev) => ({ ...prev, [reqId]: err.payload?.message || 'Slug already in use.' }));
      } else {
        setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to approve request.');
      }
    }
  };

  const handleReject = async (reqId) => {
    const reason = window.prompt('Optional reason for rejection:', '') || '';
    try {
      setErrorMsg('');
      setStatusMsg('Rejecting…');
      await adminRejectSpaceRequest(reqId, reason || null);
      setRequests((prev) => prev.filter((r) => r.id !== reqId));
      setStatusMsg('Rejected.');
      await Promise.all([loadBilling(), loadAudit(), loadActivity()]);
    } catch (err) {
      console.error(err);
      if (setAuthErrorFrom(err)) return;
      setErrorMsg(err.payload?.message || err.payload?.error || 'Failed to reject request.');
    }
  };

  // ───────────────── Render ─────────────────
  if (booting) {
    return (
      <div className="login-shell">
        <div className="login-card">
          <h1>Admin</h1>
          <p>Loading…</p>
        </div>
      </div>
    );
  }

  if (forbidden) {
    return (
      <div className="login-shell">
        <div className="login-card" style={{ maxWidth: 720 }}>
          <h1>Admin</h1>
          <p style={{ color: 'var(--danger)' }}>
            You’re signed in, but you’re not authorized to access the admin dashboard.
          </p>
          <button className="button small" type="button" onClick={() => navigate('/')}>
            Back to app
          </button>
        </div>
      </div>
    );
  }


  return (
    <div style={{ minHeight: '100vh', width: '100%', padding: 18, background: 'var(--bg-elevated)', boxSizing: 'border-box' }}>
      <div
        className="login-card"
        style={{
          width: 'min(1200px, 96vw)',
          maxWidth: 1200,
          minHeight: 'calc(100vh - 36px)',
          margin: '0 auto',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}
      >
        {/* Header + tabs */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
          <div>
            <h1 style={{ marginBottom: 6 }}>Admin</h1>
            <p style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              User drawer opens from Activity/Audit/Billing. Sessions can be revoked from anywhere.
            </p>
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button type="button" className={`button small ${tab === 'activity' ? 'primary' : ''}`} onClick={() => setTab('activity')}>Activity</button>
            <button type="button" className={`button small ${tab === 'requests' ? 'primary' : ''}`} onClick={() => setTab('requests')}>Requests</button>
            <button type="button" className={`button small ${tab === 'identity' ? 'primary' : ''}`} onClick={() => setTab('identity')}>Identity</button>
            <button type="button" className={`button small ${tab === 'billing' ? 'primary' : ''}`} onClick={() => setTab('billing')}>Billing</button>
            <button type="button" className={`button small ${tab === 'create' ? 'primary' : ''}`} onClick={() => setTab('create')}>Create Space</button>
            <button type="button" className={`button small ${tab === 'email' ? 'primary' : ''}`} onClick={() => setTab('email')}>Send Email</button>
            <button type="button" className={`button small ${tab === 'templates' ? 'primary' : ''}`} onClick={() => setTab('templates')}>Templates</button>
            <button type="button" className={`button small ${tab === 'audit' ? 'primary' : ''}`} onClick={() => setTab('audit')}>Audit</button>
            <button type="button" className={`button small ${tab === 'doctor' ? 'primary' : ''}`} onClick={() => setTab('doctor')}>Doctor</button>
            <button type="button" className="button small" onClick={() => navigate('/')}>Back</button>
          </div>
        </div>

        {(statusMsg || errorMsg) && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {statusMsg && <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{statusMsg}</div>}
            {errorMsg && <div style={{ fontSize: 12, color: 'var(--danger)' }}>{errorMsg}</div>}
          </div>
        )}

        {/* ───────── Activity tab ───────── */}
        {tab === 'activity' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
              <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>Activity feed</h2>

              <button type="button" className="button small" onClick={loadActivity} disabled={activityLoading}>
                {activityLoading ? 'Loading…' : 'Refresh'}
              </button>

              <input
                type="number"
                value={activityLimit}
                onChange={(e) => setActivityLimit(Number(e.target.value) || 200)}
                style={{
                  width: 120,
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                }}
                min={1}
                max={2000}
              />

              <input
                type="text"
                value={activityQ}
                onChange={(e) => setActivityQ(e.target.value)}
                placeholder="filter… (slug, email, action, discordId)"
                style={{
                  flex: '1 1 260px',
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                  marginLeft: 'auto',
                }}
              />
            </div>

            {filteredActivity.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No items.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {filteredActivity.map((it, idx) => {
                  const actor = it.actor || {};
                  const target = it.target || {};
                  const actorLabel =
                    actor.discordUsername ? `@${actor.discordUsername}` :
                    actor.discordId ? actor.discordId :
                    actor.userId ? actor.userId : '';

                  const tgtLabel =
                    target.slug ? `space:${target.slug}` :
                    target.id ? `${target.type || 'target'}:${target.id}` :
                    target.email ? `email:${target.email}` :
                    target.userId ? `user:${target.userId}` :
                    target.type || 'target';

                  const uid = extractUserId(it);

                  return (
                    <div key={`${it.kind}-${it.id || idx}`} style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                        <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                          <strong>{it.action}</strong>{' '}
                          <span style={{ color: 'var(--text-muted)' }}>· {fmtWhen(it.at)}</span>
                          <span className="pill pill--tiny" style={{ marginLeft: 8 }}>{it.kind}</span>
                        </div>

                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {actorLabel ? <>{actorLabel} → </> : null}<code>{tgtLabel}</code>
                          </div>

                          {uid && (
                            <>
                              <button type="button" className="button small" onClick={() => openUserDrawer(uid)}>
                                Open user
                              </button>
                              <button type="button" className="button small" onClick={() => openSessionsModal(uid)}>
                                Sessions
                              </button>
                            </>
                          )}
                        </div>
                      </div>

                      {it.detail ? (
                        <pre style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'pre-wrap' }}>
                          {JSON.stringify(it.detail, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ───────── Requests tab ───────── */}
        {tab === 'requests' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
              <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>Workspace requests</h2>

              <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                Status
                <select className="theme-select" value={reqStatusFilter} onChange={(e) => setReqStatusFilter(e.target.value)} style={{ marginLeft: 8 }}>
                  <option value="pending">pending</option>
                  <option value="approved">approved</option>
                  <option value="rejected">rejected</option>
                  <option value="all">all</option>
                </select>
              </label>

              <button type="button" className="button small" onClick={loadRequests} disabled={requestsLoading}>
                {requestsLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>

            {requestsLoading ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Loading…</div>
            ) : requests.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No requests.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {requests.map((r) => {
                  const slugValue = getSlugForRequest(r);
                  const slugError = slugErrors[r.id] || null;
                  const slugIsValid = slugValue && isValidSlug(slugValue);

                  const who =
                    (r.discordUsername ? `@${r.discordUsername}` : '') ||
                    (r.discordGlobalName ? String(r.discordGlobalName) : '') ||
                    (r.email ? String(r.email) : '') ||
                    (r.userId ? String(r.userId) : r.id);

                  return (
                    <div key={r.id} style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                        <div style={{ fontSize: 13, color: 'var(--text-main)' }}>
                          <strong>{who}</strong>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                            requestId: {r.id} · userId: {r.userId || '—'} · {r.createdAt || ''}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                          {r.userId && (
                            <button type="button" className="button small" onClick={() => openUserDrawer(r.userId)}>
                              Open user
                            </button>
                          )}
                        </div>
                      </div>

                      <div style={{ marginTop: 10, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                        <label style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          Space slug
                          <input
                            type="text"
                            value={slugValue}
                            onChange={(e) => handleSlugChange(r.id, e.target.value)}
                            placeholder="e.g. southphilly-hud"
                            style={{
                              marginTop: 6,
                              width: 260,
                              borderRadius: 999,
                              border: '1px solid var(--panel-border)',
                              background: 'var(--bg-main)',
                              color: 'var(--text-main)',
                              padding: '8px 12px',
                              fontSize: 13,
                              outline: 'none',
                            }}
                          />
                        </label>

                        {slugError && <div style={{ fontSize: 12, color: 'var(--danger)' }}>{slugError}</div>}

                        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <button type="button" className="button small" onClick={() => handleApprove(r.id, 100)} disabled={!slugIsValid}>
                            Approve
                          </button>
                          <button
                            type="button"
                            className="button small"
                            onClick={() => {
                              const q = window.prompt('Quota in MB:', '100');
                              const n = q ? Number(q) : 100;
                              handleApprove(r.id, n);
                            }}
                            disabled={!slugIsValid}
                          >
                            Approve (custom quota)
                          </button>
                          <button type="button" className="button small" onClick={() => handleReject(r.id)}>
                            Reject
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ───────── Billing tab ───────── */}
        {tab === 'billing' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
              <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>Billing & entitlement</h2>

              <button type="button" className="button small" onClick={loadBilling} disabled={billingLoading}>
                {billingLoading ? 'Loading…' : 'Refresh'}
              </button>

              <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {['all','comped','paid','unpaid','expiringSoon','inactive'].map((k) => (
                  <button key={k} type="button" className={`button small ${billingFilter === k ? 'primary' : ''}`} onClick={() => setBillingFilter(k)}>
                    {k}
                  </button>
                ))}
              </div>
            </div>

            {billingCounts && (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
                Total {billingCounts.total} · comped {billingCounts.comped} · paid {billingCounts.paid} · unpaid {billingCounts.unpaid} · expiring soon {billingCounts.expiringSoon} · inactive {billingCounts.inactive}
              </div>
            )}

            {filteredBillingUsers.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No users in this view.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {filteredBillingUsers.slice(0, 160).map((u) => {
                  const ent = u.entitlement || {};
                  const edit = billingEdits[u.id] || {};
                  const busy = !!billingSaving[u.id];

                  const pill =
                    !ent.isActive ? { text: 'inactive', cls: 'pill--warn' } :
                    ent.isComped ? { text: 'comped', cls: 'pill--ok' } :
                    ent.isPaid ? { text: `paid (${ent.daysLeft ?? '—'}d)`, cls: ent.expiringSoon ? 'pill--warn' : 'pill--ok' } :
                    { text: 'unpaid', cls: 'pill--warn' };

                  return (
                    <div key={u.id} style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                        <div style={{ minWidth: 260 }}>
                          <div style={{ fontSize: 13, color: 'var(--text-main)' }}>
                            <strong>{bestHandle(u)}</strong>{' '}
                            <span className={`pill pill--tiny ${pill.cls}`} style={{ marginLeft: 8 }}>{pill.text}</span>
                          </div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                            userId: {u.id} · lastLogin: {fmtWhen(u.lastLoginAt)}
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                          <button type="button" className="button small" onClick={() => openUserDrawer(u.id)} disabled={busy}>
                            Open user
                          </button>
                          <button type="button" className="button small" onClick={() => openSessionsModal(u)} disabled={busy}>
                            Sessions
                          </button>
                          <button type="button" className="button small" onClick={() => quickCompIndefinitely(u)} disabled={busy}>
                            Comp indefinitely
                          </button>
                          <button type="button" className="button small" onClick={() => quickExtend30(u)} disabled={busy || !!edit.comped}>
                            Extend 30 days
                          </button>
                        </div>
                      </div>

                      <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 8 }}>
                        <label style={{ gridColumn: 'span 2', fontSize: 12, color: 'var(--text-muted)' }}>
                          Comped
                          <div style={{ marginTop: 6 }}>
                            <input
                              type="checkbox"
                              checked={!!edit.comped}
                              onChange={(e) => setBillingField(u.id, 'comped', e.target.checked)}
                              disabled={busy}
                            />
                          </div>
                        </label>

                        <label style={{ gridColumn: 'span 3', fontSize: 12, color: 'var(--text-muted)' }}>
                          Paid until
                          <input
                            type="date"
                            value={fmtDateInput(edit.paidUntil)}
                            onChange={(e) => setBillingField(u.id, 'paidUntil', dateInputToIsoOrNull(e.target.value))}
                            disabled={busy || !!edit.comped}
                            style={{
                              marginTop: 6,
                              width: '100%',
                              borderRadius: 999,
                              border: '1px solid var(--panel-border)',
                              background: 'var(--bg-main)',
                              color: 'var(--text-main)',
                              padding: '8px 12px',
                              fontSize: 13,
                              outline: 'none',
                            }}
                          />
                        </label>

                        <label style={{ gridColumn: 'span 2', fontSize: 12, color: 'var(--text-muted)' }}>
                          Tier
                          <input
                            type="text"
                            value={String(edit.tier || '')}
                            onChange={(e) => setBillingField(u.id, 'tier', e.target.value)}
                            disabled={busy}
                            placeholder="e.g. pro"
                            style={{
                              marginTop: 6,
                              width: '100%',
                              borderRadius: 999,
                              border: '1px solid var(--panel-border)',
                              background: 'var(--bg-main)',
                              color: 'var(--text-main)',
                              padding: '8px 12px',
                              fontSize: 13,
                              outline: 'none',
                            }}
                          />
                        </label>

                        <label style={{ gridColumn: 'span 3', fontSize: 12, color: 'var(--text-muted)' }}>
                          Status
                          <select
                            className="theme-select"
                            value={String(edit.status || u.status || 'active')}
                            onChange={(e) => setBillingField(u.id, 'status', e.target.value)}
                            disabled={busy}
                            style={{ marginTop: 6, width: '100%' }}
                          >
                            <option value="active">active</option>
                            <option value="inactive">inactive</option>
                          </select>
                        </label>

                        <div style={{ gridColumn: 'span 2', display: 'flex', alignItems: 'end', justifyContent: 'flex-end' }}>
                          <button type="button" className="button small primary" onClick={() => saveBillingRow(u)} disabled={busy}>
                            {busy ? 'Saving…' : 'Save'}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}

                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  Showing first 160 users in this view (expand later with paging/search).
                </div>
              </div>
            )}
          </div>
        )}

        {/* ───────── Create Space tab ───────── */}
        {tab === 'create' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <h2 style={{ fontSize: 14, margin: '0 0 10px', color: 'var(--text-main)' }}>Create space</h2>

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
              Pick an owner via the user search UI in your existing build (or wire it back in if you removed it).
            </div>

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
              Owner:
              <div style={{ marginTop: 4, color: 'var(--text-main)' }}>
                {createOwnerUser ? (
                  <>
                    <strong>{bestHandle(createOwnerUser)}</strong> <span style={{ opacity: 0.7 }}>({createOwnerUser.id})</span>
                  </>
                ) : (
                  <span style={{ opacity: 0.8 }}>none</span>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
              <input
                type="text"
                value={createSlug}
                onChange={(e) => setCreateSlug(e.target.value)}
                placeholder="slug (e.g. demo-hud)"
                style={{
                  flex: '1 1 220px',
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <input
                type="number"
                value={createQuotaMb}
                onChange={(e) => setCreateQuotaMb(e.target.value)}
                placeholder="quota MB"
                style={{
                  width: 160,
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                }}
              />
              <button type="button" className="button small primary" onClick={handleCreateSpace} disabled={creatingSpace}>
                {creatingSpace ? 'Creating…' : 'Create'}
              </button>
            </div>
          </div>
        )}

        {/* ───────── Send Email tab ───────── */}
        {tab === 'email' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <h2 style={{ fontSize: 14, margin: '0 0 10px', color: 'var(--text-main)' }}>Send email</h2>

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
              Pick a recipient via user drawer (Open user → copy id) or your search UI.
            </div>

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
              Recipient:
              <div style={{ marginTop: 4, color: 'var(--text-main)' }}>
                {emailUser ? (
                  <>
                    <strong>{bestHandle(emailUser)}</strong> <span style={{ opacity: 0.7 }}>({emailUser.id})</span>
                  </>
                ) : (
                  <span style={{ opacity: 0.8 }}>none</span>
                )}
              </div>
            </div>

            <input
              type="text"
              value={emailSubject}
              onChange={(e) => setEmailSubject(e.target.value)}
              placeholder="subject"
              style={{
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '8px 12px',
                fontSize: 13,
                outline: 'none',
                marginBottom: 8,
              }}
            />

            <textarea
              value={emailBody}
              onChange={(e) => setEmailBody(e.target.value)}
              placeholder="Body…"
              style={{
                width: '100%',
                minHeight: 160,
                borderRadius: 12,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '10px 12px',
                fontSize: 13,
                outline: 'none',
                resize: 'vertical',
                marginBottom: 8,
              }}
            />

            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
              <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                <input type="checkbox" checked={emailAsHtml} onChange={(e) => setEmailAsHtml(e.target.checked)} />
                Send as HTML
              </label>

              <input
                type="text"
                value={emailFrom}
                onChange={(e) => setEmailFrom(e.target.value)}
                placeholder="from override (optional)"
                style={{
                  flex: '1 1 220px',
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                }}
              />

              <button type="button" className="button small primary" onClick={handleSendEmail} disabled={sendingEmail}>
                {sendingEmail ? 'Sending…' : 'Send'}
              </button>
            </div>
          </div>
        )}

{tab === 'templates' && (
  <div
    style={{
      border: '1px solid var(--panel-border)',
      borderRadius: 12,
      padding: 12,
      background: 'var(--bg-main)',
    }}
  >
    <div
      style={{
        display: 'flex',
        gap: 10,
        alignItems: 'center',
        flexWrap: 'wrap',
        marginBottom: 10,
      }}
    >
      <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>
        Email templates
      </h2>

      <button
        type="button"
        className="button small"
        onClick={loadTemplates}
        disabled={tplLoading}
      >
        {tplLoading ? 'Loading…' : 'Refresh'}
      </button>

      <button
        type="button"
        className="button small"
        onClick={newTemplate}
        disabled={tplSaving || tplDeleting}
      >
        New
      </button>

      <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
        Variables:{' '}
        <code>
          {'{{handle}} {{email}} {{slug}} {{iframeUrl}} {{appUrl}} {{nowIso}}'}
        </code>
      </div>
    </div>

    {tplError && (
      <div style={{ fontSize: 12, color: 'var(--danger)', marginBottom: 10 }}>
        {tplError}
      </div>
    )}

    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 10 }}>
      {/* Left: template list */}
      <div
        style={{
          gridColumn: 'span 4',
          border: '1px solid var(--panel-border)',
          borderRadius: 12,
          padding: 10,
          maxHeight: 560,
          overflowY: 'auto',
        }}
      >
        <input
          type="text"
          value={tplQuery}
          onChange={(e) => setTplQuery(e.target.value)}
          placeholder="Filter templates…"
          style={{
            width: '100%',
            borderRadius: 999,
            border: '1px solid var(--panel-border)',
            background: 'var(--bg-main)',
            color: 'var(--text-main)',
            padding: '8px 12px',
            fontSize: 13,
            outline: 'none',
            marginBottom: 10,
          }}
        />

        {(templates || [])
          .filter((t) => {
            const q = String(tplQuery || '').trim().toLowerCase();
            if (!q) return true;
            const hay = [t?.name, t?.subject, t?.mode, t?.id]
              .filter(Boolean)
              .join(' ')
              .toLowerCase();
            return hay.includes(q);
          })
          .map((t) => {
            const active = t.id === activeTplId;
            return (
              <button
                key={t.id}
                type="button"
                className={`button small ${active ? 'primary' : ''}`}
                style={{
                  width: '100%',
                  justifyContent: 'flex-start',
                  borderRadius: 12,
                  marginBottom: 6,
                  textAlign: 'left',
                }}
                onClick={() => selectTemplate(t)}
              >
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 2,
                    width: '100%',
                  }}
                >
                  <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                    <strong>{t.name}</strong>{' '}
                    <span className="pill pill--tiny" style={{ marginLeft: 6 }}>
                      {t.mode}
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {t.subject}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', opacity: 0.8 }}>
                    {t.id}
                  </div>
                </div>
              </button>
            );
          })}
      </div>

      {/* Right: editor + send */}
      <div
        style={{
          gridColumn: 'span 8',
          border: '1px solid var(--panel-border)',
          borderRadius: 12,
          padding: 10,
        }}
      >
        <div
          style={{
            display: 'flex',
            gap: 8,
            flexWrap: 'wrap',
            alignItems: 'center',
            marginBottom: 10,
          }}
        >
          <button
            type="button"
            className="button small primary"
            onClick={saveTemplate}
            disabled={tplSaving || tplDeleting}
          >
            {tplSaving ? 'Saving…' : tplDraft.id ? (tplDirty ? 'Save' : 'Saved') : 'Create'}
          </button>

          <button
            type="button"
            className="button small"
            onClick={deleteTemplate}
            disabled={!tplDraft.id || tplSaving || tplDeleting}
          >
            {tplDeleting ? 'Deleting…' : 'Delete'}
          </button>

          {tplSendStatus && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{tplSendStatus}</div>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 8 }}>
          <label style={{ gridColumn: 'span 5', fontSize: 12, color: 'var(--text-muted)' }}>
            Name
            <input
              type="text"
              value={tplDraft.name}
              onChange={(e) => setDraftField('name', e.target.value)}
              style={{
                marginTop: 6,
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '8px 12px',
                fontSize: 13,
                outline: 'none',
              }}
            />
          </label>

          <label style={{ gridColumn: 'span 7', fontSize: 12, color: 'var(--text-muted)' }}>
            Subject
            <input
              type="text"
              value={tplDraft.subject}
              onChange={(e) => setDraftField('subject', e.target.value)}
              style={{
                marginTop: 6,
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '8px 12px',
                fontSize: 13,
                outline: 'none',
              }}
            />
          </label>

          <label style={{ gridColumn: 'span 4', fontSize: 12, color: 'var(--text-muted)' }}>
            Mode
            <select
              className="theme-select"
              value={tplDraft.mode}
              onChange={(e) => setDraftField('mode', e.target.value)}
              style={{ marginTop: 6, width: '100%' }}
            >
              <option value="text">text</option>
              <option value="html">html</option>
              <option value="both">both</option>
            </select>
          </label>

          <label style={{ gridColumn: 'span 8', fontSize: 12, color: 'var(--text-muted)' }}>
            Optional space slug for template variables (when sending)
            <input
              type="text"
              value={tplSendSpaceSlug}
              onChange={(e) => setTplSendSpaceSlug(e.target.value)}
              placeholder="e.g. scott-hud"
              style={{
                marginTop: 6,
                width: '100%',
                borderRadius: 999,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '8px 12px',
                fontSize: 13,
                outline: 'none',
              }}
            />
          </label>

          <label style={{ gridColumn: 'span 12', fontSize: 12, color: 'var(--text-muted)' }}>
            Text body
            <textarea
              value={tplDraft.text}
              onChange={(e) => setDraftField('text', e.target.value)}
              placeholder="Plain text email…"
              style={{
                marginTop: 6,
                width: '100%',
                minHeight: 120,
                borderRadius: 12,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '10px 12px',
                fontSize: 13,
                outline: 'none',
                resize: 'vertical',
              }}
            />
          </label>

          <label style={{ gridColumn: 'span 12', fontSize: 12, color: 'var(--text-muted)' }}>
            HTML body
            <textarea
              value={tplDraft.html}
              onChange={(e) => setDraftField('html', e.target.value)}
              placeholder="<div>HTML email…</div>"
              style={{
                marginTop: 6,
                width: '100%',
                minHeight: 120,
                borderRadius: 12,
                border: '1px solid var(--panel-border)',
                background: 'var(--bg-main)',
                color: 'var(--text-main)',
                padding: '10px 12px',
                fontSize: 13,
                outline: 'none',
                resize: 'vertical',
              }}
            />
          </label>
        </div>

        {/* Send panel */}
        <div style={{ marginTop: 12, borderTop: '1px solid var(--panel-border)', paddingTop: 12 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)' }}>
              Send using template
            </div>

            <button
              type="button"
              className="button small primary"
              onClick={sendTemplate}
              disabled={tplSending || !tplSendUser || !tplDraft.id}
            >
              {tplSending ? 'Sending…' : 'Send'}
            </button>

            <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
              Recipient:{' '}
              <code>
                {tplSendUser ? (tplSendUser.email || tplSendUser.pendingEmail || tplSendUser.id) : 'none'}
              </code>
            </div>
          </div>

          <input
            type="text"
            value={tplSendQuery}
            onChange={(e) => setTplSendQuery(e.target.value)}
            placeholder="Search recipient user… (@handle, email, u_…)"
            style={{
              width: '100%',
              borderRadius: 999,
              border: '1px solid var(--panel-border)',
              background: 'var(--bg-main)',
              color: 'var(--text-main)',
              padding: '8px 12px',
              fontSize: 13,
              outline: 'none',
              marginBottom: 10,
            }}
          />

          {tplSendQuery.trim() && (
            <div
              style={{
                maxHeight: 180,
                overflowY: 'auto',
                border: '1px solid var(--panel-border)',
                borderRadius: 12,
                padding: 8,
              }}
            >
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
                {tplSendSearching ? 'Searching…' : `Results (${tplSendResults.length})`}
              </div>

              {tplSendResults.map((u) => {
                const label =
                  (u.discordUsername ? `@${u.discordUsername}` : '') ||
                  (u.discordGlobalName ? String(u.discordGlobalName) : '') ||
                  (u.email ? String(u.email) : '') ||
                  u.id;

                return (
                  <button
                    key={u.id}
                    type="button"
                    className="button small"
                    style={{
                      width: '100%',
                      justifyContent: 'flex-start',
                      borderRadius: 12,
                      marginBottom: 6,
                      textAlign: 'left',
                    }}
                    onClick={() => {
                      setTplSendUser(u);
                      setTplSendStatus('');
                    }}
                  >
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      <div style={{ fontSize: 12, color: 'var(--text-main)' }}>{label}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {u.id} · {u.emailVerifiedAt ? 'verified' : 'unverified'}
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  </div>
)} 

{tab === 'identity' && (
  <div
    style={{
      border: '1px solid var(--panel-border)',
      borderRadius: 12,
      padding: 12,
      background: 'var(--bg-main)',
    }}
  >
    <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
      <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>
        Identity
      </h2>

      <button
        type="button"
        className="button small"
        onClick={loadIdentity}
        disabled={idLoading}
      >
        {idLoading ? 'Loading…' : 'Refresh'}
      </button>

      <input
        type="text"
        value={idQuery}
        onChange={(e) => setIdQuery(e.target.value)}
        placeholder="Filter (email, userId, discordId, @handle)…"
        style={{
          marginLeft: 'auto',
          width: 'min(420px, 92vw)',
          borderRadius: 999,
          border: '1px solid var(--panel-border)',
          background: 'var(--bg-main)',
          color: 'var(--text-main)',
          padding: '8px 12px',
          fontSize: 13,
          outline: 'none',
        }}
      />
    </div>

    {idError && (
      <div style={{ fontSize: 12, color: 'var(--danger)', marginBottom: 10 }}>
        {idError}
      </div>
    )}

    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
      Duplicates are detected by the same email appearing across <code>email</code>, <code>pendingEmail</code>, or <code>emails[]</code>.
      Merge and delete actions are intended for Godmode only.
    </div>

    {/* Duplicate groups */}
    {filteredDupGroups.length === 0 ? (
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
        No duplicate groups found.
      </div>
    ) : (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {filteredDupGroups.map((g) => {
          const email = g.email;
          const users = Array.isArray(g.users) ? g.users : [];
          const recommended = g.recommendedTargetUserId || null;

          return (
            <div
              key={email}
              style={{
                border: '1px solid var(--panel-border)',
                borderRadius: 12,
                padding: 10,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                <div style={{ fontSize: 13, color: 'var(--text-main)' }}>
                  <strong>{email}</strong>{' '}
                  <span className="pill pill--tiny" style={{ marginLeft: 6 }}>
                    {users.length} users
                  </span>
                </div>

                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  recommended target: <code>{recommended || '—'}</code>
                </div>
              </div>

              <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
                {users.map((u) => {
                  const isTarget = u.userId === recommended;
                  const hasDiscord = !!String(u.discordId || '').trim();
                  const label =
                    (u.discordUsername ? `@${u.discordUsername}` : '') ||
                    (u.discordId ? u.discordId : '') ||
                    (u.email ? u.email : '') ||
                    u.userId;

                  return (
                    <div
                      key={u.userId}
                      style={{
                        border: '1px solid var(--panel-border)',
                        borderRadius: 12,
                        padding: 10,
                        display: 'flex',
                        justifyContent: 'space-between',
                        gap: 10,
                        flexWrap: 'wrap',
                        alignItems: 'center',
                      }}
                    >
                      <div style={{ minWidth: 280 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                          <strong>{label}</strong>{' '}
                          {isTarget ? (
                            <span className="pill pill--tiny pill--ok" style={{ marginLeft: 6 }}>
                              target
                            </span>
                          ) : null}
                          {hasDiscord ? (
                            <span className="pill pill--tiny" style={{ marginLeft: 6 }}>
                              discord
                            </span>
                          ) : (
                            <span className="pill pill--tiny pill--warn" style={{ marginLeft: 6 }}>
                              legacy
                            </span>
                          )}
                        </div>

                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          userId: <code>{u.userId}</code>
                        </div>

                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          hit: <code>{u.hit?.email}</code>{' '}
                          {u.hit?.verifiedAt ? (
                            <span className="pill pill--tiny pill--ok" style={{ marginLeft: 6 }}>
                              verified
                            </span>
                          ) : (
                            <span className="pill pill--tiny pill--warn" style={{ marginLeft: 6 }}>
                              unverified
                            </span>
                          )}
                        </div>

                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                          lastLogin: {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '—'}
                        </div>
                      </div>

                      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        <button
                          type="button"
                          className="button small"
                          onClick={() => openUserDrawer?.(u.userId)}
                        >
                          Open
                        </button>

                        <button
                          type="button"
                          className="button small"
                          onClick={() => openSessionsModal?.(u.userId)}
                        >
                          Sessions
                        </button>

                        {!isTarget && recommended ? (
                          <button
                            type="button"
                            className="button small primary"
                            disabled={mergeBusyKey === `${email}:${u.userId}`}
                            onClick={() =>
                              confirmMerge({
                                email,
                                sourceUserId: u.userId,
                                targetUserId: recommended,
                              })
                            }
                          >
                            {mergeBusyKey === `${email}:${u.userId}` ? 'Merging…' : 'Merge → target'}
                          </button>
                        ) : null}

                        <button
                          type="button"
                          className="button small"
                          disabled={deleteBusyId === u.userId}
                          onClick={() => confirmDeleteUser(u.userId)}
                          title="Soft delete (Godmode)"
                        >
                          {deleteBusyId === u.userId ? 'Deleting…' : 'Delete'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    )}
  </div>
)}


        {/* ───────── Audit tab ───────── */}
        {tab === 'audit' && (
          <div style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 12, background: 'var(--bg-main)' }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
              <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>Audit log</h2>

              <button type="button" className="button small" onClick={loadAudit} disabled={auditLoading}>
                {auditLoading ? 'Loading…' : 'Refresh'}
              </button>

              <input
                type="number"
                value={auditLimit}
                onChange={(e) => setAuditLimit(Number(e.target.value) || 200)}
                style={{
                  width: 120,
                  borderRadius: 999,
                  border: '1px solid var(--panel-border)',
                  background: 'var(--bg-main)',
                  color: 'var(--text-main)',
                  padding: '8px 12px',
                  fontSize: 13,
                  outline: 'none',
                }}
                min={1}
                max={2000}
              />
            </div>

            {auditEntries.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No audit entries.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {auditEntries.map((e) => {
                  const a = e.actor || {};
                  const t = e.target || {};
                  const who = a.discordUsername ? `@${a.discordUsername}` : (a.discordId || a.userId || 'admin');
                  const tgt = t.slug ? `space:${t.slug}` : (t.id ? `${t.type || 'target'}:${t.id}` : (t.email ? `email:${t.email}` : (t.type || 'target')));
                  const uid = extractUserId(e);

                  return (
                    <div key={e.id} style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                        <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                          <strong>{e.action}</strong>{' '}
                          <span style={{ color: 'var(--text-muted)' }}>· {fmtWhen(e.at)}</span>
                        </div>

                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {who} → <code>{tgt}</code>
                          </div>

                          {uid && (
                            <>
                              <button type="button" className="button small" onClick={() => openUserDrawer(uid)}>
                                Open user
                              </button>
                              <button type="button" className="button small" onClick={() => openSessionsModal(uid)}>
                                Sessions
                              </button>
                            </>
                          )}
                        </div>
                      </div>

                      {e.detail ? (
                        <pre style={{ marginTop: 8, fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'pre-wrap' }}>
                          {JSON.stringify(e.detail, null, 2)}
                        </pre>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

{tab === 'doctor' && (
  <div
    style={{
      border: '1px solid var(--panel-border)',
      borderRadius: 12,
      padding: 12,
      background: 'var(--bg-main)',
    }}
  >
    <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
      <h2 style={{ fontSize: 14, margin: 0, color: 'var(--text-main)' }}>System Doctor</h2>

      <button type="button" className="button small" onClick={loadDoctor} disabled={doctorLoading}>
        {doctorLoading ? 'Loading…' : 'Refresh'}
      </button>

      <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
        {doctorData?.at ? <>as of {new Date(doctorData.at).toLocaleString()}</> : null}
      </div>
    </div>

    {doctorError && (
      <div style={{ fontSize: 12, color: 'var(--danger)', marginBottom: 10 }}>
        {doctorError}
      </div>
    )}

    {!doctorData ? (
      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No data loaded.</div>
    ) : (
      <>
        {/* Checklist */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
          {(doctorData.checks || []).map((c) => (
            <div
              key={c.key}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                gap: 10,
                padding: '8px 10px',
                border: '1px solid var(--panel-border)',
                borderRadius: 12,
              }}
            >
              <div style={{ fontSize: 12, color: 'var(--text-main)' }}>{c.label}</div>
              <span className={`pill pill--tiny ${c.ok ? 'pill--ok' : 'pill--warn'}`}>
                {c.ok ? 'OK' : 'WARN'}
              </span>
            </div>
          ))}
        </div>

        {/* Services */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: 10 }}>
          <div style={{ gridColumn: 'span 6', border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>Services</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              <div>SendGrid: <code>{doctorData.services?.sendgrid?.configured ? 'configured' : 'missing'}</code></div>
              <div>Discord OAuth: <code>{doctorData.services?.discord?.configured ? 'configured' : 'missing'}</code></div>
              <div>Discord guild check: <code>{doctorData.services?.discord?.guildConfigured ? 'configured' : 'missing'}</code></div>
              <div>OpenAI: <code>{doctorData.services?.openai?.configured ? 'configured' : 'missing'}</code></div>
              <div style={{ marginTop: 6 }}>
                Default model: <code>{doctorData.services?.openai?.defaultModel || '—'}</code>
              </div>
            </div>
          </div>

          <div style={{ gridColumn: 'span 6', border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>Config</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              <div>env: <code>{doctorData.config?.env || '—'}</code></div>
              <div>app base: <code>{doctorData.config?.appBaseUrl || '—'}</code></div>
              <div>iframe base: <code>{doctorData.config?.publicIframeBaseUrl || '—'}</code></div>
              <div>trust proxy: <code>{doctorData.config?.trustProxy ? 'true' : 'false'}</code></div>
              <div style={{ marginTop: 6 }}>
                request host: <code>{doctorData.request?.host || '—'}</code>
              </div>
              <div>
                request origin: <code>{doctorData.request?.origin || '—'}</code>
              </div>
            </div>
          </div>

          {/* Meta store health */}
          <div style={{ gridColumn: 'span 12', border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>Meta stores</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {Object.entries(doctorData.meta || {}).map(([k, v]) => (
                <div
                  key={k}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    gap: 10,
                    padding: '8px 10px',
                    border: '1px solid var(--panel-border)',
                    borderRadius: 12,
                  }}
                >
                  <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                    <strong>{k}</strong> · <code>{v?.path || '—'}</code>
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span className={`pill pill--tiny ${v?.readable ? 'pill--ok' : 'pill--warn'}`}>{v?.readable ? 'R' : 'no R'}</span>
                    <span className={`pill pill--tiny ${v?.writable ? 'pill--ok' : 'pill--warn'}`}>{v?.writable ? 'W' : 'no W'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Largest spaces */}
          <div style={{ gridColumn: 'span 12', border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>Largest spaces (sample)</div>
            {(doctorData.storage?.largestSpaces || []).length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No space size data available.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {doctorData.storage.largestSpaces.map((s) => (
                  <div
                    key={s.slug}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      gap: 10,
                      padding: '8px 10px',
                      border: '1px solid var(--panel-border)',
                      borderRadius: 12,
                    }}
                  >
                    <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                      <strong>{s.slug}</strong> · quota <code>{s.quotaMb ?? '—'}MB</code> · used{' '}
                      <code>{s.usedMb != null ? `${s.usedMb}MB` : '—'}</code>
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <span className="pill pill--tiny">{s.ownerUserId ? `owner ${s.ownerUserId}` : 'no ownerUserId'}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </>
    )}
  </div>
)}

        {/* User Drawer */}
        {drawerOpen && (
          <div
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0,0,0,0.45)',
              zIndex: 2000,
              display: 'flex',
              justifyContent: 'flex-end',
            }}
            onClick={closeUserDrawer}
          >
            <div
              style={{
                width: 'min(520px, 92vw)',
                height: '100%',
                background: 'var(--bg-main)',
                borderLeft: '1px solid var(--panel-border)',
                boxShadow: '0 0 24px rgba(0,0,0,0.35)',
                padding: 14,
                boxSizing: 'border-box',
                overflowY: 'auto',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-main)' }}>User</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{drawerUserId || '—'}</div>
                </div>
                <button type="button" className="button small" onClick={closeUserDrawer} disabled={drawerLoading}>
                  Close
                </button>
              </div>

              {drawerLoading ? (
                <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>Loading…</div>
              ) : drawerError ? (
                <div style={{ marginTop: 10, fontSize: 12, color: 'var(--danger)' }}>{drawerError}</div>
              ) : !drawerUser ? (
                <div style={{ marginTop: 10, fontSize: 12, color: 'var(--text-muted)' }}>No user loaded.</div>
              ) : (
                <>
                  <div style={{ marginTop: 12, border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                    <div style={{ fontSize: 13, color: 'var(--text-main)' }}>
                      <strong>{bestHandle(drawerUser)}</strong>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                      email: <code>{drawerUser.email || drawerUser.pendingEmail || '—'}</code>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                      discord: <code>{drawerUser.discordId || '—'}</code>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
                      last login: {fmtWhen(drawerUser.lastLoginAt)}
                    </div>
                  </div>

                  <div style={{ marginTop: 12, border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>
                      Quick actions
                    </div>

                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      <button type="button" className="button small" onClick={() => openSessionsModal(drawerUser)}>
                        Sessions
                      </button>

                      <button type="button" className="button small" onClick={() => openUserDrawer(drawerUser.id)}>
                        Refresh user
                      </button>

                      <button
                        type="button"
                        className="button small"
                        onClick={() => {
                          try {
                            navigator.clipboard?.writeText?.(String(drawerUser.id));
                            setStatusMsg('Copied userId.');
                          } catch {}
                        }}
                      >
                        Copy userId
                      </button>
                    </div>
                  </div>

                  {Array.isArray(drawerUser.spaces) && drawerUser.spaces.length > 0 && (
                    <div style={{ marginTop: 12, border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-main)', marginBottom: 8 }}>
                        Spaces ({drawerUser.spaces.length})
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {drawerUser.spaces.map((s) => (
                          <div key={s.slug} style={{ border: '1px solid var(--panel-border)', borderRadius: 10, padding: 8 }}>
                            <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                              <strong>{s.slug}</strong> <span style={{ color: 'var(--text-muted)' }}>· {s.quotaMb ?? '—'} MB</span>
                            </div>
                            <div style={{ marginTop: 8, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                              <a className="button small" href={s.iframeUrl} target="_blank" rel="noreferrer">
                                Open live
                              </a>
                              <a className="button small" href={s.paywallPreviewUrl} target="_blank" rel="noreferrer">
                                Paywall preview
                              </a>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* Sessions modal */}
        {sessionsOpen && sessionsUser && (
          <div className="preview-modal-backdrop" onClick={closeSessionsModal}>
            <div className="preview-modal" onClick={(e) => e.stopPropagation()} style={{ width: 'min(860px, 92vw)', maxWidth: 860, height: 'auto', minHeight: 0 }}>
              <div className="preview-modal-header">
                <div>
                  <div className="preview-modal-title">Sessions</div>
                  <div className="preview-modal-subtitle">
                    {bestHandle(sessionsUser) || sessionsUser.id} · {sessionsUser.id}
                  </div>
                </div>
                <button type="button" className="preview-modal-close" onClick={closeSessionsModal} aria-label="Close">
                  ×
                </button>
              </div>

              <div className="preview-modal-body" style={{ display: 'block', padding: 16 }}>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 10 }}>
                  <button type="button" className="button small" onClick={refreshSessions} disabled={sessionsLoading || !!revokingSid}>
                    {sessionsLoading ? 'Loading…' : 'Refresh'}
                  </button>

                  <button type="button" className="button small primary" onClick={revokeAllSessions} disabled={sessionsLoading || !!revokingSid}>
                    {revokingSid === '__all__' ? 'Revoking…' : 'Revoke all'}
                  </button>

                  <button type="button" className="button small" onClick={() => { loadAudit(); loadActivity(); }} disabled={sessionsLoading || !!revokingSid}>
                    Refresh logs
                  </button>

                  <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)' }}>
                    {sessionsList.length} session(s)
                  </div>
                </div>

                {sessionsError && (
                  <div style={{ fontSize: 12, color: 'var(--danger)', marginBottom: 10 }}>
                    {sessionsError}
                  </div>
                )}

                {sessionsList.length === 0 && !sessionsLoading ? (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>No sessions found.</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {sessionsList.map((s) => (
                      <div key={s.id} style={{ border: '1px solid var(--panel-border)', borderRadius: 12, padding: 10 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                          <div style={{ fontSize: 12, color: 'var(--text-main)' }}>
                            <strong>{s.id}</strong>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                              created: {fmtWhen(s.createdAt)} · ip: <code>{s.ip || '—'}</code>
                            </div>
                            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                              ua: <code style={{ whiteSpace: 'pre-wrap' }}>{s.userAgent || '—'}</code>
                            </div>
                          </div>

                          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
                            <button type="button" className="button small" onClick={() => revokeOneSession(s.id)} disabled={!!revokingSid}>
                              {revokingSid === s.id ? 'Revoking…' : 'Revoke'}
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-muted)' }}>
                  Revoking removes the server-side session record. The user will be logged out on their next request.
                </div>
              </div>
            </div>
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
