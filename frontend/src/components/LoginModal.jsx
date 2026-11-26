import React, { useState } from 'react';
import { api, getRuntimeModeSync, saveSession } from '../api';
import { getStandaloneDemoPassphrase } from '../standaloneEngine';

const QUICK_ACCOUNTS = [
  { username: 'admin', label: 'Admin (Operator)' },
  { username: 'alice', label: 'Alice (Owner)' },
  { username: 'bob', label: 'Bob (Owner)' },
  { username: 'charlie', label: 'Charlie (Owner)' },
];

function resolveDefaultPassphrase() {
  const configured = import.meta.env.VITE_DEMO_PASSWORD;
  if (configured && String(configured).trim()) {
    return String(configured).trim();
  }
  return getRuntimeModeSync() === 'standalone' ? getStandaloneDemoPassphrase() : '';
}

export default function LoginModal({ open, onClose, onAuthenticated, standalone = false }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState(() => resolveDefaultPassphrase());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!open && !standalone) return null;

  const submitLogin = async (userToAuth, passToAuth) => {
    setLoading(true);
    setError('');
    try {
      const res = await api.login(userToAuth, passToAuth);
      saveSession(res);
      onAuthenticated(res);
      if (onClose) onClose();
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const formContent = (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" fill="#3fa66c" />
          <path d="M9 12.2L11 14.2L15.5 9.7" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div>
          <h2 style={{ margin: 0, fontSize: '18px' }}>TRUSTGUARD Sign In</h2>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Identity & Security Operations Console
          </div>
        </div>
      </div>

      <div className="banner banner-info" style={{ fontSize: '12px' }}>
        {getRuntimeModeSync() === 'standalone'
          ? 'Offline standalone browser mode uses an ephemeral local session passphrase. Click any Quick Sign-In account to inspect.'
          : 'Sign in with your configured environment passphrase to manage devices, keys, access policies, messaging, and alerts.'}
      </div>

      {error && <div className="banner banner-danger">{error}</div>}

      <form
        onSubmit={(e) => {
          e.preventDefault();
          submitLogin(username, password);
        }}
      >
        <div className="field" style={{ marginBottom: '12px' }}>
          <label htmlFor="tg-username">Username</label>
          <input
            id="tg-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
          />
        </div>
        <div className="field" style={{ marginBottom: '14px' }}>
          <label htmlFor="tg-password">Password</label>
          <input
            id="tg-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        <div className="flex-row" style={{ justifyContent: 'space-between', marginBottom: '14px' }}>
          {!standalone && (
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
          )}
          <button type="submit" className="btn btn-primary" style={{ flex: 1 }} disabled={loading}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </div>
      </form>

      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
          Quick Sign-In:
        </div>
        <div className="flex-row">
          {QUICK_ACCOUNTS.map((u) => (
            <button
              key={u.username}
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={loading}
              onClick={() => {
                const resolved = password || resolveDefaultPassphrase();
                setUsername(u.username);
                if (resolved) {
                  setPassword(resolved);
                  submitLogin(u.username, resolved);
                } else {
                  setError(`Enter the configured password above to sign in as ${u.username}.`);
                }
              }}
            >
              {u.label}
            </button>
          ))}
        </div>
      </div>
    </>
  );

  if (standalone) {
    return (
      <div className="login-shell">
        <div className="login-card">{formContent}</div>
      </div>
    );
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-card">{formContent}</div>
    </div>
  );
}
