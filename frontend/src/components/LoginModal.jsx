import React, { useState } from 'react';
import { api, saveSession } from '../api';
import StatusBadge from './StatusBadge';

const DEMO_USERS = [
  { username: 'admin', role: 'ADMIN', label: 'Admin (Operator)' },
  { username: 'alice', role: 'USER', label: 'Alice (Owner)' },
  { username: 'bob', role: 'USER', label: 'Bob (Owner)' },
  { username: 'charlie', role: 'USER', label: 'Charlie (Owner)' },
];

export default function LoginModal({ open, onClose, onAuthenticated, standalone = false, runtimeMode = 'checking' }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('TrustGuard!Demo2026');
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
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="rail-logo" style={{ marginBottom: 0 }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" stroke="#FFFFFF" strokeWidth="2" />
              <path d="M9 12.2L11 14.2L15.5 9.7" stroke="#FFFFFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: '18px' }}>TrustGuard Sign In</h2>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Track 4 · Identity & Access Console
            </div>
          </div>
        </div>
        <StatusBadge
          status={runtimeMode === 'backend' ? 'Spring Boot' : 'Standalone Edge'}
          variant={runtimeMode === 'backend' ? 'success' : 'lavender'}
        />
      </div>

      <div className="banner banner-info" style={{ fontSize: '12px' }}>
        Synthetic hackathon identities only. Password: <span className="mono">TrustGuard!Demo2026</span>
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
          <label htmlFor="tg-password">Synthetic Demo Password</label>
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
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </div>
      </form>

      <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '12px' }}>
        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '8px' }}>
          Quick Authenticate Synthetic User:
        </div>
        <div className="flex-row">
          {DEMO_USERS.map((u) => (
            <button
              key={u.username}
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={loading}
              onClick={() => {
                setUsername(u.username);
                setPassword('TrustGuard!Demo2026');
                submitLogin(u.username, 'TrustGuard!Demo2026');
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
