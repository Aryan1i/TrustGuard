import React from 'react';
import StatusBadge from './StatusBadge';

export default function Navbar({ title, session, onLogout, onOpenLogin }) {
  return (
    <header className="navbar">
      <div className="navbar-title-wrap">
        <h1 className="navbar-title">{title}</h1>
        <StatusBadge status="SYNTHETIC LAB" variant="info" />
      </div>

      <div className="navbar-actions">
        {session ? (
          <>
            <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
              Signed in as <strong>{session.username}</strong> ({session.role})
            </span>
            <button type="button" className="btn btn-secondary btn-sm" onClick={onOpenLogin}>
              Switch Identity
            </button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={onLogout}>
              Sign Out
            </button>
          </>
        ) : (
          <button type="button" className="btn btn-primary btn-sm" onClick={onOpenLogin}>
            Sign In
          </button>
        )}
      </div>
    </header>
  );
}
