import React from 'react';
import { NavLink } from 'react-router-dom';
import StatusBadge from './StatusBadge';
import { MODULES } from './Sidebar';

const IDENTITIES = [
  { key: 'AD', name: 'admin', bg: '#1d4ed8' },
  { key: 'AL', name: 'alice', bg: '#7c3aed' },
  { key: 'BO', name: 'bob', bg: '#0f766e' },
  { key: 'CH', name: 'charlie', bg: '#b45309' },
];

export default function Navbar({ title, session, onLogout, onOpenLogin }) {
  return (
    <header className="top-header">
      <div className="top-header-row">
        <div>
          <h1 className="page-heading">
            <span>{title}</span>
            <span style={{ fontSize: '16px' }}>⚡</span>
          </h1>
          <div className="page-breadcrumb">
            TrustGuard / Security Operations / {title}
          </div>
        </div>

        <div className="header-controls">
          <StatusBadge status="ACTIVE" variant="success" />

          <div className="avatar-stack" title="Switch active user account">
            {IDENTITIES.map((id) => (
              <button
                key={id.name}
                type="button"
                className="avatar-stack-item"
                style={{
                  background: id.bg,
                  outline: session?.username === id.name ? '2px solid #1d4ed8' : 'none',
                }}
                onClick={onOpenLogin}
                title={`Active: ${session?.username} — click to switch`}
              >
                {id.key}
              </button>
            ))}
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onOpenLogin}
            title="Switch Account"
          >
            {session?.username} ({session?.role})
          </button>

          <button type="button" className="btn btn-secondary btn-sm" onClick={onLogout}>
            Sign Out
          </button>
        </div>
      </div>

      <nav className="underline-tabs" aria-label="Workspace Tabs">
        {MODULES.map((m) => (
          <NavLink
            key={m.to}
            to={m.to}
            end={m.to === '/'}
            className={({ isActive }) => `underline-tab${isActive ? ' active' : ''}`}
          >
            {m.label}
          </NavLink>
        ))}
      </nav>
    </header>
  );
}
