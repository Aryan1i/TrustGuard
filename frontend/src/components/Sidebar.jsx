import React from 'react';
import { NavLink } from 'react-router-dom';

export const MODULES = [
  { to: '/', label: 'Dashboard', group: 'Main menu' },
  { to: '/devices', label: 'Devices', group: 'Main menu' },
  { to: '/keys', label: 'Key Management', group: 'Main menu', adminOnly: true },
  { to: '/access', label: 'Access Monitor', group: 'Main menu' },
  { to: '/threats', label: 'Threat Detection', group: 'Main menu' },
  { to: '/audit', label: 'Audit Logs', group: 'Security' },
  { to: '/messaging', label: 'Secure Messaging', group: 'Security' },
  { to: '/recovery', label: 'Backup & Recovery', group: 'Security', adminOnly: true },
  { to: '/settings', label: 'Settings', group: 'Admin' },
];

function MenuIcon({ path }) {
  const icons = {
    '/': <path d="M3 10.5L12 3l9 7.5V20a1 1 0 01-1 1h-5v-6H9v6H4a1 1 0 01-1-1v-9.5z" />,
    '/devices': <path d="M4 6h16v10H4V6zm6 12h4m-6 2h8" />,
    '/keys': <path d="M15 7a4 4 0 10-3.87 5H6v3h3v3h3v-2.13A4 4 0 0015 7z" />,
    '/access': <path d="M12 2l7 3.5V11c0 5-3.3 9.3-7 11-3.7-1.7-7-6-7-11V5.5L12 2z" />,
    '/threats': <path d="M12 9v4m0 4h.01M10.3 3.9L2.8 17a2 2 0 001.7 3h15a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />,
    '/audit': <path d="M7 3h10l4 4v14H3V3h4zm0 6h10m-10 4h10m-10 4h6" />,
    '/messaging': <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2v10z" />,
    '/recovery': <path d="M3 12a9 9 0 103-6.7L3 8m0-5v5h5" />,
    '/settings': <path d="M12 15a3 3 0 100-6 3 3 0 000 6zm7.4-3a7.4 7.4 0 00-.1-1l2-1.5-2-3.5-2.3.9a7.7 7.7 0 00-1.7-1L15 3h-6l-.3 2.9a7.7 7.7 0 00-1.7 1L4.7 6l-2 3.5 2 1.5a7.4 7.4 0 000 2l-2 1.5 2 3.5 2.3-.9c.5.4 1.1.8 1.7 1L9 21h6l.3-2.9c.6-.2 1.2-.6 1.7-1l2.3.9 2-3.5-2-1.5c.1-.3.1-.7.1-1z" />,
  };

  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {icons[path]}
    </svg>
  );
}

export default function Sidebar({ session, onOpenLogin, onLogout }) {
  const groups = ['Main menu', 'Security', 'Admin'];

  return (
    <aside className="sidebar" aria-label="Primary Navigation">
      <div className="sidebar-top">
        <NavLink to="/" className="sidebar-brand">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" fill="#3fa66c" />
            <path d="M9 12.2L11 14.2L15.5 9.7" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="sidebar-wordmark">TRUSTGUARD</span>
        </NavLink>
      </div>

      <nav className="sidebar-nav">
        {groups.map((group) => {
          const items = MODULES.filter(
            (m) => m.group === group && (!m.adminOnly || session?.role === 'ADMIN')
          );
          if (items.length === 0) return null;
          return (
            <div key={group}>
              <div className="sidebar-section-label">{group}</div>
              {items.map((m) => (
                <NavLink
                  key={m.to}
                  to={m.to}
                  end={m.to === '/'}
                  className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
                >
                  <MenuIcon path={m.to} />
                  <span>{m.label}</span>
                </NavLink>
              ))}
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="sidebar-user-row">
          <div className="avatar-circle">
            {(session?.username || 'TG').slice(0, 2).toUpperCase()}
          </div>
          <div className="sidebar-user-meta">
            <div className="sidebar-user-name">{session?.displayName || session?.username}</div>
            <div className="sidebar-user-email">{session?.username}@trustguard.local</div>
          </div>
          <button
            type="button"
            className="icon-btn icon-btn-ghost"
            title="Sign out"
            onClick={onLogout}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4m7 14l5-5-5-5m5 5H9" />
            </svg>
          </button>
        </div>

        <button type="button" className="btn btn-secondary" style={{ width: '100%' }} onClick={onOpenLogin}>
          Switch Account
        </button>
      </div>
    </aside>
  );
}
