import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';

export const MODULES = [
  { to: '/', label: 'Dashboard', category: 'Security', sub: 'Core • Live Posture' },
  { to: '/devices', label: 'Devices', category: 'Security', sub: 'Identity • Revocation' },
  { to: '/keys', label: 'Key Management', category: 'Security', sub: 'ML-KEM • Quorum' },
  { to: '/access', label: 'Access Monitor', category: 'Security', sub: 'Zero-Trust • Policy' },
  { to: '/threats', label: 'Threat Detection', category: 'Security', sub: '22 Events • Rules' },
  { to: '/audit', label: 'Audit Logs', category: 'Ops', sub: 'SHA-256 • Hash Chain' },
  { to: '/messaging', label: 'Secure Messaging', category: 'Ops', sub: 'E2EE • Forward Secrecy' },
  { to: '/recovery', label: 'Backup & Recovery', category: 'Ops', sub: 'Checksums • Restore' },
  { to: '/settings', label: 'Settings', category: 'Ops', sub: 'Nodes • Boundaries' },
];

function RailIcon({ path }) {
  const icons = {
    '/': (
      <path d="M4 4h7v7H4V4zm9 0h7v7h-7V4zM4 13h7v7H4v-7zm9 0h7v7h-7v-7z" />
    ),
    '/devices': (
      <path d="M4 6h16v10H4V6zm6 12h4m-6 2h8" />
    ),
    '/keys': (
      <path d="M15 7a4 4 0 10-3.87 5H6v3h3v3h3v-2.13A4 4 0 0015 7z" />
    ),
    '/access': (
      <path d="M12 2l7 3.5V11c0 5-3.3 9.3-7 11-3.7-1.7-7-6-7-11V5.5L12 2z" />
    ),
    '/threats': (
      <path d="M12 9v4m0 4h.01M10.3 3.9L2.8 17a2 2 0 001.7 3h15a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
    ),
    '/audit': (
      <path d="M7 3h10l4 4v14H3V3h4zm0 6h10m-10 4h10m-10 4h6" />
    ),
    '/messaging': (
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2v10z" />
    ),
    '/recovery': (
      <path d="M3 12a9 9 0 103-6.7L3 8m0-5v5h5" />
    ),
    '/settings': (
      <path d="M12 15a3 3 0 100-6 3 3 0 000 6zm7.4-3a7.4 7.4 0 00-.1-1l2-1.5-2-3.5-2.3.9a7.7 7.7 0 00-1.7-1L15 3h-6l-.3 2.9a7.7 7.7 0 00-1.7 1L4.7 6l-2 3.5 2 1.5a7.4 7.4 0 000 2l-2 1.5 2 3.5 2.3-.9c.5.4 1.1.8 1.7 1L9 21h6l.3-2.9c.6-.2 1.2-.6 1.7-1l2.3.9 2-3.5-2-1.5c.1-.3.1-.7.1-1z" />
    ),
  };

  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      {icons[path]}
    </svg>
  );
}

export default function Sidebar({ session, onOpenLogin }) {
  const [search, setSearch] = useState('');
  const [tab, setTab] = useState('All');

  const filteredModules = MODULES.filter((m) => {
    const matchTab = tab === 'All' || m.category === tab;
    const q = search.trim().toLowerCase();
    const matchSearch = !q || m.label.toLowerCase().includes(q) || m.sub.toLowerCase().includes(q);
    return matchTab && matchSearch;
  });

  return (
    <>
      <aside className="icon-rail" aria-label="Icon Navigation">
        <div className="rail-top">
          <div className="rail-logo" title="TrustGuard">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z" stroke="#FFFFFF" strokeWidth="2" />
              <path d="M9 12.2L11 14.2L15.5 9.7" stroke="#FFFFFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          {MODULES.map((m) => (
            <NavLink
              key={m.to}
              to={m.to}
              end={m.to === '/'}
              title={m.label}
              className={({ isActive }) => `rail-btn${isActive ? ' active' : ''}`}
            >
              <RailIcon path={m.to} />
            </NavLink>
          ))}
        </div>

        <div className="rail-bottom">
          <button
            type="button"
            className="avatar-circle"
            title={`Signed in as ${session?.username || 'guest'} (click to switch)`}
            onClick={onOpenLogin}
          >
            {(session?.username || 'TG').slice(0, 2).toUpperCase()}
          </button>
        </div>
      </aside>

      <aside className="module-drawer" aria-label="All Modules">
        <h2 className="drawer-title">All Modules</h2>

        <div className="drawer-search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
          <input
            type="text"
            placeholder="Search Module"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="drawer-filter-pills">
          <button
            type="button"
            className={`filter-pill${tab === 'All' ? ' active' : ''}`}
            onClick={() => setTab('All')}
          >
            Active({String(MODULES.length).padStart(2, '0')})
          </button>
          <button
            type="button"
            className={`filter-pill${tab === 'Security' ? ' active' : ''}`}
            onClick={() => setTab('Security')}
          >
            Security(05)
          </button>
          <button
            type="button"
            className={`filter-pill${tab === 'Ops' ? ' active' : ''}`}
            onClick={() => setTab('Ops')}
          >
            Ops(04)
          </button>
        </div>

        <div className="drawer-list">
          {filteredModules.map((m) => (
            <NavLink
              key={m.to}
              to={m.to}
              end={m.to === '/'}
              className={({ isActive }) => `drawer-item${isActive ? ' active' : ''}`}
            >
              <div className="drawer-item-icon">
                <RailIcon path={m.to} />
              </div>
              <div className="drawer-item-body">
                <div className="drawer-item-title">{m.label}</div>
                <div className="drawer-item-sub">{m.sub}</div>
              </div>
              <span style={{ color: '#9ca3af', fontSize: '14px' }}>›</span>
            </NavLink>
          ))}
        </div>
      </aside>
    </>
  );
}
