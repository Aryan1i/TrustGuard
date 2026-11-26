import React from 'react';
import { NavLink } from 'react-router-dom';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard' },
  { to: '/devices', label: 'Devices' },
  { to: '/keys', label: 'Key Management' },
  { to: '/access', label: 'Access Monitor' },
  { to: '/threats', label: 'Threat Detection' },
  { to: '/audit', label: 'Audit Logs' },
  { to: '/messaging', label: 'Secure Messaging' },
  { to: '/recovery', label: 'Backup & Recovery' },
  { to: '/settings', label: 'Settings' },
];

function ShieldLogo() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2L4 5.5V11.5C4 16.8 7.4 21.5 12 23C16.6 21.5 20 16.8 20 11.5V5.5L12 2Z"
        fill="#2563EB"
        stroke="#93C5FD"
        strokeWidth="1.4"
      />
      <path
        d="M9 12.2L11 14.2L15.5 9.7"
        stroke="#FFFFFF"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <ShieldLogo />
        <div>
          <div className="sidebar-brand-title">TrustGuard</div>
          <div className="sidebar-brand-sub">Track 4 · Trust, but verify</div>
        </div>
      </div>

      <nav className="sidebar-nav" aria-label="Primary Navigation">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) => `sidebar-link${isActive ? ' active' : ''}`}
          >
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div>ML-KEM-768 · ML-DSA-65</div>
        <div>AES-256-GCM · SHA-256 Chain</div>
      </div>
    </aside>
  );
}
