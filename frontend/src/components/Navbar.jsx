import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

export default function Navbar({ title, session, onOpenLogin }) {
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  const handleSearch = (e) => {
    e.preventDefault();
    const q = query.trim().toLowerCase();
    if (!q) return;
    if (q.includes('dev') || q.includes('revok')) navigate('/devices');
    else if (q.includes('key') || q.includes('rotat')) navigate('/keys');
    else if (q.includes('access')) navigate('/access');
    else if (q.includes('alert') || q.includes('threat')) navigate('/threats');
    else if (q.includes('audit') || q.includes('log')) navigate('/audit');
    else if (q.includes('msg') || q.includes('messag')) navigate('/messaging');
    else if (q.includes('bak') || q.includes('recover')) navigate('/recovery');
    else navigate('/');
  };

  return (
    <header className="top-header">
      <h1 className="top-header-title">{title}</h1>

      <div className="top-header-right">
        <form className="header-search" onSubmit={handleSearch}>
          <input
            type="text"
            placeholder="Search devices, users, or alerts"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <path d="M21 21l-4.35-4.35" />
          </svg>
        </form>

        <button
          type="button"
          className="icon-btn"
          title="View Security Alerts"
          onClick={() => navigate('/threats')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9m-4.27 13a2 2 0 01-3.46 0" />
          </svg>
        </button>

        <button
          type="button"
          className="avatar-circle"
          style={{ border: 'none', cursor: 'pointer' }}
          title={`Signed in as ${session?.username} (${session?.role})`}
          onClick={onOpenLogin}
        >
          {(session?.username || 'TG').slice(0, 2).toUpperCase()}
        </button>
      </div>
    </header>
  );
}
