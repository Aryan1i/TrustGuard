import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api';

const PAGE_SHORTCUTS = [
  { type: 'Page', title: 'Security Dashboard', subtitle: 'Overview metrics, allowed vs denied chart, recent events', to: '/', keywords: 'dashboard overview metrics home' },
  { type: 'Page', title: 'Devices', subtitle: 'Manage enrolled devices, owners, fingerprints, and revocations', to: '/devices', keywords: 'device revoke enroll hardware macbook' },
  { type: 'Page', title: 'Key Management', subtitle: 'Key lifecycle, rotation quorum, cutoffs, and cluster acks', to: '/keys', keywords: 'key rotation quorum cutoff version' },
  { type: 'Page', title: 'Access Monitor', subtitle: 'Policy evaluation stream and access simulator', to: '/access', keywords: 'access allow deny policy simulator' },
  { type: 'Page', title: 'Threat Detection', subtitle: 'Security alerts, role changes, and lateral movement events', to: '/threats', keywords: 'threat alert anomaly role privilege escalation' },
  { type: 'Page', title: 'Audit Logs', subtitle: 'Tamper-evident SHA-256 hash-chained audit ledger', to: '/audit', keywords: 'audit log tamper hash verify chain' },
  { type: 'Page', title: 'Secure Messaging', subtitle: 'Encrypted device messages, forward secrecy, sessions', to: '/messaging', keywords: 'message encrypt session replay forward secrecy' },
  { type: 'Page', title: 'Backup & Recovery', subtitle: 'Checksum-verified snapshot archive and crash recovery', to: '/recovery', keywords: 'backup restore snapshot corrupt checksum' },
  { type: 'Page', title: 'Settings', subtitle: 'User directory, security policies, and cluster nodes', to: '/settings', keywords: 'user account policy settings nodes role' },
];

export default function Navbar({ title, session, onOpenLogin }) {
  const [query, setQuery] = useState('');
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const [indexData, setIndexData] = useState({
    devices: [],
    users: [],
    alerts: [],
    keys: [],
    nodes: [],
    audits: [],
  });
  const [loadingIndex, setLoadingIndex] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const containerRef = useRef(null);
  const lastLoadedRef = useRef(0);

  const isAdmin = session?.role === 'ADMIN';

  const loadSearchIndex = useCallback(async (force = false) => {
    const now = Date.now();
    if (!force && now - lastLoadedRef.current < 15000 && lastLoadedRef.current > 0) return;
    setLoadingIndex(true);
    try {
      const [devsRes, usersRes, alertsRes, rotRes, auditRes] = await Promise.allSettled([
        api.getDevices(),
        api.getUsers(),
        api.getAlerts(),
        isAdmin ? api.getRotationStatus() : Promise.resolve(null),
        api.getAuditLogs(),
      ]);
      lastLoadedRef.current = Date.now();
      setIndexData({
        devices: devsRes.status === 'fulfilled' && Array.isArray(devsRes.value) ? devsRes.value : [],
        users: usersRes.status === 'fulfilled' && Array.isArray(usersRes.value) ? usersRes.value : [],
        alerts: alertsRes.status === 'fulfilled' && Array.isArray(alertsRes.value) ? alertsRes.value : [],
        keys: rotRes.status === 'fulfilled' && Array.isArray(rotRes.value?.versions) ? rotRes.value.versions : [],
        nodes: rotRes.status === 'fulfilled' && Array.isArray(rotRes.value?.nodes) ? rotRes.value.nodes : [],
        audits: auditRes.status === 'fulfilled' && Array.isArray(auditRes.value?.entries) ? auditRes.value.entries : [],
      });
    } finally {
      setLoadingIndex(false);
    }
  }, [isAdmin]);

  useEffect(() => {
    loadSearchIndex(true);
  }, [session?.username, loadSearchIndex]);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];

    const items = [];

    indexData.devices.forEach((d) => {
      const hay = `${d.deviceName || ''} ${d.deviceUid || ''} ${d.ownerUsername || ''} ${d.status || ''} ${d.publicKeyFingerprint || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `dev-${d.deviceUid || d.id}`,
          type: 'Device',
          tone: d.status === 'ACTIVE' ? 'green' : 'red',
          badge: d.status || 'DEVICE',
          title: d.deviceName || d.deviceUid,
          subtitle: `${d.deviceUid || ''} · Owner: ${d.ownerUsername || '—'}`,
          to: `/devices?q=${encodeURIComponent(d.deviceUid || query.trim())}`,
        });
      }
    });

    indexData.users.forEach((u) => {
      const hay = `${u.username || ''} ${u.displayName || ''} ${u.email || ''} ${u.role || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `usr-${u.username}`,
          type: 'User',
          tone: u.active ? 'green' : 'red',
          badge: u.role || 'USER',
          title: `${u.displayName || u.username} (${u.username})`,
          subtitle: u.email || `${u.username}@trustguard.local`,
          to: `/settings?q=${encodeURIComponent(u.username)}`,
        });
      }
    });

    indexData.alerts.forEach((a) => {
      const hay = `${a.alertUid || ''} ${a.ruleName || ''} ${a.actor || ''} ${a.severity || ''} ${a.servicePath || ''} ${a.explanation || ''} ${a.eventIdsJson || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `alt-${a.alertUid || a.ruleName}`,
          type: 'Alert',
          tone: a.severity === 'CRITICAL' || a.severity === 'HIGH' ? 'red' : a.severity === 'MEDIUM' ? 'amber' : 'dark',
          badge: a.severity || 'ALERT',
          title: `${a.ruleName || 'Security Alert'} · ${a.actor || '—'}`,
          subtitle: `${a.alertUid || ''} · ${a.explanation ? a.explanation.slice(0, 72) : a.servicePath || ''}`,
          to: `/threats?q=${encodeURIComponent(a.actor || a.alertUid || query.trim())}`,
        });
      }
    });

    indexData.keys.forEach((k) => {
      const ver = `v${k.versionNumber}`;
      const hay = `${k.keyAlias || ''} ${ver} ${k.status || ''} ${k.algorithm || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `key-${k.id || k.versionNumber}`,
          type: 'Key',
          tone: k.status === 'COMMITTED' ? 'green' : 'amber',
          badge: k.status || ver,
          title: `${k.keyAlias || 'trustguard-data-key'} (${ver})`,
          subtitle: `Algorithm: ${k.algorithm || 'ML-KEM-768'}`,
          to: `/keys?q=${encodeURIComponent(ver)}`,
        });
      }
    });

    indexData.nodes.forEach((n) => {
      const hay = `${n.nodeCode || ''} ${n.nodeName || ''} ${n.region || ''} ${n.status || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `node-${n.nodeCode}`,
          type: 'Node',
          tone: n.status === 'ONLINE' ? 'green' : 'amber',
          badge: n.status || 'NODE',
          title: `${n.nodeName || n.nodeCode} (${n.nodeCode})`,
          subtitle: `Region: ${n.region || '—'} · Key v${n.currentKeyVersion}`,
          to: `/settings?q=${encodeURIComponent(n.nodeCode)}`,
        });
      }
    });

    indexData.audits.slice(0, 40).forEach((e) => {
      const hay = `${e.eventId || ''} ${e.actor || ''} ${e.action || ''} ${e.resource || ''} ${e.detail || ''}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `aud-${e.eventId || e.seqNumber}`,
          type: 'Audit',
          tone: 'dark',
          badge: e.action || 'AUDIT',
          title: `${e.action || 'EVENT'} · ${e.actor || 'system'}`,
          subtitle: `${e.eventId || `#${e.seqNumber}`} · ${e.resource || ''}`,
          to: `/audit?q=${encodeURIComponent(e.eventId || e.actor || query.trim())}`,
        });
      }
    });

    PAGE_SHORTCUTS.forEach((p) => {
      const hay = `${p.title} ${p.subtitle} ${p.keywords}`.toLowerCase();
      if (hay.includes(q)) {
        items.push({
          id: `page-${p.to}`,
          type: 'Page',
          tone: 'green',
          badge: 'NAVIGATE',
          title: p.title,
          subtitle: p.subtitle,
          to: p.to,
        });
      }
    });

    return items.slice(0, 12);
  }, [query, indexData]);

  useEffect(() => {
    setActiveIndex(0);
  }, [results.length, query]);

  const selectResult = (item) => {
    setOpen(false);
    navigate(item.to);
  };

  const handleSearch = (e) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    if (results.length > 0) {
      const chosen = results[activeIndex] || results[0];
      selectResult(chosen);
      return;
    }

    const lower = q.toLowerCase();
    if (lower.includes('dev') || lower.includes('revok')) navigate(`/devices?q=${encodeURIComponent(q)}`);
    else if (lower.includes('key') || lower.includes('rotat')) navigate(`/keys?q=${encodeURIComponent(q)}`);
    else if (lower.includes('access')) navigate(`/access?q=${encodeURIComponent(q)}`);
    else if (lower.includes('alert') || lower.includes('threat')) navigate(`/threats?q=${encodeURIComponent(q)}`);
    else if (lower.includes('audit') || lower.includes('log')) navigate(`/audit?q=${encodeURIComponent(q)}`);
    else if (lower.includes('msg') || lower.includes('messag')) navigate(`/messaging?q=${encodeURIComponent(q)}`);
    else if (lower.includes('bak') || lower.includes('recover')) navigate(`/recovery?q=${encodeURIComponent(q)}`);
    else navigate(`/devices?q=${encodeURIComponent(q)}`);
    setOpen(false);
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      setOpen(false);
    } else if (e.key === 'ArrowDown' && results.length > 0) {
      e.preventDefault();
      setOpen(true);
      setActiveIndex((prev) => (prev + 1) % results.length);
    } else if (e.key === 'ArrowUp' && results.length > 0) {
      e.preventDefault();
      setOpen(true);
      setActiveIndex((prev) => (prev - 1 + results.length) % results.length);
    }
  };

  const clearSearch = () => {
    setQuery('');
    setOpen(false);
    if (new URLSearchParams(location.search).has('q')) {
      navigate(location.pathname, { replace: true });
    }
  };

  return (
    <header className="top-header">
      <h1 className="top-header-title">{title}</h1>

      <div className="top-header-right">
        <div className="header-search-wrap" ref={containerRef}>
          <form className="header-search" onSubmit={handleSearch} role="search">
            <button type="submit" className="header-search-submit" aria-label="Submit search" style={{ order: -1 }}>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            </button>
            <input
              type="text"
              placeholder="Search devices, users, or alerts"
              aria-label="Search devices, users, or alerts"
              value={query}
              onFocus={() => {
                loadSearchIndex(false);
                if (query.trim()) setOpen(true);
              }}
              onChange={(e) => {
                setQuery(e.target.value);
                setOpen(Boolean(e.target.value.trim()));
              }}
              onKeyDown={handleKeyDown}
            />
            {query && (
              <button
                type="button"
                className="header-search-clear"
                aria-label="Clear search"
                onClick={clearSearch}
              >
                ×
              </button>
            )}
          </form>

          {open && query.trim() && (
            <div className="header-search-dropdown" role="listbox" aria-label="Search results">
              {loadingIndex && results.length === 0 ? (
                <div className="header-search-empty">Searching directory…</div>
              ) : results.length === 0 ? (
                <div className="header-search-empty">
                  No devices, users, or alerts matching &ldquo;{query.trim()}&rdquo;
                </div>
              ) : (
                results.map((item, idx) => (
                  <button
                    key={item.id}
                    type="button"
                    role="option"
                    aria-selected={idx === activeIndex}
                    className={`header-search-item${idx === activeIndex ? ' active' : ''}`}
                    onMouseEnter={() => setActiveIndex(idx)}
                    onClick={() => selectResult(item)}
                  >
                    <div className="header-search-item-top">
                      <span className="header-search-type">{item.type}</span>
                      <span className={`header-search-badge tone-${item.tone}`}>{item.badge}</span>
                    </div>
                    <div className="header-search-item-title">{item.title}</div>
                    <div className="header-search-item-sub">{item.subtitle}</div>
                  </button>
                ))
              )}
            </div>
          )}
        </div>

        <button
          type="button"
          className="icon-btn"
          title="View Security Alerts"
          onClick={() => navigate('/threats')}
          style={{ position: 'relative' }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
            <path d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9m-4.27 13a2 2 0 01-3.46 0" />
          </svg>
        </button>

        {/* Light / dark placeholder (cosmetic, like Dealport) */}
        <button
          type="button"
          className="icon-btn"
          title="Display settings"
          style={{ color: '#9ca3af' }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
          </svg>
        </button>

        <button
          type="button"
          className="avatar-circle"
          style={{ border: 'none', cursor: 'pointer', fontSize: '13px', fontWeight: 700 }}
          title={`Signed in as ${session?.username} (${session?.role})`}
          onClick={onOpenLogin}
        >
          {(session?.username || 'TG').slice(0, 2).toUpperCase()}
        </button>
      </div>
    </header>
  );
}
