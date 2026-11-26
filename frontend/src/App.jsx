import React, { useEffect, useState } from 'react';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { clearSession, getRuntimeModeSync, getSavedSession, resolveRuntimeMode } from './api';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import LoginModal from './components/LoginModal';
import Dashboard from './pages/Dashboard';
import Devices from './pages/Devices';
import KeyManagement from './pages/KeyManagement';
import AccessMonitor from './pages/AccessMonitor';
import ThreatDetection from './pages/ThreatDetection';
import AuditLogs from './pages/AuditLogs';
import Messaging from './pages/Messaging';
import Recovery from './pages/Recovery';
import Settings from './pages/Settings';

const PAGE_TITLES = {
  '/': 'TrustGuard Security Hub',
  '/devices': 'Identity & Device Management',
  '/keys': 'Post-Quantum Key Management',
  '/access': 'Zero-Trust Access Monitor',
  '/threats': 'Deterministic Threat Detection',
  '/audit': 'Tamper-Evident Audit Logs',
  '/messaging': 'Post-Quantum Secure Messaging',
  '/recovery': 'Backup & Crash Recovery',
  '/settings': 'Platform Settings & Boundaries',
};

function AppShell() {
  const location = useLocation();
  const [session, setSession] = useState(() => getSavedSession());
  const [runtimeMode, setRuntimeMode] = useState(() => getRuntimeModeSync());
  const [loginOpen, setLoginOpen] = useState(false);

  useEffect(() => {
    const onUnauth = () => setSession(null);
    const onMode = (e) => setRuntimeMode(e.detail);
    window.addEventListener('trustguard:unauthorized', onUnauth);
    window.addEventListener('trustguard:mode', onMode);
    resolveRuntimeMode().then((mode) => {
      setRuntimeMode(mode);
      // If session belongs to a different runtime mode, clear so user authenticates cleanly in current mode
      const saved = getSavedSession();
      if (saved) {
        const isStandaloneToken = saved.token?.startsWith('tg-standalone.');
        if (mode === 'backend' && isStandaloneToken) {
          clearSession();
          setSession(null);
        } else if (mode === 'standalone' && !isStandaloneToken) {
          clearSession();
          setSession(null);
        }
      }
    });
    return () => {
      window.removeEventListener('trustguard:unauthorized', onUnauth);
      window.removeEventListener('trustguard:mode', onMode);
    };
  }, []);

  if (!session) {
    return (
      <LoginModal
        standalone
        open
        runtimeMode={runtimeMode}
        onAuthenticated={(newSession) => setSession(newSession)}
      />
    );
  }

  const title = PAGE_TITLES[location.pathname] || 'TrustGuard';

  return (
    <div className="app-shell">
      <Sidebar session={session} onOpenLogin={() => setLoginOpen(true)} />
      <div className="main-column">
        <Navbar
          title={title}
          session={session}
          runtimeMode={runtimeMode}
          onOpenLogin={() => setLoginOpen(true)}
          onLogout={() => {
            clearSession();
            setSession(null);
          }}
        />
        <main className="page-content">
          {runtimeMode === 'standalone' && (
            <div className="banner banner-info" style={{ fontSize: '12.5px' }}>
              <strong>Vercel Standalone Mode active:</strong> No Spring Boot server detected at{' '}
              <span className="mono">/api/v1</span>. Authentication, deterministic 22-event detection, SHA-256 audit hash chaining, and WebCrypto AES-256-GCM messaging run persistently in your browser. Set <span className="mono">VITE_API_BASE_URL</span> to connect a hosted Java Spring Boot backend for BouncyCastle ML-KEM-768 / ML-DSA-65 and MySQL.
            </div>
          )}
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/devices" element={<Devices session={session} />} />
            <Route path="/keys" element={<KeyManagement session={session} />} />
            <Route path="/access" element={<AccessMonitor session={session} />} />
            <Route path="/threats" element={<ThreatDetection />} />
            <Route path="/audit" element={<AuditLogs session={session} />} />
            <Route path="/messaging" element={<Messaging session={session} />} />
            <Route path="/recovery" element={<Recovery session={session} />} />
            <Route path="/settings" element={<Settings session={session} onOpenLogin={() => setLoginOpen(true)} />} />
          </Routes>
        </main>
      </div>

      <LoginModal
        open={loginOpen}
        runtimeMode={runtimeMode}
        onClose={() => setLoginOpen(false)}
        onAuthenticated={(newSession) => setSession(newSession)}
      />
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
