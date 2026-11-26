import React, { useEffect, useState } from 'react';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { clearSession, getSavedSession } from './api';
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
  '/': 'Security Dashboard',
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
  const [loginOpen, setLoginOpen] = useState(false);

  useEffect(() => {
    const onUnauth = () => {
      setSession(null);
    };
    window.addEventListener('trustguard:unauthorized', onUnauth);
    return () => window.removeEventListener('trustguard:unauthorized', onUnauth);
  }, []);

  if (!session) {
    return (
      <LoginModal
        standalone
        open
        onAuthenticated={(newSession) => setSession(newSession)}
      />
    );
  }

  const title = PAGE_TITLES[location.pathname] || 'TrustGuard';

  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main-column">
        <Navbar
          title={title}
          session={session}
          onOpenLogin={() => setLoginOpen(true)}
          onLogout={() => {
            clearSession();
            setSession(null);
          }}
        />
        <main className="page-content">
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
