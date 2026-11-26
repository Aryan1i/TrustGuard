import React, { useEffect, useState } from 'react';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { api, clearSession, getSavedSession, resolveRuntimeMode } from './api';
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
  '/devices': 'Device Management',
  '/keys': 'Key Management',
  '/access': 'Access Monitor',
  '/threats': 'Threat Detection',
  '/audit': 'Audit Logs',
  '/messaging': 'Secure Messaging',
  '/recovery': 'Backup & Recovery',
  '/settings': 'Settings',
};

function AppShell() {
  const location = useLocation();
  const [session, setSession] = useState(() => getSavedSession());
  const [loginOpen, setLoginOpen] = useState(false);

  useEffect(() => {
    const onUnauth = () => setSession(null);
    window.addEventListener('trustguard:unauthorized', onUnauth);
    resolveRuntimeMode().then((mode) => {
      const saved = getSavedSession();
      if (saved) {
        const isStandaloneToken = saved.token?.startsWith('tg-standalone.');
        if ((mode === 'backend' && isStandaloneToken) || (mode === 'standalone' && !isStandaloneToken)) {
          clearSession();
          setSession(null);
        }
      }
    });
    return () => {
      window.removeEventListener('trustguard:unauthorized', onUnauth);
    };
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
  const handleLogout = async () => {
    try {
      await api.logout();
    } catch {
      // Ignore network/token errors while clearing local session state
    } finally {
      clearSession();
      setSession(null);
    }
  };

  return (
    <div className="app-shell">
      <Sidebar session={session} onOpenLogin={() => setLoginOpen(true)} onLogout={handleLogout} />
      <div className="main-column">
        <Navbar
          title={title}
          session={session}
          onOpenLogin={() => setLoginOpen(true)}
        />
        <main className="page-content">
          <Routes>
            <Route path="/" element={<Dashboard session={session} />} />
            <Route path="/devices" element={<Devices session={session} />} />
            <Route path="/keys" element={<KeyManagement session={session} />} />
            <Route path="/access" element={<AccessMonitor session={session} />} />
            <Route path="/threats" element={<ThreatDetection session={session} />} />
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
