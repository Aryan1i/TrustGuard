import axios from 'axios';
import { standaloneEngine } from './standaloneEngine';

const STORAGE_KEY = 'trustguard_auth_session';
const API_ORIGIN = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

const apiClient = axios.create({
  baseURL: API_ORIGIN ? `${API_ORIGIN}/api/v1` : '/api/v1',
  timeout: 8000,
  headers: {
    'Content-Type': 'application/json',
  },
});

let detectedMode = null; // 'backend' | 'standalone'
let modeProbePromise = null;

function notifyMode(mode) {
  window.dispatchEvent(new CustomEvent('trustguard:mode', { detail: mode }));
}

export async function resolveRuntimeMode(force = false) {
  if (detectedMode && !force) return detectedMode;
  if (modeProbePromise && !force) return modeProbePromise;

  modeProbePromise = (async () => {
    try {
      const res = await apiClient.get('/health', { timeout: 3500 });
      if (
        res.status === 200 &&
        res.data &&
        typeof res.data === 'object' &&
        res.data.service === 'trustguard-backend'
      ) {
        detectedMode = 'backend';
        notifyMode('backend');
        return 'backend';
      }
    } catch {
      // Backend unreachable (e.g., static Vercel deployment without Spring Boot host)
    }
    detectedMode = 'standalone';
    notifyMode('standalone');
    return 'standalone';
  })();

  try {
    return await modeProbePromise;
  } finally {
    modeProbePromise = null;
  }
}

export function getRuntimeModeSync() {
  return detectedMode || 'checking';
}

export function getSavedSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function saveSession(session) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(STORAGE_KEY);
}

apiClient.interceptors.request.use((config) => {
  const session = getSavedSession();
  if (session?.token) {
    config.headers.Authorization = `Bearer ${session.token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    const data = error.response?.data;
    const message = data?.message || error.message || 'Unexpected API communication failure';
    if (status === 401 && !error.config?.url?.includes('/auth/login')) {
      clearSession();
      window.dispatchEvent(new CustomEvent('trustguard:unauthorized'));
    }
    const normalized = new Error(message);
    normalized.status = status;
    normalized.code = data?.code || 'API_ERROR';
    normalized.validationErrors = data?.validationErrors || null;
    return Promise.reject(normalized);
  }
);

async function dispatch(backendCall, standaloneCall) {
  const session = getSavedSession();
  if (session?.token?.startsWith('tg-standalone.')) {
    detectedMode = 'standalone';
    notifyMode('standalone');
    return standaloneCall(session);
  }
  const mode = await resolveRuntimeMode();
  if (mode === 'backend') {
    return backendCall();
  }
  return standaloneCall(session);
}

export const api = {
  login: async (username, password) => {
    const mode = await resolveRuntimeMode(true);
    if (mode === 'backend') {
      return apiClient.post('/auth/login', { username, password }).then((r) => r.data);
    }
    return standaloneEngine.login(username, password);
  },
  me: () => dispatch(() => apiClient.get('/auth/me').then((r) => r.data), (s) => standaloneEngine.me(s)),
  getDashboard: () => dispatch(() => apiClient.get('/dashboard').then((r) => r.data), (s) => standaloneEngine.getDashboard(s)),
  getUsers: () => dispatch(() => apiClient.get('/users').then((r) => r.data), (s) => standaloneEngine.getUsers(s)),
  getDevices: () => dispatch(() => apiClient.get('/devices').then((r) => r.data), (s) => standaloneEngine.getDevices(s)),
  enrolDevice: (payload) =>
    dispatch(() => apiClient.post('/devices/enrol', payload).then((r) => r.data), (s) => standaloneEngine.enrolDevice(s, payload)),
  revokeDevice: (id, reason) =>
    dispatch(() => apiClient.post(`/devices/${id}/revoke`, { reason }).then((r) => r.data), (s) => standaloneEngine.revokeDevice(s, id, reason)),
  getNodes: () => dispatch(() => apiClient.get('/nodes').then((r) => r.data), (s) => standaloneEngine.getNodes(s)),
  toggleNodeFailure: (id, simulateAckFailure) =>
    dispatch(
      () => apiClient.post(`/nodes/${id}/toggle-failure`, { simulateAckFailure }).then((r) => r.data),
      (s) => standaloneEngine.toggleNodeFailure(s, id, simulateAckFailure)
    ),
  getKeys: () => dispatch(() => apiClient.get('/keys').then((r) => r.data), (s) => standaloneEngine.getKeys(s)),
  getRotationStatus: () =>
    dispatch(() => apiClient.get('/keys/rotation-status').then((r) => r.data), (s) => standaloneEngine.getRotationStatus(s)),
  prepareKey: (payload) =>
    dispatch(() => apiClient.post('/keys/prepare', payload).then((r) => r.data), (s) => standaloneEngine.prepareKey(s, payload)),
  acknowledgeKey: (id, nodeCode) =>
    dispatch(
      () => apiClient.post(`/keys/${id}/acknowledge`, nodeCode ? { nodeCode } : {}).then((r) => r.data),
      (s) => standaloneEngine.acknowledgeKey(s, id, nodeCode)
    ),
  commitKey: (id) => dispatch(() => apiClient.post(`/keys/${id}/commit`).then((r) => r.data), (s) => standaloneEngine.commitKey(s, id)),
  getResources: () => dispatch(() => apiClient.get('/resources').then((r) => r.data), (s) => standaloneEngine.getResources(s)),
  checkAccess: (payload) =>
    dispatch(() => apiClient.post('/access/check', payload).then((r) => r.data), (s) => standaloneEngine.checkAccess(s, payload)),
  getAccessEvents: () =>
    dispatch(() => apiClient.get('/access/events').then((r) => r.data), (s) => standaloneEngine.getAccessEvents(s)),
  getAuditLogs: () => dispatch(() => apiClient.get('/audit').then((r) => r.data), (s) => standaloneEngine.getAuditLogs(s)),
  verifyAuditChain: () =>
    dispatch(() => apiClient.post('/audit/verify').then((r) => r.data), (s) => standaloneEngine.verifyAuditChain(s)),
  simulateAuditTamper: (seqNumber) =>
    dispatch(
      () => apiClient.post('/audit/simulate-tamper', seqNumber ? { seqNumber } : {}).then((r) => r.data),
      (s) => standaloneEngine.simulateAuditTamper(s, seqNumber)
    ),
  revertAuditTamper: () =>
    dispatch(() => apiClient.post('/audit/revert-tamper').then((r) => r.data), (s) => standaloneEngine.revertAuditTamper(s)),
  getAlerts: () => dispatch(() => apiClient.get('/alerts').then((r) => r.data), (s) => standaloneEngine.getAlerts(s)),
  evaluateDetection: () =>
    dispatch(() => apiClient.post('/detection/evaluate').then((r) => r.data), (s) => standaloneEngine.evaluateDetection(s)),
  getSecurityMetrics: () =>
    dispatch(() => apiClient.get('/metrics/security').then((r) => r.data), (s) => standaloneEngine.getSecurityMetrics(s)),
  getMessages: () => dispatch(() => apiClient.get('/messages').then((r) => r.data), (s) => standaloneEngine.getMessages(s)),
  sendMessage: (payload) =>
    dispatch(() => apiClient.post('/messages', payload).then((r) => r.data), (s) => standaloneEngine.sendMessage(s, payload)),
  receiveMessage: (messageId, payload) =>
    dispatch(
      () => apiClient.post(`/messages/${encodeURIComponent(messageId)}/receive`, payload || {}).then((r) => r.data),
      (s) => standaloneEngine.receiveMessage(s, messageId, payload)
    ),
  getBackups: () => dispatch(() => apiClient.get('/backups').then((r) => r.data), (s) => standaloneEngine.getBackups(s)),
  createBackup: () => dispatch(() => apiClient.post('/backups/create').then((r) => r.data), (s) => standaloneEngine.createBackup(s)),
  verifyBackup: (id) =>
    dispatch(() => apiClient.post(`/backups/${encodeURIComponent(id)}/verify`).then((r) => r.data), (s) => standaloneEngine.verifyBackup(s, id)),
  restoreBackup: (id) =>
    dispatch(() => apiClient.post(`/backups/${encodeURIComponent(id)}/restore`).then((r) => r.data), (s) => standaloneEngine.restoreBackup(s, id)),
  simulateBackupCorruption: (id) =>
    dispatch(
      () => apiClient.post(`/backups/${encodeURIComponent(id)}/simulate-corruption`).then((r) => r.data),
      (s) => standaloneEngine.simulateBackupCorruption(s, id)
    ),
  getSessions: () => dispatch(() => apiClient.get('/sessions').then((r) => r.data), (s) => standaloneEngine.getSessions(s)),
  openSession: (peerDeviceId) =>
    dispatch(
      () => apiClient.post('/sessions/open', peerDeviceId ? { peerDeviceId } : {}).then((r) => r.data),
      (s) => standaloneEngine.openSession(s, peerDeviceId)
    ),
  closeSession: (sessionId) =>
    dispatch(
      () => apiClient.post(`/sessions/${encodeURIComponent(sessionId)}/close`).then((r) => r.data),
      (s) => standaloneEngine.closeSession(s, sessionId)
    ),
  resumeSession: (sessionId) =>
    dispatch(
      () => apiClient.post(`/sessions/${encodeURIComponent(sessionId)}/resume`).then((r) => r.data),
      (s) => standaloneEngine.resumeSession(s, sessionId)
    ),
  runSessionTests: () =>
    dispatch(() => apiClient.post('/sessions/run-tests').then((r) => r.data), (s) => standaloneEngine.runSessionTests(s)),
};
