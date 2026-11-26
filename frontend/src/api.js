import axios from 'axios';

const STORAGE_KEY = 'trustguard_auth_session';
const API_ORIGIN = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '');

const apiClient = axios.create({
  baseURL: API_ORIGIN ? `${API_ORIGIN}/api/v1` : '/api/v1',
  timeout: 15000,
  headers: {
    'Content-Type': 'application/json',
  },
});

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
    const message =
      data?.message ||
      error.message ||
      'Unexpected API communication failure';
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

export const api = {
  login: (username, password) =>
    apiClient.post('/auth/login', { username, password }).then((r) => r.data),
  me: () => apiClient.get('/auth/me').then((r) => r.data),
  getDashboard: () => apiClient.get('/dashboard').then((r) => r.data),
  getUsers: () => apiClient.get('/users').then((r) => r.data),
  getDevices: () => apiClient.get('/devices').then((r) => r.data),
  enrolDevice: (payload) => apiClient.post('/devices/enrol', payload).then((r) => r.data),
  revokeDevice: (id, reason) =>
    apiClient.post(`/devices/${id}/revoke`, { reason }).then((r) => r.data),
  getNodes: () => apiClient.get('/nodes').then((r) => r.data),
  toggleNodeFailure: (id, simulateAckFailure) =>
    apiClient.post(`/nodes/${id}/toggle-failure`, { simulateAckFailure }).then((r) => r.data),
  getKeys: () => apiClient.get('/keys').then((r) => r.data),
  getRotationStatus: () => apiClient.get('/keys/rotation-status').then((r) => r.data),
  prepareKey: (payload) => apiClient.post('/keys/prepare', payload).then((r) => r.data),
  acknowledgeKey: (id, nodeCode) =>
    apiClient.post(`/keys/${id}/acknowledge`, nodeCode ? { nodeCode } : {}).then((r) => r.data),
  commitKey: (id) => apiClient.post(`/keys/${id}/commit`).then((r) => r.data),
  getResources: () => apiClient.get('/resources').then((r) => r.data),
  checkAccess: (payload) => apiClient.post('/access/check', payload).then((r) => r.data),
  getAccessEvents: () => apiClient.get('/access/events').then((r) => r.data),
  getAuditLogs: () => apiClient.get('/audit').then((r) => r.data),
  verifyAuditChain: () => apiClient.post('/audit/verify').then((r) => r.data),
  simulateAuditTamper: (seqNumber) =>
    apiClient.post('/audit/simulate-tamper', seqNumber ? { seqNumber } : {}).then((r) => r.data),
  revertAuditTamper: () => apiClient.post('/audit/revert-tamper').then((r) => r.data),
  getAlerts: () => apiClient.get('/alerts').then((r) => r.data),
  evaluateDetection: () => apiClient.post('/detection/evaluate').then((r) => r.data),
  getSecurityMetrics: () => apiClient.get('/metrics/security').then((r) => r.data),
  getMessages: () => apiClient.get('/messages').then((r) => r.data),
  sendMessage: (payload) => apiClient.post('/messages', payload).then((r) => r.data),
  receiveMessage: (messageId, payload) =>
    apiClient.post(`/messages/${encodeURIComponent(messageId)}/receive`, payload || {}).then((r) => r.data),
  getBackups: () => apiClient.get('/backups').then((r) => r.data),
  createBackup: () => apiClient.post('/backups/create').then((r) => r.data),
  verifyBackup: (id) => apiClient.post(`/backups/${encodeURIComponent(id)}/verify`).then((r) => r.data),
  restoreBackup: (id) => apiClient.post(`/backups/${encodeURIComponent(id)}/restore`).then((r) => r.data),
  simulateBackupCorruption: (id) =>
    apiClient.post(`/backups/${encodeURIComponent(id)}/simulate-corruption`).then((r) => r.data),
  getSessions: () => apiClient.get('/sessions').then((r) => r.data),
  openSession: (peerDeviceId) =>
    apiClient.post('/sessions/open', peerDeviceId ? { peerDeviceId } : {}).then((r) => r.data),
  closeSession: (sessionId) =>
    apiClient.post(`/sessions/${encodeURIComponent(sessionId)}/close`).then((r) => r.data),
  resumeSession: (sessionId) =>
    apiClient.post(`/sessions/${encodeURIComponent(sessionId)}/resume`).then((r) => r.data),
  runSessionTests: () => apiClient.post('/sessions/run-tests').then((r) => r.data),
};
