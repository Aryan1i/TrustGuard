import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import ConfirmModal from '../components/ConfirmModal';
import LoadingState from '../components/LoadingState';

export default function Devices({ session }) {
  const [devices, setDevices] = useState([]);
  const [users, setUsers] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [ownerUsername, setOwnerUsername] = useState('alice');
  const [deviceName, setDeviceName] = useState('');
  const [replacesDeviceId, setReplacesDeviceId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revokeReason, setRevokeReason] = useState('Lost device scenario');

  const loadAll = async () => {
    setLoading(true);
    setError('');
    try {
      const [d, u, n] = await Promise.all([api.getDevices(), api.getUsers(), api.getNodes()]);
      setDevices(d);
      setUsers(u);
      setNodes(n);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
  }, []);

  const handleEnrol = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    setNotice('');
    try {
      const payload = {
        ownerUsername: session?.role === 'ADMIN' ? ownerUsername : session?.username,
        deviceName,
        replacesDeviceId: replacesDeviceId ? Number(replacesDeviceId) : null,
      };
      const created = await api.enrolDevice(payload);
      setNotice(`Enrolled replacement/new device ${created.deviceUid} for ${created.ownerUsername}`);
      setDeviceName('');
      setReplacesDeviceId('');
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const confirmRevoke = async () => {
    if (!revokeTarget) return;
    setSubmitting(true);
    setError('');
    setNotice('');
    try {
      const res = await api.revokeDevice(revokeTarget.id, revokeReason);
      setNotice(
        `Revoked ${res.device.deviceUid} (revocation v${res.revocationVersion}). ` +
          `Propagated to ${res.nodesEnforced}/${res.totalNodes} simulated nodes in ${res.propagationLatencyMs} ms. ` +
          `Other users' permissions preserved.`
      );
      setRevokeTarget(null);
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && devices.length === 0) return <LoadingState />;

  return (
    <div>
      {error && <div className="banner banner-danger">{error}</div>}
      {notice && <div className="banner banner-success">{notice}</div>}

      <div className="grid grid-2 section-gap">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Enroll / Replace Device</h2>
              <p className="card-subtitle">Generates ML-KEM-768 + ML-DSA-65 device keys (private keys kept outside DB).</p>
            </div>
          </div>
          <form onSubmit={handleEnrol}>
            <div className="form-grid" style={{ marginBottom: '12px' }}>
              <div className="field">
                <label>Owner (Synthetic User)</label>
                <select
                  value={session?.role === 'ADMIN' ? ownerUsername : session?.username || 'alice'}
                  disabled={session?.role !== 'ADMIN'}
                  onChange={(e) => setOwnerUsername(e.target.value)}
                >
                  {users.map((u) => (
                    <option key={u.username} value={u.username}>
                      {u.username} ({u.role})
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label>Device Name</label>
                <input
                  value={deviceName}
                  onChange={(e) => setDeviceName(e.target.value)}
                  placeholder="e.g., Alice Replacement Laptop"
                  required
                />
              </div>
              <div className="field">
                <label>Replaces Revoked Device (Optional)</label>
                <select value={replacesDeviceId} onChange={(e) => setReplacesDeviceId(e.target.value)}>
                  <option value="">None (New enrollment)</option>
                  {devices
                    .filter((d) => d.status === 'REVOKED')
                    .map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.deviceUid} ({d.ownerUsername})
                      </option>
                    ))}
                </select>
              </div>
            </div>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? 'Generating PQC Keys...' : 'Enroll Device'}
            </button>
          </form>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Simulated Node Revocation Enforcement</h2>
              <p className="card-subtitle">All nodes enforce current revocation version on every access check.</p>
            </div>
          </div>
          <DataTable
            rowKey={(n) => n.nodeCode}
            rows={nodes}
            columns={[
              { key: 'nodeCode', header: 'Node', render: (n) => <span className="mono">{n.nodeCode}</span> },
              { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
              { key: 'currentRevocationVersion', header: 'Revocation Ver', render: (n) => `v${n.currentRevocationVersion}` },
              {
                key: 'lastPropagationMs',
                header: 'Propagation',
                render: (n) => (n.lastPropagationMs != null ? `${n.lastPropagationMs} ms` : '—'),
              },
            ]}
          />
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <h2 className="card-title">Registered Devices ({devices.length})</h2>
          <button type="button" className="btn btn-secondary btn-sm" onClick={loadAll}>
            Refresh
          </button>
        </div>
        <DataTable
          rowKey={(d) => d.id}
          rows={devices}
          columns={[
            { key: 'ownerUsername', header: 'Owner', render: (d) => <strong>{d.ownerUsername}</strong> },
            { key: 'deviceUid', header: 'Device ID', render: (d) => <span className="mono">{d.deviceUid}</span> },
            { key: 'deviceName', header: 'Device Name' },
            {
              key: 'publicKeyFingerprint',
              header: 'ML-KEM-768 Fingerprint',
              render: (d) => <span className="mono">{d.publicKeyFingerprint?.slice(0, 16)}…</span>,
            },
            {
              key: 'enrolledAt',
              header: 'Enrolled',
              render: (d) => <span className="mono">{new Date(d.enrolledAt).toISOString()}</span>,
            },
            {
              key: 'lastSeenAt',
              header: 'Last Seen',
              render: (d) => <span className="mono">{new Date(d.lastSeenAt).toISOString()}</span>,
            },
            { key: 'status', header: 'Status', render: (d) => <StatusBadge status={d.status} /> },
            {
              key: 'actions',
              header: 'Actions',
              render: (d) =>
                d.status === 'ACTIVE' ? (
                  <button
                    type="button"
                    className="btn btn-danger btn-sm"
                    onClick={() => setRevokeTarget(d)}
                  >
                    Revoke
                  </button>
                ) : (
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {d.replacedByDeviceId ? `Replaced (#${d.replacedByDeviceId})` : 'Revoked'}
                  </span>
                ),
            },
          ]}
        />
      </div>

      <ConfirmModal
        open={Boolean(revokeTarget)}
        title={`Revoke Device ${revokeTarget?.deviceUid || ''}?`}
        message={`This will revoke ${revokeTarget?.ownerUsername}'s device across all 3 simulated nodes, increment revocation version, and preserve peer users' permissions.`}
        confirmLabel="Confirm Revocation"
        danger
        busy={submitting}
        onCancel={() => setRevokeTarget(null)}
        onConfirm={confirmRevoke}
      >
        <div className="field">
          <label>Revocation Reason</label>
          <input value={revokeReason} onChange={(e) => setRevokeReason(e.target.value)} />
        </div>
      </ConfirmModal>
    </div>
  );
}
