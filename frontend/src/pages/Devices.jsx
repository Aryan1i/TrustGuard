import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import ConfirmModal from '../components/ConfirmModal';
import LoadingState from '../components/LoadingState';

export default function Devices({ session }) {
  const [devices, setDevices] = useState([]);
  const [users, setUsers] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [statusTab, setStatusTab] = useState('ALL');
  const [showEnrolForm, setShowEnrolForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const [ownerUsername, setOwnerUsername] = useState('alice');
  const [deviceName, setDeviceName] = useState('');
  const [replacesDeviceId, setReplacesDeviceId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const [revokeTarget, setRevokeTarget] = useState(null);
  const [revokeReason, setRevokeReason] = useState('Lost or compromised device');

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
      setNotice(`Enrolled device ${created.deviceUid} for ${created.ownerUsername}`);
      setDeviceName('');
      setReplacesDeviceId('');
      setShowEnrolForm(false);
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
          `Propagated across ${res.nodesEnforced}/${res.totalNodes} nodes in ${res.propagationLatencyMs} ms.`
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

  const activeCount = devices.filter((d) => d.status === 'ACTIVE').length;
  const revokedCount = devices.filter((d) => d.status === 'REVOKED').length;
  const onlineNodes = nodes.filter((n) => n.status === 'ONLINE').length;

  const visibleDevices = devices.filter((d) => {
    if (statusTab === 'ACTIVE') return d.status === 'ACTIVE';
    if (statusTab === 'REVOKED') return d.status === 'REVOKED';
    return true;
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Device List</h2>
        <div className="flex-row">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => setShowEnrolForm((v) => !v)}
          >
            {showEnrolForm ? 'Close Form' : '+ Enrol Device'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={loadAll}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}
      {notice && <div className="banner banner-success">{notice}</div>}

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Total Devices"
          value={devices.length}
          delta={`${users.length} owners`}
          deltaTone="up"
          meta="Registered identities"
        />
        <StatCard
          label="Active Devices"
          value={activeCount}
          delta={devices.length ? `${Math.round((activeCount / devices.length) * 100)}%` : '0%'}
          deltaTone="up"
          meta="Authorized for access"
        />
        <StatCard
          label="Revoked Devices"
          value={revokedCount}
          delta={revokedCount > 0 ? 'Blocked' : '0 blocked'}
          deltaTone={revokedCount > 0 ? 'down' : 'neutral'}
          meta="Rejected on all nodes"
        />
        <StatCard
          label="Enforcing Nodes"
          value={`${onlineNodes} / ${nodes.length}`}
          delta="Synced"
          deltaTone="up"
          meta="Cluster revocation state"
        />
      </div>

      {showEnrolForm && (
        <div className="card section-gap">
          <div className="card-header">
            <div>
              <h2 className="card-title">Enroll / Replace Device</h2>
              <p className="card-subtitle">Creates a new device credential and public key fingerprint.</p>
            </div>
          </div>
          <form onSubmit={handleEnrol}>
            <div className="form-grid" style={{ marginBottom: '12px' }}>
              <div className="field">
                <label>Device Owner</label>
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
              {submitting ? 'Generating Keys...' : 'Enroll Device'}
            </button>
          </form>
        </div>
      )}

      <div className="card section-gap">
        <DataTable
          searchable
          searchPlaceholder="Search device report"
          activeTab={statusTab}
          onTabChange={setStatusTab}
          tabs={[
            { id: 'ALL', label: `All devices (${devices.length})` },
            { id: 'ACTIVE', label: `Active (${activeCount})` },
            { id: 'REVOKED', label: `Revoked (${revokedCount})` },
          ]}
          rowKey={(d) => d.id}
          rows={visibleDevices}
          columns={[
            { key: 'no', header: 'No.', render: (_, idx) => idx + 1 },
            { key: 'deviceUid', header: 'Device Id', render: (d) => <span className="mono">{d.deviceUid}</span> },
            { key: 'deviceName', header: 'Device', render: (d) => <strong>{d.deviceName}</strong> },
            { key: 'ownerUsername', header: 'Owner', render: (d) => d.ownerUsername },
            {
              key: 'publicKeyFingerprint',
              header: 'Key Fingerprint',
              render: (d) => <span className="mono">{d.publicKeyFingerprint?.slice(0, 12)}…</span>,
            },
            {
              key: 'enrolledAt',
              header: 'Enrolled',
              render: (d) => <span className="mono">{new Date(d.enrolledAt).toISOString().slice(0, 10)}</span>,
            },
            {
              key: 'trust',
              header: 'Trust',
              render: (d) => (
                <DotStatus
                  label={d.status === 'ACTIVE' ? 'Trusted' : 'Blocked'}
                  tone={d.status === 'ACTIVE' ? 'green' : 'red'}
                />
              ),
            },
            {
              key: 'status',
              header: 'Status',
              render: (d) => <StatusBadge status={d.status === 'ACTIVE' ? 'Active' : 'Revoked'} variant={d.status === 'ACTIVE' ? 'success' : 'danger'} />,
            },
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

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Cluster Node Enforcement</h2>
            <p className="card-subtitle">Revocation versions enforced per node.</p>
          </div>
        </div>
        <DataTable
          rowKey={(n) => n.nodeCode}
          rows={nodes}
          columns={[
            { key: 'nodeCode', header: 'Node', render: (n) => <span className="mono">{n.nodeCode}</span> },
            { key: 'nodeName', header: 'Node Name' },
            { key: 'currentRevocationVersion', header: 'Revocation Ver', render: (n) => `v${n.currentRevocationVersion}` },
            {
              key: 'lastPropagationMs',
              header: 'Propagation',
              render: (n) => (n.lastPropagationMs != null ? `${n.lastPropagationMs} ms` : '—'),
            },
            { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
          ]}
        />
      </div>

      <ConfirmModal
        open={Boolean(revokeTarget)}
        title={`Revoke Device ${revokeTarget?.deviceUid || ''}?`}
        message={`This revokes ${revokeTarget?.ownerUsername}'s device across all policy nodes while keeping other users' devices active.`}
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
