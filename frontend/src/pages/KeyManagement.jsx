import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import Timeline from '../components/Timeline';
import ConfirmModal from '../components/ConfirmModal';
import LoadingState from '../components/LoadingState';

export default function KeyManagement({ session }) {
  const [statusData, setStatusData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [gracePeriodSeconds, setGracePeriodSeconds] = useState(60);
  const [busy, setBusy] = useState(false);
  const [commitCandidate, setCommitCandidate] = useState(null);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getRotationStatus();
      setStatusData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handlePrepare = async () => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.prepareKey({
        keyAlias: 'trustguard-data-key',
        gracePeriodSeconds: Number(gracePeriodSeconds),
      });
      setNotice(`Prepared and distributed key v${res.versionNumber} (${res.status}). Require node acknowledgements before commit.`);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleAck = async (keyId, nodeCode = null) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.acknowledgeKey(keyId, nodeCode);
      setNotice(
        res.status === 'ACKNOWLEDGED'
          ? `All simulated nodes acknowledged v${res.versionNumber}. Ready to commit.`
          : `Acknowledgement state updated for v${res.versionNumber}: ${res.failureReason || res.status}`
      );
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleCommit = async () => {
    if (!commitCandidate) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.commitKey(commitCandidate.id);
      setNotice(`Committed key v${res.versionNumber}. Previous key retired with explicit cutoff enforcement.`);
      setCommitCandidate(null);
      await load();
    } catch (err) {
      setError(err.message);
      setCommitCandidate(null);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const handleToggleNodeFailure = async (node) => {
    setBusy(true);
    setError('');
    try {
      await api.toggleNodeFailure(node.id, !node.simulateAckFailure);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (loading && !statusData) return <LoadingState />;

  const versions = statusData?.versions || [];
  const nodes = statusData?.nodes || [];
  const isAdmin = session?.role === 'ADMIN';

  const timelineItems = [];
  versions.forEach((v) => {
    if (v.createdAt) {
      timelineItems.push({
        title: `Key v${v.versionNumber} Prepared & Distributed`,
        status: 'DISTRIBUTED',
        timestamp: v.distributedAt || v.createdAt,
        detail: `Alias ${v.keyAlias} · Grace window ${v.gracePeriodSeconds}s · Fingerprint ${v.publicKeyFingerprint?.slice(0, 12)}`,
      });
    }
    if (v.committedAt) {
      timelineItems.push({
        title: `Key v${v.versionNumber} Committed & Activated`,
        status: 'COMMITTED',
        timestamp: v.committedAt,
        detail: `Active across all ${nodes.length} nodes`,
      });
    }
    if (v.cutoffTime) {
      timelineItems.push({
        title: `Key v${v.versionNumber} Retired / Cutoff Boundary`,
        status: 'RETIRED',
        timestamp: v.cutoffTime,
        detail: `Grace window ends at ${new Date(v.cutoffTime).toISOString()}; requests using v${v.versionNumber} at/after cutoff are rejected.`,
      });
    }
  });

  return (
    <div>
      {!isAdmin && (
        <div className="banner banner-warning">
          Signed in as {session?.username}. Key preparation, node failure simulation, and rotation commit require ADMIN privileges.
        </div>
      )}
      {error && <div className="banner banner-danger">{error}</div>}
      {notice && <div className="banner banner-success">{notice}</div>}

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Post-Quantum Key Rotation Control</h2>
            <p className="card-subtitle">
              Lifecycle: PREPARED → DISTRIBUTED → ACKNOWLEDGED → COMMITTED. Commit is blocked until all 3 nodes acknowledge.
            </p>
          </div>
          <div className="flex-row">
            <label style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
              Old-key grace (sec):{' '}
              <input
                type="number"
                min="0"
                max="3600"
                value={gracePeriodSeconds}
                onChange={(e) => setGracePeriodSeconds(e.target.value)}
                style={{ width: '76px', padding: '4px 8px', borderRadius: '4px', border: '1px solid #cbd5e1' }}
              />
            </label>
            <button type="button" className="btn btn-primary" disabled={!isAdmin || busy} onClick={handlePrepare}>
              Prepare & Distribute New Key
            </button>
          </div>
        </div>

        <DataTable
          rowKey={(k) => k.id}
          rows={versions}
          columns={[
            { key: 'keyAlias', header: 'Alias', render: (k) => <span className="mono">{k.keyAlias}</span> },
            { key: 'versionNumber', header: 'Version', render: (k) => <strong>v{k.versionNumber}</strong> },
            { key: 'algorithm', header: 'Algorithm' },
            { key: 'status', header: 'Status', render: (k) => <StatusBadge status={k.status} /> },
            {
              key: 'createdAt',
              header: 'Created',
              render: (k) => <span className="mono">{new Date(k.createdAt).toISOString()}</span>,
            },
            {
              key: 'activationTime',
              header: 'Activation Time',
              render: (k) => (k.activationTime ? <span className="mono">{new Date(k.activationTime).toISOString()}</span> : '—'),
            },
            {
              key: 'cutoffTime',
              header: 'Cutoff / Grace End',
              render: (k) => (k.cutoffTime ? <span className="mono">{new Date(k.cutoffTime).toISOString()}</span> : 'Active'),
            },
            {
              key: 'acks',
              header: 'Node Acks',
              render: (k) => (
                <div className="flex-row">
                  {(k.acknowledgements || []).map((a) => (
                    <StatusBadge key={a.nodeCode} status={`${a.nodeCode.replace('node-', '')}:${a.ackStatus}`} variant={a.ackStatus === 'ACKNOWLEDGED' ? 'success' : a.ackStatus === 'FAILED' ? 'danger' : 'warning'} />
                  ))}
                </div>
              ),
            },
            {
              key: 'actions',
              header: 'Actions',
              render: (k) =>
                k.status === 'DISTRIBUTED' || k.status === 'ACKNOWLEDGED' ? (
                  <div className="flex-row">
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      disabled={!isAdmin || busy}
                      onClick={() => handleAck(k.id)}
                    >
                      Acknowledge All
                    </button>
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      disabled={!isAdmin || busy}
                      onClick={() => setCommitCandidate(k)}
                    >
                      Commit Key
                    </button>
                  </div>
                ) : (
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {k.failureReason ? k.failureReason : k.status}
                  </span>
                ),
            },
          ]}
        />
      </div>

      <div className="grid grid-2">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Simulated Nodes & Failure Injection</h2>
              <p className="card-subtitle">Toggle a node to fail acknowledgements to verify commit blocking.</p>
            </div>
          </div>
          <DataTable
            rowKey={(n) => n.id}
            rows={nodes}
            columns={[
              { key: 'nodeCode', header: 'Node Code', render: (n) => <span className="mono">{n.nodeCode}</span> },
              { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
              { key: 'currentKeyVersion', header: 'Key Ver', render: (n) => `v${n.currentKeyVersion}` },
              {
                key: 'action',
                header: 'Simulation',
                render: (n) => (
                  <button
                    type="button"
                    className={`btn btn-sm ${n.simulateAckFailure ? 'btn-primary' : 'btn-danger'}`}
                    disabled={!isAdmin || busy}
                    onClick={() => handleToggleNodeFailure(n)}
                  >
                    {n.simulateAckFailure ? 'Recover Node' : 'Simulate Ack Failure'}
                  </button>
                ),
              },
            ]}
          />
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Rotation Timeline</h2>
          </div>
          <Timeline items={timelineItems} />
        </div>
      </div>

      <ConfirmModal
        open={Boolean(commitCandidate)}
        title={`Commit Key v${commitCandidate?.versionNumber || ''}?`}
        message="Commit will activate the new key across all nodes and retire the previous committed key after its configured grace window. If any node has not acknowledged, the commit will be rejected."
        confirmLabel="Commit Rotation"
        busy={busy}
        onCancel={() => setCommitCandidate(null)}
        onConfirm={handleCommit}
      />
    </div>
  );
}
