import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import Timeline from '../components/Timeline';
import ConfirmModal from '../components/ConfirmModal';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function KeyManagement({ session }) {
  const [statusData, setStatusData] = useState(null);
  const [activeTab, setActiveTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [gracePeriodSeconds, setGracePeriodSeconds] = useState(60);
  const [busy, setBusy] = useState(false);
  const [commitCandidate, setCommitCandidate] = useState(null);

  const load = async (clearError = true) => {
    setLoading(true);
    if (clearError) setError('');
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
      setNotice(`Prepared and distributed key v${res.versionNumber}. Collect all node acknowledgements before commit.`);
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
          ? `All cluster nodes acknowledged v${res.versionNumber}. Ready to commit.`
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
      await load(false);
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
  const committedCount = versions.filter((v) => v.status === 'COMMITTED').length;
  const retiredCount = versions.filter((v) => v.status === 'RETIRED').length;
  const filteredVersions = versions.filter((v) => activeTab === 'ALL' || v.status === activeTab);

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
        detail: `Grace window ends at ${formatUtcIso(v.cutoffTime)}; requests using v${v.versionNumber} at/after cutoff are rejected.`,
      });
    }
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Key Lifecycle</h2>
        <div className="flex-row">
          <label style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>
            Grace (sec):{' '}
            <input
              type="number"
              min="0"
              max="3600"
              value={gracePeriodSeconds}
              onChange={(e) => setGracePeriodSeconds(e.target.value)}
              style={{ width: '74px', padding: '6px 8px', borderRadius: '8px', border: '1px solid #d1d5db' }}
            />
          </label>
          <button type="button" className="btn btn-primary" disabled={!isAdmin || busy} onClick={handlePrepare}>
            + Prepare Key
          </button>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {!isAdmin && (
        <div className="banner banner-warning">
          Signed in as {session?.username}. Key preparation, fault simulation, and rotation commits require ADMIN privileges.
        </div>
      )}
      {error && <div className="banner banner-danger">{error}</div>}
      {notice && <div className="banner banner-success">{notice}</div>}

      <div className="grid grid-4 section-gap">
        <StatCard label="Active Key" value={`v${statusData?.activeVersion ?? 1}`} delta="COMMITTED" deltaTone="up" meta={statusData?.activeAlias} />
        <StatCard label="Total Versions" value={versions.length} delta={`${retiredCount} retired`} deltaTone="neutral" meta="Key version history" />
        <StatCard
          label="Node Quorum"
          value={`${statusData?.acknowledgedNodesOnLatest ?? 0} / ${nodes.length}`}
          delta={statusData?.acknowledgedNodesOnLatest === nodes.length ? 'Synced' : 'Pending'}
          deltaTone={statusData?.acknowledgedNodesOnLatest === nodes.length ? 'up' : 'down'}
          meta="Latest key acks"
        />
        <StatCard label="Grace Window" value={`${gracePeriodSeconds}s`} delta="Cutoff enforced" deltaTone="up" meta="Old-key retirement policy" />
      </div>

      <div className="card section-gap">
        <DataTable
          searchable
          searchPlaceholder="Search key versions..."
          activeTab={activeTab}
          onTabChange={setActiveTab}
          tabs={[
            { id: 'ALL', label: `All versions (${versions.length})` },
            { id: 'COMMITTED', label: `Committed (${committedCount})` },
            { id: 'RETIRED', label: `Retired (${retiredCount})` },
          ]}
          rowKey={(k) => k.id}
          rows={filteredVersions}
          columns={[
            { key: 'versionNumber', header: 'Version', render: (k) => <strong>v{k.versionNumber}</strong> },
            { key: 'keyAlias', header: 'Alias', render: (k) => <span className="mono">{k.keyAlias}</span> },
            { key: 'createdAt', header: 'Created', render: (k) => <span className="mono">{formatUtcIso(k.createdAt)}</span> },
            { key: 'activationTime', header: 'Activation', render: (k) => (k.activationTime ? <span className="mono">{formatUtcIso(k.activationTime)}</span> : '—') },
            { key: 'cutoffTime', header: 'Cutoff', render: (k) => (k.cutoffTime ? <span className="mono">{formatUtcIso(k.cutoffTime)}</span> : 'Active') },
            {
              key: 'acks',
              header: 'Node Acks',
              render: (k) => (
                <div className="flex-row">
                  {(k.acknowledgements || []).map((a) => (
                    <DotStatus
                      key={a.nodeCode}
                      label={`${a.nodeCode.replace('node-', '')}:${a.ackStatus}`}
                      tone={a.ackStatus === 'ACKNOWLEDGED' ? 'green' : a.ackStatus === 'FAILED' ? 'red' : 'amber'}
                    />
                  ))}
                </div>
              ),
            },
            { key: 'status', header: 'Status', render: (k) => <StatusBadge status={k.status} /> },
            {
              key: 'actions',
              header: 'Actions',
              render: (k) =>
                k.status === 'DISTRIBUTED' || k.status === 'ACKNOWLEDGED' ? (
                  <div className="flex-row">
                    <button type="button" className="btn btn-secondary btn-sm" disabled={!isAdmin || busy} onClick={() => handleAck(k.id)}>
                      Acknowledge
                    </button>
                    <button type="button" className="btn btn-primary btn-sm" disabled={!isAdmin || busy} onClick={() => setCommitCandidate(k)}>
                      Commit
                    </button>
                  </div>
                ) : (
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                    {k.failureReason || k.status}
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
              <h2 className="card-title">Cluster Nodes & Fault Testing</h2>
              <p className="card-subtitle">Toggle a node acknowledgement fault to verify quorum commit protection.</p>
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
                header: 'Fault Control',
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
        message="Commit activates the new key across all nodes and retires the previous committed key after its configured grace window. If any node has not acknowledged, the commit is blocked."
        confirmLabel="Commit Rotation"
        busy={busy}
        onCancel={() => setCommitCandidate(null)}
        onConfirm={handleCommit}
      />
    </div>
  );
}
