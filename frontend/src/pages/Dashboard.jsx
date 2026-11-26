import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import StatusBadge from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import MetricCard from '../components/MetricCard';
import LoadingState from '../components/LoadingState';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [viewMode, setViewMode] = useState('board'); // 'board' | 'table' | 'metrics'
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getDashboard();
      setData(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  if (loading && !data) return <LoadingState />;
  if (error) return <div className="banner banner-danger">{error}</div>;
  if (!data) return null;

  const totalAccess = (data.allowedAccessCount || 0) + (data.deniedAccessCount || 0);
  const allowPct = totalAccess > 0 ? Math.round((data.allowedAccessCount / totalAccess) * 100) : 100;
  const denyPct = totalAccess > 0 ? 100 - allowPct : 0;
  const m = data.metricsSummary || {};
  const sev = data.openAlertsBySeverity || {};

  return (
    <div>
      <div className="toolbar-row">
        <div className="view-switcher" role="tablist" aria-label="Dashboard View Switcher">
          <button
            type="button"
            className={`view-tab-btn${viewMode === 'board' ? ' active' : ''}`}
            onClick={() => setViewMode('board')}
          >
            Board
          </button>
          <button
            type="button"
            className={`view-tab-btn${viewMode === 'table' ? ' active' : ''}`}
            onClick={() => setViewMode('table')}
          >
            Audit Table
          </button>
          <button
            type="button"
            className={`view-tab-btn${viewMode === 'metrics' ? ' active' : ''}`}
            onClick={() => setViewMode('metrics')}
          >
            Metrics View
          </button>
        </div>

        <div className="flex-row">
          <Link to="/devices" className="btn btn-primary">
            + Enrol / Revoke Device
          </Link>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh Live Data
          </button>
        </div>
      </div>

      {viewMode === 'board' && (
        <div className="kanban-grid">
          {/* Column 1: Identity & Access */}
          <div className="kanban-col">
            <div className="kanban-col-header">
              <div className="kanban-col-title">
                <span className="col-dot" style={{ background: '#a855f7' }} />
                <span>IDENTITY & ACCESS</span>
                <span className="col-count">2</span>
              </div>
              <Link to="/devices" style={{ textDecoration: 'none', color: '#6b7280', fontWeight: 700 }}>+</Link>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="Identity" variant="lavender" />
                  <StatusBadge status={`${data.activeDevices} Active`} variant="success" />
                </div>
                <Link to="/devices" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">
                Users ({data.activeUsers}) & Enrolled Devices ({data.activeDevices} active, {data.revokedDevices} revoked)
              </div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Revocation Version: <strong className="mono">v{data.latestRevocationVersion}</strong>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Last-Node Propagation:{' '}
                  <strong>
                    {data.lastRevocationPropagationMs != null ? `${data.lastRevocationPropagationMs} ms` : 'Pending test'}
                  </strong>
                </div>
              </div>
              <div className="board-card-footer">
                <span>Users: alice, bob, charlie, admin</span>
                <Link to="/devices" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Manage →
                </Link>
              </div>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="Zero-Trust" variant="info" />
                  <StatusBadge status={`${totalAccess} Checks`} variant="neutral" />
                </div>
                <Link to="/access" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Access Allowed vs. Denied Policy Telemetry</div>
              <div className="board-preview">
                <div className="bar-track" style={{ marginBottom: '8px' }}>
                  <div className="bar-allow" style={{ width: `${allowPct}%` }} />
                  <div className="bar-deny" style={{ width: `${denyPct}%` }} />
                </div>
                <div className="flex-row" style={{ justifyContent: 'space-between', fontSize: '11.5px' }}>
                  <span style={{ color: 'var(--success-text)', fontWeight: 600 }}>Allow: {data.allowedAccessCount}</span>
                  <span style={{ color: 'var(--danger-text)', fontWeight: 600 }}>Deny: {data.deniedAccessCount}</span>
                </div>
              </div>
              <div className="board-card-footer">
                <span>Zero-disclosure on deny</span>
                <Link to="/access" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Simulate →
                </Link>
              </div>
            </div>
          </div>

          {/* Column 2: Key Lifecycle & Nodes */}
          <div className="kanban-col">
            <div className="kanban-col-header">
              <div className="kanban-col-title">
                <span className="col-dot" style={{ background: '#eab308' }} />
                <span>KEY LIFECYCLE & NODES</span>
                <span className="col-count">2</span>
              </div>
              <Link to="/keys" style={{ textDecoration: 'none', color: '#6b7280', fontWeight: 700 }}>+</Link>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status={`Key v${data.activeKeyVersion}`} variant="pink" />
                  <StatusBadge status={data.activeKeyStatus} />
                </div>
                <Link to="/keys" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Active Post-Quantum Key Version & Quorum Status</div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', fontWeight: 600, marginBottom: '6px' }}>{data.activeKeyAlgorithm}</div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Simulated Nodes Acknowledged: <strong>{data.acknowledgedNodes} / {data.totalNodes}</strong>
                </div>
              </div>
              <div className="board-card-footer">
                <span>Cutoff & grace enforced</span>
                <Link to="/keys" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Rotate →
                </Link>
              </div>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="E2EE Messaging" variant="lavender" />
                  <StatusBadge status="Forward Secrecy" variant="info" />
                </div>
                <Link to="/messaging" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Authenticated Encryption, Replay Guard & Session Suite</div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Ephemeral session key erasure, recipient AAD binding, and 7 repeatable delivery checks.
                </div>
              </div>
              <div className="board-card-footer">
                <span>ML-KEM-768 / WebCrypto</span>
                <Link to="/messaging" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Verify →
                </Link>
              </div>
            </div>
          </div>

          {/* Column 3: Threat Detection */}
          <div className="kanban-col">
            <div className="kanban-col-header">
              <div className="kanban-col-title">
                <span className="col-dot" style={{ background: '#f97316' }} />
                <span>THREAT DETECTION</span>
                <span className="col-count">{data.openAlertCount}</span>
              </div>
              <Link to="/threats" style={{ textDecoration: 'none', color: '#6b7280', fontWeight: 700 }}>+</Link>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="Deterministic Rules" variant="warning" />
                  <StatusBadge status="No AI/ML" variant="neutral" />
                </div>
                <Link to="/threats" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Open Alerts by Severity ({data.openAlertCount} total)</div>
              <div className="board-preview">
                <div className="flex-row" style={{ justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                  <span>CRITICAL / HIGH</span>
                  <strong>{(sev.CRITICAL || 0)} / {(sev.HIGH || 0)}</strong>
                </div>
                <div className="flex-row" style={{ justifyContent: 'space-between', fontSize: '12px', marginBottom: '4px' }}>
                  <span>MEDIUM / LOW</span>
                  <strong>{(sev.MEDIUM || 0)} / {(sev.LOW || 0)}</strong>
                </div>
                <div className="flex-row" style={{ justifyContent: 'space-between', fontSize: '12px' }}>
                  <span>INFO (Timing / Approved)</span>
                  <strong>{sev.INFO || 0}</strong>
                </div>
              </div>
              <div className="board-card-footer">
                <span>Distinguishes DENIED_ATTEMPT</span>
                <Link to="/threats" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Inspect →
                </Link>
              </div>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="22 Events" variant="info" />
                  <StatusBadge status={`F1 ${m.f1Score ?? 0}`} variant="success" />
                </div>
                <Link to="/threats" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Practice Dataset Evaluation (Post-Detection Only)</div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  Precision: <strong>{m.precision}</strong> · Recall: <strong>{m.recall}</strong> · FP/1k: <strong>{m.falseAlertsPer1000Benign}</strong>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  Sample n = {m.practiceSampleSize} synthetic events; labels excluded from detector logic.
                </div>
              </div>
              <div className="board-card-footer">
                <span>Median latency: {m.medianAlertLatencyMs} ms</span>
                <Link to="/threats" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Details →
                </Link>
              </div>
            </div>
          </div>

          {/* Column 4: Verified & Recovery */}
          <div className="kanban-col">
            <div className="kanban-col-header">
              <div className="kanban-col-title">
                <span className="col-dot" style={{ background: '#22c55e' }} />
                <span>VERIFIED & RECOVERY</span>
                <span className="col-count">2</span>
              </div>
              <Link to="/audit" style={{ textDecoration: 'none', color: '#6b7280', fontWeight: 700 }}>+</Link>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="SHA-256 Chain" variant="pink" />
                  <StatusBadge status={data.auditChainVerified ? 'VERIFIED' : 'CORRUPTED'} />
                </div>
                <Link to="/audit" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Tamper-Evident Security Audit Chain ({data.auditEntryCount} rows)</div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Verification Failures Recorded: <strong>{m.auditVerificationFailures ?? 0}</strong>
                </div>
                <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Canonical JSON + SHA-256 hash chain; identifies exact first mismatch sequence.
                </div>
              </div>
              <div className="board-card-footer">
                <span>Trusted principal enforced</span>
                <Link to="/audit" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Verify →
                </Link>
              </div>
            </div>

            <div className="board-card">
              <div className="flex-row" style={{ justifyContent: 'space-between' }}>
                <div className="flex-row">
                  <StatusBadge status="Backup & Restore" variant="success" />
                </div>
                <Link to="/recovery" style={{ textDecoration: 'none', color: '#9ca3af' }}>⋮</Link>
              </div>
              <div className="board-card-title">Cryptographic Snapshot & Crash Recovery</div>
              <div className="board-preview">
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  Verifies SHA-256 checksum prior to restore, rejects corrupted backups, and retains revocations & committed keys.
                </div>
              </div>
              <div className="board-card-footer">
                <span>Monotonic state retention</span>
                <Link to="/recovery" style={{ color: 'var(--primary)', fontWeight: 600, textDecoration: 'none' }}>
                  Backups →
                </Link>
              </div>
            </div>
          </div>
        </div>
      )}

      {viewMode === 'table' && (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent Security & Audit Events</h2>
          </div>
          <DataTable
            rowKey={(r) => r.eventId}
            rows={data.recentEvents || []}
            columns={[
              { key: 'seqNumber', header: 'Seq', render: (r) => <span className="mono">#{r.seqNumber}</span> },
              { key: 'actor', header: 'Actor', render: (r) => <span className="mono">{r.actor}</span> },
              { key: 'action', header: 'Action', render: (r) => <StatusBadge status={r.action} variant="info" /> },
              { key: 'resource', header: 'Resource', render: (r) => <span className="mono">{r.resource}</span> },
              { key: 'detail', header: 'Detail' },
              {
                key: 'timestampUtc',
                header: 'Timestamp (UTC)',
                render: (r) => <span className="mono">{new Date(r.timestampUtc).toISOString()}</span>,
              },
            ]}
          />
        </div>
      )}

      {viewMode === 'metrics' && (
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Measured Security Metrics</h2>
              <p className="card-subtitle">{m.sampleCaveat}</p>
            </div>
            <StatusBadge status="DETERMINISTIC RULES" variant="info" />
          </div>
          <div className="grid grid-4">
            <MetricCard
              title="Precision / Recall / F1"
              value={`${m.precision ?? 0} / ${m.recall ?? 0} / ${m.f1Score ?? 0}`}
              source={m.datasetSource || 'PRACTICE_22_EVENTS'}
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="Median Alert Latency"
              value={m.medianAlertLatencyMs ?? 0}
              unit="ms"
              source={m.datasetSource || 'PRACTICE_22_EVENTS'}
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="False Alerts / 1k Benign"
              value={m.falseAlertsPer1000Benign ?? 0}
              source={m.datasetSource || 'PRACTICE_22_EVENTS'}
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="Audit Verification Failures"
              value={m.auditVerificationFailures ?? 0}
              source="LIVE_AUDIT_CHAIN"
              sampleSize={data.auditEntryCount ?? 0}
            />
          </div>
        </div>
      )}
    </div>
  );
}
