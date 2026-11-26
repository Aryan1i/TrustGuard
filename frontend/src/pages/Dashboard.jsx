import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import MetricCard from '../components/MetricCard';
import LoadingState from '../components/LoadingState';

export default function Dashboard() {
  const [data, setData] = useState(null);
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
  const allowPct = totalAccess > 0 ? Math.round((data.allowedAccessCount / totalAccess) * 100) : 50;
  const denyPct = totalAccess > 0 ? 100 - allowPct : 50;
  const m = data.metricsSummary || {};

  return (
    <div>
      <div className="flex-row section-gap" style={{ justifyContent: 'space-between' }}>
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
          Real-time post-quantum platform telemetry from Spring Boot + database.
        </div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={load}>
          Refresh Dashboard
        </button>
      </div>

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Active Users & Devices"
          value={`${data.activeUsers} / ${data.activeDevices}`}
          meta={`${data.revokedDevices} revoked device(s)`}
          badge={<StatusBadge status="ACTIVE" />}
        />
        <StatCard
          label="Active Key Version"
          value={`v${data.activeKeyVersion}`}
          meta={data.activeKeyAlgorithm}
          badge={<StatusBadge status={data.activeKeyStatus} />}
        />
        <StatCard
          label="Simulated Nodes & Acks"
          value={`${data.acknowledgedNodes} / ${data.totalNodes}`}
          meta="Nodes acknowledging latest key"
          badge={
            <StatusBadge
              status={data.acknowledgedNodes === data.totalNodes ? 'ACKNOWLEDGED' : 'PENDING'}
            />
          }
        />
        <StatCard
          label="Audit Hash Chain"
          value={data.auditChainVerified ? 'Verified' : 'Mismatch'}
          meta={`${data.auditEntryCount} chained event(s)`}
          badge={
            <StatusBadge
              status={data.auditChainVerified ? 'VERIFIED' : 'CORRUPTED'}
            />
          }
        />
      </div>

      <div className="grid grid-2 section-gap">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Open Alerts by Severity</h2>
              <p className="card-subtitle">Total open alerts: {data.openAlertCount}</p>
            </div>
            <StatusBadge status={data.openAlertCount > 0 ? 'NEEDS_REVIEW' : 'ONLINE'} />
          </div>
          <div className="flex-row" style={{ gap: '12px' }}>
            {Object.entries(data.openAlertsBySeverity || {}).map(([sev, count]) => (
              <div
                key={sev}
                style={{
                  flex: '1 1 80px',
                  padding: '10px',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  textAlign: 'center',
                }}
              >
                <StatusBadge status={sev} />
                <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '6px' }}>{count}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Access Allowed vs. Denied & Revocation Latency</h2>
              <p className="card-subtitle">
                Revocation v{data.latestRevocationVersion} · Last-node propagation:{' '}
                {data.lastRevocationPropagationMs != null
                  ? `${data.lastRevocationPropagationMs} ms`
                  : 'No revocation executed yet'}
              </p>
            </div>
          </div>

          <div className="bar-track" style={{ marginBottom: '10px' }}>
            <div className="bar-allow" style={{ width: `${allowPct}%` }} title={`Allowed: ${data.allowedAccessCount}`} />
            <div className="bar-deny" style={{ width: `${denyPct}%` }} title={`Denied: ${data.deniedAccessCount}`} />
          </div>
          <div className="flex-row" style={{ justifyContent: 'space-between', fontSize: '13px' }}>
            <span style={{ color: 'var(--success-text)', fontWeight: 600 }}>
              Allowed: {data.allowedAccessCount} ({totalAccess ? `${allowPct}%` : '0%'})
            </span>
            <span style={{ color: 'var(--danger-text)', fontWeight: 600 }}>
              Denied: {data.deniedAccessCount} ({totalAccess ? `${denyPct}%` : '0%'})
            </span>
          </div>
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Measured Threat Detection Metrics</h2>
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
    </div>
  );
}
