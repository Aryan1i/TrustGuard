import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api';
import StatCard from '../components/StatCard';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import DataTable from '../components/DataTable';
import MetricCard from '../components/MetricCard';
import LoadingState from '../components/LoadingState';
import { formatUtc } from '../dateUtils';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [tab, setTab] = useState('activity');
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
  const recentRows = data.recentEvents || [];

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Security Overview</h2>
        <div className="flex-row">
          <Link to="/devices" className="btn btn-primary">
            + Enrol Device
          </Link>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Active Devices"
          value={data.activeDevices}
          delta={`${data.activeUsers} users`}
          deltaTone="up"
          meta={`${data.revokedDevices} revoked · Revocation v${data.latestRevocationVersion}`}
        />
        <StatCard
          label="Active Key Version"
          value={`v${data.activeKeyVersion}`}
          delta={`${data.acknowledgedNodes}/${data.totalNodes} nodes`}
          deltaTone={data.acknowledgedNodes === data.totalNodes ? 'up' : 'down'}
          meta={`${data.activeKeyStatus} · Quorum synchronized`}
        />
        <StatCard
          label="Open Alerts"
          value={data.openAlertCount}
          delta={`F1 ${m.f1Score ?? 0}`}
          deltaTone={data.openAlertCount > 0 ? 'neutral' : 'up'}
          meta={`Critical: ${sev.CRITICAL || 0} · High: ${sev.HIGH || 0} · Info: ${sev.INFO || 0}`}
        />
        <StatCard
          label="Audit Integrity"
          value={data.auditChainVerified ? 'Verified' : 'Mismatch'}
          delta={`${data.auditEntryCount} entries`}
          deltaTone={data.auditChainVerified ? 'up' : 'down'}
          meta={
            data.lastRevocationPropagationMs != null
              ? `Last revocation sync: ${data.lastRevocationPropagationMs} ms`
              : 'Hash chain healthy'
          }
        />
      </div>

      <div className="card section-gap">
        <div className="table-toolbar" style={{ marginBottom: '14px' }}>
          <div className="mint-tabs" role="tablist">
            <button
              type="button"
              className={`mint-tab${tab === 'activity' ? ' active' : ''}`}
              onClick={() => setTab('activity')}
            >
              Recent Activity ({recentRows.length})
            </button>
            <button
              type="button"
              className={`mint-tab${tab === 'access' ? ' active' : ''}`}
              onClick={() => setTab('access')}
            >
              Allowed vs Denied ({totalAccess})
            </button>
            <button
              type="button"
              className={`mint-tab${tab === 'metrics' ? ' active' : ''}`}
              onClick={() => setTab('metrics')}
            >
              Security Metrics
            </button>
          </div>
          <Link to="/audit" className="btn btn-secondary btn-sm">
            Verify Audit Chain
          </Link>
        </div>

        {tab === 'activity' && (
          <DataTable
            searchable
            searchPlaceholder="Search activity..."
            rowKey={(r) => r.eventId}
            rows={recentRows}
            columns={[
              { key: 'seqNumber', header: 'No.', render: (r) => <span className="mono">{r.seqNumber}</span> },
              { key: 'eventId', header: 'Event ID', render: (r) => <span className="mono">{r.eventId}</span> },
              { key: 'actor', header: 'Actor', render: (r) => <strong>{r.actor}</strong> },
              { key: 'resource', header: 'Target', render: (r) => <span className="mono">{r.resource}</span> },
              {
                key: 'timestampUtc',
                header: 'Date',
                render: (r) => <span className="mono">{formatUtc(r.timestampUtc || r.eventTimestampUtc)}</span>,
              },
              {
                key: 'detail',
                header: 'Verification',
                render: (r) => (
                  <DotStatus
                    label={String(r.action || '').includes('REJECT') || String(r.action || '').includes('DENY') || String(r.action || '').includes('FAIL') ? 'Blocked' : 'Recorded'}
                    tone={String(r.action || '').includes('REJECT') || String(r.action || '').includes('DENY') || String(r.action || '').includes('FAIL') ? 'red' : 'green'}
                  />
                ),
              },
              {
                key: 'action',
                header: 'Status',
                render: (r) => <StatusBadge status={r.action} variant={String(r.action).includes('REJECT') || String(r.action).includes('DENY') || String(r.action).includes('REVOKED') ? 'danger' : 'success'} />,
              },
            ]}
          />
        )}

        {tab === 'access' && (
          <div style={{ padding: '8px 4px' }}>
            <div className="flex-row" style={{ justifyContent: 'space-between', marginBottom: '10px' }}>
              <strong>Policy Decision Ratio</strong>
              <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {data.allowedAccessCount} allowed · {data.deniedAccessCount} denied
              </span>
            </div>
            <div className="bar-track" style={{ marginBottom: '12px' }}>
              <div className="bar-allow" style={{ width: `${allowPct}%` }} />
              <div className="bar-deny" style={{ width: `${denyPct}%` }} />
            </div>
            <div className="flex-row" style={{ justifyContent: 'space-between' }}>
              <DotStatus label={`Allowed (${allowPct}%)`} tone="green" />
              <DotStatus label={`Denied (${denyPct}%)`} tone="red" />
              <Link to="/access" className="btn btn-primary btn-sm">
                Open Access Simulator
              </Link>
            </div>
          </div>
        )}

        {tab === 'metrics' && (
          <div className="grid grid-4">
            <MetricCard
              title="Precision / Recall / F1"
              value={`${m.precision ?? 0} / ${m.recall ?? 0} / ${m.f1Score ?? 0}`}
              source="Alert Evaluation"
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="Median Alert Latency"
              value={m.medianAlertLatencyMs ?? 0}
              unit="ms"
              source="Alert Evaluation"
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="False Alerts / 1k Benign"
              value={m.falseAlertsPer1000Benign ?? 0}
              source="Alert Evaluation"
              sampleSize={m.practiceSampleSize ?? 0}
            />
            <MetricCard
              title="Audit Verification Failures"
              value={m.auditVerificationFailures ?? 0}
              source="Audit Chain"
              sampleSize={data.auditEntryCount ?? 0}
            />
          </div>
        )}
      </div>
    </div>
  );
}
