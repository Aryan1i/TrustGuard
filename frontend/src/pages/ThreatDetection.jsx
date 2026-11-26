import React, { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { api } from '../api';
import StatCard from '../components/StatCard';
import AlertCard from '../components/AlertCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function ThreatDetection() {
  const location = useLocation();
  const urlQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search]);

  const [evaluation, setEvaluation] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [alertQuery, setAlertQuery] = useState(urlQuery);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    setAlertQuery(urlQuery);
  }, [urlQuery]);

  const runAndLoad = async () => {
    setRunning(true);
    setError('');
    try {
      const [ev, allAlerts] = await Promise.all([api.evaluateDetection(), api.getAlerts()]);
      setEvaluation(ev);
      setAlerts(allAlerts);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setRunning(false);
    }
  };

  useEffect(() => {
    runAndLoad();
  }, []);

  if (loading && !evaluation) return <LoadingState />;

  const metrics = evaluation?.postDetectionEvaluation;
  const qLower = alertQuery.trim().toLowerCase();
  const filteredAlerts = alerts.filter((a) => {
    const matchesSeverity = severityFilter === 'ALL' || a.severity === severityFilter;
    if (!matchesSeverity) return false;
    if (!qLower) return true;
    const hay = `${a.alertUid || ''} ${a.ruleName || ''} ${a.actor || ''} ${a.severity || ''} ${a.servicePath || ''} ${a.explanation || ''} ${a.eventIdsJson || ''}`.toLowerCase();
    return hay.includes(qLower);
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Threat Detection & Alerts</h2>
        <button type="button" className="btn btn-primary" disabled={running} onClick={runAndLoad}>
          {running ? 'Evaluating...' : 'Re-run Evaluation'}
        </button>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}

      {metrics && (
        <div className="grid grid-4 section-gap">
          <StatCard label="Events Evaluated" value={metrics.sampleSize} delta={`${metrics.exactLabelMatches} matched`} deltaTone="up" meta="Rule-based classifier" />
          <StatCard label="True Positives / FP" value={`${metrics.truePositives} / ${metrics.falsePositives}`} delta={`TN: ${metrics.trueNegatives}`} deltaTone="up" meta={`False negatives: ${metrics.falseNegatives}`} />
          <StatCard label="Precision / Recall" value={`${metrics.precision} / ${metrics.recall}`} delta={`F1 ${metrics.f1Score}`} deltaTone="up" meta="Alert quality" />
          <StatCard label="False Alerts / 1k" value={metrics.falseAlertsPer1000Benign} delta={`${alerts.length} alerts`} deltaTone="neutral" meta="Benign baseline rate" />
        </div>
      )}

      <div className="card section-gap">
        <div className="table-toolbar">
          <div className="mint-tabs" role="tablist">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
              <button
                key={sev}
                type="button"
                className={`mint-tab${severityFilter === sev ? ' active' : ''}`}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev}
              </button>
            ))}
          </div>
          <div className="flex-row">
            <div className="table-search">
              <input
                type="text"
                placeholder="Filter alerts..."
                value={alertQuery}
                onChange={(e) => setAlertQuery(e.target.value)}
              />
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            </div>
            <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
              {filteredAlerts.length} alert(s)
            </span>
          </div>
        </div>

        {filteredAlerts.length === 0 ? (
          <div className="empty-state">No alerts match the current severity or search filter.</div>
        ) : (
          filteredAlerts.map((alert) => (
            <AlertCard key={alert.alertUid} alert={alert} />
          ))
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Event Timeline & Clock Correction</h2>
            <p className="card-subtitle">Preserves raw source time, offset-corrected time, and collector receipt ordering.</p>
          </div>
        </div>
        <DataTable
          searchable
          searchPlaceholder="Search events..."
          rowKey={(r) => r.eventId}
          rows={evaluation?.classifiedEvents || []}
          columns={[
            { key: 'eventId', header: 'Event ID', render: (r) => <span className="mono">{r.eventId}</span> },
            { key: 'actor', header: 'Actor', render: (r) => <strong>{r.actor}</strong> },
            { key: 'edge', header: 'Service Edge', render: (r) => <span className="mono">{r.sourceService} → {r.targetService} ({r.action})</span> },
            { key: 'outcome', header: 'Outcome', render: (r) => <DotStatus label={r.outcome} tone={r.outcome === 'deny' ? 'red' : 'green'} /> },
            { key: 'rawEventTimeUtc', header: 'Raw Time', render: (r) => <span className="mono">{formatUtcIso(r.rawEventTimeUtc)}</span> },
            { key: 'sourceClockOffsetMs', header: 'Offset', render: (r) => `${r.sourceClockOffsetMs} ms` },
            { key: 'correctedEventTimeUtc', header: 'Corrected Time', render: (r) => <span className="mono">{formatUtcIso(r.correctedEventTimeUtc)}</span> },
            {
              key: 'outOfOrderArrival',
              header: 'Delivery',
              render: (r) => <StatusBadge status={r.outOfOrderArrival ? 'OUT_OF_ORDER' : 'IN_ORDER'} />,
            },
            { key: 'predictedLabel', header: 'Classification', render: (r) => <StatusBadge status={r.predictedLabel} /> },
            { key: 'explanation', header: 'Explanation' },
          ]}
        />
      </div>
    </div>
  );
}
