import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import AlertCard from '../components/AlertCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function ThreatDetection() {
  const [evaluation, setEvaluation] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');

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
  const filteredAlerts = alerts.filter((a) => severityFilter === 'ALL' || a.severity === severityFilter);

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
          <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
            Showing {filteredAlerts.length} alert(s)
          </span>
        </div>

        {filteredAlerts.map((alert) => (
          <AlertCard key={alert.alertUid} alert={alert} />
        ))}
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
