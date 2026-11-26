import React, { useEffect, useState } from 'react';
import { api } from '../api';
import AlertCard from '../components/AlertCard';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import MetricCard from '../components/MetricCard';
import LoadingState from '../components/LoadingState';

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
      {error && <div className="banner banner-danger">{error}</div>}

      <div className="banner banner-info">
        <strong>Deterministic Rules Only (No AI/ML):</strong> Detection processes <span className="mono">events.csv</span> and{' '}
        <span className="mono">approvals.json</span> without reading <span className="mono">labels.csv</span>. Ground-truth labels are
        applied strictly post-detection for evaluation.
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Practice Dataset Evaluation (22 Synthetic Events)</h2>
            <p className="card-subtitle">{evaluation?.limitationNotice}</p>
          </div>
          <button type="button" className="btn btn-primary" disabled={running} onClick={runAndLoad}>
            {running ? 'Running Rules...' : 'Re-run Deterministic Evaluation'}
          </button>
        </div>

        {metrics && (
          <div className="grid grid-4">
            <MetricCard
              title="Exact Label Matches"
              value={`${metrics.exactLabelMatches} / ${metrics.sampleSize}`}
              source={evaluation.datasetSource}
              sampleSize={metrics.sampleSize}
            />
            <MetricCard
              title="Confusion Matrix (TP / FP / TN / FN)"
              value={`${metrics.truePositives} / ${metrics.falsePositives} / ${metrics.trueNegatives} / ${metrics.falseNegatives}`}
              source="Post-detection labels.csv"
              sampleSize={metrics.sampleSize}
            />
            <MetricCard
              title="Precision / Recall / F1"
              value={`${metrics.precision} / ${metrics.recall} / ${metrics.f1Score}`}
              source={evaluation.datasetSource}
              sampleSize={metrics.sampleSize}
            />
            <MetricCard
              title="False Alerts / 1,000 Benign"
              value={metrics.falseAlertsPer1000Benign}
              source={evaluation.datasetSource}
              sampleSize={metrics.sampleSize}
              caveat="Functional demo sample only."
            />
          </div>
        )}
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Explainable Security Alerts ({filteredAlerts.length})</h2>
            <p className="card-subtitle">Distinguishes DENIED_ATTEMPT from CONFIRMED_VIOLATION and INFO timing findings.</p>
          </div>
          <div className="flex-row">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((sev) => (
              <button
                key={sev}
                type="button"
                className={`btn btn-sm ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {filteredAlerts.map((alert) => (
          <AlertCard key={alert.alertUid} alert={alert} />
        ))}
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">22-Event Timeline & Clock-Offset Preservation</h2>
            <p className="card-subtitle">Preserves raw source event time, corrected event time (offset subtracted), and receipt order.</p>
          </div>
        </div>
        <DataTable
          rowKey={(r) => r.eventId}
          rows={evaluation?.classifiedEvents || []}
          columns={[
            { key: 'eventId', header: 'Event ID', render: (r) => <span className="mono">{r.eventId}</span> },
            { key: 'actor', header: 'Actor', render: (r) => <span className="mono">{r.actor}</span> },
            { key: 'edge', header: 'Service Edge', render: (r) => <span className="mono">{r.sourceService} → {r.targetService} ({r.action})</span> },
            { key: 'outcome', header: 'Outcome', render: (r) => <StatusBadge status={r.outcome === 'deny' ? 'DENY' : 'ALLOW'} /> },
            { key: 'rawEventTimeUtc', header: 'Raw Event Time', render: (r) => <span className="mono">{new Date(r.rawEventTimeUtc).toISOString()}</span> },
            { key: 'sourceClockOffsetMs', header: 'Clock Offset', render: (r) => `${r.sourceClockOffsetMs} ms` },
            { key: 'correctedEventTimeUtc', header: 'Corrected Time', render: (r) => <span className="mono">{new Date(r.correctedEventTimeUtc).toISOString()}</span> },
            { key: 'deliveryDelayMs', header: 'Collector Delay', render: (r) => `${r.deliveryDelayMs} ms` },
            {
              key: 'outOfOrderArrival',
              header: 'Delivery Order',
              render: (r) =>
                r.outOfOrderArrival ? <StatusBadge status="OUT_OF_ORDER" variant="warning" /> : <StatusBadge status="IN_ORDER" variant="neutral" />,
            },
            { key: 'predictedLabel', header: 'Classification', render: (r) => <StatusBadge status={r.predictedLabel} variant="info" /> },
            { key: 'explanation', header: 'Deterministic Explanation' },
          ]}
        />
      </div>
    </div>
  );
}
