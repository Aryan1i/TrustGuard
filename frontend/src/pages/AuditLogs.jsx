import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function AuditLogs({ session }) {
  const [entries, setEntries] = useState([]);
  const [verification, setVerification] = useState(null);
  const [actorFilter, setActorFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getAuditLogs();
      setEntries(res.entries || []);
      setVerification(res.latestVerification);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleVerify = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await api.verifyAuditChain();
      setVerification(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleSimulateTamper = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await api.simulateAuditTamper(1);
      setVerification(res);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleRevertTamper = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await api.revertAuditTamper();
      setVerification(res);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (loading && entries.length === 0) return <LoadingState />;

  const isAdmin = session?.role === 'ADMIN';
  const filtered = entries.filter(
    (e) =>
      !actorFilter ||
      e.actor.toLowerCase().includes(actorFilter.toLowerCase()) ||
      e.action.toLowerCase().includes(actorFilter.toLowerCase())
  );

  return (
    <div>
      {error && <div className="banner banner-danger">{error}</div>}

      {verification && (
        <div className={`banner ${verification.valid ? 'banner-success' : 'banner-danger'}`}>
          <div className="flex-row" style={{ justifyContent: 'space-between', marginBottom: '6px' }}>
            <div>
              <strong>{verification.valid ? 'Audit Hash Chain Verified' : 'Tamper Detected in Audit Hash Chain!'}</strong>{' '}
              — {verification.message}
            </div>
            <StatusBadge status={verification.valid ? 'VERIFIED' : 'CORRUPTED'} />
          </div>
          {!verification.valid && (
            <div className="mono" style={{ fontSize: '12px', marginBottom: '6px' }}>
              First mismatch: seq #{verification.firstMismatchSeq} ({verification.firstMismatchEventId}) · Expected:{' '}
              {verification.expectedHash?.slice(0, 16)}… · Actual: {verification.actualHash?.slice(0, 16)}…
            </div>
          )}
          <div style={{ fontSize: '12px', opacity: 0.9 }}>{verification.limitationNotice}</div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Append-Oriented SHA-256 Hash-Chained Audit Log ({filtered.length})</h2>
            <p className="card-subtitle">Canonical JSON serialization with server-enforced trusted actor identity.</p>
          </div>
          <div className="flex-row">
            <input
              placeholder="Filter actor or action..."
              value={actorFilter}
              onChange={(e) => setActorFilter(e.target.value)}
              style={{ padding: '6px 10px', borderRadius: '6px', border: '1px solid #cbd5e1', fontSize: '13px' }}
            />
            <button type="button" className="btn btn-primary" disabled={busy} onClick={handleVerify}>
              Verify Chain
            </button>
            {isAdmin && (
              <>
                <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={handleSimulateTamper}>
                  Simulate Row Tamper
                </button>
                <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={handleRevertTamper}>
                  Revert Tamper
                </button>
              </>
            )}
          </div>
        </div>

        <DataTable
          rowKey={(e) => e.eventId}
          rows={filtered}
          columns={[
            { key: 'seqNumber', header: 'Seq', render: (e) => <span className="mono">#{e.seqNumber}</span> },
            { key: 'eventId', header: 'Event ID', render: (e) => <span className="mono">{e.eventId}</span> },
            { key: 'actor', header: 'Trusted Actor', render: (e) => <span className="mono">{e.actor}</span> },
            { key: 'action', header: 'Action', render: (e) => <StatusBadge status={e.action} variant="info" /> },
            { key: 'resource', header: 'Resource', render: (e) => <span className="mono">{e.resource}</span> },
            { key: 'detail', header: 'Detail' },
            {
              key: 'prevHash',
              header: 'Prev Hash',
              render: (e) => <span className="mono">{e.prevHash?.slice(0, 12)}…</span>,
            },
            {
              key: 'currentHash',
              header: 'Current Hash',
              render: (e) => <span className="mono">{e.currentHash?.slice(0, 12)}…</span>,
            },
            {
              key: 'eventTimestampUtc',
              header: 'Timestamp (UTC)',
              render: (e) => <span className="mono">{formatUtcIso(e.eventTimestampUtc)}</span>,
            },
          ]}
        />
      </div>
    </div>
  );
}
