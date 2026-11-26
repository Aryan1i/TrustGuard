import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function AuditLogs({ session }) {
  const [entries, setEntries] = useState([]);
  const [verification, setVerification] = useState(null);
  const [activeTab, setActiveTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getAuditLogs();
      setEntries(res.entries || []);
      setVerification(res.latestVerification || null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [session?.username, session?.role]);

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
  const accessEntries = entries.filter((e) => /READ|ACCESS|MESSAGE/i.test(e.action || ''));
  const securityEntries = entries.filter((e) => !/READ|ACCESS|MESSAGE/i.test(e.action || ''));

  const filtered = entries.filter((e) => {
    if (activeTab === 'ACCESS') return /READ|ACCESS|MESSAGE/i.test(e.action || '');
    if (activeTab === 'SECURITY') return !/READ|ACCESS|MESSAGE/i.test(e.action || '');
    return true;
  });

  const uniqueActors = new Set(entries.map((e) => e.actor).filter(Boolean)).size;
  const mismatchCount = verification?.verificationFailuresCount ?? 0;

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Audit Ledger</h2>
        <div className="flex-row">
          {isAdmin && (
            <>
              <button type="button" className="btn btn-primary" disabled={busy} onClick={handleVerify}>
                Verify Chain
              </button>
              <button type="button" className="btn btn-danger" disabled={busy} onClick={handleSimulateTamper}>
                Simulate Row Tamper
              </button>
              <button type="button" className="btn btn-secondary" disabled={busy} onClick={handleRevertTamper}>
                Revert Tamper
              </button>
            </>
          )}
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}

      {verification && (
        <div className={`banner ${verification.valid ? 'banner-success' : 'banner-danger'}`}>
          <div className="flex-row" style={{ justifyContent: 'space-between', marginBottom: '6px' }}>
            <div>
              <strong>{verification.valid ? 'Audit Hash Chain Verified' : 'Tamper Detected in Audit Hash Chain'}</strong>{' '}
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
          {verification.limitationNotice && (
            <div style={{ fontSize: '12px', opacity: 0.9 }}>{verification.limitationNotice}</div>
          )}
        </div>
      )}

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Audit Entries"
          value={entries.length}
          delta="Hash-chained"
          deltaTone="up"
          meta="Canonical JSON log"
        />
        <StatCard
          label="Chain Integrity"
          value={verification ? (verification.valid ? 'VERIFIED' : 'CORRUPTED') : 'PENDING'}
          delta={verification ? `${verification.checkedEntries ?? entries.length} checked` : 'Not verified'}
          deltaTone={verification?.valid === false ? 'down' : 'up'}
          meta="SHA-256 link status"
        />
        <StatCard
          label="Hash Mismatches"
          value={mismatchCount}
          delta={verification?.valid === false ? `Seq #${verification.firstMismatchSeq}` : '0 breaks'}
          deltaTone={verification?.valid === false ? 'down' : 'up'}
          meta="Tamper checks"
        />
        <StatCard
          label="Unique Actors"
          value={uniqueActors}
          delta="Server verified"
          deltaTone="neutral"
          meta="Authenticated identities"
        />
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Tamper-Evident Security Audit Log</h2>
            <p className="card-subtitle">
              Chronological SHA-256 hash-linked event stream linking every entry from genesis.
            </p>
          </div>
        </div>

        <DataTable
          searchable
          searchPlaceholder="Search actor, action, resource, or detail..."
          activeTab={activeTab}
          onTabChange={setActiveTab}
          tabs={[
            { id: 'ALL', label: `All entries (${entries.length})` },
            { id: 'ACCESS', label: `Access & Messaging (${accessEntries.length})` },
            { id: 'SECURITY', label: `Keys & Identity (${securityEntries.length})` },
          ]}
          rowKey={(e) => e.eventId || String(e.seqNumber)}
          rows={filtered}
          emptyTitle="No audit entries found"
          emptyMessage="No audit records match the active filter."
          columns={[
            { key: 'seqNumber', header: 'Seq', render: (e) => <span className="mono">#{e.seqNumber}</span> },
            { key: 'eventId', header: 'Event ID', render: (e) => <span className="mono">{e.eventId}</span> },
            { key: 'actor', header: 'Actor', render: (e) => <DotStatus label={e.actor} tone="dark" /> },
            {
              key: 'action',
              header: 'Action',
              render: (e) => (
                <StatusBadge
                  status={e.action}
                  variant={
                    /DENY|REVOKE|TAMPER|CORRUPT|FAIL/i.test(e.action || '')
                      ? 'danger'
                      : /ALLOW|VERIFY|COMMIT|RESTORE/i.test(e.action || '')
                      ? 'success'
                      : 'info'
                  }
                />
              ),
            },
            { key: 'resource', header: 'Resource', render: (e) => <span className="mono">{e.resource}</span> },
            { key: 'detail', header: 'Detail' },
            {
              key: 'currentHash',
              header: 'Current Hash',
              render: (e) => <span className="mono">{e.currentHash ? `${e.currentHash.slice(0, 12)}…` : '—'}</span>,
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
