import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import ConfirmModal from '../components/ConfirmModal';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function Recovery({ session }) {
  const [backups, setBackups] = useState([]);
  const [activeTab, setActiveTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [restoreTarget, setRestoreTarget] = useState(null);

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.getBackups();
      setBackups(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleCreate = async () => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.createBackup();
      setNotice(res.message);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleVerify = async (b) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.verifyBackup(b.backupId);
      setNotice(`${res.backupId}: ${res.message}`);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleCorrupt = async (b) => {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.simulateBackupCorruption(b.backupId);
      setNotice(`${res.backupId}: ${res.message}`);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const confirmRestore = async () => {
    if (!restoreTarget) return;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const res = await api.restoreBackup(restoreTarget.backupId);
      setNotice(res.message);
      setRestoreTarget(null);
      await load();
    } catch (err) {
      setError(err.message);
      setRestoreTarget(null);
      await load();
    } finally {
      setBusy(false);
    }
  };

  if (loading && backups.length === 0) return <LoadingState />;

  const isAdmin = session?.role === 'ADMIN';
  const verifiedCount = backups.filter((b) => b.verificationStatus === 'VERIFIED').length;
  const corruptedCount = backups.filter((b) => b.verificationStatus === 'CORRUPTED').length;
  const restoredCount = backups.filter((b) => b.restoreStatus === 'RESTORED').length;

  const filtered = backups.filter((b) => {
    if (activeTab === 'VERIFIED') return b.verificationStatus === 'VERIFIED';
    if (activeTab === 'CORRUPTED') return b.verificationStatus === 'CORRUPTED';
    return true;
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Backup &amp; Recovery</h2>
        <div className="flex-row">
          <button type="button" className="btn btn-primary" disabled={!isAdmin || busy} onClick={handleCreate}>
            + Create Verified Backup
          </button>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {!isAdmin && (
        <div className="banner banner-warning">
          Signed in as {session?.username}. Creating, testing corruption on, and restoring backups require ADMIN privileges.
        </div>
      )}
      {error && <div className="banner banner-danger">{error}</div>}
      {notice && <div className="banner banner-info">{notice}</div>}

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Total Backups"
          value={backups.length}
          delta="Encrypted snapshots"
          deltaTone="neutral"
          meta="Stored recovery points"
        />
        <StatCard
          label="Verified"
          value={verifiedCount}
          delta="SHA-256 intact"
          deltaTone="up"
          meta="Passed integrity check"
        />
        <StatCard
          label="Corrupted"
          value={corruptedCount}
          delta={corruptedCount > 0 ? 'Restore blocked' : '0 tampered'}
          deltaTone={corruptedCount > 0 ? 'down' : 'up'}
          meta="Checksum mismatch"
        />
        <StatCard
          label="Restored"
          value={restoredCount}
          delta="Monotonic guard"
          deltaTone="up"
          meta="Revocations preserved"
        />
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Verified Snapshot Archive</h2>
            <p className="card-subtitle">
              SHA-256 checksums are verified before every restore; corrupted snapshots are rejected while committed key versions and revocations remain preserved.
            </p>
          </div>
        </div>

        <DataTable
          searchable
          searchPlaceholder="Search backup ID or checksum..."
          activeTab={activeTab}
          onTabChange={setActiveTab}
          tabs={[
            { id: 'ALL', label: `All backups (${backups.length})` },
            { id: 'VERIFIED', label: `Verified (${verifiedCount})` },
            { id: 'CORRUPTED', label: `Corrupted (${corruptedCount})` },
          ]}
          rowKey={(b) => b.backupId}
          rows={filtered}
          emptyTitle="No backups created yet"
          emptyMessage="Click '+ Create Verified Backup' to snapshot devices, revocations, and protected assets."
          columns={[
            { key: 'backupId', header: 'Backup ID', render: (b) => <span className="mono">{b.backupId}</span> },
            { key: 'keyVersionNumber', header: 'Key Ver', render: (b) => `v${b.keyVersionNumber}` },
            { key: 'revocationVersion', header: 'Revocation Ver', render: (b) => `v${b.revocationVersion}` },
            {
              key: 'checksumSha256',
              header: 'SHA-256 Checksum',
              render: (b) => <span className="mono">{b.checksumSha256?.slice(0, 16)}…</span>,
            },
            {
              key: 'createdAt',
              header: 'Created (UTC)',
              render: (b) => <span className="mono">{formatUtcIso(b.createdAt)}</span>,
            },
            {
              key: 'verificationStatus',
              header: 'Integrity',
              render: (b) => (
                <DotStatus
                  label={b.verificationStatus}
                  tone={b.verificationStatus === 'VERIFIED' ? 'green' : b.verificationStatus === 'CORRUPTED' ? 'red' : 'amber'}
                />
              ),
            },
            { key: 'restoreStatus', header: 'Restore Status', render: (b) => <StatusBadge status={b.restoreStatus} /> },
            {
              key: 'actions',
              header: 'Actions',
              render: (b) => (
                <div className="flex-row">
                  <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => handleVerify(b)}>
                    Verify
                  </button>
                  {isAdmin && (
                    <>
                      <button type="button" className="btn btn-danger btn-sm" disabled={busy} onClick={() => handleCorrupt(b)}>
                        Corrupt Test
                      </button>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        disabled={busy}
                        onClick={() => setRestoreTarget(b)}
                      >
                        Restore
                      </button>
                    </>
                  )}
                </div>
              ),
            },
          ]}
        />
      </div>

      <ConfirmModal
        open={Boolean(restoreTarget)}
        title={`Restore Backup ${restoreTarget?.backupId || ''}?`}
        message="TrustGuard verifies the SHA-256 checksum immediately before restoring. Corrupted backups will be rejected. Existing revocations and higher committed key versions are retained."
        confirmLabel="Verify & Restore"
        busy={busy}
        onCancel={() => setRestoreTarget(null)}
        onConfirm={confirmRestore}
      />
    </div>
  );
}
