import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';

export default function Settings({ session, onOpenLogin }) {
  const [users, setUsers] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [u, n] = await Promise.all([api.getUsers(), api.getNodes()]);
      setUsers(u);
      setNodes(n);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  if (loading && users.length === 0) return <LoadingState />;

  return (
    <div>
      {error && <div className="banner banner-danger">{error}</div>}

      <div className="grid grid-2 section-gap">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">User Accounts & Roles</h2>
              <p className="card-subtitle">Signed in as {session?.username} ({session?.role})</p>
            </div>
            <button type="button" className="btn btn-primary btn-sm" onClick={onOpenLogin}>
              Switch User
            </button>
          </div>
          <DataTable
            rowKey={(u) => u.username}
            rows={users}
            columns={[
              { key: 'username', header: 'Username', render: (u) => <span className="mono">{u.username}</span> },
              { key: 'displayName', header: 'Name' },
              { key: 'role', header: 'Role', render: (u) => <StatusBadge status={u.role} variant="info" /> },
              { key: 'active', header: 'Status', render: (u) => <StatusBadge status={u.active ? 'ACTIVE' : 'DISABLED'} /> },
            ]}
          />
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Security Policies</h2>
              <p className="card-subtitle">Active controls enforced across identity, key rotation, messaging, and audit logs.</p>
            </div>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '13.5px', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
            <li>
              <strong>Device Trust & Revocation:</strong> Revoked devices are immediately blocked across all cluster policy nodes while unaffected peers retain access.
            </li>
            <li>
              <strong>Key Rotation Quorum:</strong> Rotated encryption keys require acknowledgement from every active node prior to commit and enforce explicit retirement cutoffs.
            </li>
            <li>
              <strong>Protected Messaging:</strong> Messages bind intended recipient metadata, verify signatures/integrity before decryption, block duplicate IDs, and erase ephemeral keys on receipt.
            </li>
            <li>
              <strong>Audit & Backup Integrity:</strong> Audit logs are hash-chained from genesis with mismatch detection, and snapshot restores verify cryptographic checksums first.
            </li>
          </ul>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Cluster Nodes ({nodes.length})</h2>
        </div>
        <DataTable
          rowKey={(n) => n.nodeCode}
          rows={nodes}
          columns={[
            { key: 'nodeCode', header: 'Node Code', render: (n) => <span className="mono">{n.nodeCode}</span> },
            { key: 'nodeName', header: 'Name' },
            { key: 'region', header: 'Region' },
            { key: 'currentKeyVersion', header: 'Key Version', render: (n) => `v${n.currentKeyVersion}` },
            { key: 'currentRevocationVersion', header: 'Revocation Ver', render: (n) => `v${n.currentRevocationVersion}` },
            { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
          ]}
        />
      </div>
    </div>
  );
}
