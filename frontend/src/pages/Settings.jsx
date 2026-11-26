import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';

export default function Settings({ session, onOpenLogin }) {
  const [users, setUsers] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [userTab, setUserTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const isAdmin = session?.role === 'ADMIN';

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [u, n] = await Promise.all([
        api.getUsers(),
        isAdmin ? api.getNodes() : Promise.resolve([]),
      ]);
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
  }, [isAdmin, session?.username]);

  if (loading && users.length === 0) return <LoadingState />;

  const activeUsers = users.filter((u) => u.active).length;
  const onlineNodes = nodes.filter((n) => n.status === 'ONLINE').length;
  const maxKeyVersion = nodes.reduce((max, n) => Math.max(max, Number(n.currentKeyVersion) || 1), 1);
  const maxRevVersion = nodes.reduce((max, n) => Math.max(max, Number(n.currentRevocationVersion) || 1), 1);

  const filteredUsers = users.filter((u) => {
    if (userTab === 'ADMIN') return u.role === 'ADMIN';
    if (userTab === 'USER') return u.role !== 'ADMIN';
    return true;
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Directory &amp; Cluster Settings</h2>
        <div className="flex-row">
          <button type="button" className="btn btn-primary" onClick={onOpenLogin}>
            Switch Account
          </button>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}

      <div className="grid grid-4 section-gap">
        <StatCard
          label="User Accounts"
          value={users.length}
          delta={`${activeUsers} active`}
          deltaTone="up"
          meta="Identity directory"
        />
        {isAdmin && (
          <>
            <StatCard
              label="Cluster Nodes"
              value={nodes.length}
              delta={`${onlineNodes} online`}
              deltaTone={onlineNodes === nodes.length ? 'up' : 'down'}
              meta="Distributed policy fleet"
            />
            <StatCard
              label="Active Key Version"
              value={`v${maxKeyVersion}`}
              delta="Quorum enforced"
              deltaTone="up"
              meta="Cluster encryption key"
            />
            <StatCard
              label="Revocation Epoch"
              value={`v${maxRevVersion}`}
              delta="Monotonic state"
              deltaTone="neutral"
              meta="Cluster revocation version"
            />
          </>
        )}
      </div>

      <div className="grid grid-2 section-gap">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">User Accounts &amp; Roles</h2>
              <p className="card-subtitle">
                Signed in as <strong>{session?.username}</strong> ({session?.role})
              </p>
            </div>
          </div>
          <DataTable
            searchable
            searchPlaceholder="Search users..."
            activeTab={userTab}
            onTabChange={setUserTab}
            tabs={[
              { id: 'ALL', label: `All accounts (${users.length})` },
              { id: 'ADMIN', label: `Admins (${users.filter((u) => u.role === 'ADMIN').length})` },
              { id: 'USER', label: `Users (${users.filter((u) => u.role !== 'ADMIN').length})` },
            ]}
            rowKey={(u) => u.username}
            rows={filteredUsers}
            columns={[
              { key: 'username', header: 'Username', render: (u) => <span className="mono">{u.username}</span> },
              { key: 'displayName', header: 'Name' },
              { key: 'role', header: 'Role', render: (u) => <StatusBadge status={u.role} variant="info" /> },
              {
                key: 'active',
                header: 'Status',
                render: (u) => <DotStatus label={u.active ? 'Active' : 'Disabled'} tone={u.active ? 'green' : 'red'} />,
              },
            ]}
          />
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Security Policies</h2>
              <p className="card-subtitle">
                Active enforcement controls spanning identity, key lifecycle, messaging, and audit logs.
              </p>
            </div>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '13.5px', lineHeight: 1.75, color: 'var(--text-secondary)' }}>
            <li>
              <strong>Device Trust &amp; Revocation:</strong> Revoked devices are immediately blocked across all cluster nodes while unaffected peers retain access.
            </li>
            <li>
              <strong>Key Rotation Quorum:</strong> Rotated keys require acknowledgement from every active node prior to commit and enforce explicit retirement cutoffs.
            </li>
            <li>
              <strong>Protected Messaging:</strong> Messages bind intended recipient metadata, verify signatures and integrity before decryption, block duplicate IDs, and erase ephemeral keys on receipt.
            </li>
            <li>
              <strong>Audit &amp; Backup Integrity:</strong> Audit logs are hash-chained from genesis with mismatch detection, and snapshot restores verify cryptographic checksums first.
            </li>
          </ul>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Cluster Nodes ({nodes.length})</h2>
            <p className="card-subtitle">Key version and revocation synchronization status across all cluster nodes.</p>
          </div>
        </div>
        <DataTable
          searchable
          searchPlaceholder="Search nodes or regions..."
          rowKey={(n) => n.nodeCode}
          rows={nodes}
          columns={[
            { key: 'nodeCode', header: 'Node Code', render: (n) => <span className="mono">{n.nodeCode}</span> },
            { key: 'nodeName', header: 'Name' },
            { key: 'region', header: 'Region' },
            {
              key: 'currentKeyVersion',
              header: 'Key Version',
              render: (n) => <DotStatus label={`v${n.currentKeyVersion}`} tone="green" />,
            },
            {
              key: 'currentRevocationVersion',
              header: 'Revocation Ver',
              render: (n) => <DotStatus label={`v${n.currentRevocationVersion}`} tone="dark" />,
            },
            { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
          ]}
        />
      </div>
    </div>
  );
}
