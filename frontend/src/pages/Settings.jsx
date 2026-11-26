import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';

export default function Settings({ session, onOpenLogin }) {
  const [users, setUsers] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [u, n, m] = await Promise.all([api.getUsers(), api.getNodes(), api.getSecurityMetrics()]);
      setUsers(u);
      setNodes(n);
      setMetrics(m);
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
              <h2 className="card-title">Synthetic Identities & Auth Configuration</h2>
              <p className="card-subtitle">Active identity: {session?.username} ({session?.role})</p>
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
              { key: 'displayName', header: 'Display Name' },
              { key: 'role', header: 'Role', render: (u) => <StatusBadge status={u.role} variant="info" /> },
              { key: 'active', header: 'Status', render: (u) => <StatusBadge status={u.active ? 'ACTIVE' : 'DISABLED'} /> },
            ]}
          />
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Cryptographic & Architectural Boundaries</h2>
              <p className="card-subtitle">Honest scope and documented limitations for Track 4 review.</p>
            </div>
          </div>
          <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '13px', lineHeight: 1.65, color: 'var(--text-secondary)' }}>
            <li>
              <strong>Python Compatibility Adapter:</strong> Standalone <span className="mono">track4_service.py</span> +{' '}
              <span className="mono">pqcrypto==0.4.0</span> ML-KEM-768 + HMAC-SHA-256 proof, atomic <span className="mono">TRACK4_STATE_DIR</span> persistence.
            </li>
            <li>
              <strong>Backend Post-Quantum Crypto:</strong> BouncyCastle 1.80 ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), HKDF-SHA-256, AES-256-GCM.
            </li>
            <li>
              <strong>Private Key Storage:</strong> Device & key-version private keys stored in isolated <span className="mono">0600</span> keystore outside MySQL columns.
            </li>
            <li>
              <strong>Deterministic Threat Detection:</strong> Zero AI/ML; 22-event practice dataset caveat applies ({metrics?.sampleCaveat}).
            </li>
            <li>
              <strong>Audit Chain Limitation:</strong> Same-database SHA-256 hash chain detects partial/non-privileged row tampering, not full DB + checkpoint rewrites.
            </li>
          </ul>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Simulated Nodes Configuration ({nodes.length})</h2>
        </div>
        <DataTable
          rowKey={(n) => n.nodeCode}
          rows={nodes}
          columns={[
            { key: 'nodeCode', header: 'Node Code', render: (n) => <span className="mono">{n.nodeCode}</span> },
            { key: 'nodeName', header: 'Name' },
            { key: 'region', header: 'Simulated Region' },
            { key: 'currentKeyVersion', header: 'Key Version', render: (n) => `v${n.currentKeyVersion}` },
            { key: 'currentRevocationVersion', header: 'Revocation Ver', render: (n) => `v${n.currentRevocationVersion}` },
            { key: 'status', header: 'Status', render: (n) => <StatusBadge status={n.status} /> },
          ]}
        />
      </div>
    </div>
  );
}
