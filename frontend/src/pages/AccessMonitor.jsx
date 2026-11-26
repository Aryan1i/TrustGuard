import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function AccessMonitor({ session }) {
  const [events, setEvents] = useState([]);
  const [resources, setResources] = useState([]);
  const [devices, setDevices] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [decisionTab, setDecisionTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastResult, setLastResult] = useState(null);

  const [simulationMode, setSimulationMode] = useState(false);
  const [simulatedActor, setSimulatedActor] = useState('alice');
  const [deviceId, setDeviceId] = useState('');
  const [sourceService, setSourceService] = useState('portal');
  const [targetService, setTargetService] = useState('vault');
  const [resourceKey, setResourceKey] = useState('brief-alice');
  const [nodeCode, setNodeCode] = useState('node-alpha');
  const [requestedKeyVersion, setRequestedKeyVersion] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const isAdmin = session?.role === 'ADMIN';

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [ev, res, dev, nd] = await Promise.all([
        api.getAccessEvents(),
        api.getResources(),
        api.getDevices(),
        isAdmin ? api.getNodes() : Promise.resolve([]),
      ]);
      setEvents(ev);
      setResources(res);
      setDevices(dev);
      setNodes(nd);
      if (res.length > 0 && !res.some((r) => r.resourceKey === resourceKey)) {
        setResourceKey(res[0].resourceKey);
      }
      if (dev.length > 0 && deviceId && !dev.some((d) => String(d.id) === String(deviceId))) {
        setDeviceId('');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, [isAdmin, session?.username]);

  const runSimulation = async (overrides = {}) => {
    setSubmitting(true);
    setError('');
    try {
      const payload = {
        simulationMode: overrides.simulationMode ?? simulationMode,
        simulatedActor: (overrides.simulationMode ?? simulationMode) ? (overrides.simulatedActor ?? simulatedActor) : null,
        deviceId: (overrides.deviceId !== undefined ? overrides.deviceId : deviceId) ? Number(overrides.deviceId !== undefined ? overrides.deviceId : deviceId) : null,
        sourceService: overrides.sourceService ?? sourceService,
        targetService: overrides.targetService ?? targetService,
        resourceKey: overrides.resourceKey ?? resourceKey,
        action: 'read',
        nodeCode: overrides.nodeCode ?? nodeCode,
        requestedKeyVersion: requestedKeyVersion ? Number(requestedKeyVersion) : null,
      };
      const result = await api.checkAccess(payload);
      setLastResult(result);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && events.length === 0) return <LoadingState />;

  const revokedDev = devices.find((d) => d.status === 'REVOKED');
  const allowCount = events.filter((e) => e.decision === 'ALLOW').length;
  const denyCount = events.filter((e) => e.decision === 'DENY').length;
  const filteredEvents = events.filter((e) => decisionTab === 'ALL' || e.decision === decisionTab);

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Access Policy Monitor</h2>
        <div className="flex-row">
          <button type="button" className="btn btn-primary" disabled={submitting} onClick={() => runSimulation()}>
            {submitting ? 'Evaluating...' : 'Evaluate Access'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}

      <div className="grid grid-4 section-gap">
        <StatCard label="Access Checks" value={events.length} delta="Recorded" deltaTone="neutral" meta="Total policy evaluations" />
        <StatCard label="Allowed" value={allowCount} delta={events.length ? `${Math.round((allowCount / events.length) * 100)}%` : '0%'} deltaTone="up" meta="Verified owner & device" />
        <StatCard label="Denied" value={denyCount} delta="Zero disclosure" deltaTone={denyCount > 0 ? 'down' : 'neutral'} meta="Blocked unauthorized requests" />
        <StatCard label="Protected Assets" value={resources.length} delta={`${nodes.length} nodes`} deltaTone="up" meta="Policy-guarded resources" />
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Policy Simulator</h2>
            <p className="card-subtitle">
              Evaluate device trust, resource ownership, key validity, and service-level authorization policies.
            </p>
          </div>
          <div className="flex-row">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!isAdmin || submitting}
              onClick={() => {
                setSimulationMode(true);
                setSimulatedActor('alice');
                setDeviceId('');
                setSourceService('portal');
                setTargetService('vault');
                setResourceKey('brief-alice');
                runSimulation({ simulationMode: true, simulatedActor: 'alice', deviceId: '', sourceService: 'portal', targetService: 'vault', resourceKey: 'brief-alice' });
              }}
            >
              Test Correct Owner
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!isAdmin || submitting}
              onClick={() => {
                setSimulationMode(true);
                setSimulatedActor('alice');
                setDeviceId('');
                setSourceService('portal');
                setTargetService('vault');
                setResourceKey('ledger-bob');
                runSimulation({ simulationMode: true, simulatedActor: 'alice', deviceId: '', sourceService: 'portal', targetService: 'vault', resourceKey: 'ledger-bob' });
              }}
            >
              Test Wrong Owner
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!isAdmin || !revokedDev || submitting}
              onClick={() => {
                if (!revokedDev) return;
                setSimulationMode(true);
                setSimulatedActor(revokedDev.ownerUsername);
                setDeviceId(String(revokedDev.id));
                setSourceService('portal');
                setTargetService('catalog');
                setResourceKey('compliance-charlie');
                runSimulation({ simulationMode: true, simulatedActor: revokedDev.ownerUsername, deviceId: String(revokedDev.id), sourceService: 'portal', targetService: 'catalog', resourceKey: 'compliance-charlie' });
              }}
            >
              {revokedDev ? 'Test Revoked Device' : 'Revoke a Device First'}
            </button>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!isAdmin || submitting}
              onClick={() => {
                setSimulationMode(true);
                setSimulatedActor('alice');
                setDeviceId('');
                setSourceService('portal');
                setTargetService('billing');
                setResourceKey('brief-alice');
                runSimulation({ simulationMode: true, simulatedActor: 'alice', deviceId: '', sourceService: 'portal', targetService: 'billing', resourceKey: 'brief-alice' });
              }}
            >
              Test Unauthorized Service
            </button>
          </div>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            runSimulation();
          }}
        >
          <div className="form-grid" style={{ marginBottom: '12px' }}>
            <div className="field">
              <label>Identity Mode</label>
              <select
                value={simulationMode ? 'demo' : 'auth'}
                disabled={!isAdmin}
                onChange={(e) => setSimulationMode(e.target.value === 'demo')}
              >
                <option value="auth">Current User ({session?.username})</option>
                {isAdmin && <option value="demo">Simulate User (Admin)</option>}
              </select>
            </div>
            {simulationMode && isAdmin && (
              <div className="field">
                <label>Target Actor</label>
                <select value={simulatedActor} onChange={(e) => setSimulatedActor(e.target.value)}>
                  <option value="alice">alice</option>
                  <option value="bob">bob</option>
                  <option value="charlie">charlie</option>
                  <option value="admin">admin</option>
                </select>
              </div>
            )}
            <div className="field">
              <label>Device</label>
              <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
                <option value="">Auto-select active device</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.deviceUid} ({d.ownerUsername} · {d.status})
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Source Service</label>
              <select value={sourceService} onChange={(e) => setSourceService(e.target.value)}>
                <option value="portal">portal</option>
                <option value="admin-console">admin-console</option>
                <option value="reports">reports</option>
              </select>
            </div>
            <div className="field">
              <label>Target Service</label>
              <select value={targetService} onChange={(e) => setTargetService(e.target.value)}>
                <option value="vault">vault</option>
                <option value="catalog">catalog</option>
                <option value="identity">identity</option>
                <option value="billing">billing</option>
              </select>
            </div>
            <div className="field">
              <label>Resource</label>
              <select value={resourceKey} onChange={(e) => setResourceKey(e.target.value)}>
                {resources.map((r) => (
                  <option key={r.resourceKey} value={r.resourceKey}>
                    {r.resourceKey} (owner: {r.ownerUsername})
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Enforcement Node</label>
              <select value={nodeCode} onChange={(e) => setNodeCode(e.target.value)}>
                {(nodes.length > 0
                  ? nodes
                  : [{ nodeCode: 'node-alpha' }, { nodeCode: 'node-beta' }, { nodeCode: 'node-gamma' }]
                ).map((n) => (
                  <option key={n.nodeCode} value={n.nodeCode}>
                    {n.nodeCode}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Key Version (Optional)</label>
              <input
                type="number"
                min="1"
                value={requestedKeyVersion}
                onChange={(e) => setRequestedKeyVersion(e.target.value)}
                placeholder="Latest committed"
              />
            </div>
          </div>
        </form>

        {lastResult && (
          <div
            className={`banner ${lastResult.decision === 'ALLOW' ? 'banner-success' : 'banner-danger'}`}
            style={{ marginTop: '14px', marginBottom: 0 }}
          >
            <div className="flex-row" style={{ justifyContent: 'space-between' }}>
              <div>
                <strong>Decision: {lastResult.decision}</strong> · {lastResult.reason}
              </div>
              <span className="mono">{lastResult.requestId}</span>
            </div>
            <div style={{ marginTop: '6px', fontSize: '12.5px' }}>
              {lastResult.decision === 'ALLOW'
                ? `Protected Content: ${lastResult.body}`
                : 'Protected content withheld on denied access.'}
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <DataTable
          searchable
          searchPlaceholder="Search access events..."
          activeTab={decisionTab}
          onTabChange={setDecisionTab}
          tabs={[
            { id: 'ALL', label: `All decisions (${events.length})` },
            { id: 'ALLOW', label: `Allowed (${allowCount})` },
            { id: 'DENY', label: `Denied (${denyCount})` },
          ]}
          rowKey={(e) => e.requestId}
          rows={filteredEvents}
          columns={[
            { key: 'requestId', header: 'Request ID', render: (e) => <span className="mono">{e.requestId}</span> },
            { key: 'actor', header: 'Actor', render: (e) => <strong>{e.actor}</strong> },
            { key: 'deviceUid', header: 'Device', render: (e) => <span className="mono">{e.deviceUid}</span> },
            { key: 'path', header: 'Service Edge', render: (e) => <span className="mono">{e.sourceService} → {e.targetService}</span> },
            { key: 'resource', header: 'Resource', render: (e) => <span className="mono">{e.resource}</span> },
            { key: 'nodeCode', header: 'Node', render: (e) => <span className="mono">{e.nodeCode}</span> },
            {
              key: 'trust',
              header: 'Policy',
              render: (e) => <DotStatus label={e.decision === 'ALLOW' ? 'Permitted' : 'Blocked'} tone={e.decision === 'ALLOW' ? 'green' : 'red'} />,
            },
            { key: 'decision', header: 'Decision', render: (e) => <StatusBadge status={e.decision} /> },
            { key: 'reason', header: 'Reason' },
            { key: 'timestampUtc', header: 'Timestamp', render: (e) => <span className="mono">{formatUtcIso(e.timestampUtc)}</span> },
          ]}
        />
      </div>
    </div>
  );
}
