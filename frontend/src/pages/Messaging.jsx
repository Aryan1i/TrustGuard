import React, { useEffect, useState } from 'react';
import { api } from '../api';
import StatCard from '../components/StatCard';
import DataTable from '../components/DataTable';
import StatusBadge, { DotStatus } from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import { formatUtcIso } from '../dateUtils';

export default function Messaging({ session }) {
  const [messages, setMessages] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [suiteResults, setSuiteResults] = useState([]);
  const [users, setUsers] = useState([]);
  const [msgTab, setMsgTab] = useState('ALL');
  const [sessTab, setSessTab] = useState('ALL');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [deliveryResult, setDeliveryResult] = useState(null);

  const [recipientUsername, setRecipientUsername] = useState('bob');
  const [plaintext, setPlaintext] = useState('Secure device channel status verified.');
  const [tamperRecipient, setTamperRecipient] = useState(false);
  const [tamperCiphertext, setTamperCiphertext] = useState(false);

  const load = async (clearError = true) => {
    setLoading(true);
    if (clearError) setError('');
    try {
      const [msgs, sess, us, metrics] = await Promise.all([
        api.getMessages(),
        api.getSessions(),
        api.getUsers(),
        api.getSecurityMetrics(),
      ]);
      setMessages(msgs);
      setSessions(sess);
      setUsers(us);
      setSuiteResults(metrics.sessionAndDeliveryTests || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSend = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    setDeliveryResult(null);
    try {
      await api.sendMessage({
        recipientUsername,
        plaintext,
        simulateTamperedRecipient: tamperRecipient,
        simulateTamperedCiphertext: tamperCiphertext,
      });
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleReceive = async (msg) => {
    setBusy(true);
    setError('');
    try {
      const res = await api.receiveMessage(msg.messageId, {
        claimedRecipientUsername: session?.username,
      });
      setDeliveryResult(res);
      await load();
    } catch (err) {
      setDeliveryResult(null);
      setError(err.message);
      await load(false);
    } finally {
      setBusy(false);
    }
  };

  const handleRunSuite = async () => {
    setBusy(true);
    setError('');
    try {
      const res = await api.runSessionTests();
      setSuiteResults(res);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const handleOpenSession = async () => {
    setBusy(true);
    setError('');
    try {
      await api.openSession();
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  if (loading && messages.length === 0) return <LoadingState />;

  const deliveredCount = messages.filter((m) => m.status === 'DELIVERED').length;
  const pendingCount = messages.filter((m) => m.status !== 'DELIVERED').length;
  const erasedCount = messages.filter((m) => m.forwardSecrecyErased).length;
  const activeSessions = sessions.filter((s) => s.status === 'ACTIVE' || s.status === 'RESUMED');
  const closedSessions = sessions.filter((s) => s.status === 'CLOSED');
  const passedChecks = suiteResults.filter((r) => /PASS|VERIFIED|ACTIVE/i.test(r.status || '')).length;

  const filteredMessages = messages.filter((m) => {
    if (msgTab === 'DELIVERED') return m.status === 'DELIVERED';
    if (msgTab === 'PENDING') return m.status !== 'DELIVERED';
    return true;
  });

  const filteredSessions = sessions.filter((s) => {
    if (sessTab === 'ACTIVE') return s.status === 'ACTIVE' || s.status === 'RESUMED';
    if (sessTab === 'CLOSED') return s.status === 'CLOSED';
    return true;
  });

  return (
    <div>
      <div className="page-subheader">
        <h2 className="page-subheader-title">Secure Messaging</h2>
        <div className="flex-row">
          <button type="button" className="btn btn-primary" disabled={busy} onClick={handleRunSuite}>
            Run Delivery Checks
          </button>
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={handleOpenSession}>
            + Open Session
          </button>
          <button type="button" className="btn btn-secondary" onClick={load}>
            Refresh
          </button>
        </div>
      </div>

      {error && <div className="banner banner-danger">{error}</div>}
      {deliveryResult && (
        <div className="banner banner-success">
          <strong>Delivered &amp; Verified ({deliveryResult.messageId}):</strong> &ldquo;{deliveryResult.decryptedPlaintext}&rdquo; ·{' '}
          {deliveryResult.verificationOutcome} · Ephemeral key erased:{' '}
          <strong>{String(deliveryResult.forwardSecrecyErased)}</strong>
        </div>
      )}

      <div className="grid grid-4 section-gap">
        <StatCard
          label="Encrypted Messages"
          value={messages.length}
          delta={`${deliveredCount} delivered`}
          deltaTone="up"
          meta="Signed & encrypted ledger"
        />
        <StatCard
          label="Keys Erased"
          value={erasedCount}
          delta="Forward secrecy"
          deltaTone="up"
          meta="Ephemeral session keys"
        />
        <StatCard
          label="Active Sessions"
          value={activeSessions.length}
          delta={`of ${sessions.length} total`}
          deltaTone="neutral"
          meta="Peer device channels"
        />
        <StatCard
          label="Delivery Checks"
          value={`${passedChecks} / ${suiteResults.length}`}
          delta={suiteResults.length > 0 && passedChecks === suiteResults.length ? 'All passed' : 'Verification ready'}
          deltaTone={suiteResults.length > 0 && passedChecks < suiteResults.length ? 'down' : 'up'}
          meta="Replay & binding suite"
        />
      </div>

      <div className="grid grid-2 section-gap">
        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Send Encrypted Message</h2>
              <p className="card-subtitle">
                End-to-end encrypted device messaging with recipient binding and forward secrecy.
              </p>
            </div>
          </div>

          <form onSubmit={handleSend}>
            <div className="form-grid" style={{ marginBottom: '12px' }}>
              <div className="field">
                <label>Sender</label>
                <input value={session?.username || ''} disabled />
              </div>
              <div className="field">
                <label>Intended Recipient</label>
                <select value={recipientUsername} onChange={(e) => setRecipientUsername(e.target.value)}>
                  {users.map((u) => (
                    <option key={u.username} value={u.username}>
                      {u.username}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="field" style={{ marginBottom: '12px' }}>
              <label>Message Plaintext</label>
              <textarea rows="2" value={plaintext} onChange={(e) => setPlaintext(e.target.value)} required />
            </div>
            <div className="flex-row" style={{ marginBottom: '14px', fontSize: '12.5px' }}>
              <label className="flex-row">
                <input
                  type="checkbox"
                  checked={tamperRecipient}
                  onChange={(e) => setTamperRecipient(e.target.checked)}
                />
                Test Recipient Mismatch
              </label>
              <label className="flex-row">
                <input
                  type="checkbox"
                  checked={tamperCiphertext}
                  onChange={(e) => setTamperCiphertext(e.target.checked)}
                />
                Test Altered Ciphertext
              </label>
            </div>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? 'Encrypting...' : 'Send Protected Message'}
            </button>
          </form>
        </div>

        <div className="card">
          <div className="card-header">
            <div>
              <h2 className="card-title">Session &amp; Delivery Verification</h2>
              <p className="card-subtitle">
                Checks replay blocking, recipient binding, ephemeral key erasure, resumption, and reordering.
              </p>
            </div>
          </div>
          <DataTable
            rowKey={(r) => r.testName}
            rows={suiteResults}
            emptyTitle="Checks not run yet"
            emptyMessage="Click 'Run Delivery Checks' above to run the security delivery suite."
            columns={[
              { key: 'testName', header: 'Check', render: (r) => <strong>{r.testName}</strong> },
              { key: 'status', header: 'Result', render: (r) => <StatusBadge status={r.status} /> },
              { key: 'detail', header: 'Observed Outcome' },
            ]}
          />
        </div>
      </div>

      <div className="card section-gap">
        <div className="card-header">
          <div>
            <h2 className="card-title">Encrypted Message Ledger</h2>
            <p className="card-subtitle">All encrypted envelopes with delivery outcome and ephemeral key erasure state.</p>
          </div>
        </div>
        <DataTable
          searchable
          searchPlaceholder="Search messages..."
          activeTab={msgTab}
          onTabChange={setMsgTab}
          tabs={[
            { id: 'ALL', label: `All messages (${messages.length})` },
            { id: 'DELIVERED', label: `Delivered (${deliveredCount})` },
            { id: 'PENDING', label: `Pending (${pendingCount})` },
          ]}
          rowKey={(m) => m.messageId}
          rows={filteredMessages}
          emptyTitle="No messages found"
          emptyMessage="Send a protected message above to record a new envelope."
          columns={[
            { key: 'messageId', header: 'Message ID', render: (m) => <span className="mono">{m.messageId}</span> },
            { key: 'senderUsername', header: 'Sender', render: (m) => <strong>{m.senderUsername}</strong> },
            { key: 'recipientUsername', header: 'Recipient', render: (m) => <strong>{m.recipientUsername}</strong> },
            {
              key: 'forwardSecrecyErased',
              header: 'Key Erased',
              render: (m) => (
                <DotStatus
                  label={m.forwardSecrecyErased ? 'Erased' : 'Retained'}
                  tone={m.forwardSecrecyErased ? 'green' : 'amber'}
                />
              ),
            },
            { key: 'status', header: 'Status', render: (m) => <StatusBadge status={m.status} /> },
            { key: 'verificationOutcome', header: 'Verification', render: (m) => <span className="mono">{m.verificationOutcome}</span> },
            {
              key: 'createdAt',
              header: 'Created (UTC)',
              render: (m) => <span className="mono">{formatUtcIso(m.createdAt)}</span>,
            },
            {
              key: 'actions',
              header: 'Actions',
              render: (m) => (
                <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => handleReceive(m)}>
                  {m.status === 'DELIVERED' ? 'Test Replay' : 'Receive & Verify'}
                </button>
              ),
            },
          ]}
        />
      </div>

      <div className="card">
        <div className="card-header">
          <div>
            <h2 className="card-title">Encrypted Transport Sessions</h2>
            <p className="card-subtitle">Active and resumable device channels tracked by session identity.</p>
          </div>
        </div>
        <DataTable
          searchable
          searchPlaceholder="Search sessions..."
          activeTab={sessTab}
          onTabChange={setSessTab}
          tabs={[
            { id: 'ALL', label: `All sessions (${sessions.length})` },
            { id: 'ACTIVE', label: `Active (${activeSessions.length})` },
            { id: 'CLOSED', label: `Closed (${closedSessions.length})` },
          ]}
          rowKey={(s) => s.sessionId}
          rows={filteredSessions}
          emptyTitle="No sessions found"
          emptyMessage="Click 'Open Session' to start a protected session."
          columns={[
            { key: 'sessionId', header: 'Session ID', render: (s) => <span className="mono">{s.sessionId}</span> },
            { key: 'actorUsername', header: 'Actor', render: (s) => <strong>{s.actorUsername}</strong> },
            { key: 'deviceUid', header: 'Device', render: (s) => <span className="mono">{s.deviceUid}</span> },
            {
              key: 'resumedCount',
              header: 'Resumes',
              render: (s) => <DotStatus label={`${s.resumedCount ?? 0} resumed`} tone="dark" />,
            },
            { key: 'status', header: 'Status', render: (s) => <StatusBadge status={s.status} /> },
            {
              key: 'lastActiveAt',
              header: 'Last Active (UTC)',
              render: (s) => <span className="mono">{formatUtcIso(s.lastActiveAt || s.createdAt)}</span>,
            },
            {
              key: 'actions',
              header: 'Actions',
              render: (s) => (
                <div className="flex-row">
                  {s.status === 'ACTIVE' || s.status === 'RESUMED' ? (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        try {
                          await api.closeSession(s.sessionId);
                          await load();
                        } catch (err) {
                          setError(err.message);
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      Close
                    </button>
                  ) : null}
                  {s.status === 'CLOSED' ? (
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      disabled={busy}
                      onClick={async () => {
                        setBusy(true);
                        try {
                          await api.resumeSession(s.sessionId);
                          await load();
                        } catch (err) {
                          setError(err.message);
                        } finally {
                          setBusy(false);
                        }
                      }}
                    >
                      Resume Session
                    </button>
                  ) : null}
                </div>
              ),
            },
          ]}
        />
      </div>
    </div>
  );
}
