import React, { useEffect, useState } from 'react';
import { api } from '../api';
import DataTable from '../components/DataTable';
import StatusBadge from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';

export default function Messaging({ session }) {
  const [messages, setMessages] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [suiteResults, setSuiteResults] = useState([]);
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [deliveryResult, setDeliveryResult] = useState(null);

  const [recipientUsername, setRecipientUsername] = useState('bob');
  const [plaintext, setPlaintext] = useState('Secure device channel status verified.');
  const [tamperRecipient, setTamperRecipient] = useState(false);
  const [tamperCiphertext, setTamperCiphertext] = useState(false);

  const load = async () => {
    setLoading(true);
    setError('');
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
      setError(err.message);
      await load();
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

  if (loading && messages.length === 0) return <LoadingState />;

  return (
    <div>
      {error && <div className="banner banner-danger">{error}</div>}
      {deliveryResult && (
        <div className="banner banner-success">
          <strong>Delivered & Verified ({deliveryResult.messageId}):</strong> &ldquo;{deliveryResult.decryptedPlaintext}&rdquo; ·{' '}
          {deliveryResult.verificationOutcome} · Ephemeral key erased:{' '}
          <strong>{String(deliveryResult.forwardSecrecyErased)}</strong>
        </div>
      )}

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
            <div className="flex-row" style={{ marginBottom: '12px', fontSize: '12.5px' }}>
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
              <h2 className="card-title">Session & Delivery Checks</h2>
              <p className="card-subtitle">Verifies replay blocking, recipient binding, key erasure, resumption, and reordering.</p>
            </div>
            <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={handleRunSuite}>
              Run Delivery Checks
            </button>
          </div>
          <DataTable
            rowKey={(r) => r.testName}
            rows={suiteResults}
            emptyTitle="Checks not run yet"
            emptyMessage="Click 'Run Delivery Checks' to verify replay protection, recipient binding, and session resumption."
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
          <h2 className="card-title">Encrypted Message Ledger ({messages.length})</h2>
        </div>
        <DataTable
          rowKey={(m) => m.messageId}
          rows={messages}
          columns={[
            { key: 'messageId', header: 'Message ID', render: (m) => <span className="mono">{m.messageId}</span> },
            { key: 'senderUsername', header: 'Sender', render: (m) => <strong>{m.senderUsername}</strong> },
            { key: 'recipientUsername', header: 'Intended Recipient', render: (m) => <strong>{m.recipientUsername}</strong> },
            { key: 'status', header: 'Status', render: (m) => <StatusBadge status={m.status} /> },
            { key: 'verificationOutcome', header: 'Verification', render: (m) => <span className="mono">{m.verificationOutcome}</span> },
            {
              key: 'forwardSecrecyErased',
              header: 'Key Erased',
              render: (m) => <StatusBadge status={m.forwardSecrecyErased ? 'YES' : 'NO'} variant={m.forwardSecrecyErased ? 'success' : 'warning'} />,
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
          <h2 className="card-title">Active Sessions ({sessions.length})</h2>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await api.openSession();
                await load();
              } catch (err) {
                setError(err.message);
              } finally {
                setBusy(false);
              }
            }}
          >
            Open New Session
          </button>
        </div>
        <DataTable
          rowKey={(s) => s.sessionId}
          rows={sessions}
          columns={[
            { key: 'sessionId', header: 'Session ID', render: (s) => <span className="mono">{s.sessionId}</span> },
            { key: 'actorUsername', header: 'Actor' },
            { key: 'deviceUid', header: 'Device', render: (s) => <span className="mono">{s.deviceUid}</span> },
            { key: 'status', header: 'Status', render: (s) => <StatusBadge status={s.status} /> },
            { key: 'resumedCount', header: 'Resumes' },
            {
              key: 'actions',
              header: 'Actions',
              render: (s) => (
                <div className="flex-row">
                  {s.status === 'ACTIVE' || s.status === 'RESUMED' ? (
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={async () => {
                        await api.closeSession(s.sessionId);
                        await load();
                      }}
                    >
                      Close
                    </button>
                  ) : null}
                  {s.status === 'CLOSED' ? (
                    <button
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={async () => {
                        try {
                          await api.resumeSession(s.sessionId);
                          await load();
                        } catch (err) {
                          setError(err.message);
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
