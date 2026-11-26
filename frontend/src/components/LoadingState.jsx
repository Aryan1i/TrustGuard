import React from 'react';

export default function LoadingState({ label = 'Loading live backend telemetry...' }) {
  return (
    <div className="card" style={{ padding: '28px', textAlign: 'center', color: 'var(--text-secondary)' }}>
      <div style={{ fontSize: '14px', fontWeight: 500 }}>{label}</div>
    </div>
  );
}
