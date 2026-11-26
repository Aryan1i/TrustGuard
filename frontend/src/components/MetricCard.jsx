import React from 'react';

export default function MetricCard({ title, value, unit, source, sampleSize, caveat }) {
  return (
    <div className="card">
      <div className="stat-label">{title}</div>
      <div className="stat-value">
        {value}
        {unit ? <span style={{ fontSize: '14px', fontWeight: 500, marginLeft: '4px' }}>{unit}</span> : null}
      </div>
      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
        <strong>Source:</strong> {source} · <strong>n =</strong> {sampleSize}
      </div>
      {caveat && (
        <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
          {caveat}
        </div>
      )}
    </div>
  );
}
