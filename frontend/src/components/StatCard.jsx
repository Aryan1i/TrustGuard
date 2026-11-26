import React from 'react';

export default function StatCard({ label, value, meta, delta, deltaTone = 'up' }) {
  const deltaClass =
    deltaTone === 'down' ? 'kpi-delta-down' : deltaTone === 'neutral' ? 'kpi-delta-neutral' : 'kpi-delta-up';

  return (
    <div className="kpi-card">
      <div className="kpi-top">
        <span className="kpi-title">{label}</span>
        <span style={{ color: '#9ca3af', fontWeight: 700, fontSize: '14px' }}>⋮</span>
      </div>
      <div className="kpi-value-row">
        <span className="kpi-value">{value}</span>
        {delta && <span className={deltaClass}>{delta}</span>}
      </div>
      {meta && <div className="kpi-sub">{meta}</div>}
    </div>
  );
}
