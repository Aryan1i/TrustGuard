import React from 'react';

export default function StatCard({ label, value, meta, delta, deltaTone = 'up' }) {
  const deltaClass =
    deltaTone === 'down' ? 'kpi-delta-down' : deltaTone === 'neutral' ? 'kpi-delta-neutral' : 'kpi-delta-up';

  return (
    <div className="kpi-card">
      <div className="kpi-top">
        <span className="kpi-title">{label}</span>
        <button
          type="button"
          style={{
            border: 'none',
            background: 'transparent',
            color: '#d1d5db',
            fontWeight: 700,
            fontSize: '16px',
            cursor: 'pointer',
            padding: '0 2px',
            lineHeight: 1,
          }}
          aria-label="More options"
        >
          ⋮
        </button>
      </div>
      <div className="kpi-value-row">
        <span className="kpi-value">{value}</span>
        {delta && <span className={deltaClass}>{delta}</span>}
      </div>
      {meta && <div className="kpi-sub">{meta}</div>}
    </div>
  );
}
