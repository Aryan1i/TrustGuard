import React from 'react';

export default function StatCard({ label, value, meta, badge }) {
  return (
    <div className="card">
      <div className="flex-row" style={{ justifyContent: 'space-between' }}>
        <span className="stat-label">{label}</span>
        {badge}
      </div>
      <div className="stat-value">{value}</div>
      {meta && <div className="stat-meta">{meta}</div>}
    </div>
  );
}
