import React from 'react';
import StatusBadge from './StatusBadge';

export default function Timeline({ items }) {
  if (!items || items.length === 0) {
    return <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>No timeline entries yet.</p>;
  }
  return (
    <div className="timeline">
      {items.map((item, idx) => (
        <div className="timeline-item" key={idx}>
          <div className="timeline-dot" />
          <div style={{ flex: 1 }}>
            <div className="flex-row" style={{ justifyContent: 'space-between' }}>
              <div className="flex-row">
                <strong style={{ fontSize: '13.5px' }}>{item.title}</strong>
                {item.status && <StatusBadge status={item.status} />}
              </div>
              <span className="mono" style={{ color: 'var(--text-muted)' }}>
                {item.timestamp ? new Date(item.timestamp).toISOString() : ''}
              </span>
            </div>
            {item.detail && (
              <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                {item.detail}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
