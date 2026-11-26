import React from 'react';

export default function EmptyState({ title = 'No items', message = 'Nothing to display.' }) {
  return (
    <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
      <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
        {title}
      </div>
      <div style={{ fontSize: '13px' }}>{message}</div>
    </div>
  );
}
