import React from 'react';
import StatusBadge from './StatusBadge';
import { formatUtcIso } from '../dateUtils';

export default function AlertCard({ alert }) {
  return (
    <div className="card" style={{ marginBottom: '12px' }}>
      <div className="flex-row" style={{ justifyContent: 'space-between', marginBottom: '8px' }}>
        <div className="flex-row">
          <StatusBadge status={alert.severity} />
          <StatusBadge status={alert.outcomeClassification} />
          <strong className="mono">{alert.ruleName}</strong>
        </div>
        <span className="mono" style={{ color: 'var(--text-muted)' }}>
          {alert.timestamp ? formatUtcIso(alert.timestamp) : ''}
        </span>
      </div>
      <p style={{ margin: '0 0 8px', fontSize: '13.5px', lineHeight: 1.5 }}>{alert.explanation}</p>
      <div className="flex-row" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
        <span>
          <strong>Actor:</strong> <span className="mono">{alert.actor}</span>
        </span>
        <span>·</span>
        <span>
          <strong>Path:</strong> <span className="mono">{alert.servicePath}</span>
        </span>
        <span>·</span>
        <span>
          <strong>Events:</strong>{' '}
          <span className="mono">{Array.isArray(alert.eventIds) ? alert.eventIds.join(', ') : ''}</span>
        </span>
        {alert.correlationId && (
          <>
            <span>·</span>
            <span>
              <strong>Correlation:</strong> <span className="mono">{alert.correlationId}</span>
            </span>
          </>
        )}
      </div>
    </div>
  );
}
