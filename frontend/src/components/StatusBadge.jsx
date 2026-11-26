import React from 'react';

const STATUS_CLASS_MAP = {
  ACTIVE: 'badge-success',
  ALLOW: 'badge-success',
  ALLOWED: 'badge-success',
  COMMITTED: 'badge-success',
  ACKNOWLEDGED: 'badge-success',
  VERIFIED: 'badge-success',
  DELIVERED: 'badge-success',
  ONLINE: 'badge-success',
  MEASURED_PASS: 'badge-success',
  RESTORED: 'badge-success',
  RESUMED: 'badge-success',
  LOW: 'badge-info',
  INFO: 'badge-lavender',
  PREPARED: 'badge-info',
  DISTRIBUTED: 'badge-warning',
  PENDING: 'badge-warning',
  DEGRADED: 'badge-warning',
  RETIRED: 'badge-pink',
  MEDIUM: 'badge-warning',
  CLOSED: 'badge-neutral',
  NOT_RESTORED: 'badge-neutral',
  SENT: 'badge-info',
  PENDING_DELIVERY: 'badge-warning',
  REVOKED: 'badge-danger',
  DENY: 'badge-danger',
  DENIED: 'badge-danger',
  FAILED: 'badge-danger',
  REJECTED: 'badge-danger',
  CORRUPTED: 'badge-danger',
  CRITICAL: 'badge-danger',
  HIGH: 'badge-danger',
  DENIED_ATTEMPT: 'badge-warning',
  CONFIRMED_VIOLATION: 'badge-danger',
  NEEDS_REVIEW: 'badge-pink',
};

export default function StatusBadge({ status, variant }) {
  const normalized = String(status || '').toUpperCase();
  const cls = variant ? `badge-${variant}` : STATUS_CLASS_MAP[normalized] || 'badge-neutral';
  return <span className={`badge ${cls}`}>{status}</span>;
}
