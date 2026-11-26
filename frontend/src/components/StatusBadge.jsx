import React from 'react';

const TONE_MAP = {
  ACTIVE: 'green',
  ALLOW: 'green',
  ALLOWED: 'green',
  COMMITTED: 'green',
  ACKNOWLEDGED: 'green',
  VERIFIED: 'green',
  DELIVERED: 'green',
  ONLINE: 'green',
  MEASURED_PASS: 'green',
  RESTORED: 'green',
  RESUMED: 'green',
  YES: 'green',
  DISTRIBUTED: 'amber',
  PENDING: 'amber',
  DEGRADED: 'amber',
  MEDIUM: 'amber',
  PENDING_DELIVERY: 'amber',
  DENIED_ATTEMPT: 'amber',
  NEEDS_REVIEW: 'amber',
  RETIRED: 'amber',
  REVOKED: 'red',
  DENY: 'red',
  DENIED: 'red',
  FAILED: 'red',
  REJECTED: 'red',
  CORRUPTED: 'red',
  TAMPERED: 'red',
  DISABLED: 'red',
  BLOCKED: 'red',
  BROKEN: 'red',
  CRITICAL: 'red',
  HIGH: 'red',
  CONFIRMED_VIOLATION: 'red',
  NO: 'red',
  VALID: 'green',
  PASS: 'green',
  INFO: 'dark',
  LOW: 'dark',
  PREPARED: 'dark',
  CLOSED: 'dark',
  SENT: 'dark',
  NOT_RESTORED: 'dark',
  IN_ORDER: 'dark',
  OUT_OF_ORDER: 'amber',
};

const VARIANT_TO_TONE = {
  success: 'green',
  warning: 'amber',
  danger: 'red',
  info: 'dark',
  neutral: 'dark',
  lavender: 'dark',
  pink: 'amber',
};

function StatusIcon({ tone }) {
  if (tone === 'green') {
    return (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 2l7 3.5V11c0 5-3.3 9.3-7 11-3.7-1.7-7-6-7-11V5.5L12 2z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    );
  }
  if (tone === 'amber') {
    return (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </svg>
    );
  }
  if (tone === 'red') {
    return (
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="9" />
        <path d="M15 9l-6 6M9 9l6 6" />
      </svg>
    );
  }
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M7 10h10M7 14h6" />
    </svg>
  );
}

export function DotStatus({ label, tone = 'green' }) {
  const colors = {
    green: '#16a34a',
    amber: '#d97706',
    red: '#dc2626',
    dark: '#374151',
  };
  const c = colors[tone] || colors.dark;
  return (
    <span className="dot-inline" style={{ color: c }}>
      <span className="dot-circle" style={{ background: c }} />
      <span>{label}</span>
    </span>
  );
}

export default function StatusBadge({ status, variant }) {
  const normalized = String(status || '').toUpperCase();
  const tone = variant ? (VARIANT_TO_TONE[variant] || 'dark') : (TONE_MAP[normalized] || 'dark');
  return (
    <span className={`status-inline status-${tone}`}>
      <StatusIcon tone={tone} />
      <span>{status}</span>
    </span>
  );
}
