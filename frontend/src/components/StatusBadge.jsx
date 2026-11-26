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
  VALID: 'green',
  PASS: 'green',
  RECORDED: 'green',
  DISTRIBUTED: 'amber',
  PENDING: 'amber',
  DEGRADED: 'amber',
  MEDIUM: 'amber',
  PENDING_DELIVERY: 'amber',
  DENIED_ATTEMPT: 'amber',
  NEEDS_REVIEW: 'amber',
  RETIRED: 'amber',
  SHIPPED: 'blue',
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
  CANCELLED: 'red',
  CANCEL: 'red',
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

/* Small truck / package icon for delivered */
function DeliveredIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 17H3V7h11v10H8m-3 0a2 2 0 104 0m6-5h3l2 3v3h-5m0-6V9a2 2 0 00-2-2h-1" />
      <circle cx="17" cy="17" r="2" />
    </svg>
  );
}

function PendingIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </svg>
  );
}

function ShippedIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 12h14M12 5l7 7-7 7" />
    </svg>
  );
}

function CancelledIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M15 9l-6 6M9 9l6 6" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M5 13l4 4L19 7" />
    </svg>
  );
}

function WarningIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 9v4m0 4h.01M10.3 3.9L2.8 17a2 2 0 001.7 3h15a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 16v-4M12 8h.01" />
    </svg>
  );
}

function StatusIcon({ tone, normalized }) {
  // Use context-aware icons
  if (normalized === 'DELIVERED' || normalized === 'ACTIVE' || normalized === 'ONLINE') return <DeliveredIcon />;
  if (normalized === 'SHIPPED') return <ShippedIcon />;
  if (normalized === 'PENDING' || normalized === 'PENDING_DELIVERY') return <PendingIcon />;
  if (normalized === 'CANCELLED' || normalized === 'CANCEL' || normalized === 'REVOKED') return <CancelledIcon />;
  if (tone === 'green') return <CheckIcon />;
  if (tone === 'amber') return <WarningIcon />;
  if (tone === 'red') return <CancelledIcon />;
  return <InfoIcon />;
}

export function DotStatus({ label, tone = 'green' }) {
  const colors = {
    green: '#16a34a',
    amber: '#d97706',
    red: '#dc2626',
    blue: '#2563eb',
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
      <StatusIcon tone={tone} normalized={normalized} />
      <span>{status}</span>
    </span>
  );
}
