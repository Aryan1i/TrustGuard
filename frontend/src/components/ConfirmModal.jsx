import React from 'react';

export default function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  danger = false,
  onConfirm,
  onCancel,
  busy = false,
  children,
}) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <div className="modal-card">
        <h3 style={{ margin: '0 0 8px', fontSize: '16px' }}>{title}</h3>
        <p style={{ margin: '0 0 14px', fontSize: '13.5px', color: 'var(--text-secondary)' }}>{message}</p>
        {children && <div style={{ marginBottom: '14px' }}>{children}</div>}
        <div className="flex-row" style={{ justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? 'Processing...' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
