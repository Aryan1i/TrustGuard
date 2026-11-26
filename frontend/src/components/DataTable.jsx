import React from 'react';
import EmptyState from './EmptyState';

export default function DataTable({ columns, rows, rowKey, emptyTitle, emptyMessage }) {
  if (!rows || rows.length === 0) {
    return <EmptyState title={emptyTitle || 'No records found'} message={emptyMessage || 'No data matches the current view.'} />;
  }
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key}>{col.header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={rowKey ? rowKey(row, idx) : idx}>
              {columns.map((col) => (
                <td key={col.key}>{col.render ? col.render(row) : row[col.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
