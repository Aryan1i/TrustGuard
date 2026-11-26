import React, { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import EmptyState from './EmptyState';

export default function DataTable({
  columns,
  rows,
  rowKey,
  emptyTitle,
  emptyMessage,
  tabs,
  activeTab,
  onTabChange,
  searchable = false,
  searchPlaceholder = 'Search records...',
  pageSize = 10,
}) {
  const location = useLocation();
  const urlQuery = useMemo(() => new URLSearchParams(location.search).get('q') || '', [location.search]);
  const [query, setQuery] = useState(() => (searchable ? urlQuery : ''));
  const [page, setPage] = useState(1);

  useEffect(() => {
    if (!searchable) return;
    setQuery(urlQuery);
    setPage(1);
  }, [searchable, urlQuery]);

  const filtered = useMemo(() => {
    if (!rows) return [];
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q));
  }, [rows, query]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  return (
    <div>
      {(tabs || searchable) && (
        <div className="table-toolbar">
          {tabs ? (
            <div className="mint-tabs" role="tablist">
              {tabs.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`mint-tab${activeTab === t.id ? ' active' : ''}`}
                  onClick={() => {
                    setPage(1);
                    onTabChange(t.id);
                  }}
                >
                  {t.label}
                </button>
              ))}
            </div>
          ) : (
            <div />
          )}

          {searchable && (
            <div className="table-search">
              <input
                type="text"
                placeholder={searchPlaceholder}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
              />
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6b7280" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
            </div>
          )}
        </div>
      )}

      {pageRows.length === 0 ? (
        <EmptyState
          title={emptyTitle || 'No records found'}
          message={emptyMessage || 'No data matches the current view.'}
        />
      ) : (
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
              {pageRows.map((row, idx) => (
                <tr key={rowKey ? rowKey(row, idx) : idx}>
                  {columns.map((col) => (
                    <td key={col.key}>{col.render ? col.render(row, (safePage - 1) * pageSize + idx) : row[col.key]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {filtered.length > pageSize && (
        <div className="pagination-bar">
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={safePage <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            ← Previous
          </button>
          <div className="page-numbers">
            {Array.from({ length: totalPages }, (_, i) => i + 1).map((n) => (
              <button
                key={n}
                type="button"
                className={`page-num-btn${n === safePage ? ' active' : ''}`}
                onClick={() => setPage(n)}
              >
                {n}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={safePage >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
