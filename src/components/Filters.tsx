"use client";

import React from "react";

export function FilterBar(props: React.HTMLAttributes<HTMLDivElement>) {
  return <div className="dl-form" {...props} />;
}

export function Pager({
  page,
  pages,
  onChange,
}: {
  page: number;
  pages: number;
  onChange: (p: number) => void;
}) {
  return (
    <div className="pagination">
      <div className="pager-group">
        <button className="pager-btn" disabled={page <= 1} onClick={() => onChange(page - 1)}>
          Prev
        </button>
        <span>
          Page {page} of {Math.max(pages, 1)}
        </span>
        <button className="pager-btn" disabled={page >= pages} onClick={() => onChange(page + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}

export function severityClass(sev: string | null): string {
  switch (sev) {
    case "CRITICAL":
      return "sev-badge sev-CRITICAL";
    case "HIGH":
      return "sev-badge sev-HIGH";
    case "MEDIUM":
      return "sev-badge sev-MEDIUM";
    case "LOW":
      return "sev-badge sev-LOW";
    default:
      return "sev-badge";
  }
}

export function Loading() {
  return <div className="empty">Loading…</div>;
}

export function ErrorBox({ message }: { message: string }) {
  return <div className="error-box">{message}</div>;
}

export function Empty({ message }: { message: string }) {
  return <div className="empty">{message}</div>;
}
