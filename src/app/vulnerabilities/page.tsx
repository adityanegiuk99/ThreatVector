"use client";

import { useCallback, useEffect, useState } from "react";
import { Empty, ErrorBox, FilterBar, Loading, Pager, severityClass } from "@/components/Filters";
import { Cve, Page, api } from "@/lib/api";

export default function VulnerabilitiesPage() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [inKev, setInKev] = useState("");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<Cve[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, page_size: 25 };
      if (q) params.q = q;
      if (severity) params.severity = severity;
      if (inKev) params.in_kev = inKev;
      const data = await api<Page<Cve>>("/api/vulnerabilities", { params });
      setItems(data.items);
      setTotal(data.total);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }, [q, severity, inKev, page]);

  useEffect(() => {
    load();
  }, [load]);

  const pages = Math.ceil(total / 25);
  return (
    <div>
      <h1 className="page-title">Vulnerability Explorer</h1>
      <FilterBar>
        <input
          className="input"
          placeholder="Search CVE ID or description"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(1);
          }}
          style={{ minWidth: 260 }}
        />
        <select className="select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">Any severity</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select className="select" value={inKev} onChange={(e) => { setInKev(e.target.value); setPage(1); }}>
          <option value="">KEV: any</option>
          <option value="true">In KEV</option>
          <option value="false">Not in KEV</option>
        </select>
      </FilterBar>

      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message={error} />
      ) : items.length === 0 ? (
        <Empty message="No CVEs match these filters (or platform not ingested yet)." />
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>CVSS</th>
                <th>Severity</th>
                <th>Published</th>
                <th>Title / Description</th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.cve_id}>
                  <td>
                    <a href={`/vulnerabilities?q=${c.cve_id}`} style={{ color: "var(--accent)" }}>
                      {c.cve_id}
                    </a>
                  </td>
                  <td>{c.cvss_base_score?.toFixed(1) ?? "-"}</td>
                  <td>
                    <span className={severityClass(c.cvss_severity)}>{c.cvss_severity ?? "n/a"}</span>
                  </td>
                  <td>{c.published_date?.slice(0, 10)}</td>
                  <td style={{ maxWidth: 620 }}>
                    <div style={{ fontWeight: 500 }}>{c.title ?? "(untitled)"}</div>
                    <div style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 3 }}>
                      {(c.description ?? "").slice(0, 180)}…
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager page={page} pages={pages} onChange={setPage} />
        </div>
      )}
    </div>
  );
}
