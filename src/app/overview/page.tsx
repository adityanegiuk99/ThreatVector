"use client";

import { useEffect, useState } from "react";
import { ErrorBox, Loading } from "@/components/Filters";
import { Asset, Page, api } from "@/lib/api";

interface CvePage extends Page<{ cve_id: string; cvss_base_score: number | null }> {}

interface OverviewData {
  cves_total: number;
  cves_kev: number;
  cves_critical_high: number;
  assets_total: number;
  ingestion: IngestionStatusLike;
  kev_recent: { cve_id: string; name: string; date_added: string }[];
}

interface IngestionStatusLike {
  latest_by_source: Record<
    string,
    { source: string; status: string; started_at: string; records_fetched: number; records_upserted: number }
  >;
}

function Kpi({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="card">
      <div className="kpi-label">{label}</div>
      <div className="kpi">{value}</div>
      {hint && <div style={{ color: "var(--muted)", fontSize: 12, marginTop: 6 }}>{hint}</div>}
    </div>
  );
}

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        const ingest = await api<IngestionStatusLike>("/api/ingestion/status");
        const cveCrit = await api<Page<{ cve_id: string }>>("/api/vulnerabilities", {
          params: { severity: "CRITICAL", page_size: 1 },
        });
        const allCve = await api<Page<{ cve_id: string }>>("/api/vulnerabilities", {
          params: { page_size: 1 },
        });
        const kevOnly = await api<Page<{ cve_id: string }>>("/api/vulnerabilities", {
          params: { in_kev: true, page_size: 1 },
        });
        const assets = await api<Page<Asset>>("/api/assets", {
          params: { page_size: 1 },
        });
        const recent = await api<Page<{ cve_id: string; title: string | null; published_date: string | null }>>(
          "/api/vulnerabilities",
          { params: { in_kev: true, page_size: 8 } }
        );
        setData({
          cves_total: allCve.total,
          cves_kev: kevOnly.total,
          cves_critical_high: cveCrit.total,
          assets_total: assets.total,
          ingestion: ingest,
          kev_recent:
            recent.items?.map(({ cve_id, title, published_date }) => ({
              cve_id,
              name: title ?? "(untitled)",
              date_added: published_date?.slice(0, 10) ?? "",
            })) ?? [],
        });
      } catch (e) {
        setError(String(e instanceof Error ? e.message : e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  const sources = Object.values(data.ingestion.latest_by_source ?? {});
  return (
    <div>
      <h1 className="page-title">Security Overview</h1>
      <div className="grid-4">
        <Kpi label="Tracked CVEs" value={data.cves_total} hint="Synced from NVD" />
        <Kpi label="In CISA KEV" value={data.cves_kev} hint="Known exploited" />
        <Kpi label="Critical severity" value={data.cves_critical_high} hint="CVSS Critical" />
        <Kpi label="Assets monitored" value={data.assets_total} hint="Synthetic inventory" />
      </div>

      <div className="card" style={{ marginTop: 18 }}>
        <h3 style={{ margin: "0 0 12px" }}>Data freshness</h3>
        {sources.length === 0 ? (
          <div className="empty">No ingestion runs yet - run a sync worker to populate the platform.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Last run</th>
                <th>Fetched</th>
                <th>Upserted</th>
              </tr>
            </thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.source}>
                  <td>{s.source}</td>
                  <td style={{ color: s.status === "success" ? "var(--good)" : "var(--crit)" }}>{s.status}</td>
                  <td>{s.started_at?.slice(0, 19).replace("T", " ")}</td>
                  <td>{s.records_fetched ?? "-"}</td>
                  <td>{s.records_upserted ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="card">
        <h3 style={{ margin: "0 0 12px" }}>Recently updated KEV-tracked vulnerabilities</h3>
        {data.kev_recent.length === 0 ? (
          <div className="empty">No KEV entries indexed.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Title</th>
                <th>Published</th>
              </tr>
            </thead>
            <tbody>
              {data.kev_recent.map((r) => (
                <tr key={r.cve_id}>
                  <td>
                    <a href={`/vulnerabilities?q=${r.cve_id}`} style={{ color: "var(--accent)" }}>
                      {r.cve_id}
                    </a>
                  </td>
                  <td>{r.name}</td>
                  <td>{r.date_added}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
