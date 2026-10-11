"use client";

import { useCallback, useEffect, useState, Fragment } from "react";
import { Empty, ErrorBox, FilterBar, Loading, Pager } from "@/components/Filters";
import { Page, RiskQueueEntry, api } from "@/lib/api";

interface QueueResp {
  items: RiskQueueEntry[];
  total: number;
  page: number;
  page_size: number;
  model: { name: string | null; version: string | null } | null;
}

interface AssetLite {
  id: number;
  hostname: string;
}

function ScoreBadge({ score }: { score: number }) {
  const color = score >= 7 ? "var(--crit)" : score >= 4 ? "var(--warn)" : "var(--good)";
  return (
    <span style={{ color, fontWeight: 700, fontVariantNumeric: "tabular-nums" }}>{score.toFixed(1)}</span>
  );
}

export default function RemediationQueue() {
  const [page, setPage] = useState(1);
  const [assetId, setAssetId] = useState<string>("");
  const [entries, setEntries] = useState<RiskQueueEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [model, setModel] = useState<string | null>(null);
  const [assets, setAssets] = useState<AssetLite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page };
      if (assetId) params.asset_id = assetId;
      const data = await api<QueueResp>("/api/risk/queue", { params });
      setEntries(data.items);
      setTotal(data.total);
      setModel(data.model?.name ? `${data.model.name} ${data.model.version}` : null);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }, [page, assetId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    (async () => {
      try {
        const res = await api<Page<AssetLite>>("/api/assets", { params: { page_size: 100 } });
        setAssets(res.items);
      } catch {
        /* ignore asset list failure on queue page */
      }
    })();
  }, []);

  const pages = Math.ceil(total / 20);
  return (
    <div>
      <h1 className="page-title">Remediation Queue (Explainable)</h1>
      {model && (
        <div style={{ color: "var(--muted)", fontSize: 13, marginBottom: 12 }}>
          Risk engine + ML model: <span style={{ color: "var(--accent)" }}>{model}</span>
        </div>
      )}
      <FilterBar>
        <select className="select" value={assetId} onChange={(e) => { setAssetId(e.target.value); setPage(1); }}>
          <option value="">All assets</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.hostname}
            </option>
          ))}
        </select>
      </FilterBar>

      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorBox message={error} />
      ) : entries.length === 0 ? (
        <Empty message="No risk entries yet - ingest vulnerability data and register assets first." />
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>CVE</th>
                <th>Asset</th>
                <th>CVSS</th>
                <th>KEV</th>
                <th>ML est.</th>
                <th>Exposure</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <Fragment key={`${e.cve_id}-${e.asset_id}`}>
                  <tr
                    style={{ cursor: "pointer" }}
                    onClick={() => setExpanded(expanded === `${e.cve_id}-${e.asset_id}` ? null : `${e.cve_id}-${e.asset_id}`)}
                  >
                    <td>
                      <ScoreBadge score={e.score} />
                    </td>
                    <td>
                      <a href={`/vulnerabilities?q=${e.cve_id}`} style={{ color: "var(--accent)" }}>{e.cve_id}</a>
                    </td>
                    <td>{e.hostname}</td>
                    <td>{e.cvss?.toFixed(1) ?? "-"}</td>
                    <td>{e.in_kev ? <span className="sev-badge sev-CRITICAL">KEV</span> : "-"}</td>
                    <td>{e.ml_score != null ? e.ml_score.toFixed(2) : "—"}</td>
                    <td>{e.exposure}</td>
                  </tr>
                  {expanded === `${e.cve_id}-${e.asset_id}` && (
                    <tr>
                      <td colSpan={7} style={{ background: "#0d1119" }}>
                        <div style={{ fontWeight: 600, marginBottom: 8 }}>
                          Score breakdown
                        </div>
                        {e.explanation.score_terms.map((t) => (
                          <div className="term-row" key={t.name}>
                            <span style={{ minWidth: 140 }}>{t.name}</span>
                            <span className="term-why">{t.reason}</span>
                            <span className="term-val" style={{ color: "var(--accent)" }}>
                              +{t.contribution.toFixed(2)}
                            </span>
                          </div>
                        ))}
                        {e.explanation.caveats.length > 0 && (
                          <div style={{ marginTop: 8, color: "var(--warn)", fontSize: 12.5 }}>
                            {e.explanation.caveats.map((c, i) => (
                              <div key={i}>⚠ {c}</div>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
          <Pager page={page} pages={pages} onChange={setPage} />
        </div>
      )}
    </div>
  );
}
