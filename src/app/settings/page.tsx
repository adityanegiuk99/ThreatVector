"use client";

import { useCallback, useEffect, useState } from "react";
import { ErrorBox, Loading } from "@/components/Filters";
import { EvalOut, Page, api } from "@/lib/api";

interface AuditEventOut {
  id: number;
  user_id: number | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  created_at: string;
}

interface IngestionStatus {
  latest_by_source: Record<
    string,
    { source: string; status: string; started_at: string; records_fetched: number; records_upserted: number; error?: string | null }
  >;
}

export default function SettingsPage() {
  const [tab, setTab] = useState<"ingestion" | "audit" | "models">("ingestion");
  const [ingest, setIngest] = useState<IngestionStatus | null>(null);
  const [audit, setAudit] = useState<Page<AuditEventOut> | null>(null);
  const [models, setModels] = useState<EvalOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadTab = useCallback(async (which: typeof tab) => {
    setLoading(true);
    setError(null);
    try {
      if (which === "ingestion") setIngest(await api<IngestionStatus>("/api/ingestion/status"));
      if (which === "audit") setAudit(await api<Page<AuditEventOut>>("/api/audit", { params: { page_size: 50 } }));
      if (which === "models") setModels(await api<EvalOut[]>("/api/models/evaluation"));
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTab(tab);
  }, [tab, loadTab]);

  async function activate(id: number) {
    try {
      await api(`/api/models/${id}/activate`, { method: "POST" });
      await loadTab("models");
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }

  const tabs: Array<["ingestion" | "audit" | "models", string]> = [
    ["ingestion", "Ingestion status"],
    ["audit", "Audit history"],
    ["models", "Model versions"],
  ];

  return (
    <div>
      <h1 className="page-title">Settings</h1>
      <div className="dl-form">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            className="pager-btn"
            style={{ background: tab === key ? "var(--accent)" : "transparent", color: tab === key ? "#fff" : undefined }}
            onClick={() => setTab(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {error && <ErrorBox message={error} />}
      {loading && <Loading />}

      {!loading && tab === "ingestion" && ingest && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Status</th>
                <th>Started</th>
                <th>Fetched</th>
                <th>Upserted</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {Object.values(ingest.latest_by_source ?? {}).map((s) => (
                <tr key={s.source}>
                  <td>{s.source}</td>
                  <td style={{ color: s.status === "success" ? "var(--good)" : "var(--crit)" }}>{s.status}</td>
                  <td>{s.started_at?.slice(0, 19).replace("T", " ")}</td>
                  <td>{s.records_fetched ?? "-"}</td>
                  <td>{s.records_upserted ?? "-"}</td>
                  <td style={{ color: "var(--muted)", maxWidth: 400, overflow: "hidden", textOverflow: "ellipsis" }}>
                    {s.error ?? "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && tab === "audit" && audit && (
        <div className="card">
          {audit.items.length === 0 ? (
            <div className="empty">No audit events yet.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>When</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Object</th>
                </tr>
              </thead>
              <tbody>
                {audit.items.map((a) => (
                  <tr key={a.id}>
                    <td>{a.created_at?.slice(0, 19).replace("T", " ")}</td>
                    <td>{a.user_id ?? "-"}</td>
                    <td>{a.action}</td>
                    <td>
                      {a.object_type} {a.object_id ? `· ${a.object_id}` : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {!loading && tab === "models" && (
        <div className="card">
          {models.length === 0 ? (
            <div className="empty">No models registered.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Algorithm</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {models.map((m) => (
                  <tr key={m.model_version_id}>
                    <td>
                      {m.name} {m.version}
                    </td>
                    <td>{m.algorithm}</td>
                    <td>{m.is_active ? "active" : "inactive"}</td>
                    <td>
                      {!m.is_active && m.algorithm !== "rules_baseline" && (
                        <button className="pager-btn" onClick={() => activate(m.model_version_id)}>
                          Activate
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
