"use client";

import { useEffect, useState } from "react";
import { Empty, ErrorBox, Loading } from "@/components/Filters";
import { EvalOut, api } from "@/lib/api";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const METRIC_COLORS = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6"];
const METRIC_KEYS = ["pr_auc", "roc_auc", "precision@5%", "recall@5%", "brier"];

export default function MlEvaluationPage() {
  const [models, setModels] = useState<EvalOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [split, setSplit] = useState("test");

  useEffect(() => {
    (async () => {
      try {
        const data = await api<EvalOut[]>("/api/models/evaluation");
        setModels(data.reverse());
      } catch (e) {
        setError(String(e instanceof Error ? e.message : e));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} />;
  if (models.length === 0)
    return <Empty message="No trained models yet. Run `python -m app.services.ml.train` after ingestion." />;

  // Build chart data: one bar group per model, one bar per metric
  const chartData = models.map((m) => {
    const splitMetrics = m.metrics[split] ?? {};
    const row: Record<string, string | number> = { name: `${m.algorithm} ${m.version.slice(0, 8)}` };
    METRIC_KEYS.forEach((key) => {
      if (splitMetrics[key] !== undefined) row[key] = splitMetrics[key];
    });
    return row;
  });

  return (
    <div>
      <h1 className="page-title">ML Model Evaluation</h1>

      <div className="card">
        <div className="dl-form">
          <select className="select" value={split} onChange={(e) => setSplit(e.target.value)}>
            <option value="test">Test split</option>
            <option value="val">Validation split</option>
          </select>
          <span style={{ color: "var(--muted)", fontSize: 12.5 }}>
            Task: will a CVE be added to CISA KEV within 90 days of publication? Chronological, leakage-safe split.
          </span>
        </div>
        <ResponsiveContainer width="100%" height={360}>
          <BarChart data={chartData}>
            <CartesianGrid stroke="#1c2333" strokeDasharray="3 3" />
            <XAxis dataKey="name" stroke="#8b94a7" tick={{ fontSize: 11 }} interval={0} angle={-15} dy={8} />
            <YAxis domain={[0, 1]} stroke="#8b94a7" />
            <Tooltip contentStyle={{ background: "#161b26", border: "1px solid #232a3a", fontSize: 12 }} />
            <Legend />
            {METRIC_KEYS.map((k, i) => (
              <Bar key={k} dataKey={k} fill={METRIC_COLORS[i % METRIC_COLORS.length]} name={k} radius={[3, 3, 0, 0]} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>

      {models.map((m) => (
        <div className="card" key={m.model_version_id}>
          <h3 style={{ margin: "0 0 6px" }}>
            {m.name} {m.version} {m.is_active && <span className="tag-kev tag">ACTIVE</span>}
          </h3>
          <div style={{ color: "var(--muted)", fontSize: 12.5, marginBottom: 10 }}>
            algorithm: {m.algorithm} · trained on: {m.trained_on}
          </div>
          <table>
            <thead>
              <tr>
                <th>Split</th>
                {METRIC_KEYS.map((k) => (
                  <th key={k}>{k}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(m.metrics).map(([splitName, metrics]) => (
                <tr key={splitName}>
                  <td>{splitName}</td>
                  {METRIC_KEYS.map((k) => (
                    <td key={k}>{metrics[k]?.toFixed(4) ?? "-"}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
