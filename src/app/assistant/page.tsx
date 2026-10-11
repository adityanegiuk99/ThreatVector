"use client";

import { useState } from "react";
import { ErrorBox } from "@/components/Filters";
import { AnalystResp, api } from "@/lib/api";

const EXAMPLES = [
  "What MITRE techniques relate to CVE-2021-44228 exploitation?",
  "How should defenders respond to privilege escalation in KEV?",
  "Summarize ransomware-related KEV entries and mitigation requirements",
];

export default function AssistantPage() {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AnalystResp | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function ask(q: string) {
    setLoading(true);
    setError(null);
    try {
      const res = await api<AnalystResp>("/api/analyst", {
        method: "POST",
        body: JSON.stringify({ question: q }),
      });
      setAnswer(res);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">AI Threat Analyst</h1>
      <div className="card">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (question.trim().length >= 3) ask(question.trim());
          }}
        >
          <div style={{ display: "flex", gap: 8 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              placeholder="Ask about vulnerability exploitation, techniques, or defenses…"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              required
              minLength={3}
            />
            <button className="btn" type="submit" disabled={loading}>
              {loading ? "Analyzing…" : "Ask"}
            </button>
          </div>
        </form>
        <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
          {EXAMPLES.map((ex) => (
            <button key={ex} className="pager-btn" type="button" onClick={() => { setQuestion(ex); ask(ex); }}>
              {ex.length > 62 ? ex.slice(0, 60) + "…" : ex}
            </button>
          ))}
        </div>
      </div>

      {error && <ErrorBox message={error} />}

      {loading && <div className="empty">Retrieving evidence…</div>}

      {answer && !loading && (
        <div className="card" style={{ marginTop: 16 }}>
          <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit", margin: 0, fontSize: 13.5, lineHeight: 1.5 }}>
            {answer.answer}
          </pre>

          {answer.mode === "fallback" && (
            <div style={{ color: "var(--warn)", fontSize: 12.5, marginTop: 10 }}>
              Mode: deterministic summary (no LLM key configured). Cited sources below are retrieved, not generated.
            </div>
          )}

          {answer.uncertainty.length > 0 && (
            <div style={{ marginTop: 12, padding: 10, background: "rgba(245,158,11,0.08)", borderRadius: 6, fontSize: 12.5 }}>
              <b style={{ color: "var(--warn)" }}>Uncertainty:</b>
              {answer.uncertainty.map((u, i) => (
                <div key={i} style={{ color: "var(--warn)" }}>
                  - {u}
                </div>
              ))}
            </div>
          )}

          {answer.citations.length > 0 && (
            <div style={{ marginTop: 16 }}>
              <h4 style={{ margin: "0 0 8px" }}>Cited sources ({answer.citations.length})</h4>
              {answer.citations.map((c, i) => (
                <div key={i} className="term-row" style={{ flexDirection: "column", gap: 2 }}>
                  <div>
                    <span className="tag">{c.source}</span>
                    <span className="tag">{c.external_id}</span>
                    {c.url && (
                      <a href={c.url} target="_blank" rel="noreferrer" style={{ color: "var(--accent)", fontSize: 12.5 }}>
                        open source ↗
                      </a>
                    )}
                  </div>
                  <div style={{ color: "var(--muted)", fontSize: 12.5 }}>{c.excerpt}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
