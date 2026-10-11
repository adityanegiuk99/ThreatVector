"use client";

import { useState } from "react";
import { api, setToken } from "@/lib/api";

interface TokenResp {
  access_token: string;
}

export default function LoginPage() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const path = mode === "login" ? "/api/auth/login" : "/api/auth/register";
      const body = mode === "login" ? { username, password } : { username, email, password };
      const res = await api<TokenResp>(path, { method: "POST", body: JSON.stringify(body) });
      setToken(res.access_token);
      window.location.href = "/overview";
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 380, margin: "72px auto" }}>
      <div style={{ textAlign: "center", marginBottom: 26 }}>
        <h1 style={{ color: "var(--accent)", fontSize: 28, marginBottom: 6 }}>Veylix</h1>
        <div style={{ color: "var(--muted)", fontSize: 13.5 }}>
          AI Cyber Threat Intelligence Platform
        </div>
      </div>
      <div className="card">
        <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              className="pager-btn"
              style={{
                background: mode === m ? "var(--accent)" : "transparent",
                color: mode === m ? "#fff" : undefined,
                flex: 1,
              }}
              onClick={() => setMode(m)}
            >
              {m === "login" ? "Sign in" : "Register"}
            </button>
          ))}
        </div>
        <form onSubmit={submit} style={{ display: "grid", gap: 10 }}>
          <input
            className="input"
            placeholder="Username"
            required
            minLength={3}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
          {mode === "register" && (
            <input
              className="input"
              type="email"
              placeholder="Email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          )}
          <input
            className="input"
            type="password"
            placeholder="Password (min 8 chars)"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={mode === "login" ? "current-password" : "new-password"}
          />
          {error && <div className="error-box" style={{ fontSize: 13 }}>{error}</div>}
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
      </div>
    </div>
  );
}
