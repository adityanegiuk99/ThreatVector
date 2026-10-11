"use client";

export const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TOKEN_KEY = "veylix_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

export async function api<T = unknown>(
  path: string,
  init?: RequestInit & { params?: Record<string, string | number | boolean | undefined> }
): Promise<T> {
  const { params, ...rest } = init || {};
  let url = `${API_URL}${path}`;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") searchParams.set(key, String(value));
    }
    url += `?${searchParams.toString()}`;
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((rest.headers as Record<string, string>) || {}),
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(url, { ...rest, headers });
  if (res.status === 401) {
    clearToken();
    if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.href = "/login";
    }
    throw new Error("Unauthorized");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body.slice(0, 300)}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Cve {
  cve_id: string;
  title: string | null;
  cvss_base_score: number | null;
  cvss_severity: string | null;
  published_date: string | null;
  description: string | null;
  cwe_ids: string[] | null;
}

export interface KevInfo {
  kev_cve_id: string;
  date_added: string | null;
  known_ransomware_use: boolean;
  required_action: string | null;
}

export interface RiskQueueEntry {
  cve_id: string;
  asset_id: number;
  hostname: string;
  exposure: string;
  criticality: number;
  cvss: number | null;
  in_kev: boolean;
  ml_score: number | null;
  score: number;
  confidence: string;
  explanation: {
    score_terms: { name: string; contribution: number; reason: string }[];
    caveats: string[];
  };
}

export interface Asset {
  id: number;
  hostname: string;
  asset_type: string;
  criticality: number;
  exposure: string;
  owner: string | null;
  software?: { vendor: string; product: string; version?: string }[];
}

export interface EvalOut {
  model_version_id: number;
  name: string;
  version: string;
  algorithm: string;
  is_active: boolean;
  trained_on: string | null;
  metrics: Record<string, Record<string, number>>;
}

export interface IntelHit {
  document_id: number;
  source: string;
  external_id: string;
  title: string | null;
  url: string | null;
  content: string | null;
  excerpt?: string | null;
  score?: number | null;
  published_at?: string | null;
}

export interface AnalystResp {
  answer: string;
  citations: IntelHit[];
  mode: string;
  uncertainty: string[];
  cve_facts: Record<string, unknown> | null;
}

export interface IngestionStatus {
  latest_by_source: Record<
    string,
    {
      source: string;
      status: string;
      started_at: string;
      records_fetched: number;
      records_upserted: number;
      error?: string;
    }
  >;
}
