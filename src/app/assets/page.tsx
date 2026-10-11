"use client";

import { useCallback, useEffect, useState } from "react";
import { Empty, ErrorBox, FilterBar, Loading, Pager } from "@/components/Filters";
import { Asset, Page, api } from "@/lib/api";

interface NewAssetForm {
  hostname: string;
  criticality: number;
  exposure: string;
  asset_type: string;
  owner: string;
}

const EMPTY_FORM: NewAssetForm = { hostname: "", criticality: 3, exposure: "internal", asset_type: "server", owner: "" };

export default function AssetsPage() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<NewAssetForm>(EMPTY_FORM);
  const [editing, setEditing] = useState<number | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, page_size: 20 };
      if (q) params.q = q;
      const data = await api<Page<Asset>>("/api/assets", { params });
      setItems(data.items);
      setTotal(data.total);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  }, [q, page]);

  useEffect(() => {
    load();
  }, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const payload: Record<string, unknown> = {
        hostname: form.hostname,
        criticality: Number(form.criticality),
        exposure: form.exposure,
        asset_type: form.asset_type,
      };
      if (form.owner) payload.owner = form.owner;
      if (editing !== null) {
        await api(`/api/assets/${editing}`, { method: "PATCH", body: JSON.stringify(payload) });
      } else {
        await api("/api/assets", { method: "POST", body: JSON.stringify(payload) });
      }
      setForm(EMPTY_FORM);
      setEditing(null);
      await load();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    }
  }

  async function remove(id: number) {
    setError(null);
    try {
      await api(`/api/assets/${id}`, { method: "DELETE" });
      await load();
    } catch (err) {
      setError(String(err instanceof Error ? err.message : err));
    }
  }

  const pages = Math.ceil(total / 20);
  return (
    <div>
      <h1 className="page-title">Asset Inventory</h1>
      <FilterBar>
        <input
          className="input"
          placeholder="Search hostname"
          value={q}
          onChange={(e) => {
            setQ(e.target.value);
            setPage(1);
          }}
        />
      </FilterBar>

      <div className="card">
        <h3 style={{ margin: "0 0 12px" }}>{editing !== null ? "Edit asset" : "Add asset"}</h3>
        <form onSubmit={submit} className="dl-form">
          <input
            className="input"
            placeholder="hostname"
            required
            value={form.hostname}
            onChange={(e) => setForm({ ...form, hostname: e.target.value })}
          />
          <select
            className="select"
            value={form.criticality}
            onChange={(e) => setForm({ ...form, criticality: Number(e.target.value) })}
          >
            {[1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>
                Criticality {n}
              </option>
            ))}
          </select>
          <select
            className="select"
            value={form.exposure}
            onChange={(e) => setForm({ ...form, exposure: e.target.value })}
          >
            <option value="internal">internal</option>
            <option value="dmz">dmz</option>
            <option value="external">external</option>
          </select>
          <select
            className="select"
            value={form.asset_type}
            onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
          >
            <option value="server">server</option>
            <option value="workstation">workstation</option>
            <option value="network">network device</option>
            <option value="cloud">cloud</option>
          </select>
          <input
            className="input"
            placeholder="owner (optional)"
            value={form.owner}
            onChange={(e) => setForm({ ...form, owner: e.target.value })}
          />
          <button className="btn" type="submit">
            {editing !== null ? "Update" : "Create"}
          </button>
          {editing !== null && (
            <button
              className="btn-ghost"
              type="button"
              onClick={() => {
                setEditing(null);
                setForm(EMPTY_FORM);
              }}
            >
              Cancel
            </button>
          )}
        </form>
      </div>

      {error && <ErrorBox message={error} />}
      {loading ? (
        <Loading />
      ) : items.length === 0 ? (
        <Empty message="No assets yet - add one above." />
      ) : (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>Hostname</th>
                <th>Type</th>
                <th>Criticality</th>
                <th>Exposure</th>
                <th>Owner</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td>{a.hostname}</td>
                  <td>{a.asset_type}</td>
                  <td>{a.criticality}/5</td>
                  <td>{a.exposure}</td>
                  <td>{a.owner ?? "-"}</td>
                  <td>
                    <button
                      className="pager-btn"
                      onClick={() => {
                        setEditing(a.id);
                        setForm({
                          hostname: a.hostname,
                          criticality: a.criticality,
                          exposure: a.exposure,
                          asset_type: a.asset_type,
                          owner: a.owner ?? "",
                        });
                      }}
                    >
                      Edit
                    </button>{" "}
                    <button className="pager-btn" onClick={() => remove(a.id)}>
                      Delete
                    </button>
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
