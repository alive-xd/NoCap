/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unused-vars */
import fs from "fs";

/**
 * Local development database — in-memory store that mimics the Supabase
 * query builder interface. Returns proper Promises so Next.js server
 * components can await them correctly.
 *
 * Used automatically when NEXT_PUBLIC_SUPABASE_URL is a placeholder.
 */

// ── In-memory stores ───────────────────────────────────────────────────────────
// These are module-level so they persist across requests in dev (HMR resets them)

const globalForStores = global as unknown as {
  stores?: Record<string, Map<string, Record<string, unknown>>>;
};

const stores: Record<string, Map<string, Record<string, unknown>>> = globalForStores.stores || {
  investigations: new Map(),
  artifacts: new Map(),
  evidence: new Map(),
  findings: new Map(),
  finding_evidence: new Map(),
  notes: new Map(),
  tags: new Map(),
  investigation_tags: new Map(),
  investigation_metrics: new Map(),
  watchlist: new Map(),
  scoring_profiles: new Map([
    [
      "profile-v1",
      {
        id: "profile-v1",
        version: "1.0",
        source_weights: { virustotal: 0.35, abuseipdb: 0.25, whois: 0.15, entropy: 0.1, asn: 0.1, homograph: 0.05 },
        reasoning: { virustotal: "Primary reputation signal" },
        created_at: new Date().toISOString(),
      },
    ],
  ]),
};

if (process.env.NODE_ENV !== "production") {
  globalForStores.stores = stores;
}

function uuid(): string {
  return crypto.randomUUID();
}

function ts(): string {
  return new Date().toISOString();
}

function getStore(table: string): Map<string, Record<string, unknown>> {
  if (!stores[table]) stores[table] = new Map();
  return stores[table];
}

// ── Result type ───────────────────────────────────────────────────────────────

type QueryResult<T = Record<string, unknown>> = {
  data: T[] | T | null;
  error: null;
  count?: number;
};

// ── Query builder ─────────────────────────────────────────────────────────────

class QB {
  private table: string;
  private store: Map<string, Record<string, unknown>>;
  private filters: Array<(r: Record<string, unknown>) => boolean> = [];
  private _order?: { field: string; asc: boolean };
  private _limit?: number;
  private _single = false;
  private _head = false;
  private _count = false;

  private _action?: "insert" | "upsert" | "update" | "delete";
  private _actionData?: any;
  private _actionOpts?: any;

  constructor(table: string) {
    this.table = table;
    this.store = getStore(table);
  }

  select(fields?: string, opts?: { count?: string; head?: boolean }): this {
    if (opts?.count) this._count = true;
    if (opts?.head) this._head = true;
    return this;
  }

  eq(field: string, value: unknown): this {
    this.filters.push((r) => r[field] === value);
    return this;
  }

  neq(field: string, value: unknown): this {
    this.filters.push((r) => r[field] !== value);
    return this;
  }

  gte(field: string, value: unknown): this {
    this.filters.push((r) => String(r[field] ?? "") >= String(value ?? ""));
    return this;
  }

  in(field: string, values: unknown[]): this {
    this.filters.push((r) => values.includes(r[field]));
    return this;
  }

  ilike(field: string, pattern: string): this {
    const re = new RegExp(pattern.replace(/%/g, ".*"), "i");
    this.filters.push((r) => re.test(String(r[field] ?? "")));
    return this;
  }

  or(_q: string): this { return this; }

  order(field: string, opts?: { ascending?: boolean }): this {
    this._order = { field, asc: opts?.ascending ?? true };
    return this;
  }

  limit(n: number): this {
    this._limit = n;
    return this;
  }

  range(_from: number, _to: number): this { return this; }

  single(): this {
    this._single = true;
    return this;
  }

  // ── Chainable write operations ───────────────────────────────────────────

  insert(data: Record<string, unknown> | Record<string, unknown>[]): this {
    this._action = "insert";
    this._actionData = data;
    return this;
  }

  upsert(data: Record<string, unknown>, opts?: { onConflict?: string }): this {
    this._action = "upsert";
    this._actionData = data;
    this._actionOpts = opts;
    return this;
  }

  update(data: Record<string, unknown>): this {
    this._action = "update";
    this._actionData = data;
    return this;
  }

  delete(): this {
    this._action = "delete";
    return this;
  }

  // Await-able select — called when the QB itself is awaited
  then<T>(
    resolve: (v: QueryResult) => T,
    reject?: (e: unknown) => T
  ): Promise<T> {
    return this._resolve().then(resolve, reject);
  }

  private async _resolve(): Promise<QueryResult> {
    if (this._action === "insert") {
      const rows = Array.isArray(this._actionData) ? this._actionData : [this._actionData];
      const inserted: Record<string, unknown>[] = [];
      for (const row of rows) {
        const id = (row.id as string) || uuid();
        const record = { created_at: ts(), ...row, id };
        this.store.set(id, record);
        inserted.push(record);
      }
      if (this._single) {
        return { data: inserted[0] ?? null, error: null };
      }
      return { data: inserted, error: null };
    }

    if (this._action === "upsert") {
      const data = this._actionData;
      const opts = this._actionOpts;
      const conflictFields = opts?.onConflict?.split(",").map((f: string) => f.trim()) ?? ["id"];
      const existing = Array.from(this.store.values()).find((r) =>
        conflictFields.every((f: string) => r[f] === data[f])
      );
      if (existing) {
        const updated = { ...existing, ...data };
        this.store.set(String(existing.id), updated);
        return { data: this._single ? updated : [updated], error: null };
      }
      const id = (data.id as string) || uuid();
      const record = { created_at: ts(), ...data, id };
      this.store.set(id, record);
      return { data: this._single ? record : [record], error: null };
    }

    if (this._action === "update") {
      const data = this._actionData;
      const updated: Record<string, unknown>[] = [];
      for (const [k, r] of this.store) {
        if (this.filters.every((f) => f(r))) {
          const u = { ...r, ...data };
          this.store.set(k, u);
          updated.push(u);
        }
      }
      return { data: this._single ? (updated[0] ?? null) : updated, error: null };
    }

    if (this._action === "delete") {
      const deleted: Record<string, unknown>[] = [];
      for (const [k, r] of this.store) {
        if (this.filters.every((f) => f(r))) {
          deleted.push(r);
          this.store.delete(k);
        }
      }
      return { data: this._single ? (deleted[0] ?? null) : deleted, error: null };
    }

    let results = Array.from(this.store.values()).map((r) => {
      if (r.investigation_id) {
        const invStore = getStore("investigations");
        const inv = invStore.get(r.investigation_id as string);
        if (inv) {
          return {
            ...r,
            investigations: {
              id: inv.id,
              case_number: inv.case_number,
              target: inv.target,
              user_id: inv.user_id,
            },
            "investigations.target": inv.target,
            "investigations.user_id": inv.user_id,
          };
        }
      }
      return r;
    }).filter((r) =>
      this.filters.every((f) => f(r))
    );

    if (this._order) {
      const { field, asc } = this._order;
      results.sort((a, b) =>
        asc
          ? String(a[field] ?? "") > String(b[field] ?? "") ? 1 : -1
          : String(a[field] ?? "") < String(b[field] ?? "") ? 1 : -1
      );
    }

    const count = results.length;

    if (this._limit !== undefined) results = results.slice(0, this._limit);
    if (this._head) return { data: null, error: null, count };
    if (this._count) return { data: results, error: null, count };
    if (this._single) return { data: results[0] ?? null, error: null };
    return { data: results, error: null, count };
  }
}

// ── Local mock client ─────────────────────────────────────────────────────────

const LOCAL_USER = {
  id: "local-dev-user-id",
  email: "dev@nocap.local",
  created_at: new Date().toISOString(),
};

export function createLocalClient() {
  return {
    from(table: string) {
      return new QB(table);
    },
    auth: {
      getUser: async () => ({ data: { user: LOCAL_USER }, error: null }),
      getSession: async () => ({ data: { session: { user: LOCAL_USER } }, error: null }),
      signInWithPassword: async (_: unknown) => ({
        data: { user: LOCAL_USER, session: { access_token: "local-token" } },
        error: null,
      }),
      signUp: async (_: unknown) => ({
        data: { user: LOCAL_USER, session: null },
        error: null,
      }),
      signOut: async () => ({ error: null }),
      onAuthStateChange: (_cb: unknown) => ({
        data: { subscription: { unsubscribe: () => {} } },
      }),
    },
  };
}

export const isLocalMode =
  process.env.NODE_ENV !== "production" &&
  (!process.env.NEXT_PUBLIC_SUPABASE_URL ||
   process.env.NEXT_PUBLIC_SUPABASE_URL === "https://your-project-id.supabase.co");
