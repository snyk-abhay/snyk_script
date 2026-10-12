#!/usr/bin/env node
/**
 * bitbucket-snyk-mirror 1.0.0 (built 2026-10-12)
 *
 * Built file: edit the .mts sources, not this file.
 *
 * Onboards Bitbucket Cloud into Snyk project by project: the repositories of
 * each Bitbucket PROJECT go into one Snyk organization -- a new org created
 * from your template org, an existing org, or the template org itself --
 * through the Bitbucket Cloud App integration.
 *
 * Requirements:
 *   - Node.js 20 or later (no npm install needed)
 *   - Bitbucket: Atlassian API token with read:user, read:workspace,
 *     read:project and read:repository (Bitbucket) scopes, plus its email
 *   - Snyk: Group Admin (or Group service account) API token
 *   - A template org that has the Bitbucket Cloud App connected
 *
 * How to run:
 *   node bitbucket-snyk-mirror.mjs                    guided setup (asks for everything)
 *   node bitbucket-snyk-mirror.mjs --help             all options
 *   node bitbucket-snyk-mirror.mjs sync --plan mirror-plan.json   apply a saved plan
 *
 *   Credentials can be set first instead of typed:
 *     export BITBUCKET_EMAIL=you@company.com
 *     read -s BITBUCKET_API_TOKEN && export BITBUCKET_API_TOKEN
 *     read -s SNYK_TOKEN && export SNYK_TOKEN
 *     export SNYK_REGION=us        (or us02)
 *
 * Steps (every menu has "<- Back"; in multi-select lists type "b"):
 *   1. Snyk region                     SNYK-US-01 or SNYK-US-02
 *   2. Connect to Bitbucket Cloud      email, then API token (hidden)
 *   3. Connect to Snyk                 token (hidden), then the Snyk Group
 *   4. Template organization           must have Bitbucket connected
 *   5. Choose what to onboard          workspace -> projects -> repositories
 *                                      -> Snyk org per project; then add more
 *                                      projects, remove one, or continue
 *   6. Review and start                start now, save as a plan, change, or cancel
 *
 * Output: .mirror-state/report.csv (one row per repository) and report.json.
 * Safe to rerun: orgs and imports that already exist are reused, not duplicated.
 */

// bitbucket-snyk-mirror/bitbucket-snyk-mirror.mts
import * as fs2 from "node:fs";
import * as path3 from "node:path";
import { parseArgs } from "node:util";

// snyk_report/lib/log.mts
var useColour = Boolean(process.stderr.isTTY) && !process.env["NO_COLOR"];
var wrap = (code) => (s) => useColour ? `\x1B[${code}m${s}\x1B[0m` : s;
var c = {
  dim: wrap("2"),
  bold: wrap("1"),
  red: wrap("31"),
  yellow: wrap("33"),
  green: wrap("32"),
  cyan: wrap("36")
};
function write(line) {
  process.stderr.write(`${line}
`);
}
var log = {
  step: (msg) => write(c.cyan(`> ${msg}`)),
  info: (msg) => write(`  ${msg}`),
  dim: (msg) => write(c.dim(`  ${msg}`)),
  warn: (msg) => write(c.yellow(`  warning: ${msg}`)),
  error: (msg) => write(c.red(`error: ${msg}`)),
  blank: () => write("")
};

// snyk_report/lib/discover.mts
function attr(e, ...keys) {
  const a = e.attributes ?? {};
  for (const k of keys) {
    const v = a[k];
    if (typeof v === "string" && v !== "") return v;
  }
  return "";
}
async function collect(client, path4, params, nameKeys, hintKeys = []) {
  const out = [];
  for await (const row of client.paginate(path4, params)) {
    const id = row.id ?? "";
    if (!id) continue;
    const hint = attr(row, ...hintKeys);
    out.push({ id, name: attr(row, ...nameKeys) || id, ...hint ? { hint } : {} });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
async function listGroups(client) {
  return collect(client, "/rest/groups", { limit: "100" }, ["name", "slug"]);
}

// snyk_report/lib/regions.mts
var REGIONS = [
  { key: "us", label: "SNYK-US-01 (app.snyk.io)", url: "https://api.snyk.io" },
  { key: "us02", label: "SNYK-US-02 (app.us.snyk.io)", url: "https://api.us.snyk.io" },
  { key: "eu", label: "SNYK-EU-01 (app.eu.snyk.io)", url: "https://api.eu.snyk.io" },
  { key: "au", label: "SNYK-AU-01 (app.au.snyk.io)", url: "https://api.au.snyk.io" },
  { key: "gov", label: "SNYK-GOV-01 (app.snykgov.io)", url: "https://api.snykgov.io" }
];
var REST_VERSION = "2024-10-15";
function appUrlFor(apiBaseUrl) {
  return apiBaseUrl.replace("//api.", "//app.");
}
function describeRegion(apiBaseUrl) {
  return REGIONS.find((r) => r.url === apiBaseUrl)?.label ?? apiBaseUrl;
}

// snyk_report/lib/http.mts
var MAX_ATTEMPTS = 5;
var USER_AGENT = "snyk-auto-report";
var HttpError = class extends Error {
  status;
  requestId;
  constructor(message, status, requestId) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.requestId = requestId;
  }
};
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function backoff(attempt) {
  return Math.min(6e4, 2 ** attempt * 1e3 + Math.floor(Math.random() * 1e3));
}
var SAFE_QUERY_PARAMS = /* @__PURE__ */ new Set([
  "version",
  "limit",
  "exclude_empty",
  "starting_after",
  "ending_before",
  "cursor",
  "url",
  "expand",
  "meta.latest_issue_counts",
  "created_after",
  "include_code_flows",
  "scan_item.id",
  "scan_item.type"
]);
function redactUrl(url) {
  try {
    const u = new URL(url);
    if (!u.search) return `${u.origin}${u.pathname}`;
    const parts = [];
    let anySafe = false;
    for (const [k, v] of u.searchParams) {
      const safe = SAFE_QUERY_PARAMS.has(k);
      if (safe) anySafe = true;
      parts.push(`${k}=${safe ? v : "<redacted>"}`);
    }
    if (!anySafe) return `${u.origin}${u.pathname}?<signed>`;
    return `${u.origin}${u.pathname}?${parts.join("&")}`;
  } catch {
    return "<url>";
  }
}
async function readBody(res) {
  const text = await res.text();
  const type = res.headers.get("content-type") ?? "";
  if (text && type.includes("json")) {
    try {
      return { text, json: JSON.parse(text) };
    } catch {
    }
  }
  return { text, json: text };
}
async function request(url, init) {
  let lastError;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    let res;
    try {
      res = await fetch(url, init);
    } catch (error) {
      lastError = error;
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(backoff(attempt));
      continue;
    }
    const headers = {};
    res.headers.forEach((v, k) => headers[k.toLowerCase()] = v);
    if ((res.status === 429 || res.status >= 500) && attempt < MAX_ATTEMPTS) {
      const retryAfter = Number(headers["retry-after"]);
      const wait = Number.isFinite(retryAfter) ? retryAfter * 1e3 : backoff(attempt);
      log.dim(`${res.status} from ${redactUrl(url)}, retrying in ${Math.round(wait / 1e3)}s`);
      await sleep(wait);
      continue;
    }
    const { json } = await readBody(res);
    return {
      status: res.status,
      headers,
      data: json,
      requestId: headers["snyk-request-id"] ?? headers["x-request-id"]
    };
  }
  const cause = lastError?.cause;
  throw new Error(
    `Could not reach ${redactUrl(url)} after ${MAX_ATTEMPTS} attempts: ${cause?.code ?? cause?.message ?? lastError?.message ?? "network error"}. Check the URL, your network, and any proxy or self-signed certificate settings (NODE_EXTRA_CA_CERTS, HTTPS_PROXY).`
  );
}
function describeError(res) {
  const id = res.requestId ? ` (snyk-request-id: ${res.requestId})` : "";
  const body = res.data;
  if (typeof body === "string") {
    const trimmed = body.trim();
    return `${res.status}${trimmed ? `: ${trimmed.slice(0, 500)}` : ""}${id}`;
  }
  const parts = [];
  for (const e of body?.errors ?? []) {
    const line = [e.title, e.detail].filter(Boolean).join(" - ");
    if (line) parts.push(line);
    if (e.source) parts.push(`at ${JSON.stringify(e.source)}`);
  }
  if (parts.length === 0 && (body?.message || body?.error)) {
    parts.push(String(body.message ?? body.error));
  }
  if (parts.length === 0 && body !== void 0) {
    parts.push(JSON.stringify(body).slice(0, 500));
  }
  return `${res.status}${parts.length ? `: ${parts.join("; ")}` : ""}${id}`;
}
var SnykClient = class {
  baseUrl;
  #token;
  #scheme = "token";
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.#token = token;
  }
  get scheme() {
    return this.#scheme;
  }
  #headers(contentType) {
    const h = {
      Authorization: `${this.#scheme} ${this.#token}`,
      "User-Agent": USER_AGENT
    };
    if (contentType) h["Content-Type"] = contentType;
    return h;
  }
  /**
   * Work out which Authorization scheme this token wants, and pin it.
   *
   * Snyk personal tokens authenticate as `token <t>`, while service-account
   * and OAuth tokens (snyk_sat. / snyk_uat.) need `Bearer <t>`. The wrong one
   * returns a bare 401 that is indistinguishable from an invalid token, which
   * sends people off debugging the wrong problem -- bulk-import hardcodes
   * `token` and simply fails against a service account. So try both once and
   * remember the winner.
   */
  async detectAuth() {
    let last;
    for (const scheme of ["token", "Bearer"]) {
      this.#scheme = scheme;
      const res = await request(
        `${this.baseUrl}/rest/self?version=${REST_VERSION}`,
        { method: "GET", headers: this.#headers("application/vnd.api+json") }
      );
      if (res.status >= 200 && res.status < 300) {
        const a = res.data?.data?.attributes ?? {};
        return { name: a["name"] ?? a["username"] ?? "unknown", email: a["email"] };
      }
      last = res;
    }
    throw new HttpError(
      `Token rejected by ${this.baseUrl}. Snyk tokens are region-specific, so a token from another region fails here with exactly this error. ${describeError(last)}`,
      last.status,
      last.requestId
    );
  }
  async get(path4, params = {}) {
    const url = new URL(path4.startsWith("http") ? path4 : `${this.baseUrl}${path4}`);
    if (!url.searchParams.has("version")) url.searchParams.set("version", REST_VERSION);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const res = await request(url.toString(), {
      method: "GET",
      headers: this.#headers("application/vnd.api+json")
    });
    if (res.status < 200 || res.status >= 300) {
      throw new HttpError(describeError(res), res.status, res.requestId);
    }
    return res.data;
  }
  async post(path4, body) {
    const url = new URL(path4.startsWith("http") ? path4 : `${this.baseUrl}${path4}`);
    if (!url.searchParams.has("version")) url.searchParams.set("version", REST_VERSION);
    return request(url.toString(), {
      method: "POST",
      headers: this.#headers("application/vnd.api+json"),
      body: JSON.stringify(body)
    });
  }
  /**
   * Any method, returning the raw response instead of throwing on a non-2xx.
   *
   * The v1 API is a different service from REST: it wants plain
   * application/json, and has no `version` parameter. Sending it the JSON:API
   * content type that `post()` uses can leave the body unparsed, so the
   * format is chosen from the path.
   */
  async send(method, path4, body) {
    const url = new URL(path4.startsWith("http") ? path4 : `${this.baseUrl}${path4}`);
    const isV1 = url.pathname.startsWith("/v1/") || url.pathname.startsWith("/api/v1/");
    if (!isV1 && !url.searchParams.has("version")) url.searchParams.set("version", REST_VERSION);
    const init = {
      method,
      headers: this.#headers(isV1 ? "application/json" : "application/vnd.api+json")
    };
    if (body !== void 0) init.body = JSON.stringify(body);
    return request(url.toString(), init);
  }
  async put(path4, body) {
    return this.send("PUT", path4, body);
  }
  async patch(path4, body) {
    return this.send("PATCH", path4, body);
  }
  /**
   * Follow every page of a cursor-paginated collection.
   *
   * Four independent termination guards, because no single one is sufficient
   * and the failure mode of getting this wrong is a silently truncated report:
   *   - no links.next
   *   - a page with no rows
   *   - a cursor we have already followed (server-side loop)
   *   - a hard page cap
   *
   * The original query params are deliberately NOT re-applied to the next
   * URL: that link already carries the cursor, and re-adding the initial
   * params can reset it and loop forever.
   */
  async *paginate(path4, params = {}, opts = {}) {
    const maxPages = opts.maxPages ?? 2e4;
    let url = this.#absolute(path4, params);
    const seenCursors = /* @__PURE__ */ new Set();
    for (let page = 1; url && page <= maxPages; page++) {
      const doc = await this.get(url);
      const rows = doc.data ?? [];
      if (rows.length === 0) return;
      for (const row of rows) yield row;
      const next = this.#resolveNext(doc.links?.next);
      if (!next) return;
      if (seenCursors.has(next)) {
        log.warn("the API returned a page cursor it had already given us; stopping to avoid a loop");
        return;
      }
      seenCursors.add(next);
      url = next;
    }
  }
  #absolute(path4, params) {
    const url = new URL(path4.startsWith("http") ? path4 : `${this.baseUrl}${path4}`);
    if (!url.searchParams.has("version")) url.searchParams.set("version", REST_VERSION);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return url.toString();
  }
  /**
   * Resolve a links.next value.
   *
   * Two shapes exist in the wild -- a plain string and `{ href }` -- and
   * assuming string yields undefined and a silently short dataset. Snyk also
   * emits relative links WITHOUT the /rest prefix, a quirk already documented
   * in empty-targets/snyk_delete_empty_targets.py:199.
   */
  #resolveNext(next) {
    const raw = typeof next === "string" ? next : next?.href;
    if (!raw) return void 0;
    let resolved;
    if (raw.startsWith("http")) resolved = raw;
    else if (raw.startsWith("/rest/")) resolved = this.baseUrl + raw;
    else resolved = `${this.baseUrl}/rest${raw.startsWith("/") ? "" : "/"}${raw}`;
    if (new URL(resolved).origin !== new URL(this.baseUrl).origin) {
      throw new Error(`refusing to follow a pagination link to another origin: ${redactUrl(resolved)}`);
    }
    return resolved;
  }
};

// snyk_report/lib/prompt.mts
import { createInterface } from "node:readline/promises";
import { stdin, stderr } from "node:process";
function isInteractive() {
  return Boolean(stdin.isTTY);
}
function requireInteractive(what, flag) {
  if (!isInteractive()) {
    throw new Error(
      `${what} is needed but this is not an interactive terminal. Pass ${flag} instead.`
    );
  }
}
var InputClosedError = class extends Error {
  constructor() {
    super("input closed before the question was answered");
    this.name = "InputClosedError";
  }
};
var shared = null;
var queued = [];
var waiting = null;
var inputClosed = false;
var notifyClosed = null;
function reader() {
  if (!shared) {
    inputClosed = false;
    const r = createInterface({ input: stdin, output: stderr });
    r.on("line", (line) => {
      if (waiting) {
        const w = waiting;
        waiting = null;
        w(line);
      } else {
        queued.push(line);
      }
    });
    r.once("close", () => {
      inputClosed = true;
      shared = null;
      notifyClosed?.();
    });
    shared = r;
  }
  return shared;
}
function closePrompts() {
  shared?.close();
  shared = null;
  queued.length = 0;
  waiting = null;
}
function nextLine() {
  const buffered = queued.shift();
  if (buffered !== void 0) return Promise.resolve(buffered);
  if (inputClosed) return Promise.reject(new InputClosedError());
  return new Promise((resolve3, reject) => {
    waiting = resolve3;
    notifyClosed = () => {
      waiting = null;
      notifyClosed = null;
      reject(new InputClosedError());
    };
  });
}
async function ask(question, fallback) {
  reader();
  const suffix = fallback ? c.dim(` [${fallback}]`) : "";
  stderr.write(`${c.cyan("?")} ${question}${suffix} `);
  const answer = (await nextLine()).trim();
  return answer || fallback || "";
}
async function askSecret(question) {
  if (!isInteractive()) throw new Error("cannot prompt for a secret without a TTY");
  closePrompts();
  stderr.write(`${c.cyan("?")} ${question} `);
  return new Promise((resolve3, reject) => {
    let value = "";
    const wasRaw = stdin.isRaw ?? false;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const done = (err) => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
      stderr.write("\n");
      if (err) reject(err);
      else resolve3(value);
    };
    const onData = (chunk) => {
      for (const ch of chunk) {
        switch (ch) {
          case "\n":
          case "\r":
          case "":
            done();
            return;
          case "":
            done(new Error("cancelled"));
            return;
          case "\x7F":
          // backspace
          case "\b":
            value = value.slice(0, -1);
            break;
          default:
            if (ch >= " ") value += ch;
        }
      }
    };
    stdin.on("data", onData);
  });
}
function renderChoices(choices, limit = 40) {
  const shown = choices.slice(0, limit);
  const width = String(choices.length).length;
  for (const [i, ch] of shown.entries()) {
    const n = String(i + 1).padStart(width);
    const hint = ch.hint ? c.dim(`  ${ch.hint}`) : "";
    stderr.write(`  ${c.bold(n)}. ${ch.label}${hint}
`);
  }
  if (choices.length > shown.length) {
    stderr.write(c.dim(`  ... and ${choices.length - shown.length} more (type to filter)
`));
  }
}
async function choose(title, choices) {
  if (choices.length === 0) throw new Error(`nothing to choose from for: ${title}`);
  if (choices.length === 1) {
    stderr.write(`${c.cyan(">")} ${title}: ${c.bold(choices[0].label)} ${c.dim("(only option)")}
`);
    return choices[0].value;
  }
  requireInteractive(title, "--help for the non-interactive flags");
  let pool = choices;
  for (let attempt = 0; ; attempt++) {
    if (attempt >= 25) throw new Error(`no valid selection for: ${title}`);
    stderr.write(`
${c.cyan(">")} ${title}
`);
    renderChoices(pool);
    const answer = await ask("number, or text to filter");
    const n = Number(answer);
    if (Number.isInteger(n) && n >= 1 && n <= pool.length) return pool[n - 1].value;
    const needle = answer.toLowerCase();
    const filtered = choices.filter(
      (ch) => ch.label.toLowerCase().includes(needle) || (ch.hint ?? "").toLowerCase().includes(needle)
    );
    if (needle && filtered.length > 0) {
      pool = filtered;
      continue;
    }
    stderr.write(c.yellow(needle ? "  nothing matched that\n" : "  please enter a number\n"));
    pool = choices;
  }
}
function parseSelection(answer, count) {
  const picked = /* @__PURE__ */ new Set();
  for (const part of answer.split(",").map((p) => p.trim()).filter(Boolean)) {
    const range = /^(\d+)\s*-\s*(\d+)$/.exec(part);
    if (range) {
      const lo = Number(range[1]);
      const hi = Number(range[2]);
      if (lo < 1 || hi > count || lo > hi) return null;
      for (let i = lo; i <= hi; i++) picked.add(i);
      continue;
    }
    const n = Number(part);
    if (!Number.isInteger(n) || n < 1 || n > count) return null;
    picked.add(n);
  }
  return picked.size > 0 ? [...picked].sort((a, b) => a - b) : null;
}
var LOOKS_NUMERIC = /^[\d\s,-]+$/;
async function chooseMany(title, choices, opts = {}) {
  if (choices.length === 0) return [];
  requireInteractive(title, "--help for the non-interactive flags");
  const allLabel = opts.allLabel ?? "all";
  for (let attempt = 0; ; attempt++) {
    if (attempt >= 25) throw new Error(`no valid selection for: ${title}`);
    stderr.write(`
${c.cyan(">")} ${title}
`);
    renderChoices(choices);
    stderr.write(c.dim(`  or "${allLabel}" for everything
`));
    const answer = (await ask(`numbers (e.g. 1,3 or 2-6), or "${allLabel}"`, opts.defaultAll ? allLabel : void 0)).toLowerCase().trim();
    if (answer === allLabel || answer === "*") return choices.map((ch) => ch.value);
    const picked = parseSelection(answer, choices.length);
    if (picked) return picked.map((i) => choices[i - 1].value);
    stderr.write(c.yellow("  could not read that selection\n"));
  }
}
function interpretAnswer(raw, count, allLabel = "all") {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();
  if (!trimmed) return { kind: "empty" };
  if (lower === allLabel || lower === "*") return { kind: "all" };
  const picked = parseSelection(lower, count);
  if (picked) return { kind: "indexes", indexes: picked };
  if (LOOKS_NUMERIC.test(lower)) return { kind: "out-of-range" };
  return { kind: "text", text: trimmed };
}
function interpretAnswerWithAllEntry(raw, count, allLabel = "all") {
  const reading = interpretAnswer(raw, count + 1, allLabel);
  if (reading.kind !== "indexes") return reading;
  if (reading.indexes.includes(1)) return { kind: "all" };
  return { kind: "indexes", indexes: reading.indexes.map((i) => i - 1) };
}
async function chooseManyOrText(title, choices, opts) {
  if (choices.length === 0) return { kind: "values", values: [] };
  requireInteractive(title, "--help for the non-interactive flags");
  const allLabel = opts.allLabel ?? "all";
  const allEntry = opts.allEntry;
  const rows = allEntry ? [{ value: null, label: allEntry.label, hint: allEntry.hint }, ...choices] : choices;
  for (let attempt = 0; ; attempt++) {
    if (attempt >= 25) throw new Error(`no valid selection for: ${title}`);
    stderr.write(`
${c.cyan(">")} ${title}
`);
    renderChoices(rows);
    stderr.write(
      c.dim(
        allEntry ? `  or ${opts.textHint}
` : `  or "${allLabel}" for everything, or ${opts.textHint}
`
      )
    );
    const raw = (await ask(`numbers (e.g. 1,3 or 2-6), "${allLabel}", or name(s)`, opts.defaultAll ? allLabel : void 0)).trim();
    const reading = allEntry ? interpretAnswerWithAllEntry(raw, choices.length, allLabel) : interpretAnswer(raw, choices.length, allLabel);
    switch (reading.kind) {
      case "all":
        return { kind: "values", values: choices.map((ch) => ch.value) };
      case "indexes":
        return { kind: "values", values: reading.indexes.map((i) => choices[i - 1].value) };
      case "text":
        return { kind: "text", text: reading.text };
      case "out-of-range":
        stderr.write(c.yellow(`  no such entry -- the list has ${rows.length} items
`));
        continue;
      default:
        stderr.write(c.yellow("  could not read that selection\n"));
        continue;
    }
  }
}

// bitbucket-snyk-mirror/lib/app-gate.mts
var APP_INTEGRATION_TYPES = ["bitbucket-connect-app", "bitbucket-cloud-app"];
var API_TOKEN_INTEGRATION_TYPE = "bitbucket-cloud";
async function listIntegrations(snyk, orgId) {
  const res = await snyk.send("GET", `/v1/org/${orgId}/integrations`);
  if (res.status !== 200) throw new Error(`Could not list integrations for org ${orgId} (HTTP ${res.status}).`);
  const out = {};
  for (const [k, v] of Object.entries(res.data ?? {})) if (typeof v === "string" && v) out[k] = v;
  return out;
}
async function findBitbucketIntegration(snyk, orgId, allowApiToken) {
  const integrations = await listIntegrations(snyk, orgId);
  const types = [...APP_INTEGRATION_TYPES];
  if (allowApiToken) types.push(API_TOKEN_INTEGRATION_TYPE);
  for (const type of types) {
    const id = integrations[type];
    if (id) return { type, id };
  }
  return null;
}
async function createApiTokenIntegration(snyk, orgId, credentials) {
  const res = await snyk.send("POST", `/v1/org/${orgId}/integrations`, {
    type: API_TOKEN_INTEGRATION_TYPE,
    credentials: { username: credentials.email, password: credentials.token }
  });
  if (res.status < 200 || res.status >= 300 || typeof res.data?.id !== "string") {
    throw new Error(`Could not create the Bitbucket Cloud integration in org ${orgId} (HTTP ${res.status}).`);
  }
  return { type: API_TOKEN_INTEGRATION_TYPE, id: res.data.id };
}
function connectUrl(appBase, org) {
  return `${appBase}/org/${org.slug || org.id}/manage/integrations/bitbucket-connect-app`;
}

// bitbucket-snyk-mirror/lib/bitbucket.mts
var BITBUCKET_API = "https://api.bitbucket.org/2.0";
var MAX_ATTEMPTS2 = 5;
var USER_AGENT2 = "bitbucket-snyk-mirror";
var BitbucketError = class extends Error {
  status;
  constructor(message, status) {
    super(message);
    this.name = "BitbucketError";
    this.status = status;
  }
};
var HINTS = {
  401: "Check the email and API token (or the access token). Bitbucket app passwords no longer work.",
  403: "The token is missing a scope. It needs read:user, read:workspace, read:project and read:repository.",
  404: "Not found, or not visible to this token.",
  429: "Bitbucket rate limit reached (about 1,000 requests per hour). Wait and rerun."
};
function backoff2(attempt) {
  return Math.min(6e4, 2 ** attempt * 1e3 + Math.floor(Math.random() * 1e3));
}
var BitbucketClient = class {
  baseUrl;
  #authHeader;
  #fetch;
  #sleep;
  constructor(auth, opts = {}) {
    this.baseUrl = (opts.baseUrl ?? BITBUCKET_API).replace(/\/+$/, "");
    this.#authHeader = auth.kind === "basic" ? `Basic ${Buffer.from(`${auth.email}:${auth.token}`).toString("base64")}` : `Bearer ${auth.token}`;
    this.#fetch = opts.fetch ?? ((url, init) => fetch(url, init));
    this.#sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }
  /** Resolve a path or absolute link, refusing anything off the API origin. */
  url(pathOrUrl) {
    const base = new URL(this.baseUrl);
    let url;
    try {
      url = new URL(pathOrUrl.startsWith("http") ? pathOrUrl : `${this.baseUrl}/${pathOrUrl.replace(/^\/+/, "")}`);
    } catch {
      throw new BitbucketError("Invalid Bitbucket API link.", 0);
    }
    if (url.origin !== base.origin || !url.pathname.startsWith(`${base.pathname}/`) || url.username || url.password) {
      throw new BitbucketError("Refusing a Bitbucket API link to a different origin.", 0);
    }
    if (url.pathname.split("/").some((part) => part === "." || part === "..")) {
      throw new BitbucketError("Invalid Bitbucket API link.", 0);
    }
    return url.toString();
  }
  async get(pathOrUrl) {
    const url = this.url(pathOrUrl);
    for (let attempt = 1; ; attempt++) {
      let res;
      try {
        res = await this.#fetch(url, {
          method: "GET",
          redirect: "manual",
          headers: { Authorization: this.#authHeader, Accept: "application/json", "User-Agent": USER_AGENT2 }
        });
      } catch {
        if (attempt >= MAX_ATTEMPTS2) {
          throw new BitbucketError("Could not reach api.bitbucket.org (network error). Check proxy settings.", 0);
        }
        await this.#sleep(backoff2(attempt));
        continue;
      }
      if ((res.status === 429 || res.status >= 500) && attempt < MAX_ATTEMPTS2) {
        const retryAfter = Number(res.headers.get("retry-after"));
        await this.#sleep(Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter, 120) * 1e3 : backoff2(attempt));
        continue;
      }
      if (res.status >= 300 && res.status < 400) {
        throw new BitbucketError(`Bitbucket answered with a redirect (${res.status}); not following it.`, res.status);
      }
      if (!res.ok) {
        throw new BitbucketError(`Bitbucket GET returned HTTP ${res.status}. ${HINTS[res.status] ?? ""}`.trim(), res.status);
      }
      const text = await res.text();
      try {
        return text ? JSON.parse(text) : {};
      } catch {
        throw new BitbucketError("Bitbucket returned a response that is not JSON.", res.status);
      }
    }
  }
  /** Yield every row of a paginated collection, following `next`. */
  async *paginate(pathOrUrl) {
    const seen = /* @__PURE__ */ new Set();
    let next = this.url(pathOrUrl);
    while (next) {
      if (seen.has(next)) throw new BitbucketError("Bitbucket returned a repeated pagination link.", 0);
      seen.add(next);
      const page = await this.get(next);
      if (!Array.isArray(page.values)) throw new BitbucketError("Unexpected Bitbucket paginated response.", 0);
      yield* page.values;
      next = page.next ? this.url(page.next) : void 0;
    }
  }
};

// bitbucket-snyk-mirror/lib/credentials.mts
var EMAIL = /^[^\s@:+]+(?:\+[^\s@:+]+)?@[^\s@:+]+\.[^\s@:+]+$/;
var looksLikeToken = (s) => /^AT[AC]TT/.test(s) || s.length >= 40 && !s.includes("@") && !/\s/.test(s);
function interpretCredentialInput(raw) {
  const s = raw.trim();
  if (!s) return { kind: "blank" };
  if (EMAIL.test(s)) return { kind: "email", email: s };
  if (looksLikeToken(s)) return s.startsWith("ATCTT") ? { kind: "access-token", token: s } : { kind: "api-token", token: s };
  const m = /^(\S+@[^\s@:+]+\.[^\s@:+]+)[\s:+]+(\S+)$/.exec(s);
  if (m && EMAIL.test(m[1]) && looksLikeToken(m[2])) return { kind: "email+token", email: m[1], token: m[2] };
  return { kind: "invalid" };
}

// bitbucket-snyk-mirror/lib/discover.mts
var WORKSPACE_SLUG = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;
var PROJECT_KEY = /^[A-Za-z0-9_-]{1,100}$/;
function validWorkspace(slug) {
  const s = slug.trim();
  if (!WORKSPACE_SLUG.test(s)) throw new Error(`"${slug}" is not a valid Bitbucket workspace slug.`);
  return s;
}
function validProjectKey(key) {
  if (!PROJECT_KEY.test(key)) throw new Error(`"${key}" is not a valid Bitbucket project key.`);
  return key;
}
async function verifyBitbucket(client, workspaces = []) {
  try {
    const me = await client.get("/user");
    return me.display_name ?? me.username ?? me.nickname ?? "authenticated user";
  } catch (err) {
    if (!(err instanceof BitbucketError) || err.status !== 401 && err.status !== 403 || workspaces.length === 0) {
      throw err;
    }
    const ws = await client.get(`/workspaces/${encodeURIComponent(validWorkspace(workspaces[0]))}`);
    return `access to workspace ${ws.slug ?? workspaces[0]}`;
  }
}
async function listWorkspaces(client) {
  const collect2 = async (path4) => {
    const out = /* @__PURE__ */ new Map();
    for await (const row of client.paginate(path4)) {
      const ws = row.workspace ?? row;
      if (ws.slug && WORKSPACE_SLUG.test(ws.slug)) out.set(ws.slug, { slug: ws.slug, name: ws.name ?? ws.slug });
    }
    return [...out.values()].sort((a, b) => a.name.localeCompare(b.name));
  };
  try {
    return await collect2("/user/workspaces?pagelen=100");
  } catch (err) {
    if (!(err instanceof BitbucketError) || ![403, 404, 410].includes(err.status)) throw err;
    return collect2("/workspaces?pagelen=100");
  }
}
async function listProjects(client, workspace) {
  const ws = encodeURIComponent(validWorkspace(workspace));
  const out = [];
  for await (const row of client.paginate(
    `/workspaces/${ws}/projects?pagelen=100`
  )) {
    if (row.key && PROJECT_KEY.test(row.key)) out.push({ key: row.key, name: row.name ?? row.key, uuid: row.uuid ?? "" });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
async function listRepositories(client, workspace, projectKey) {
  const ws = encodeURIComponent(validWorkspace(workspace));
  const q = encodeURIComponent(`project.key="${validProjectKey(projectKey)}"`);
  const fields = encodeURIComponent(
    "next,values.slug,values.name,values.uuid,values.mainbranch.name,values.links.html.href,values.project.key"
  );
  const out = /* @__PURE__ */ new Map();
  for await (const row of client.paginate(`/repositories/${ws}?q=${q}&pagelen=100&fields=${fields}`)) {
    if (!row.slug || out.has(row.slug)) continue;
    if (row.project?.key !== void 0 && row.project.key !== projectKey) continue;
    out.set(row.slug, {
      slug: row.slug,
      name: row.name ?? row.slug,
      uuid: row.uuid ?? "",
      branch: row.mainbranch?.name || null,
      url: row.links?.html?.href ?? `https://bitbucket.org/${workspace}/${row.slug}`
    });
  }
  return [...out.values()].sort((a, b) => a.slug.localeCompare(b.slug));
}
async function discoverProject(client, workspace, project) {
  return {
    key: `${workspace}/${project.key}`,
    workspace,
    projectKey: project.key,
    projectName: project.name,
    projectUuid: project.uuid,
    repositories: await listRepositories(client, workspace, project.key)
  };
}

// bitbucket-snyk-mirror/lib/jobs.mts
var SNYK_HOSTS = /* @__PURE__ */ new Set([
  "api.snyk.io",
  "api.us.snyk.io",
  "api.eu.snyk.io",
  "api.au.snyk.io",
  "snyk.io",
  "app.snyk.io",
  "app.us.snyk.io",
  "app.eu.snyk.io",
  "app.au.snyk.io"
]);
async function listGroupOrgs(snyk, groupId) {
  const out = [];
  for await (const row of snyk.paginate(
    `/rest/groups/${groupId}/orgs`,
    { limit: "100" }
  )) {
    if (!row.id) continue;
    out.push({ id: row.id, name: row.attributes?.name ?? row.id, slug: row.attributes?.slug ?? "" });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
function normalizeJobPath(location, orgId, integrationId) {
  let parsed;
  try {
    parsed = new URL(location, "https://api.snyk.io");
  } catch {
    throw new Error("Import job Location is not a valid URL.");
  }
  if (parsed.protocol !== "https:" || !SNYK_HOSTS.has(parsed.host)) {
    throw new Error("Import job Location points to an unrecognized origin.");
  }
  if (parsed.search || parsed.hash) throw new Error("Unexpected import job Location.");
  let p = parsed.pathname;
  if (p.startsWith("/api/v1/")) p = p.slice(4);
  const prefix = `/v1/org/${orgId}/integrations/${integrationId}/import/`;
  if (!p.startsWith(prefix) || !/^[A-Za-z0-9_-]+$/.test(p.slice(prefix.length))) {
    throw new Error("Import job Location does not match the organization and integration.");
  }
  return p;
}
function summarizeJob(body) {
  const logs = body.logs ?? [];
  const entries = logs.flatMap((l) => l.projects ?? []);
  const good = [];
  for (const project of entries) {
    let id = project.projectId;
    if (!id && project.projectUrl) {
      id = /\/project\/([0-9a-fA-F-]{36})(?:\/|$)/.exec(project.projectUrl)?.[1];
    }
    if (project.success === true && id) good.push(id);
  }
  const projectIds = [...new Set(good)].sort();
  const some = projectIds.length > 0;
  switch (body.status) {
    case "pending":
      return { status: "pending", projectIds };
    case "failed":
    case "aborted":
      return { status: some ? "partial" : "failed", projectIds };
    case "complete":
      if (logs.some((l) => l.truncated || l.status !== "complete") || good.length !== entries.length) {
        return { status: some ? "partial" : "failed", projectIds };
      }
      return { status: some ? "imported" : "no-projects", projectIds };
    default:
      throw new Error(`Unknown import job status "${body.status ?? ""}".`);
  }
}

// bitbucket-snyk-mirror/lib/mapping.mts
var fold = (s) => s.trim().toLocaleLowerCase();
function findOrg(ref, orgs) {
  const r = ref.trim();
  return orgs.find((o) => o.id === r) ?? orgs.find((o) => fold(o.name) === fold(r));
}
function defaultDestination(entry, orgs, templateOrgId, saved) {
  const savedOrg = saved && orgs.find((o) => o.id === saved.orgId);
  if (savedOrg) return { kind: "existing", orgId: savedOrg.id, name: savedOrg.name };
  const byName = findOrg(entry.projectName, orgs);
  if (byName) return { kind: "existing", orgId: byName.id, name: byName.name };
  return { kind: "new", name: entry.projectName.trim().slice(0, 60) };
}
function validateMapping(projects, orgs, opts = {}) {
  const errors = [];
  const newNames = /* @__PURE__ */ new Map();
  const existingByOrg = /* @__PURE__ */ new Map();
  for (const p of projects) {
    const d = p.destination;
    if (d.kind === "new") {
      const name = d.name.trim();
      if (name.length < 1 || name.length > 60) {
        errors.push(`${p.key}: org names must be 1 to 60 characters.`);
        continue;
      }
      const clash = opts.allowExistingNames ? void 0 : findOrg(name, orgs);
      if (clash) {
        errors.push(`${p.key}: an org named "${clash.name}" already exists; choose "use existing" instead.`);
      }
      const other = newNames.get(fold(name));
      if (other) errors.push(`${p.key} and ${other} would both create an org named "${name}".`);
      newNames.set(fold(name), p.key);
    } else if (d.kind === "existing") {
      if (!orgs.some((o) => o.id === d.orgId)) errors.push(`${p.key}: org ${d.orgId} is not in the selected Snyk Group.`);
      const set = existingByOrg.get(d.orgId) ?? /* @__PURE__ */ new Set();
      set.add(p.workspace);
      existingByOrg.set(d.orgId, set);
    }
  }
  for (const [orgId, workspaces] of existingByOrg) {
    if (workspaces.size > 1) {
      const name = orgs.find((o) => o.id === orgId)?.name ?? orgId;
      errors.push(
        `"${name}" would receive projects from workspaces ${[...workspaces].join(", ")}; the Bitbucket Cloud App connects one workspace per Snyk org.`
      );
    }
  }
  return errors;
}
function splitCsvLine(line) {
  const out = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  out.push(cur.trim());
  return out;
}
function csvField(value) {
  const s = String(value);
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}
function parseMappingCsv(text) {
  const rows = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [workspace = "", projectKey = "", org = ""] = splitCsvLine(line);
    if (i === 0 && fold(workspace) === "workspace") continue;
    if (!workspace || !projectKey || !org) throw new Error(`Mapping file line ${i + 1}: expected workspace,projectKey,org`);
    rows.push({ workspace, projectKey, org });
  }
  return rows;
}
function applyMapping(projects, rows, orgs) {
  const byKey = new Map(rows.map((r) => [`${r.workspace}/${r.projectKey}`.toLowerCase(), r]));
  const mapped = [];
  const unmentioned = [];
  for (const p of projects) {
    const row = byKey.get(p.key.toLowerCase());
    let destination;
    if (!row) {
      unmentioned.push(p.key);
      destination = { kind: "skip" };
    } else if (fold(row.org) === "skip") {
      destination = { kind: "skip" };
    } else {
      const org = findOrg(row.org, orgs);
      destination = org ? { kind: "existing", orgId: org.id, name: org.name } : { kind: "new", name: row.org.trim() };
    }
    mapped.push({ ...p, destination });
  }
  return { mapped, unmentioned };
}
var plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
function projectLabel(p) {
  return `"${p.projectName}" (project ${p.projectKey}, workspace ${p.workspace})`;
}
function describeDestination(d, templateName = "the template", templateOrgId) {
  if (d.kind === "new") return `Snyk org "${d.name}"  [new, created from ${templateName}]`;
  if (d.kind === "existing") return `Snyk org "${d.name}"  [${d.orgId === templateOrgId ? "the template org itself" : "existing"}]`;
  return "(skipped)";
}
function summaryTree(projects, templateName, templateOrgId) {
  const lines = [];
  const template = templateName ? `template "${templateName}"` : "the template";
  for (const ws of [...new Set(projects.map((p) => p.workspace))]) {
    lines.push(`Workspace ${ws}`);
    for (const p of projects.filter((x) => x.workspace === ws)) {
      lines.push(`  Project "${p.projectName}" (${p.projectKey})  ->  ${describeDestination(p.destination, template, templateOrgId)}`);
      if (p.destination.kind === "skip") continue;
      for (const r of p.repositories) lines.push(`    - ${r.slug}${r.branch ? `  (${r.branch})` : "  (empty, nothing to import)"}`);
    }
  }
  return lines;
}
function nextSteps(projects, templateName, reportPath, templateOrgId) {
  const active = projects.filter((p) => p.destination.kind !== "skip");
  const created = [...new Set(active.flatMap((p) => p.destination.kind === "new" ? [p.destination.name] : []))];
  const reused = [
    ...new Set(
      active.flatMap(
        (p) => p.destination.kind === "existing" && p.destination.orgId !== templateOrgId ? [p.destination.name] : []
      )
    )
  ];
  const intoTemplate = active.some((p) => p.destination.kind === "existing" && p.destination.orgId === templateOrgId);
  const repos = active.reduce((n, p) => n + p.repositories.filter((r) => r.branch).length, 0);
  const steps = [];
  const quote = (names) => names.map((n) => `"${n}"`).join(", ");
  if (created.length) {
    steps.push(`Create ${plural(created.length, "Snyk org", "Snyk orgs")} from template${templateName ? ` "${templateName}"` : ""}: ${quote(created)}`);
  }
  if (intoTemplate) steps.push(`Use the template org itself${templateName ? ` "${templateName}"` : ""} (its settings are left as they are)`);
  if (reused.length) steps.push(`Use ${plural(reused.length, "existing org", "existing orgs")}: ${quote(reused)}`);
  steps.push("Check each org has a Bitbucket integration. An org without one fails and nothing is imported into it");
  if (reused.length) steps.push(`Apply the template's settings to the existing ${reused.length === 1 ? "org" : "orgs"} (new orgs already get them from the template copy)`);
  steps.push(`Import ${plural(repos, "repository", "repositories")} and wait for Snyk to finish`);
  steps.push(`Save the results to ${reportPath}`);
  return steps.map((step, i) => `${i + 1}. ${step}`);
}
function mappingCsv(projects) {
  const lines = ["workspace,projectKey,org"];
  for (const p of projects) {
    const d = p.destination;
    lines.push([p.workspace, p.projectKey, d.kind === "skip" ? "skip" : d.name].map(csvField).join(","));
  }
  return `${lines.join("\n")}
`;
}

// bitbucket-snyk-mirror/lib/state.mts
import * as fs from "node:fs";
import * as path from "node:path";
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 448 });
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}-${process.pid}-${Date.now()}`);
  try {
    const fd = fs.openSync(tmp, "w", 384);
    try {
      fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}
`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}
function writeText(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 448 });
  fs.writeFileSync(file, text, { mode: 384 });
}
function localPath(value) {
  const base = fs.realpathSync(process.cwd());
  const resolved = path.resolve(base, value);
  const rel = path.relative(base, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error("Output, plan and state paths must be inside the current working directory.");
  }
  return resolved;
}
function loadState(dir, binding) {
  const file = path.join(dir, "state.json");
  if (!fs.existsSync(file)) return { version: 1, binding, orgs: {}, jobs: {} };
  const state = JSON.parse(fs.readFileSync(file, "utf8"));
  if (state.version !== 1 || JSON.stringify(state.binding) !== JSON.stringify(binding)) {
    throw new Error(
      "This state directory belongs to a different Snyk region or Group. Use a different --state-dir."
    );
  }
  state.orgs ??= {};
  state.jobs ??= {};
  return state;
}
function peekState(dir) {
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, "state.json"), "utf8"));
  } catch {
    return null;
  }
}
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === "EPERM";
  }
}
async function withLock(dir, fn) {
  fs.mkdirSync(dir, { recursive: true, mode: 448 });
  const lock = path.join(dir, "run.lock");
  for (let attempt = 0; ; attempt++) {
    try {
      fs.writeFileSync(lock, String(process.pid), { flag: "wx", mode: 384 });
      break;
    } catch (err) {
      if (err.code !== "EEXIST" || attempt > 0) {
        throw new Error("Another sync is using this state directory.");
      }
      const pid = Number(fs.readFileSync(lock, "utf8").trim());
      if (Number.isInteger(pid) && pid > 0 && alive(pid)) {
        throw new Error(`Another sync (PID ${pid}) is using this state directory.`);
      }
      fs.rmSync(lock, { force: true });
    }
  }
  try {
    return await fn();
  } finally {
    fs.rmSync(lock, { force: true });
  }
}

// bitbucket-snyk-mirror/lib/wizard.mts
var BACK = Symbol("back");
var BACK_WORDS = /* @__PURE__ */ new Set(["b", "back", "<"]);
var isBackWord = (answer) => BACK_WORDS.has(answer.trim().toLowerCase());
function stepHeader(n, total, title) {
  log.blank();
  log.step(c.bold(`Step ${n} of ${total}: ${title}`));
}
async function pick(title, choices, opts = {}) {
  if (!opts.back) return choose(title, choices);
  const rows = [...choices, { value: BACK, label: "\u2190 Back" }];
  return choose(title, rows);
}
async function pickMany(title, choices, opts = {}) {
  for (; ; ) {
    const answer = await chooseManyOrText(title, choices, {
      defaultAll: opts.defaultAll ?? true,
      textHint: opts.back ? '"b" to go back' : "press Enter for all"
    });
    if (answer.kind === "values") return answer.values;
    if (opts.back && isBackWord(answer.text)) return BACK;
    log.warn(`could not read "${answer.text}"; enter numbers like 1,3 or 2-5, "all"${opts.back ? ', or "b" to go back' : ""}`);
  }
}

// bitbucket-snyk-mirror/lib/sync.mts
import * as path2 from "node:path";

// bitbucket-snyk-mirror/lib/template.mts
import { isDeepStrictEqual } from "node:util";
var TemplateError = class extends Error {
  status;
  constructor(message, status) {
    super(message);
    this.name = "TemplateError";
    this.status = status;
  }
};
var NOTIFICATION_FIELDS = {
  "new-issues-remediations": ["enabled", "issueSeverity", "issueType"],
  "project-imported": ["enabled"],
  "test-limit": ["enabled"],
  "weekly-report": ["enabled"],
  "request-updates": ["enabled"],
  "pending-requests": ["enabled"]
};
var INTEGRATION_FIELDS = [
  "autoDepUpgradeLimit",
  "autoDepUpgradeIgnoredDependencies",
  "autoDepUpgradeEnabled",
  "autoDepUpgradeMinAge",
  "pullRequestFailOnAnyVulns",
  "pullRequestFailOnlyForHighSeverity",
  "pullRequestTestCodeEnabled",
  "pullRequestTestCodeSeverity",
  "pullRequestTestSecretsEnabled",
  "pullRequestTestSecretsSeverity",
  "pullRequestTestEnabled",
  "pullRequestAssignment",
  "dockerfileSCMEnabled"
];
var NESTED_INTEGRATION_FIELDS = {
  autoRemediationPrs: ["backlogPrsEnabled", "backlogPrStrategy", "freshPrsEnabled", "usePatchRemediation"],
  manualRemediationPrs: ["useManualPatchRemediation"]
};
var IAC_FIELDS = ["inherit_from_parent", "is_enabled", "oci_registry_tag", "oci_registry_url"];
var LANGUAGE_FIELDS = {
  javascript: Object.fromEntries(
    ["npm", "yarn", "pnpm"].map((k) => [k, ["include_dev_dependencies", "strict_out_of_sync", "exclude_lockfile_in_pr", "registries"]])
  ),
  python: { pip: ["python_version"], pipenv: ["include_dev_dependencies"], poetry: ["include_dev_dependencies"] },
  dotnet: { nuget: ["include_dev_dependencies"] },
  php: { composer: ["include_dev_dependencies"] },
  golang: { gomodules: ["full_source_code_analysis"] },
  java: { maven: ["mirrors", "repositories"] }
};
var REPOSITORY_FIELDS = ["type", "repository", "integration_type", "url", "scope", "mirror_of"];
var REST_SETTINGS = {
  sast: { suffix: "sast", read: "2023-06-22", write: "2023-09-11" },
  iac: { suffix: "iac", read: "2021-12-09", write: "2021-12-09" },
  languages: { suffix: "open_source/languages", read: "2024-08-25~beta", write: "2024-08-25~beta" }
};
var isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
function pick2(value, fields) {
  if (!isObj(value)) return {};
  const out = {};
  for (const k of fields) if (k in value) out[k] = structuredClone(value[k]);
  return out;
}
var nonEmpty = (o) => Object.keys(o).length > 0;
function selectOrganization(v) {
  const item = pick2(v["requestAccess"], ["enabled"]);
  return nonEmpty(item) ? { requestAccess: item } : {};
}
function selectNotifications(v) {
  const out = {};
  for (const [k, fields] of Object.entries(NOTIFICATION_FIELDS)) {
    const item = pick2(v[k], fields);
    if (nonEmpty(item)) out[k] = item;
  }
  return out;
}
function selectIntegrationSettings(v) {
  const out = pick2(v, INTEGRATION_FIELDS);
  for (const [k, fields] of Object.entries(NESTED_INTEGRATION_FIELDS)) {
    const item = pick2(v[k], fields);
    if (nonEmpty(item)) out[k] = item;
  }
  return out;
}
function attributes(v) {
  const data = v["data"];
  return isObj(data) && isObj(data["attributes"]) ? data["attributes"] : {};
}
var selectSast = (v) => pick2(attributes(v), ["sast_enabled"]);
function selectIac(v) {
  const item = pick2(attributes(v)["custom_rules"], IAC_FIELDS);
  return nonEmpty(item) ? { custom_rules: item } : {};
}
function selectLanguages(v) {
  const languages = attributes(v)["languages"];
  const out = {};
  if (!isObj(languages)) return out;
  for (const [language, managers] of Object.entries(LANGUAGE_FIELDS)) {
    const source = languages[language];
    if (!isObj(source)) continue;
    const selected = {};
    for (const [manager, fields] of Object.entries(managers)) {
      const item = pick2(source[manager], fields);
      for (const key of ["registries", "repositories", "mirrors"]) {
        if (key in item) {
          const rows = item[key];
          if (!Array.isArray(rows)) throw new TemplateError("Template language registry settings have an invalid shape.");
          item[key] = rows.map((row) => pick2(row, REPOSITORY_FIELDS));
        }
      }
      if (nonEmpty(item)) selected[manager] = item;
    }
    if (nonEmpty(selected)) out[language] = selected;
  }
  return out;
}
async function call(snyk, method, path4, body) {
  let res;
  try {
    res = await snyk.send(method, path4, body);
  } catch {
    throw new TemplateError(`Template API ${method} failed: network error.`);
  }
  if (res.status < 200 || res.status >= 300) {
    throw new TemplateError(`${method} returned ${describeError(res)}`, res.status);
  }
  if (res.data === void 0 || res.data === "") return {};
  if (!isObj(res.data)) throw new TemplateError("Template API returned an invalid response shape.");
  return res.data;
}
async function optional(snyk, path4, category, limits) {
  try {
    return await call(snyk, "GET", path4);
  } catch (err) {
    if (!(err instanceof TemplateError) || err.status !== 403 && err.status !== 404) throw err;
    limits.push({
      category,
      reason: err.status === 403 ? "HTTP 403: the token cannot read this template setting." : "HTTP 404: setting unavailable or inaccessible for this template."
    });
    return null;
  }
}
async function loadTemplate(snyk, templateId, scmIntegrationId) {
  const template = { id: templateId, settings: {}, limitations: [] };
  const limits = template.limitations;
  const v1 = [
    ["organization", "settings", selectOrganization],
    ["notifications", "notification-settings", selectNotifications]
  ];
  for (const [category, suffix, select] of v1) {
    const value = await optional(snyk, `/v1/org/${templateId}/${suffix}`, category, limits);
    if (!value) continue;
    const selected = select(value);
    if (nonEmpty(selected)) template.settings[category] = selected;
    else limits.push({ category, reason: "No supported writable fields returned." });
  }
  if (scmIntegrationId) {
    const value = await optional(snyk, `/v1/org/${templateId}/integrations/${scmIntegrationId}/settings`, "scm_integration", limits);
    if (value) {
      const selected = selectIntegrationSettings(value);
      if (nonEmpty(selected)) template.settings["scm_integration"] = selected;
      else limits.push({ category: "scm_integration", reason: "No supported writable fields returned." });
    }
  } else {
    limits.push({ category: "scm_integration", reason: "The template has no Bitbucket integration to copy settings from." });
  }
  const rest = [
    ["sast", selectSast],
    ["iac", selectIac],
    ["languages", selectLanguages]
  ];
  for (const [category, select] of rest) {
    const { suffix, read } = REST_SETTINGS[category];
    const value = await optional(snyk, `/rest/orgs/${templateId}/settings/${suffix}?version=${read}`, category, limits);
    if (!value) continue;
    const selected = select(value);
    if (!nonEmpty(selected)) {
      limits.push({ category, reason: "No supported writable fields returned." });
      continue;
    }
    template.settings[category] = selected;
    if (category === "sast") {
      const data = value["data"];
      const kind = isObj(data) ? data["type"] : void 0;
      if (typeof kind !== "string" || !kind) throw new TemplateError("Template SAST resource type is missing.");
      template.sastType = kind;
    }
  }
  limits.push({
    category: "other_settings",
    reason: "Reused organizations: policies, ignores, members, service accounts, other integrations and undocumented settings are not synchronized. New organizations also use sourceOrgId."
  });
  return template;
}
function contains(actual, desired) {
  if (isObj(desired)) {
    return isObj(actual) && Object.entries(desired).every(([k, v]) => k in actual && contains(actual[k], v));
  }
  return isDeepStrictEqual(actual, desired);
}
async function writeVerify(snyk, method, writePath, payload, readPath, desired, select, category) {
  await call(snyk, method, writePath, payload);
  const actual = select(await call(snyk, "GET", readPath));
  if (!contains(actual, desired)) {
    throw new TemplateError("the value read back after writing does not match the template.");
  }
}
async function applyTemplateSettings(snyk, template, orgId, integrationId) {
  const result = { copied: [], skipped: structuredClone(template.limitations), issues: [] };
  if (orgId === template.id) {
    result.skipped.push({ category: "template", reason: "Source template is unchanged." });
    return result;
  }
  const attempt = async (category, fn) => {
    try {
      await fn();
      result.copied.push(category);
    } catch (err) {
      if (!(err instanceof TemplateError)) throw err;
      result.issues.push(`${category}: ${err.message}`);
    }
  };
  const values = template.settings;
  const v1 = [
    ["organization", "settings", selectOrganization],
    ["notifications", "notification-settings", selectNotifications]
  ];
  for (const [category, suffix, select] of v1) {
    const desired = values[category];
    if (!isObj(desired)) continue;
    const p = `/v1/org/${orgId}/${suffix}`;
    await attempt(category, () => writeVerify(snyk, "PUT", p, desired, p, desired, select, category));
  }
  const scm = values["scm_integration"];
  if (isObj(scm)) {
    await attempt("scm_integration", async () => {
      if (!integrationId) throw new TemplateError("A Bitbucket integration is required to copy its settings.");
      const p = `/v1/org/${orgId}/integrations/${integrationId}/settings`;
      await writeVerify(snyk, "PUT", p, scm, p, scm, selectIntegrationSettings, "scm_integration");
    });
  }
  for (const [category, select] of [["sast", selectSast], ["iac", selectIac]]) {
    const desired = values[category];
    if (!isObj(desired)) continue;
    const { suffix, read, write: write2 } = REST_SETTINGS[category];
    const base = `/rest/orgs/${orgId}/settings/${suffix}?version=`;
    const data = { type: category === "sast" ? template.sastType : "iac_settings", attributes: desired };
    if (category === "sast") data["id"] = orgId;
    await attempt(category, () => writeVerify(snyk, "PATCH", base + write2, { data }, base + read, desired, select, category));
  }
  const languages = values["languages"];
  if (isObj(languages)) {
    for (const [language, managers] of Object.entries(languages)) {
      const base = `/rest/orgs/${orgId}/settings/open_source/languages`;
      const q = `?version=${REST_SETTINGS.languages.write}`;
      const payload = { data: { id: orgId, type: "language_settings", attributes: { package_managers: managers } } };
      await attempt(
        `languages/${language}`,
        () => writeVerify(snyk, "PATCH", `${base}/${language}${q}`, payload, base + q, { [language]: managers }, selectLanguages, `languages/${language}`)
      );
    }
  }
  return result;
}

// bitbucket-snyk-mirror/lib/sync.mts
var OK_STATUSES = /* @__PURE__ */ new Set(["imported", "already-imported", "no-projects", "no-default-branch"]);
async function forgetDeletedOrgs(projects, orgs, state, snyk, opts) {
  const listed = new Set(orgs.map((o) => o.id));
  const deleted = [];
  for (const p of projects) {
    const saved = state.orgs[p.key];
    if (!saved || listed.has(saved.orgId)) continue;
    const res = await snyk.send("GET", `/rest/orgs/${saved.orgId}`);
    if (res.status === 404) deleted.push(p.key);
    else if (res.status >= 400) throw new Error(`Could not check saved org ${saved.orgId}: ${describeError(res)}`);
  }
  if (deleted.length === 0) return;
  opts.io.say(`Saved Snyk orgs no longer exist for: ${deleted.join(", ")}`);
  if (!opts.forgetDeleted) {
    if (!opts.io.confirm) {
      throw new Error("Saved orgs were deleted from Snyk. Rerun with --forget-deleted-orgs to drop them from state.json.");
    }
    if (!await opts.io.confirm("Forget them and recreate or reuse them by name?")) {
      throw new Error("Saved org state was left unchanged.");
    }
  }
  const gone = /* @__PURE__ */ new Set();
  for (const key of deleted) {
    gone.add(state.orgs[key].orgId);
    delete state.orgs[key];
  }
  for (const k of Object.keys(state.jobs)) {
    if (gone.has(JSON.parse(k)[0])) delete state.jobs[k];
  }
}
async function runSync(plan, snyk, opts) {
  const { io } = opts;
  const sleep2 = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  const now = opts.now ?? (() => Date.now());
  const dir = opts.stateDir;
  const binding = { source: "bitbucket-cloud", snykApi: snyk.baseUrl, groupId: plan.groupId };
  if (plan.snykApi !== snyk.baseUrl) throw new Error("The plan was made for a different Snyk region.");
  const state = loadState(dir, binding);
  const orgs = await listGroupOrgs(snyk, plan.groupId);
  if (!orgs.some((o) => o.id === plan.templateOrgId)) {
    throw new Error("The template org must be in the destination Snyk Group.");
  }
  const projects = plan.projects.filter((p) => p.destination.kind !== "skip");
  await forgetDeletedOrgs(projects, orgs, state, snyk, opts);
  const errors = validateMapping(projects, orgs, { allowExistingNames: true });
  if (errors.length > 0) throw new Error(`The mapping cannot be applied:
  ${errors.join("\n  ")}`);
  const templateIntegration = await findBitbucketIntegration(snyk, plan.templateOrgId, true);
  if (!templateIntegration) {
    const name = orgs.find((o) => o.id === plan.templateOrgId)?.name ?? plan.templateOrgId;
    throw new Error(
      `Template org "${name}" has no Bitbucket integration, so orgs created from it could not import. Connect Bitbucket in the template (Settings > Integrations) or choose another template.`
    );
  }
  const template = await loadTemplate(snyk, plan.templateOrgId, templateIntegration?.id ?? null);
  const report = {
    binding,
    templateOrgId: plan.templateOrgId,
    templateLimitations: template.limitations,
    organizations: [],
    repositories: []
  };
  const targets = [];
  const save = () => {
    writeJson(path2.join(dir, "state.json"), state);
    writeJson(path2.join(dir, "report.json"), report);
    writeJson(path2.join(dir, "snyk-import-targets.json"), { targets });
    writeText(path2.join(dir, "report.csv"), reportCsv(report));
  };
  save();
  const orgFor = /* @__PURE__ */ new Map();
  const orgReportFor = /* @__PURE__ */ new Map();
  for (const p of projects) {
    const d = p.destination;
    const saved = state.orgs[p.key];
    let org;
    let action;
    if (d.kind === "existing") {
      org = orgs.find((o) => o.id === d.orgId);
      action = "existing";
    } else {
      const name = d.kind === "new" ? d.name.trim() : "";
      const savedOrg = saved && orgs.find((o) => o.id === saved.orgId);
      org = (savedOrg && savedOrg.name.trim().toLowerCase() === name.toLowerCase() ? savedOrg : void 0) ?? findOrg(name, orgs);
      action = "reused";
      if (!org) {
        const res = await snyk.send("POST", "/v1/org", {
          name,
          groupId: plan.groupId,
          sourceOrgId: plan.templateOrgId
        });
        if (res.status < 200 || res.status >= 300 || typeof res.data?.id !== "string") {
          throw new Error(`Could not create Snyk org "${name}": ${describeError(res)}`);
        }
        org = { id: res.data.id, name: res.data.name ?? name, slug: res.data.slug ?? "" };
        orgs.push(org);
        action = "created";
      }
    }
    if (!org) throw new Error(`${p.key}: destination org is not accessible.`);
    const createdFromTemplate = action === "created" || saved?.orgId === org.id && saved.createdFromTemplate === true;
    state.orgs[p.key] = { orgId: org.id, name: org.name, ...createdFromTemplate ? { createdFromTemplate: true } : {} };
    const orgReport = { project: p.key, name: org.name, id: org.id, action, appConnection: "missing" };
    report.organizations.push(orgReport);
    orgFor.set(p.key, org);
    orgReportFor.set(p.key, orgReport);
    save();
    io.say(`Project "${p.projectName}" (workspace ${p.workspace}) -> Snyk org "${org.name}" (${action === "created" ? "created from the template" : action})`);
  }
  const integrationFor = /* @__PURE__ */ new Map();
  const missing = /* @__PURE__ */ new Map();
  for (const p of projects) {
    const org = orgFor.get(p.key);
    if (integrationFor.has(org.id) || missing.has(org.id)) continue;
    let integration = await findBitbucketIntegration(snyk, org.id, true);
    if (!integration && opts.fallbackCredentials) {
      integration = await createApiTokenIntegration(snyk, org.id, opts.fallbackCredentials);
    }
    if (integration) integrationFor.set(org.id, integration);
    else missing.set(org.id, org);
  }
  for (const org of missing.values()) {
    io.say(`FAILED: Snyk org "${org.name}" has no Bitbucket integration; nothing will be imported into it.`);
    io.say(`        Connect it here, then rerun sync: ${connectUrl(opts.appBase, org)}`);
  }
  for (const p of projects) {
    const integration = integrationFor.get(orgFor.get(p.key).id);
    const r = orgReportFor.get(p.key);
    if (integration) {
      r.appConnection = integration.type === "bitbucket-cloud" ? "api-token-fallback" : "connected";
      r.integrationType = integration.type;
    }
  }
  save();
  const settingsFor = /* @__PURE__ */ new Map();
  const polling = [];
  for (const p of projects) {
    const org = orgFor.get(p.key);
    const integration = integrationFor.get(org.id);
    const rowFor = (repo, status, message) => {
      const row = {
        workspace: p.workspace,
        project: p.projectKey,
        repository: repo.slug,
        branch: repo.branch,
        orgId: org.id,
        orgName: org.name,
        status
      };
      if (message) row.message = message;
      report.repositories.push(row);
      return row;
    };
    if (!integration) {
      for (const repo of p.repositories) {
        rowFor(repo, "no-bitbucket-integration", `Org has no Bitbucket integration. Connect it (${connectUrl(opts.appBase, org)}) and rerun sync.`);
      }
      save();
      continue;
    }
    const orgReport = orgReportFor.get(p.key);
    if (!settingsFor.has(org.id)) {
      let settings;
      if (state.orgs[p.key]?.createdFromTemplate) {
        settings = {
          copied: [],
          skipped: [{ category: "all", reason: "New org: Snyk copied the template settings and integrations at creation (sourceOrgId)." }],
          issues: []
        };
      } else {
        settings = await applyTemplateSettings(snyk, template, org.id, integration.id);
        for (const issue of settings.issues) io.say(`  warning: ${org.name}: template setting not applied - ${issue}`);
      }
      settingsFor.set(org.id, settings);
    }
    orgReport.settings = settingsFor.get(org.id);
    for (const repo of p.repositories) {
      if (!repo.branch) {
        rowFor(repo, "no-default-branch", "Empty repository with no main branch.");
        continue;
      }
      const target = { owner: p.workspace, name: repo.slug, branch: repo.branch };
      targets.push({ orgId: org.id, integrationId: integration.id, target });
      const key = JSON.stringify([org.id, integration.id, p.workspace, repo.slug, repo.branch]);
      let job = state.jobs[key];
      if (job?.status === "imported" && !opts.reimport) {
        let present = (job.projectIds ?? []).length > 0;
        for (const id of job.projectIds ?? []) {
          const res = await snyk.send("GET", `/rest/orgs/${org.id}/projects/${id}`);
          if (res.status === 404) present = false;
          else if (res.status >= 400) throw new Error(`Could not verify project ${id}: ${describeError(res)}`);
        }
        if (present) {
          const row = rowFor(repo, "already-imported");
          row.projectIds = job.projectIds ?? [];
          save();
          continue;
        }
      }
      if ((job?.status === "submitting" || job?.status === "uncertain") && !opts.reimport) {
        rowFor(repo, "uncertain", "An earlier submission got no confirmed answer. Check Snyk, then use --reimport to retry.");
        save();
        continue;
      }
      if (job?.status === "pending" && job.jobPath) {
        job.jobPath = normalizeJobPath(job.jobPath, org.id, integration.id);
      } else {
        job = { status: "submitting", repository: `${p.workspace}/${repo.slug}` };
        state.jobs[key] = job;
        save();
        let res;
        try {
          res = await snyk.send("POST", `/v1/org/${org.id}/integrations/${integration.id}/import`, { target });
        } catch {
          job.status = "uncertain";
          rowFor(repo, "uncertain", "Network error while submitting; check Snyk before retrying with --reimport.");
          save();
          continue;
        }
        if (res.status === 409) {
          job.status = "already-imported";
          rowFor(repo, "already-imported", "Snyk reports this target is already imported.");
          save();
          continue;
        }
        if (res.status >= 500) {
          job.status = "uncertain";
          rowFor(repo, "uncertain", describeError(res));
          save();
          continue;
        }
        if (res.status < 200 || res.status >= 300) {
          job.status = "failed";
          job.message = describeError(res);
          rowFor(repo, "failed", job.message);
          save();
          continue;
        }
        const location = res.headers["location"];
        try {
          if (!location) throw new Error("Import accepted without a Location header.");
          job.jobPath = normalizeJobPath(location, org.id, integration.id);
          job.status = "pending";
        } catch (err) {
          job.status = "uncertain";
          rowFor(repo, "uncertain", err.message);
          save();
          continue;
        }
      }
      polling.push({ job, row: rowFor(repo, "pending") });
      save();
    }
  }
  const deadline = now() + opts.pollTimeoutMs;
  let open = polling;
  while (open.length > 0) {
    const still = [];
    for (const item of open) {
      if (now() >= deadline) {
        still.push(item);
        continue;
      }
      try {
        const res = await snyk.send("GET", item.job.jobPath);
        if (res.status !== 200) throw new Error(`Import job check returned HTTP ${res.status}.`);
        const summary = summarizeJob(res.data);
        item.job.status = summary.status;
        item.job.projectIds = summary.projectIds;
        item.row.status = summary.status;
        item.row.projectIds = summary.projectIds;
        delete item.row.message;
      } catch (err) {
        item.row.message = err.message;
      }
      if (item.job.status === "pending") still.push(item);
      else io.say(`  ${item.row.workspace}/${item.row.repository}: ${item.row.status}`);
      save();
    }
    open = still;
    if (open.length === 0 || now() >= deadline) break;
    await sleep2(Math.min(opts.pollIntervalMs, Math.max(0, deadline - now())));
  }
  for (const { row } of open) row.message = "Import still running; rerun sync to collect the result.";
  save();
  const counts = {};
  for (const row of report.repositories) counts[row.status] = (counts[row.status] ?? 0) + 1;
  io.say("");
  io.say(`Organizations: ${report.organizations.length}`);
  for (const [status, n] of Object.entries(counts).sort()) io.say(`  ${status}: ${n}`);
  io.say(`Report: ${path2.join(dir, "report.csv")} (and report.json)`);
  const clean = report.organizations.every((o) => o.appConnection !== "missing" && !o.settings?.issues.length) && report.repositories.every((r) => OK_STATUSES.has(r.status));
  return clean ? 0 : 2;
}
function reportCsv(report) {
  const lines = ["workspace,project,repository,branch,snyk_org,snyk_org_id,status,snyk_project_count,message"];
  for (const r of report.repositories) {
    lines.push(
      [r.workspace, r.project, r.repository, r.branch ?? "", r.orgName, r.orgId, r.status, r.projectIds?.length ?? 0, r.message ?? ""].map(csvField).join(",")
    );
  }
  return `${lines.join("\n")}
`;
}

// bitbucket-snyk-mirror/bitbucket-snyk-mirror.mts
var TOOL_VERSION = "1.0.0";
var CMD = `node ${path3.relative(process.cwd(), process.argv[1] ?? "bitbucket-snyk-mirror.mjs") || "bitbucket-snyk-mirror.mjs"}`;
var HELP = `
bitbucket-snyk-mirror ${TOOL_VERSION} - one Snyk org per Bitbucket Cloud project

Usage:
  ${CMD}                       guided setup (asks for everything)
  ${CMD} <command> [options]

Guided setup steps (every menu has "<- Back"; in multi-select lists type "b"):
  1. Snyk region                  SNYK-US-01 or SNYK-US-02
  2. Connect to Bitbucket Cloud   email, then API token (hidden)
  3. Connect to Snyk              token (hidden), then the Snyk Group
  4. Template organization        must have Bitbucket connected
  5. Choose what to onboard       workspace -> projects -> repositories -> Snyk org
                                  per project; then add more, remove one, or continue
  6. Review and start             start now, save as a plan, change, or cancel

Commands:
  plan    Discover projects and decide the org mapping; writes mirror-plan.json.
          Reads from Snyk but changes nothing.
  sync    Create/reuse orgs, require a Bitbucket integration in each, copy template
          settings and import every repository. Resumable: rerun it any time.

Options:
  --region <us|us02>          Snyk region                       (env SNYK_REGION)
  --snyk-group <id>           Destination Snyk Group ID         (env SNYK_GROUP_ID)
  --template-org <id|name>    Template org                      (env SNYK_TEMPLATE_ORG_ID)
  --workspaces <a,b>          Bitbucket workspace slugs         (env BITBUCKET_WORKSPACES)
  --projects <ws/KEY,...>     Only these projects (default: choose, or all)
  --repos <slug,...>          Only these repositories (default: choose, or all)
  --mapping <file.csv>        workspace,projectKey,org rows; org = existing name/id,
                              a new org name, or "skip"
  --output <file>             plan: where to write the plan     (default mirror-plan.json)
  --plan <file>               sync: apply a saved plan (no Bitbucket login needed)
  --state-dir <dir>           Run state and reports             (default .mirror-state)
  --reimport                  Re-import repos already imported, and retry uncertain ones
  --forget-deleted-orgs       Drop saved orgs that were deleted in Snyk
  --poll-timeout <seconds>    How long to wait for import jobs  (default 600)
  --poll-interval <seconds>   Polling interval                  (default 5)
  --fallback-api-token        If an org has no Cloud App, create the classic
                              "Bitbucket Cloud" API-token integration instead
  --yes                       Do not ask for the final confirmation
  --non-interactive           Never prompt (requires the flags/env above)
  -h, --help                  Show this help

Anything not passed as a flag is read from the environment variable shown,
and anything still missing is asked for interactively.

Credentials (environment, or prompted):
  BITBUCKET_EMAIL + BITBUCKET_API_TOKEN   Atlassian API token (recommended)
  BITBUCKET_ACCESS_TOKEN                  Workspace/project access token
  SNYK_TOKEN                              Snyk API token (Group admin)
`;
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var SUPPORTED_REGIONS = /* @__PURE__ */ new Set(["us", "us02"]);
var list = (v) => (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
var env = (k) => process.env[k]?.trim() || void 0;
function parse(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      region: { type: "string" },
      "snyk-group": { type: "string" },
      "template-org": { type: "string" },
      workspaces: { type: "string" },
      projects: { type: "string" },
      repos: { type: "string" },
      mapping: { type: "string" },
      output: { type: "string" },
      plan: { type: "string" },
      "state-dir": { type: "string" },
      reimport: { type: "boolean" },
      "forget-deleted-orgs": { type: "boolean" },
      "poll-timeout": { type: "string" },
      "poll-interval": { type: "string" },
      "fallback-api-token": { type: "boolean" },
      yes: { type: "boolean" },
      "non-interactive": { type: "boolean" },
      help: { type: "boolean", short: "h" }
    }
  });
  const interactive = !values["non-interactive"] && isInteractive();
  const command = positionals[0] ?? (interactive ? "menu" : void 0);
  if (values.help || !command || command === "help") return null;
  if (command !== "plan" && command !== "sync" && command !== "menu") {
    throw new Error(`Unknown command "${command}". Use plan or sync, or run with no command for the guided setup.`);
  }
  const seconds = (v, fallback, label) => {
    const n = v === void 0 ? fallback : Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error(`${label} must be a non-negative number of seconds.`);
    return n * 1e3;
  };
  const pollIntervalMs = seconds(values["poll-interval"], 5, "--poll-interval");
  if (pollIntervalMs === 0) throw new Error("--poll-interval must be positive.");
  return {
    command,
    region: values.region ?? env("SNYK_REGION"),
    snykGroup: values["snyk-group"] ?? env("SNYK_GROUP_ID"),
    templateOrg: values["template-org"] ?? env("SNYK_TEMPLATE_ORG_ID"),
    workspaces: list(values.workspaces ?? env("BITBUCKET_WORKSPACES")),
    projects: list(values.projects),
    repos: list(values.repos),
    mapping: values.mapping,
    output: values.output ?? "mirror-plan.json",
    plan: values.plan,
    stateDir: values["state-dir"] ?? env("MIRROR_STATE_DIR") ?? ".mirror-state",
    reimport: Boolean(values.reimport),
    forgetDeleted: Boolean(values["forget-deleted-orgs"]),
    pollTimeoutMs: seconds(values["poll-timeout"], 600, "--poll-timeout"),
    pollIntervalMs,
    fallbackApiToken: Boolean(values["fallback-api-token"]),
    yes: Boolean(values.yes),
    interactive
  };
}
async function chooseRegion(args) {
  let key = args.region?.toLowerCase();
  if (!key) {
    if (!args.interactive) throw new Error("Pass --region us or --region us02 (or set SNYK_REGION).");
    key = await choose(
      "Snyk region (the Bitbucket Cloud App runs on these)",
      REGIONS.filter((r) => SUPPORTED_REGIONS.has(r.key)).map((r) => ({ value: r.key, label: r.label }))
    );
  }
  const region = REGIONS.find((r) => r.key === key);
  if (!region) throw new Error(`Unknown region "${key}". Use one of: ${REGIONS.map((r) => r.key).join(", ")}.`);
  if (!SUPPORTED_REGIONS.has(region.key)) {
    log.warn(`The Bitbucket Cloud App integration is not available on ${region.label}; only --fallback-api-token can work there.`);
  }
  return region.url;
}
async function secret(name, label, interactive) {
  const fromEnv = env(name);
  if (fromEnv) log.info(c.dim(`using ${name} from the environment`));
  const value = fromEnv ?? (interactive ? (await askSecret(`${label} (hidden):`)).trim() : "");
  if (!value) {
    throw new Error(interactive ? `No ${label} entered.` : `Set ${name} in the environment, or run in a terminal to be asked for it.`);
  }
  return value;
}
async function bitbucketCredentials(interactive, opts = {}) {
  const access = env("BITBUCKET_ACCESS_TOKEN");
  if (access) {
    log.info(c.dim("using BITBUCKET_ACCESS_TOKEN from the environment"));
    return { auth: { kind: "bearer", token: access }, basic: null };
  }
  let email = env("BITBUCKET_EMAIL");
  if (email) log.info(c.dim(`using BITBUCKET_EMAIL from the environment (${email})`));
  if (!email && interactive) {
    log.info(c.dim("Bitbucket login: your Atlassian account email, then your API token (asked separately, hidden)."));
    log.info(c.dim(`Using a workspace access token instead? Leave the email blank.${opts.back ? ' Type "b" to go back.' : ""}`));
    for (let attempt = 0; !email; attempt++) {
      if (attempt >= 5) throw new Error("No Bitbucket email entered.");
      const raw = await ask("Atlassian account email");
      if (opts.back && isBackWord(raw)) return BACK;
      const input = interpretCredentialInput(raw);
      const exposed = () => log.warn("that token was visible on screen. Revoke it at id.atlassian.com > Security > API tokens once you are done, and type tokens only at the hidden prompt.");
      switch (input.kind) {
        case "email":
          email = input.email;
          break;
        case "email+token":
          exposed();
          return { auth: { kind: "basic", email: input.email, token: input.token }, basic: { email: input.email, token: input.token } };
        case "access-token":
          exposed();
          return { auth: { kind: "bearer", token: input.token }, basic: null };
        case "api-token": {
          exposed();
          log.info("An API token also needs the email of the Atlassian account that created it.");
          const owner = interpretCredentialInput(await ask("Atlassian account email"));
          if (owner.kind !== "email") throw new Error("That is not an email address.");
          return { auth: { kind: "basic", email: owner.email, token: input.token }, basic: { email: owner.email, token: input.token } };
        }
        case "blank":
          return { auth: { kind: "bearer", token: await secret("BITBUCKET_ACCESS_TOKEN", "Bitbucket access token", true) }, basic: null };
        default:
          log.warn("enter an email address like you@company.com (or leave it blank for an access token)");
      }
    }
  }
  if (!email) throw new Error("Set BITBUCKET_EMAIL and BITBUCKET_API_TOKEN (or BITBUCKET_ACCESS_TOKEN).");
  const token = await secret("BITBUCKET_API_TOKEN", "Bitbucket API token", interactive);
  return { auth: { kind: "basic", email, token }, basic: { email, token } };
}
async function snykClient(baseUrl, interactive) {
  const snyk = new SnykClient(baseUrl, await secret("SNYK_TOKEN", "Snyk API token", interactive));
  const me = await snyk.detectAuth();
  log.info(`${c.green("ok")} Snyk: ${me.name}${me.email ? ` <${me.email}>` : ""}`);
  return snyk;
}
async function chooseGroup(snyk, args) {
  if (args.snykGroup) {
    if (!UUID.test(args.snykGroup)) throw new Error("--snyk-group must be a Group ID (UUID).");
    return args.snykGroup;
  }
  if (!args.interactive) throw new Error("Pass --snyk-group (or set SNYK_GROUP_ID).");
  let groups;
  try {
    groups = await listGroups(snyk);
  } catch {
    groups = [];
  }
  if (groups.length === 0) {
    const id = (await ask("Snyk Group ID (Group settings page)")).trim();
    if (!UUID.test(id)) throw new Error("That is not a Group ID.");
    return id;
  }
  return choose("Destination Snyk Group", groups.map((g) => ({ value: g.id, label: g.name, hint: g.id })));
}
async function chooseTemplate(orgs, args, statusOf) {
  if (args.templateOrg) {
    const org = findOrg(args.templateOrg, orgs);
    if (!org) throw new Error(`Template org "${args.templateOrg}" is not in the selected Group.`);
    const status = await statusOf(org.id);
    if (!usable(status)) throw new Error(`Template org "${org.name}" ${STATUS_TEXT[status]}. ${FIX_HINT}`);
    return org;
  }
  if (!args.interactive) throw new Error("Pass --template-org (or set SNYK_TEMPLATE_ORG_ID).");
  let pool = [...orgs];
  for (; ; ) {
    if (pool.length === 0) throw new Error(`No org in this Group has a Bitbucket integration to use as a template. ${FIX_HINT}`);
    const org = await choose(
      "Template organization (new orgs copy its settings and Bitbucket integration)",
      pool.map((o) => ({ value: o, label: o.name, hint: o.slug }))
    );
    const status = await statusOf(org.id);
    if (usable(status)) {
      log.info(`${c.green("ok")} template "${org.name}": ${STATUS_TEXT[status]}`);
      return org;
    }
    log.warn(`"${org.name}" ${STATUS_TEXT[status]}. Choose another template. ${FIX_HINT}`);
    pool = pool.filter((o) => o.id !== org.id);
  }
}
async function chooseWorkspaces(bb, args) {
  if (args.workspaces.length > 0) return args.workspaces.map(validWorkspace);
  if (!args.interactive) throw new Error("Pass --workspaces (or set BITBUCKET_WORKSPACES).");
  let found = [];
  try {
    found = await listWorkspaces(bb);
  } catch (err) {
    log.warn(`could not list workspaces: ${err.message}`);
  }
  if (found.length === 0) {
    return list(await ask("Bitbucket workspace slug(s), comma-separated")).map(validWorkspace);
  }
  if (found.length === 1) {
    log.info(`workspace: ${found[0].name} ${c.dim(found[0].slug)}`);
    return [found[0].slug];
  }
  return chooseMany(
    "Which Bitbucket workspace(s) hold the projects you want to onboard?",
    found.map((w) => ({ value: w.slug, label: w.name, hint: w.slug }))
  );
}
async function discover(bb, workspaces, args) {
  const wanted = new Set(args.projects.map((p) => p.toLowerCase()));
  const wantedRepos = new Set(args.repos.map((r) => r.toLowerCase()));
  const entries = [];
  for (const ws of workspaces) {
    log.step(`Workspace ${ws}`);
    let projects = await listProjects(bb, ws);
    if (projects.length === 0) {
      log.warn(`no projects visible in ${ws}`);
      continue;
    }
    if (wanted.size > 0) projects = projects.filter((p) => wanted.has(`${ws}/${p.key}`.toLowerCase()));
    else if (args.interactive) {
      projects = await chooseMany(
        `Projects in workspace ${ws} to onboard (each project's repositories go into one Snyk org)`,
        projects.map((p) => ({ value: p, label: p.name, hint: p.key })),
        { defaultAll: true }
      );
    }
    for (const project of projects) {
      const found = await discoverProject(bb, ws, project);
      log.blank();
      log.info(`${c.bold(`Project "${found.projectName}"`)} ${c.dim(`(key ${found.projectKey})`)}: ${plural(found.repositories.length, "repository", "repositories")}`);
      for (const r of found.repositories) {
        log.info(`  - ${r.slug}${c.dim(r.branch ? `  branch ${r.branch}` : "  empty, nothing to import")}`);
      }
      if (found.repositories.length === 0) {
        log.warn(`project "${found.projectName}" has no repositories; skipping it`);
        continue;
      }
      let repositories = found.repositories;
      if (wantedRepos.size > 0) {
        repositories = repositories.filter((r) => wantedRepos.has(r.slug.toLowerCase()) || wantedRepos.has(`${ws}/${r.slug}`.toLowerCase()));
      } else if (args.interactive && repositories.length > 1) {
        repositories = await chooseMany(
          `Repositories in project "${found.projectName}" to onboard`,
          repositories.map((r) => ({ value: r, label: r.slug, hint: r.branch ? `branch ${r.branch}` : "empty" })),
          { defaultAll: true }
        );
      }
      if (repositories.length === 0) {
        log.info(c.dim(`no repositories selected in "${found.projectName}"; skipping it`));
        continue;
      }
      entries.push({ ...found, repositories });
    }
  }
  if (wanted.size > 0) {
    const missing = [...wanted].filter((k) => !entries.some((e) => e.key.toLowerCase() === k));
    if (missing.length > 0) throw new Error(`Projects not found or empty: ${missing.join(", ")}`);
  }
  if (entries.length === 0) throw new Error("No Bitbucket projects selected.");
  return entries;
}
async function askNewName(suggested) {
  for (; ; ) {
    const name = (await ask("Name for the new Snyk org", suggested.slice(0, 60))).trim();
    if (name.length >= 1 && name.length <= 60) return name;
    log.warn("org names must be 1 to 60 characters");
  }
}
function bitbucketStatusChecker(snyk) {
  const cache = /* @__PURE__ */ new Map();
  return (orgId) => {
    let status = cache.get(orgId);
    if (!status) {
      status = findBitbucketIntegration(snyk, orgId, true).then(
        (i) => !i ? "none" : i.type === API_TOKEN_INTEGRATION_TYPE ? "api-token" : "app",
        () => "unknown"
      );
      cache.set(orgId, status);
    }
    return status;
  };
}
var STATUS_TEXT = {
  app: "Bitbucket Cloud App is connected",
  "api-token": "Bitbucket Cloud (API token) integration is configured",
  none: "has no Bitbucket integration, so it cannot be used",
  unknown: "could not be checked for a Bitbucket integration (token lacks access?), so it cannot be used"
};
var FIX_HINT = "Connect Bitbucket in that org (Settings > Integrations) first, or pick a different one.";
var usable = (s) => s === "app" || s === "api-token";
async function chooseExistingWithBitbucket(title, candidates, statusOf, templateId) {
  let pool = [...candidates];
  while (pool.length > 0) {
    const org = await pick(
      title,
      pool.map((o) => ({ value: o, label: o.name, hint: o.id === templateId ? `${o.slug}  (template org)` : o.slug })),
      { back: true }
    );
    if (org === BACK) return BACK;
    const status = await statusOf(org.id);
    if (usable(status)) {
      log.info(`${c.green("ok")} "${org.name}": ${STATUS_TEXT[status]}`);
      return org;
    }
    log.warn(`"${org.name}" ${STATUS_TEXT[status]}. ${FIX_HINT}`);
    pool = pool.filter((o) => o.id !== org.id);
  }
  return null;
}
async function promptDestination(p, orgs, template, def, statusOf) {
  log.blank();
  log.info(c.bold(`Snyk org for project ${projectLabel(p)}`));
  log.info(`${plural(p.repositories.length, "repository", "repositories")} to onboard: ${p.repositories.map((r) => r.slug).join(", ")}`);
  const choices = [];
  let suggested = p.projectName;
  if (def.kind === "existing" && usable(await statusOf(def.orgId))) {
    log.info(`Snyk org "${def.name}" already exists and ${STATUS_TEXT[await statusOf(def.orgId)]}.`);
    choices.push({ value: "default", label: `Onboard the repositories into "${def.name}"` });
    choices.push({ value: "existing", label: "Onboard into a different existing org" });
    choices.push({ value: "new", label: `Create a new org from template "${template.name}" instead` });
  } else if (def.kind === "existing") {
    log.warn(`Snyk org "${def.name}" exists but ${STATUS_TEXT[await statusOf(def.orgId)]}.`);
    suggested = `${p.projectName} (Bitbucket)`.slice(0, 60);
    choices.push({ value: "new", label: `Create a new org from template "${template.name}"`, hint: `you choose the name; suggested "${suggested}"` });
    choices.push({ value: "existing", label: "Onboard into a different existing org" });
  } else {
    log.info("There is no Snyk org for this project yet.");
    choices.push({ value: "new", label: `Create one from template "${template.name}"`, hint: `you choose the name; suggested "${p.projectName}"` });
    choices.push({ value: "existing", label: "Onboard into an existing Snyk org instead" });
  }
  if (!(def.kind === "existing" && def.orgId === template.id)) {
    choices.push({ value: "template", label: `Onboard into the template org "${template.name}" itself`, hint: "Bitbucket already connected" });
  }
  choices.push({ value: "skip", label: "Skip this project" });
  for (; ; ) {
    const choice = await pick(`Which Snyk org should the repositories of "${p.projectName}" go into?`, choices, { back: true });
    if (choice === BACK) return BACK;
    if (choice === "template") return { kind: "existing", orgId: template.id, name: template.name };
    if (choice === "default") return def;
    if (choice === "skip") return { kind: "skip" };
    if (choice === "new") return { kind: "new", name: await askNewName(suggested) };
    const org = await chooseExistingWithBitbucket(
      `Existing Snyk org for project "${p.projectName}" (must have Bitbucket connected)`,
      orgs,
      statusOf,
      template.id
    );
    if (org === BACK) continue;
    if (!org) {
      log.warn("no existing org has a Bitbucket integration; choose another option");
      continue;
    }
    return { kind: "existing", orgId: org.id, name: org.name };
  }
}
async function buildMapping(entries, orgs, template, saved, args, statusOf) {
  let mapped;
  if (args.mapping) {
    const result = applyMapping(entries, parseMappingCsv(fs2.readFileSync(localPath(args.mapping), "utf8")), orgs);
    for (const key of result.unmentioned) log.warn(`${key} is not in ${args.mapping}; skipping it`);
    mapped = result.mapped;
  } else {
    mapped = entries.map((e) => ({ ...e, destination: defaultDestination(e, orgs, template.id, saved[e.key]) }));
  }
  const errors = await mappingErrors(mapped, orgs, statusOf);
  if (errors.length === 0) return mapped;
  for (const e of errors) log.warn(e);
  throw new Error("Fix the mapping above and rerun.");
}
async function mappingErrors(mapped, orgs, statusOf) {
  const active = mapped.filter((p) => p.destination.kind !== "skip");
  const errors = validateMapping(active, orgs);
  for (const p of active) {
    const d = p.destination;
    if (d.kind !== "existing") continue;
    const status = await statusOf(d.orgId);
    if (!usable(status)) errors.push(`${p.key}: Snyk org "${d.name}" ${STATUS_TEXT[status]}.`);
  }
  return errors;
}
function readPlan(file) {
  const plan = JSON.parse(fs2.readFileSync(localPath(file), "utf8"));
  if (plan.version !== 1 || plan.source !== "bitbucket-cloud" || !Array.isArray(plan.projects)) {
    throw new Error(`${file} is not a bitbucket-snyk-mirror plan.`);
  }
  if (!REGIONS.some((r) => r.url === plan.snykApi)) throw new Error("The plan names an unknown Snyk API host.");
  if (!UUID.test(plan.groupId) || !UUID.test(plan.templateOrgId)) throw new Error("The plan has an invalid Group or template ID.");
  return plan;
}
async function createPlanUnattended(args) {
  const snykApi = await chooseRegion(args);
  log.step("Bitbucket Cloud");
  const { auth, basic } = await bitbucketCredentials(args.interactive);
  const bb = new BitbucketClient(auth);
  let workspaces = args.workspaces.map(validWorkspace);
  if (auth.kind === "bearer" && workspaces.length === 0) {
    if (!args.interactive) throw new Error("With an access token, pass --workspaces.");
    workspaces = list(await ask("Bitbucket workspace slug for this access token")).map(validWorkspace);
  }
  log.info(`${c.green("ok")} Bitbucket: ${await verifyBitbucket(bb, workspaces)}`);
  log.step("Snyk");
  const snyk = await snykClient(snykApi, args.interactive);
  const groupId = await chooseGroup(snyk, args);
  const orgs = await listGroupOrgs(snyk, groupId);
  if (orgs.length === 0) throw new Error("The selected Group has no orgs visible to this token, so there is no template to copy.");
  const statusOf = bitbucketStatusChecker(snyk);
  const template = await chooseTemplate(orgs, args, statusOf);
  log.step("Bitbucket projects");
  if (workspaces.length === 0) workspaces = await chooseWorkspaces(bb, args);
  const entries = await discover(bb, workspaces, args);
  const prior = peekState(localPath(args.stateDir));
  const saved = prior?.binding?.snykApi === snyk.baseUrl && prior.binding.groupId === groupId ? prior.orgs : {};
  const projects = await buildMapping(entries, orgs, template, saved, args, statusOf);
  const plan = {
    version: 1,
    source: "bitbucket-cloud",
    snykApi: snyk.baseUrl,
    groupId,
    templateOrgId: template.id,
    templateOrgName: template.name,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    projects
  };
  return { plan, snyk, basic };
}
var TOTAL_STEPS = 6;
async function createPlanWizard(args) {
  let snykApi = "";
  let creds = null;
  let bb = null;
  let snyk = null;
  let groupId = "";
  let orgs = [];
  let statusOf = async () => "unknown";
  let template = null;
  let saved = {};
  let fixedWorkspaces = args.workspaces.map(validWorkspace);
  const basket = [];
  const workspaceCache = {};
  const projectCache = /* @__PURE__ */ new Map();
  const repoCache = /* @__PURE__ */ new Map();
  const buildPlan = () => ({
    version: 1,
    source: "bitbucket-cloud",
    snykApi,
    groupId,
    templateOrgId: template.id,
    templateOrgName: template.name,
    createdAt: (/* @__PURE__ */ new Date()).toISOString(),
    projects: [...basket]
  });
  const stepRegion = async () => {
    stepHeader(1, TOTAL_STEPS, "Snyk region");
    if (args.region) {
      snykApi = await chooseRegion(args);
      log.info(`region: ${describeRegion(snykApi)}`);
      return "auto";
    }
    const key = await pick(
      "Which Snyk region is your account on? (the Bitbucket Cloud App runs on these)",
      REGIONS.filter((r) => SUPPORTED_REGIONS.has(r.key)).map((r) => ({ value: r.key, label: r.label }))
    );
    snykApi = REGIONS.find((r) => r.key === key).url;
    if (snyk && snyk.baseUrl !== snykApi) snyk = null;
    return "next";
  };
  const stepBitbucket = async () => {
    stepHeader(2, TOTAL_STEPS, "Connect to Bitbucket Cloud");
    const fromEnv = Boolean(env("BITBUCKET_ACCESS_TOKEN") || env("BITBUCKET_EMAIL") && env("BITBUCKET_API_TOKEN"));
    const got = await bitbucketCredentials(true, { back: true });
    if (got === BACK) return "back";
    creds = got;
    bb = new BitbucketClient(got.auth);
    if (got.auth.kind === "bearer" && args.workspaces.length === 0) {
      const answer = await ask('Bitbucket workspace slug for this access token (or "b" to go back)');
      if (isBackWord(answer)) return "back";
      fixedWorkspaces = list(answer).map(validWorkspace);
    }
    try {
      log.info(`${c.green("ok")} Bitbucket: ${await verifyBitbucket(bb, fixedWorkspaces)}`);
    } catch (err) {
      if (fromEnv) throw err;
      log.warn(`${err.message} Let's try again.`);
      return "retry";
    }
    delete workspaceCache.list;
    projectCache.clear();
    repoCache.clear();
    return fromEnv ? "auto" : "next";
  };
  const stepSnyk = async () => {
    stepHeader(3, TOTAL_STEPS, "Connect to Snyk and choose the Group");
    const tokenFromEnv = Boolean(env("SNYK_TOKEN"));
    if (!snyk) {
      try {
        snyk = await snykClient(snykApi, true);
      } catch (err) {
        if (tokenFromEnv) throw err;
        log.warn(`${err.message} Let's try again.`);
        return "retry";
      }
    } else {
      log.info(c.dim("already signed in to Snyk"));
    }
    let auto = tokenFromEnv;
    if (args.snykGroup) {
      groupId = await chooseGroup(snyk, args);
    } else {
      auto = false;
      let groups = [];
      try {
        groups = await listGroups(snyk);
      } catch {
        groups = [];
      }
      if (groups.length === 0) {
        const id = (await ask('Snyk Group ID, from the Group settings page (or "b" to go back)')).trim();
        if (isBackWord(id)) return "back";
        if (!UUID.test(id)) {
          log.warn("that is not a Group ID");
          return "retry";
        }
        groupId = id;
      } else {
        const g = await pick("Which Snyk Group should the orgs be in?", groups.map((x) => ({ value: x.id, label: x.name, hint: x.id })), { back: true });
        if (g === BACK) return "back";
        groupId = g;
      }
    }
    orgs = await listGroupOrgs(snyk, groupId);
    if (orgs.length === 0) throw new Error("The selected Group has no orgs visible to this token, so there is no template to copy.");
    statusOf = bitbucketStatusChecker(snyk);
    const prior = peekState(localPath(args.stateDir));
    saved = prior?.binding?.snykApi === snyk.baseUrl && prior.binding.groupId === groupId ? prior.orgs : {};
    return auto ? "auto" : "next";
  };
  const stepTemplate = async () => {
    stepHeader(4, TOTAL_STEPS, "Template organization");
    log.info(c.dim("New Snyk orgs are created as copies of this org (settings and Bitbucket integration), so it must have Bitbucket connected."));
    if (args.templateOrg) {
      template = await chooseTemplate(orgs, args, statusOf);
      log.info(`template: ${template.name}`);
      return "auto";
    }
    let pool = [...orgs];
    for (; ; ) {
      if (pool.length === 0) throw new Error(`No org in this Group has a Bitbucket integration to use as a template. ${FIX_HINT}`);
      const org = await pick("Which org is the template?", pool.map((o) => ({ value: o, label: o.name, hint: o.slug })), { back: true });
      if (org === BACK) return "back";
      const status = await statusOf(org.id);
      if (usable(status)) {
        log.info(`${c.green("ok")} template "${org.name}": ${STATUS_TEXT[status]}`);
        template = org;
        return "next";
      }
      log.warn(`"${org.name}" ${STATUS_TEXT[status]}. Choose another template. ${FIX_HINT}`);
      pool = pool.filter((o) => o.id !== org.id);
    }
  };
  const workspaces = async () => {
    if (fixedWorkspaces.length > 0) return fixedWorkspaces.map((slug) => ({ slug, name: slug }));
    if (!workspaceCache.list) {
      try {
        workspaceCache.list = await listWorkspaces(bb);
      } catch (err) {
        log.warn(`could not list workspaces: ${err.message}`);
        workspaceCache.list = [];
      }
    }
    if (workspaceCache.list.length === 0) {
      const typed = list(await ask("Bitbucket workspace slug(s), comma-separated")).map(validWorkspace);
      workspaceCache.list = typed.map((slug) => ({ slug, name: slug }));
    }
    return workspaceCache.list;
  };
  const showRepos = (ws, project, repos) => {
    log.blank();
    log.info(`${c.bold(`Project "${project.name}"`)} ${c.dim(`(key ${project.key}, workspace ${ws})`)}: ${plural(repos.length, "repository", "repositories")}`);
    for (const r of repos) log.info(`  - ${r.slug}${c.dim(r.branch ? `  branch ${r.branch}` : "  empty, nothing to import")}`);
  };
  const addProjects = async () => {
    pickWorkspace: for (; ; ) {
      const list_ = await workspaces();
      let ws;
      const wsAuto = list_.length === 1;
      if (wsAuto) {
        ws = list_[0].slug;
        log.info(`workspace: ${list_[0].name} ${c.dim(ws)}`);
      } else {
        const chosen = await pick(
          "Which Bitbucket workspace are the projects in?",
          list_.map((w) => ({ value: w.slug, label: w.name, hint: w.slug })),
          { back: true }
        );
        if (chosen === BACK) return BACK;
        ws = chosen;
      }
      if (!projectCache.has(ws)) projectCache.set(ws, await listProjects(bb, ws));
      const projects = projectCache.get(ws);
      if (projects.length === 0) {
        log.warn(`no projects visible in workspace ${ws}`);
        if (wsAuto) return BACK;
        continue pickWorkspace;
      }
      pickProjects: for (; ; ) {
        const inBasket = new Set(basket.map((b) => b.key));
        const chosen = await pickMany(
          `Projects in workspace ${ws} to onboard (each project's repositories go into one Snyk org)`,
          projects.map((p) => ({ value: p, label: p.name, hint: inBasket.has(`${ws}/${p.key}`) ? `${p.key}  (already added; choosing it again replaces it)` : p.key })),
          { back: true }
        );
        if (chosen === BACK) {
          if (wsAuto) return BACK;
          continue pickWorkspace;
        }
        const picked = chosen.map(() => null);
        const repoPromptShown = chosen.map(() => false);
        let j = 0;
        let sub = "repos";
        while (j < chosen.length) {
          const project = chosen[j];
          const cacheKey = `${ws}/${project.key}`;
          if (!repoCache.has(cacheKey)) repoCache.set(cacheKey, (await discoverProject(bb, ws, project)).repositories);
          const all = repoCache.get(cacheKey);
          if (sub === "repos") {
            showRepos(ws, project, all);
            if (all.length === 0) {
              log.warn(`project "${project.name}" has no repositories; skipping it`);
              picked[j] = null;
              j++;
              continue;
            }
            let repos = all;
            repoPromptShown[j] = all.length > 1;
            if (all.length > 1) {
              const r = await pickMany(
                `Repositories in project "${project.name}" to onboard`,
                all.map((x) => ({ value: x, label: x.slug, hint: x.branch ? `branch ${x.branch}` : "empty" })),
                { back: true }
              );
              if (r === BACK) {
                if (j === 0) continue pickProjects;
                j--;
                sub = "org";
                continue;
              }
              repos = r;
            }
            picked[j] = {
              key: cacheKey,
              workspace: ws,
              projectKey: project.key,
              projectName: project.name,
              projectUuid: project.uuid,
              repositories: repos,
              destination: { kind: "skip" }
            };
            sub = "org";
            continue;
          }
          const entry = picked[j];
          const d = await promptDestination(entry, orgs, template, defaultDestination(entry, orgs, template.id, saved[entry.key]), statusOf);
          if (d === BACK) {
            if (repoPromptShown[j]) {
              sub = "repos";
            } else if (j === 0) {
              continue pickProjects;
            } else {
              j--;
              sub = "org";
            }
            continue;
          }
          picked[j] = { ...entry, destination: d };
          j++;
          sub = "repos";
        }
        for (const entry of picked) {
          if (!entry || entry.destination.kind === "skip") continue;
          const at = basket.findIndex((b) => b.key === entry.key);
          if (at >= 0) basket[at] = entry;
          else basket.push(entry);
        }
        return "added";
      }
    }
  };
  const stepSelect = async () => {
    stepHeader(5, TOTAL_STEPS, "Choose projects, repositories and Snyk orgs");
    log.info(c.dim("Add projects from any workspace, one round at a time. You review everything in step 6."));
    if (basket.length === 0) {
      const r = await addProjects();
      if (r === BACK) return "back";
    }
    for (; ; ) {
      const repos = basket.reduce((n, p) => n + p.repositories.length, 0);
      log.blank();
      log.step(c.bold(`Step 5 of 6: Your onboarding list (${plural(basket.length, "project", "projects")}, ${plural(repos, "repository", "repositories")})`));
      if (basket.length > 0) for (const line of summaryTree(basket, template.name, template.id)) log.info(line);
      else log.info("Nothing selected yet.");
      const choices = [
        { value: "add", label: basket.length > 0 ? "Add more projects" : "Add projects", hint: "from this or another workspace" }
      ];
      if (basket.length > 0) {
        choices.push({ value: "remove", label: "Remove a project from the list" });
        choices.push({ value: "review", label: "Done adding: continue to review", hint: "step 6" });
      }
      const next = await pick("What would you like to do next?", choices, { back: true });
      if (next === BACK) return "back";
      if (next === "add") {
        await addProjects();
        continue;
      }
      if (next === "remove") {
        const victim = await pick(
          "Remove which project?",
          basket.map((p) => ({ value: p.key, label: `"${p.projectName}"`, hint: `workspace ${p.workspace}` })),
          { back: true }
        );
        if (victim !== BACK) basket.splice(basket.findIndex((p) => p.key === victim), 1);
        continue;
      }
      const errors = await mappingErrors(basket, orgs, statusOf);
      if (errors.length > 0) {
        for (const e of errors) log.warn(e);
        log.warn("Fix these (remove the project and add it again with another org) before continuing.");
        continue;
      }
      return "next";
    }
  };
  const stepReview = async () => {
    stepHeader(6, TOTAL_STEPS, args.command === "plan" ? "Review and save" : "Review and start");
    const plan = buildPlan();
    showSummary(plan);
    showNextSteps(plan, path3.join(path3.relative(process.cwd(), localPath(args.stateDir)) || ".", "report.csv"));
    const choices = args.command === "plan" ? [{ value: "save", label: "Save the plan", hint: args.output }] : [
      { value: "go", label: "Yes, start onboarding now" },
      { value: "save", label: "Save this as a plan to run later", hint: args.output }
    ];
    choices.push({ value: "change", label: "Add more projects, or remove/change one", hint: "back to the list in step 5" });
    choices.push({ value: "cancel", label: "Cancel", hint: "nothing is saved or changed" });
    const choice = await pick(args.command === "plan" ? "Save this plan?" : "Start onboarding now?", choices, { back: true });
    if (choice === BACK || choice === "change") return "back";
    return { decision: choice };
  };
  const steps = [stepRegion, stepBitbucket, stepSnyk, stepTemplate, stepSelect, stepReview];
  const prompted = steps.map(() => false);
  for (let i = 0; ; ) {
    const result = await steps[i]();
    if (typeof result === "object") return { plan: buildPlan(), snyk, basic: creds?.basic ?? null, decision: result.decision };
    if (result === "retry") continue;
    if (result === "back") {
      let k = i - 1;
      while (k >= 0 && !prompted[k]) k--;
      if (k < 0) log.info(c.dim("This is the first step; there is nothing to go back to."));
      else i = k;
      continue;
    }
    prompted[i] = result === "next";
    i++;
  }
}
function showSummary(plan) {
  log.blank();
  log.step("What will be onboarded");
  for (const line of summaryTree(plan.projects, plan.templateOrgName, plan.templateOrgId)) log.info(line);
}
function showNextSteps(plan, reportPath) {
  log.blank();
  log.step("Next steps");
  for (const line of nextSteps(plan.projects, plan.templateOrgName, reportPath, plan.templateOrgId)) log.info(line);
  log.blank();
}
async function main(argv) {
  const args = parse(argv);
  if (!args) {
    process.stderr.write(HELP);
    return 0;
  }
  if (args.command === "menu") {
    log.step(`Bitbucket Cloud -> Snyk onboarding  ${c.dim(`v${TOOL_VERSION}`)}`);
    log.info(c.dim("Anything already set in the environment is used; everything else is asked for. Run with --help for flags."));
    const savedPlan = fs2.existsSync(path3.resolve(args.output)) ? args.output : void 0;
    const pick3 = await choose("What do you want to do?", [
      { value: "sync", label: "Onboard Bitbucket projects into Snyk", hint: "create/reuse orgs, then import repos" },
      { value: "plan", label: "Preview only", hint: `decide the mapping and save it to ${args.output}; no Snyk changes` },
      ...savedPlan ? [{ value: "apply", label: `Apply the saved plan in ${savedPlan}` }] : []
    ]);
    if (pick3 === "apply") {
      args.command = "sync";
      args.plan = savedPlan;
    } else {
      args.command = pick3;
    }
  }
  for (const [name, used] of [
    ["SNYK_REGION", args.region],
    ["SNYK_GROUP_ID", args.snykGroup],
    ["SNYK_TEMPLATE_ORG_ID", args.templateOrg],
    ["BITBUCKET_WORKSPACES", args.workspaces.join(",")]
  ]) {
    const value = env(name);
    if (value && list(value).join(",") === list(used).join(",")) log.info(c.dim(`using ${name}=${value} from the environment`));
  }
  let plan;
  let snyk;
  let basic = null;
  let decision = null;
  if (args.command === "sync" && args.plan) {
    plan = readPlan(args.plan);
    log.step("Snyk");
    snyk = await snykClient(plan.snykApi, args.interactive);
    if (args.fallbackApiToken) basic = (await bitbucketCredentials(args.interactive)).basic;
  } else if (args.command === "plan" && args.plan) {
    throw new Error("--plan is for sync; plan writes --output.");
  } else if (args.interactive && !args.mapping) {
    ({ plan, snyk, basic, decision } = await createPlanWizard(args));
  } else {
    ({ plan, snyk, basic } = await createPlanUnattended(args));
  }
  if (decision === "cancel") {
    log.info("Cancelled. Nothing was saved or changed in Snyk.");
    return 0;
  }
  if (!decision) showSummary(plan);
  if (plan.projects.every((p) => p.destination.kind === "skip")) throw new Error("Every project is skipped; nothing to do.");
  const savePlan = () => {
    const out = localPath(args.output);
    writeJson(out, plan);
    const csv = path3.join(path3.dirname(out), "mirror-mapping.csv");
    writeText(csv, mappingCsv(plan.projects));
    log.blank();
    log.step("Saved; nothing was changed in Snyk");
    log.info(`Plan: ${path3.relative(process.cwd(), out)}   Editable mapping: ${path3.relative(process.cwd(), csv)}`);
    log.step("Next steps");
    log.info(`1. Review the plan above (or edit ${path3.relative(process.cwd(), csv)} and use --mapping)`);
    log.info(`2. Apply it:  ${CMD} sync --plan ${path3.relative(process.cwd(), out)}`);
    log.info(`   (or run ${CMD} and choose "Apply the saved plan")`);
    return 0;
  };
  if (args.command === "plan" || decision === "save") return savePlan();
  if (args.fallbackApiToken && !basic) {
    throw new Error("--fallback-api-token needs BITBUCKET_EMAIL + BITBUCKET_API_TOKEN (an access token cannot be used).");
  }
  if (!decision) showNextSteps(plan, path3.join(path3.relative(process.cwd(), localPath(args.stateDir)) || ".", "report.csv"));
  if (!args.yes && decision !== "go") {
    if (!args.interactive) throw new Error("Pass --yes to apply without a confirmation prompt.");
    const go = await choose("Start onboarding now?", [
      { value: "go", label: "Yes, run the steps above now" },
      { value: "save", label: "No, save this as a plan to run later", hint: args.output },
      { value: "cancel", label: "Cancel", hint: "nothing is saved or changed" }
    ]);
    if (go === "save") return savePlan();
    if (go === "cancel") {
      log.info("Cancelled. Nothing was changed in Snyk.");
      return 0;
    }
  }
  const dir = localPath(args.stateDir);
  return withLock(dir, async () => {
    writeJson(path3.join(dir, "plan.json"), plan);
    const io = args.interactive ? {
      say: (line) => log.info(line),
      ask: (q) => ask(q),
      confirm: async (q) => await choose(q, [
        { value: true, label: "Yes" },
        { value: false, label: "No" }
      ])
    } : { say: (line) => log.info(line) };
    return runSync(plan, snyk, {
      stateDir: dir,
      reimport: args.reimport,
      forgetDeleted: args.forgetDeleted,
      pollTimeoutMs: args.pollTimeoutMs,
      pollIntervalMs: args.pollIntervalMs,
      appBase: appUrlFor(snyk.baseUrl),
      fallbackCredentials: args.fallbackApiToken ? basic : null,
      io
    });
  });
}
main(process.argv.slice(2)).then((code) => {
  process.exitCode = code;
}).catch((err) => {
  if (err instanceof InputClosedError || err instanceof Error && err.message === "cancelled") {
    log.error("cancelled. Saved import jobs resume when you rerun sync.");
    process.exitCode = 130;
    return;
  }
  log.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
}).finally(() => closePrompts());
export {
  TOOL_VERSION
};
