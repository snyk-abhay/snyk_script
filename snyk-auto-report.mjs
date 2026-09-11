#!/usr/bin/env node

// snyk_report/snyk-auto-report.mts
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, resolve as resolve2 } from "node:path";
import { parseArgs } from "node:util";

// snyk_report/lib/model.mts
var SEVERITIES = ["critical", "high", "medium", "low"];
var SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};
function read(issue, key2) {
  if (!(key2 in issue)) return { state: "unsupported" };
  const value = issue[key2];
  if (value === null || value === void 0 || value === "") return { state: "empty" };
  return { state: "present", value };
}
function issueIdentity(p) {
  if (p.assetFindingId) return { key: `afid:${p.assetFindingId}`, strength: "strong" };
  if (p.issueUrl) return { key: `url:${p.issueUrl}`, strength: "strong" };
  return {
    key: [
      p.orgId,
      p.projectId ?? p.projectName ?? "",
      p.problemId,
      p.packageNameAndVersion ?? p.filePath ?? "",
      p.startLine ?? ""
    ].join("|"),
    strength: "weak"
  };
}

// snyk_report/lib/availability.mts
function makeAvailability(source, entries) {
  const byField = /* @__PURE__ */ new Map();
  for (const [k, e] of entries) {
    byField.set(k, { ...e, carriedBy: e.state === "absent" ? /* @__PURE__ */ new Set() : /* @__PURE__ */ new Set([source]) });
  }
  return { sources: /* @__PURE__ */ new Set([source]), byField };
}
function stateOf(a, key2) {
  return a.byField.get(key2)?.state ?? "absent";
}
function absentFields(a) {
  const out = [];
  for (const [key2, e] of a.byField) if (e.state === "absent") out.push({ key: key2, note: e.note });
  return out.sort((x, y) => x.key.localeCompare(y.key));
}

// snyk_report/lib/vocab.mts
function clean(v) {
  return (v ?? "").trim();
}
function key(v) {
  return clean(v).toLowerCase().replace(/[\s_-]+/g, " ");
}
function normalizeSeverity(v) {
  switch (key(v)) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
    case "moderate":
      return "medium";
    case "low":
      return "low";
    default:
      return null;
  }
}
function normalizeStatus(v) {
  switch (key(v)) {
    case "open":
    case "active":
      return "open";
    case "resolved":
    case "fixed":
    case "closed":
      return "resolved";
    case "ignored":
    case "suppressed":
      return "ignored";
    default:
      return null;
  }
}
function normalizeProduct(v) {
  const k = key(v);
  if (!k) return "unknown";
  if (k.includes("open source") || k.includes("package vulnerability") || k === "sca") {
    return "open-source";
  }
  if (k.includes("secret")) return "secrets";
  if (k.includes("code") || k.includes("sast")) return "code";
  if (k.includes("container")) return "container";
  if (k.includes("iac") || k.includes("infrastructure")) return "iac";
  if (k.includes("custom")) return "custom";
  return "unknown";
}
var LEGACY_EXPLOIT = {
  mature: "attacked",
  "proof of concept": "poc",
  "proof of concept exploit": "poc",
  poc: "poc",
  "no known exploit": "no-known-exploit",
  "no data": "no-data"
};
var CVSS4_EXPLOIT = {
  attacked: "attacked",
  poc: "poc",
  "proof of concept": "poc",
  "not defined": "not-defined"
};
var EXPLOIT_RANK = {
  attacked: 0,
  poc: 1,
  "no-known-exploit": 2,
  "not-defined": 3,
  "no-data": 4
};
function exploitMaturityRank(v) {
  return EXPLOIT_RANK[v];
}
function normalizeExploitMaturity(legacy, cvss4) {
  const fromLegacy = LEGACY_EXPLOIT[key(legacy)] ?? null;
  const fromCvss4 = CVSS4_EXPLOIT[key(cvss4)] ?? null;
  if (fromLegacy && fromCvss4) {
    const expectedCollapse = fromCvss4 === "not-defined" && (fromLegacy === "no-known-exploit" || fromLegacy === "no-data");
    if (fromLegacy === fromCvss4 || expectedCollapse) {
      return { value: fromLegacy, vocab: "merged" };
    }
    return {
      value: fromLegacy,
      vocab: "merged",
      disagreement: `legacy=${fromLegacy} cvss4=${fromCvss4}`
    };
  }
  if (fromLegacy) return { value: fromLegacy, vocab: "legacy" };
  if (fromCvss4) return { value: fromCvss4, vocab: "cvss4" };
  return { value: null, vocab: null };
}
function exploitMaturityLabel(v, datasetHasCvss4) {
  switch (v) {
    case "attacked":
      return "Attacked / mature exploit";
    case "poc":
      return "Proof of concept";
    case "no-known-exploit":
      return datasetHasCvss4 ? "No known exploit / not defined" : "No known exploit";
    case "not-defined":
      return "Not defined";
    case "no-data":
      return "No data";
  }
}
function normalizeFixability(v) {
  const k = key(v);
  if (!k) return null;
  if (k === "fixable" || k === "fully fixable") return "fixable";
  if (k.startsWith("partial")) return "partially-fixable";
  if (k.includes("no supported fix")) return "no-supported-fix";
  if (k === "unfixable" || k.includes("not fixable")) return "unfixable";
  return null;
}
function normalizeReachability(v) {
  const k = key(v);
  if (!k) return null;
  if (k.startsWith("potentially")) return "potentially-reachable";
  if (k === "reachable") return "reachable";
  if (k.includes("no path")) return "no-path-found";
  if (k.includes("not reachable") || k === "unreachable") return "not-reachable";
  if (k.includes("not applicable") || k === "n a") return "not-applicable";
  return null;
}
function toPick(e) {
  if (e.score === null) return null;
  return { score: e.score, vector: e.vector, version: e.version, source: e.source };
}
function pickCvss(entries) {
  const snyk = entries.filter((e) => key(e.source) === "snyk");
  const pool = snyk.length > 0 ? snyk : entries;
  const v31 = pool.find((e) => e.version.startsWith("3.1")) ?? pool.find((e) => e.version.startsWith("3"));
  const v40 = pool.find((e) => e.version.startsWith("4"));
  const primaryEntry = v31 ?? v40 ?? pool[0];
  const nvd = entries.find((e) => key(e.source) === "nvd");
  return {
    primary: primaryEntry ? toPick(primaryEntry) : null,
    v4: v40 ? toPick(v40) : null,
    nvdScore: nvd?.score ?? null,
    nvdSeverity: nvd?.level ?? null
  };
}
function parseCvssVector(vector) {
  const m = /^CVSS:(\d+\.\d+)\//.exec(clean(vector));
  return { version: m?.[1] ?? null };
}
function splitIds(v) {
  const s = clean(v);
  if (!s) return null;
  if (s.startsWith("[") && s.endsWith("]")) {
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) {
        const ids = parsed.map((x) => (typeof x === "string" ? x : String(x ?? "")).trim()).filter(Boolean);
        return ids.length > 0 ? ids : null;
      }
    } catch {
    }
  }
  const parts = s.split(/[,;|\s]+/).map((p) => p.replace(/^[\["'\s]+/, "").replace(/[\]"'\s]+$/, "").trim()).filter(Boolean);
  return parts.length > 0 ? parts : null;
}
function flattenJsonList(v) {
  const s = clean(v);
  if (!s) return null;
  if (s.startsWith("[") && s.endsWith("]")) {
    try {
      const parsed = JSON.parse(s);
      if (Array.isArray(parsed)) {
        const parts = parsed.map((x) => (typeof x === "string" ? x : String(x ?? "")).trim()).filter(Boolean);
        return parts.length > 0 ? parts.join(", ") : null;
      }
    } catch {
    }
  }
  return s;
}
function parseBool(v) {
  switch (key(v)) {
    case "true":
    case "yes":
    case "y":
    case "1":
      return true;
    case "false":
    case "no":
    case "n":
    case "0":
      return false;
    default:
      return null;
  }
}
function parseNumber(v) {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  const s = clean(v);
  if (!s) return null;
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}
function parseSnykTimestamp(v) {
  const raw = clean(v);
  if (!raw) return null;
  let iso = raw;
  if (!/[Tt]/.test(raw) && / /.test(raw)) iso = raw.replace(" ", "T");
  if (!/[Zz]$/.test(iso) && !/[+-]\d{2}:?\d{2}$/.test(iso)) iso += "Z";
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return null;
  return { ms, raw };
}

// snyk_report/lib/aggregate/build.mts
function emptyCounts() {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}
function countBySeverity(issues) {
  const out = emptyCounts();
  for (const i of issues) out[i.severity]++;
  return out;
}
function group(issues, keyOf) {
  const map = /* @__PURE__ */ new Map();
  for (const i of issues) {
    const k = keyOf(i);
    if (!k) continue;
    let g = map.get(k.key);
    if (!g) {
      g = { key: k.key, label: k.label, total: 0, bySeverity: emptyCounts() };
      map.set(k.key, g);
    }
    g.total++;
    g.bySeverity[i.severity]++;
  }
  return [...map.values()].sort(
    (a, b) => b.bySeverity.critical - a.bySeverity.critical || b.bySeverity.high - a.bySeverity.high || b.total - a.total
  );
}
function riskScore(issue, a) {
  let score = { critical: 100, high: 75, medium: 40, low: 15 }[issue.severity];
  if (stateOf(a, "isCisaKev") !== "absent") {
    const kev = read(issue, "isCisaKev");
    if (kev.state === "present" && kev.value) score += 30;
  }
  if (stateOf(a, "epssScore") !== "absent") {
    const epss = read(issue, "epssScore");
    if (epss.state === "present") score += Math.min(epss.value * 100, 10) * 2;
  }
  if (stateOf(a, "exploitMaturity") !== "absent") {
    const em = read(issue, "exploitMaturity");
    if (em.state === "present") {
      score += [18, 10, 0, 0, 0][exploitMaturityRank(em.value)] ?? 0;
    }
  }
  if (stateOf(a, "reachability") !== "absent") {
    const r = read(issue, "reachability");
    if (r.state === "present" && r.value === "reachable") score += 12;
  }
  if (stateOf(a, "existsInDirectDependency") !== "absent") {
    const d = read(issue, "existsInDirectDependency");
    if (d.state === "present" && d.value) score += 5;
  }
  if (stateOf(a, "fixability") !== "absent") {
    const f = read(issue, "fixability");
    if (f.state === "present" && f.value === "fixable") score += 3;
  }
  if (stateOf(a, "cvss") !== "absent") {
    const cv = read(issue, "cvss");
    if (cv.state === "present") score += cv.value.score / 2;
  }
  return score;
}
var RANKING_INPUTS = [
  "isCisaKev",
  "epssScore",
  "exploitMaturity",
  "reachability",
  "existsInDirectDependency",
  "fixability",
  "cvss"
];
function buildReport(issues, availability, opts = {}) {
  const used = [];
  const unavailable = [];
  for (const k of RANKING_INPUTS) {
    (stateOf(availability, k) === "absent" ? unavailable : used).push(k);
  }
  const scored = issues.map((issue) => ({ issue, s: riskScore(issue, availability) })).sort(
    (x, y) => y.s - x.s || SEVERITY_RANK[x.issue.severity] - SEVERITY_RANK[y.issue.severity] || x.issue.title.localeCompare(y.issue.title)
  );
  const byProductMap = /* @__PURE__ */ new Map();
  const byStatus = { open: 0, resolved: 0, ignored: 0 };
  for (const i of issues) {
    byProductMap.set(i.product, (byProductMap.get(i.product) ?? 0) + 1);
    byStatus[i.status]++;
  }
  let cisaKevCount = null;
  if (stateOf(availability, "isCisaKev") !== "absent") {
    cisaKevCount = 0;
    for (const i of issues) {
      const k = read(i, "isCisaKev");
      if (k.state === "present" && k.value) cisaKevCount++;
    }
  }
  const ranked = scored.map((x) => x.issue);
  const cap = opts.maxDetailRows;
  const capped = cap !== void 0 && cap > 0 && issues.length > cap;
  const detailIssues = capped ? ranked.slice(0, cap) : ranked;
  return {
    issues,
    ranked,
    detailIssues,
    detailTruncatedTo: capped ? cap : null,
    total: issues.length,
    byStatus,
    cisaKevCount,
    bySeverity: countBySeverity(issues),
    byProduct: [...byProductMap].map(([product, total]) => ({ product, total })).sort((a, b) => b.total - a.total),
    byProject: group(issues, (i) => {
      const p = i.project;
      if (!p) return null;
      const label = p.name ?? p.targetDisplayName ?? p.id ?? null;
      return label ? { key: p.id ?? label, label } : null;
    }),
    byOrg: group(issues, (i) => ({ key: i.org.id, label: i.org.name ?? i.org.id })),
    topRisks: scored.slice(0, opts.topN ?? 25).map((x) => x.issue),
    rankingInputsUsed: used,
    rankingInputsUnavailable: unavailable
  };
}

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
async function collect(client, path, params, nameKeys, hintKeys = []) {
  const out = [];
  for await (const row of client.paginate(path, params)) {
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
async function listOrgsInGroup(client, groupId) {
  return collect(client, `/rest/groups/${groupId}/orgs`, { limit: "100" }, ["name", "slug"], ["slug"]);
}
async function listOrgs(client) {
  return collect(client, "/rest/orgs", { limit: "100" }, ["name", "slug"], ["slug"]);
}
async function listTargets(client, orgId) {
  return collect(
    client,
    `/rest/orgs/${orgId}/targets`,
    { limit: "100", exclude_empty: "false" },
    ["display_name", "displayName", "name", "url"],
    ["origin"]
  );
}
async function tryList(what, fn) {
  try {
    return await fn();
  } catch (err) {
    log.warn(`could not list ${what}: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
async function resolveOrg(client, input, candidates) {
  const q = input.trim();
  if (!q) throw new Error("no organisation given");
  if (UUID.test(q)) {
    try {
      const doc = await client.get(`/rest/orgs/${q}`);
      const e = doc.data;
      if (e?.id) return { id: e.id, name: attr(e, "name", "slug") || e.id };
    } catch {
    }
    throw new Error(
      `No organisation with id ${q} is visible to this token. Check the id, and that the token belongs to the same region and has access to that organisation.`
    );
  }
  const pool = candidates ?? await listOrgs(client);
  const lower = q.toLowerCase();
  const exact = pool.filter((o) => o.name.toLowerCase() === lower);
  const partial = exact.length ? exact : pool.filter((o) => o.name.toLowerCase().includes(lower));
  if (partial.length === 1) return partial[0];
  if (partial.length === 0) {
    if (/^\d+$/.test(q)) {
      throw new Error(
        `"${q}" looks like a list position \u2014 this prompt wants a name or a UUID. Type "back" to return to the list.`
      );
    }
    throw new Error(
      `No organisation matching "${q}". Paste the org UUID instead, or check the spelling (${pool.length.toLocaleString()} organisation${pool.length === 1 ? "" : "s"} visible to this token).`
    );
  }
  throw new Error(
    `"${q}" matches ${partial.length} organisations: ${partial.slice(0, 6).map((o) => `${o.name} (${o.id})`).join(", ")}${partial.length > 6 ? ", ..." : ""}. Paste the exact name or the UUID.`
  );
}
async function resolveTargets(client, orgId, names, candidates) {
  const pool = candidates ?? await listTargets(client, orgId);
  const resolved = [];
  const missing = [];
  const ambiguous = [];
  for (const raw of names) {
    const q = raw.trim();
    if (!q) continue;
    const lower = q.toLowerCase();
    const exact = pool.find((t) => t.name.toLowerCase() === lower);
    const byRepo = exact ?? pool.find((t) => t.name.toLowerCase().endsWith(`/${lower}`));
    if (byRepo) {
      resolved.push(byRepo.name);
      continue;
    }
    if (lower.length >= 3) {
      const hits = pool.filter((t) => t.name.toLowerCase().includes(lower));
      if (hits.length === 1) {
        resolved.push(hits[0].name);
        continue;
      }
      if (hits.length > 1) {
        ambiguous.push(
          `"${q}" matches ${hits.length}: ${hits.slice(0, 5).map((t) => t.name).join(", ")}${hits.length > 5 ? ", ..." : ""}`
        );
        continue;
      }
    }
    missing.push(q);
  }
  if (ambiguous.length) {
    throw new Error(`Ambiguous target${ambiguous.length === 1 ? "" : "s"}. ${ambiguous.join("; ")}. Use the full name.`);
  }
  if (missing.length) {
    const numeric = missing.every((m) => /^\d+$/.test(m));
    throw new Error(
      `No target matching ${missing.map((m) => `"${m}"`).join(", ")} in this organisation. ` + (numeric ? 'That looks like a list position \u2014 this prompt wants a name. Type "back" to return to the list.' : `${pool.length.toLocaleString()} target${pool.length === 1 ? "" : "s"} are visible; check the spelling, or type "back" to pick from the list.`)
    );
  }
  return [...new Set(resolved)];
}

// snyk_report/lib/ingest/csv-file.mts
import { createReadStream } from "node:fs";
import { open } from "node:fs/promises";
import { createGunzip } from "node:zlib";

// snyk_report/lib/csv.mts
var DEFAULT_MAX_FIELD = 1 << 20;
var DEFAULT_MAX_FIELDS = 512;
var CsvError = class extends Error {
  // Declared and assigned separately: Node's strip-only TypeScript mode
  // rejects constructor parameter properties, since they emit runtime code.
  line;
  constructor(message, line) {
    super(`${message} (line ${line})`);
    this.name = "CsvError";
    this.line = line;
  }
};
var CsvParser = class {
  #delimiter;
  #maxField;
  #maxFields;
  #field = "";
  #fields = [];
  #inQuotes = false;
  /** Saw a `"` inside a quoted field; the next char decides escape vs close. */
  #quotePending = false;
  /** A record is only "started" once we have seen a character for it. */
  #started = false;
  #line = 1;
  #recordLine = 1;
  #atStart = true;
  // for one-time BOM removal
  /** Suppresses the \n of a \r\n that we already treated as a terminator. */
  #skipNextLf = false;
  constructor(opts = {}) {
    this.#delimiter = opts.delimiter ?? ",";
    this.#maxField = opts.maxFieldBytes ?? DEFAULT_MAX_FIELD;
    this.#maxFields = opts.maxRecordFields ?? DEFAULT_MAX_FIELDS;
  }
  write(chunk) {
    const out = [];
    let text = chunk;
    if (this.#atStart) {
      if (text.startsWith("\uFEFF")) text = text.slice(1);
      this.#atStart = false;
    }
    for (const ch of text) {
      if (this.#skipNextLf) {
        this.#skipNextLf = false;
        if (ch === "\n") {
          this.#line++;
          continue;
        }
      }
      if (this.#quotePending) {
        this.#quotePending = false;
        if (ch === '"') {
          this.#push('"');
          continue;
        }
        this.#inQuotes = false;
      }
      if (this.#inQuotes) {
        if (ch === '"') {
          this.#quotePending = true;
        } else {
          if (ch === "\n") this.#line++;
          this.#push(ch);
        }
        continue;
      }
      if (ch === '"' && this.#field === "") {
        this.#inQuotes = true;
        this.#started = true;
        continue;
      }
      if (ch === this.#delimiter) {
        this.#endField();
        continue;
      }
      if (ch === "\r" || ch === "\n") {
        if (ch === "\r") this.#skipNextLf = true;
        this.#line++;
        const rec = this.#endRecord();
        if (rec) out.push(rec);
        continue;
      }
      this.#push(ch);
    }
    return out;
  }
  /** Flush a final record that ended without a trailing newline. */
  end() {
    if (this.#inQuotes || this.#quotePending) {
      this.#inQuotes = false;
      this.#quotePending = false;
    }
    const rec = this.#endRecord();
    return rec ? [rec] : [];
  }
  #push(ch) {
    if (this.#field.length >= this.#maxField) {
      throw new CsvError(
        `field exceeds ${this.#maxField} bytes -- probably an unterminated quote`,
        this.#recordLine
      );
    }
    this.#field += ch;
    this.#started = true;
  }
  #endField() {
    if (this.#fields.length >= this.#maxFields) {
      throw new CsvError(`record exceeds ${this.#maxFields} fields`, this.#recordLine);
    }
    this.#fields.push(this.#field);
    this.#field = "";
    this.#started = true;
  }
  #endRecord() {
    if (!this.#started && this.#field === "" && this.#fields.length === 0) {
      this.#recordLine = this.#line;
      return null;
    }
    this.#fields.push(this.#field);
    const rec = { fields: this.#fields, line: this.#recordLine };
    this.#fields = [];
    this.#field = "";
    this.#started = false;
    this.#recordLine = this.#line;
    return rec;
  }
};
async function* csvRecords(input, opts = {}) {
  const parser = new CsvParser(opts);
  const decoder = new TextDecoder("utf-8");
  for await (const chunk of input) {
    const text = typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true });
    for (const rec of parser.write(text)) yield rec;
  }
  const tail = decoder.decode();
  if (tail) for (const rec of parser.write(tail)) yield rec;
  for (const rec of parser.end()) yield rec;
}
var INJECTION_PREFIX = /^[=+\-@\t\r]/;
function toCsvLine(fields) {
  return fields.map((raw) => {
    let s = raw === null || raw === void 0 ? "" : String(raw);
    if (INJECTION_PREFIX.test(s)) s = `'${s}`;
    return /["\n\r,]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }).join(",");
}

// snyk_report/lib/columns.mts
var COLUMN_TO_FIELD = {
  SCORE: "score",
  EPSS_SCORE: "epssScore",
  EPSS_PERCENTILE: "epssPercentile",
  SNYK_CVSS_SCORE: "cvss",
  SNYK_CVSS_VECTOR: "cvss",
  NVD_SCORE: "nvdScore",
  NVD_SEVERITY: "nvdSeverity",
  CVE: "cve",
  CWE: "cwe",
  EXPLOIT_MATURITY: "exploitMaturity",
  EXPLOIT_MATURITY_CVSS_V4: "exploitMaturity",
  COMPUTED_FIXABILITY: "fixability",
  FIXED_IN_AVAILABLE: "fixedInAvailable",
  FIXED_IN_VERSION: "fixedInVersion",
  SEMVER_VULNERABLE_RANGE: "semverVulnerableRange",
  EXISTS_IN_DIRECT_DEPENDENCY: "existsInDirectDependency",
  REACHABILITY: "reachability",
  PACKAGE_NAME_AND_VERSION: "packageNameAndVersion",
  FILE_PATH: "filePath",
  CODE_REGION: "codeRegion",
  CODE_REGION_DISPLAY_VALUE: "codeRegion",
  COMMIT_ID: "commitId",
  FIRST_INTRODUCED: "firstIntroduced",
  LAST_RESOLVED: "lastResolved",
  VULNERABILITY_PUBLICATION_DATE: "vulnerabilityPublicationDate",
  UPDATED_AT: "updatedAt",
  DELETED_AT: "deletedAt",
  ISSUE_URL: "issueUrl",
  ASSET_FINDING_ID: "assetFindingId",
  PROJECT_NAME: "project",
  PROJECT_URL: "project",
  PROJECT_PUBLIC_ID: "project",
  PROJECT_TYPE: "project",
  PROJECT_TARGET_DISPLAY_NAME: "project",
  PROJECT_CRITICALITY: "project",
  PROJECT_ENVIRONMENT: "project",
  PROJECT_LIFECYCLE: "project",
  PROJECT_OWNER: "project",
  PROJECT_ORIGIN: "project",
  PROJECT_TAGS: "project",
  GROUP_PUBLIC_ID: "group",
  GROUP_DISPLAY_NAME: "group",
  // Observed on a real Reports-tab export, absent from the Export API docs.
  IS_CISA_KEV: "isCisaKev",
  VULN_DB_URL: "vulnDbUrl",
  ISSUE_TYPE: "issueType",
  INTRODUCTION_CATEGORY: "introductionCategory",
  LAST_INTRODUCED: "lastIntroduced",
  LAST_IGNORED: "lastIgnored",
  ASSET_ID: "asset",
  ASSET_NAME: "asset",
  ASSET_TYPE: "asset",
  ASSET_CLASS: "asset",
  ASSET_LINK: "asset",
  ASSET_TAGS: "asset",
  // Export API spellings. ISSUE_DELETED_AT is the important one: the export
  // has no bare DELETED_AT, so before this was mapped every deleted issue
  // silently survived the "exclude deleted" default on API-sourced data.
  ISSUE_SUB_TYPE: "issueSubType",
  PROJECT_TARGET_REF: "project",
  PROJECT_TARGET_FILE: "project",
  PROJECT_OWNER_EMAIL: "project",
  PROJECT_OWNER_USERNAME: "project",
  PROJECT_TYPE_DISPLAY_NAME: "project",
  JIRA_ISSUES: "jiraIssues",
  HAS_JIRA_ISSUE_ASSIGNED: "jiraIssues",
  LATEST_JIRA_ISSUE: "jiraIssues"
};
var CORE_COLUMNS = [
  "PROBLEM_ID",
  "PROBLEM_TITLE",
  "ISSUE_SEVERITY",
  "ISSUE_STATUS",
  "PRODUCT_NAME",
  "ORG_PUBLIC_ID",
  "ORG_DISPLAY_NAME"
];
var ALIASES = {
  ISSUE_SEVERITY_LEVEL: "ISSUE_SEVERITY",
  SEVERITY: "ISSUE_SEVERITY",
  EFFECTIVE_SEVERITY: "ISSUE_SEVERITY",
  TITLE: "PROBLEM_TITLE",
  ISSUE_TITLE: "PROBLEM_TITLE",
  ISSUE_ID: "PROBLEM_ID",
  VULNERABILITY_ID: "PROBLEM_ID",
  STATUS: "ISSUE_STATUS",
  PRODUCT: "PRODUCT_NAME",
  ORGANIZATION: "ORG_DISPLAY_NAME",
  ORGANISATION: "ORG_DISPLAY_NAME",
  ORG_NAME: "ORG_DISPLAY_NAME",
  ORG_ID: "ORG_PUBLIC_ID",
  GROUP: "GROUP_DISPLAY_NAME",
  GROUP_NAME: "GROUP_DISPLAY_NAME",
  GROUP_ID: "GROUP_PUBLIC_ID",
  PROJECT: "PROJECT_NAME",
  PROJECT_ID: "PROJECT_PUBLIC_ID",
  TARGET: "PROJECT_TARGET_DISPLAY_NAME",
  TARGET_NAME: "PROJECT_TARGET_DISPLAY_NAME",
  PACKAGE: "PACKAGE_NAME_AND_VERSION",
  DEPENDENCY: "PACKAGE_NAME_AND_VERSION",
  CVSS_SCORE: "SNYK_CVSS_SCORE",
  CVSS_VECTOR: "SNYK_CVSS_VECTOR",
  PRIORITY_SCORE: "SCORE",
  RISK_SCORE: "SCORE",
  FIXABILITY: "COMPUTED_FIXABILITY",
  FIXED_IN: "FIXED_IN_VERSION",
  INTRODUCED: "FIRST_INTRODUCED",
  FIRST_INTRODUCED_DATE: "FIRST_INTRODUCED",
  // Reports-tab splits a hyperlink cell into text + URL.
  ISSUE_URL_LINK: "ISSUE_URL",
  PROJECT_URL_LINK: "PROJECT_URL",
  // Spellings confirmed against a real Reports-tab export. PROJECT_TARGET in
  // particular is the target display name -- missing this alias meant the
  // target column silently vanished from the report.
  PROJECT_TARGET: "PROJECT_TARGET_DISPLAY_NAME",
  PROJECT_TARGET_NAME: "PROJECT_TARGET_DISPLAY_NAME",
  PROJECT_CRITICALITIES: "PROJECT_CRITICALITY",
  PROJECT_ENVIRONMENTS: "PROJECT_ENVIRONMENT",
  PROJECT_LIFECYCLES: "PROJECT_LIFECYCLE",
  PROJECT_COLLECTIONS: "PROJECT_COLLECTION",
  CISA_KEV: "IS_CISA_KEV",
  IS_KEV: "IS_CISA_KEV",
  // The Export API emits ISSUE_DELETED_AT; the Reports tab emits DELETED_AT.
  // They mean the same thing and both must reach the deleted-issue filter.
  ISSUE_DELETED_AT: "DELETED_AT"
};
function canonicaliseName(raw) {
  const base = raw.replace(/^﻿/, "").trim().toUpperCase().replace(/[\s\-.]+/g, "_").replace(/[^A-Z0-9_]/g, "").replace(/_+/g, "_").replace(/^_|_$/g, "");
  return ALIASES[base] ?? base;
}
var IGNORED_COLUMNS = /* @__PURE__ */ new Set([
  "ISSUE_SEVERITY_RANK",
  // redundant with ISSUE_SEVERITY
  "IDENTIFIERS",
  // superseded by the dedicated CVE / CWE columns
  "SOURCE_CODE",
  "PARENT_ASSET_ID",
  "PARENT_ASSET_NAME",
  "PARENT_ASSET_LINK",
  "PROJECT_TARGET_REFERENCE",
  "PROJECT_COLLECTION",
  "INITIAL_ISSUE_TYPE",
  "PROJECT_IS_MONITORED",
  "PROJECT_TEST_FREQUENCY",
  // Present in a full Export API result; nothing in the report uses them.
  "ORG_SLUG",
  "GROUP_SLUG",
  "PROJECT_DELETED_AT",
  "GROUP_DELETED_AT",
  "PROJECT_TARGET_RUNTIME",
  "PROJECT_IS_PRIVATE_TARGET",
  "PROJECT_TARGET_SOURCE_TYPE",
  "PROJECT_TARGET_SOURCE_TYPE_DISPLAY_VALUE",
  "PROJECT_TARGET_UPSTREAM_URL",
  "REPOSITORY_FRESHNESS",
  "ASSET_APPLICATION",
  "ASSET_OWNER",
  "ASSET_CATEGORY",
  "ASSET_CATALOG_NAME",
  "ASSET_LIFECYCLE"
]);
var KNOWN = /* @__PURE__ */ new Set([
  ...Object.keys(COLUMN_TO_FIELD),
  ...CORE_COLUMNS,
  ...IGNORED_COLUMNS
]);
function canonicaliseHeader(raw) {
  const columns = raw.map(canonicaliseName);
  const index = /* @__PURE__ */ new Map();
  const unknown = [];
  columns.forEach((name, i) => {
    index.set(name, i);
    if (!KNOWN.has(name) && name !== "") unknown.push(name);
  });
  return { columns, index, unknown };
}
function cell(header, fields, name) {
  const i = header.index.get(name);
  if (i === void 0) return void 0;
  return fields[i] ?? "";
}

// snyk_report/lib/normalize/export-row.mts
function exportAvailability(header, source) {
  const present = new Set(header.columns);
  const reason = source === "csv" ? "not-in-csv-header" : "not-in-export-columns";
  const noteFor = (col) => source === "csv" ? `Column ${col} is not present in the uploaded CSV. Add it in the Snyk Reports column picker before exporting, or use the Export API, which returns every column by default.` : `Column ${col} was not requested from the Export API. Omit the columns parameter to receive all of them.`;
  const byField = /* @__PURE__ */ new Map();
  for (const [col, field] of Object.entries(COLUMN_TO_FIELD)) {
    const e = byField.get(field) ?? { cols: [], any: false };
    e.cols.push(col);
    if (present.has(col)) e.any = true;
    byField.set(field, e);
  }
  return makeAvailability(
    source,
    [...byField].map(
      ([field, e]) => e.any ? [field, { state: "carried", reason: "carried", note: "" }] : [
        field,
        { state: "absent", reason, note: noteFor(e.cols.join(" / ")) }
      ]
    )
  );
}
function makeExportNormalizer(header, opts) {
  const has = (name) => header.index.has(name);
  const hasEpss = has("EPSS_SCORE") || has("EPSS_PERCENTILE");
  const hasCvss = has("SNYK_CVSS_SCORE") || has("SNYK_CVSS_VECTOR");
  const hasExploit = has("EXPLOIT_MATURITY") || has("EXPLOIT_MATURITY_CVSS_V4");
  const hasProject = has("PROJECT_NAME") || has("PROJECT_PUBLIC_ID") || has("PROJECT_URL") || has("PROJECT_TYPE") || has("PROJECT_TARGET_DISPLAY_NAME");
  const hasGroup = has("GROUP_PUBLIC_ID") || has("GROUP_DISPLAY_NAME");
  const hasCodeRegion = has("CODE_REGION") || has("CODE_REGION_DISPLAY_VALUE");
  const hasAsset = has("ASSET_ID") || has("ASSET_NAME") || has("ASSET_TYPE") || has("ASSET_CLASS") || has("ASSET_LINK");
  return (fields, rowNumber) => {
    const get = (name) => cell(header, fields, name);
    const problemId = (get("PROBLEM_ID") ?? "").trim();
    const title = (get("PROBLEM_TITLE") ?? "").trim();
    const severity = normalizeSeverity(get("ISSUE_SEVERITY"));
    if (!problemId && !title) {
      return { ok: false, reason: "unparseable", detail: `row ${rowNumber}: no problem id/title` };
    }
    if (!severity) {
      return {
        ok: false,
        reason: "unparseable",
        detail: `row ${rowNumber}: unrecognised severity ${JSON.stringify(get("ISSUE_SEVERITY"))}`
      };
    }
    const deletedAt = parseSnykTimestamp(get("DELETED_AT"));
    if (deletedAt && !opts.includeDeleted) return { ok: false, reason: "deleted" };
    const orgId = (get("ORG_PUBLIC_ID") ?? opts.defaultOrg?.id ?? "").trim();
    const org = {
      id: orgId || "unknown",
      name: (get("ORG_DISPLAY_NAME") ?? opts.defaultOrg?.name ?? null) || null
    };
    const packageNameAndVersion = (get("PACKAGE_NAME_AND_VERSION") ?? "") || null;
    const filePath = (get("FILE_PATH") ?? "") || null;
    const assetFindingId = (get("ASSET_FINDING_ID") ?? "") || null;
    const projectId = (get("PROJECT_PUBLIC_ID") ?? "") || null;
    const projectName = (get("PROJECT_NAME") ?? "") || null;
    const issueUrl = (get("ISSUE_URL") ?? "") || null;
    const identity = issueIdentity({
      assetFindingId,
      issueUrl,
      orgId: org.id,
      projectId,
      projectName,
      problemId,
      packageNameAndVersion,
      filePath
    });
    const issue = {
      source: opts.source,
      issueKey: identity.key,
      problemId: problemId || title,
      title: title || problemId,
      severity,
      status: normalizeStatus(get("ISSUE_STATUS")) ?? "open",
      product: normalizeProduct(get("PRODUCT_NAME")),
      org
    };
    if (hasGroup) {
      const gid = (get("GROUP_PUBLIC_ID") ?? "").trim();
      const gname = (get("GROUP_DISPLAY_NAME") ?? "").trim();
      issue.group = gid || gname ? { id: gid || gname, name: gname || null } : null;
    }
    if (hasProject) {
      const p = {
        id: projectId,
        name: projectName,
        url: (get("PROJECT_URL") ?? "") || null,
        type: (get("PROJECT_TYPE") ?? "") || null,
        targetDisplayName: (get("PROJECT_TARGET_DISPLAY_NAME") ?? "") || null,
        criticality: (get("PROJECT_CRITICALITY") ?? "") || null,
        environment: (get("PROJECT_ENVIRONMENT") ?? "") || null,
        lifecycle: (get("PROJECT_LIFECYCLE") ?? "") || null,
        owner: (get("PROJECT_OWNER") ?? get("PROJECT_OWNER_USERNAME") ?? "") || null,
        ownerEmail: (get("PROJECT_OWNER_EMAIL") ?? "") || null,
        targetRef: (get("PROJECT_TARGET_REF") ?? "") || null,
        targetFile: (get("PROJECT_TARGET_FILE") ?? "") || null,
        origin: (get("PROJECT_ORIGIN") ?? "") || null,
        tags: splitIds(get("PROJECT_TAGS"))
      };
      issue.project = p.id || p.name || p.targetDisplayName ? p : null;
    }
    if (has("SCORE")) issue.score = parseNumber(get("SCORE"));
    if (hasEpss) {
      issue.epssScore = parseNumber(get("EPSS_SCORE"));
      issue.epssPercentile = parseNumber(get("EPSS_PERCENTILE"));
    }
    if (hasCvss) {
      const score = parseNumber(get("SNYK_CVSS_SCORE"));
      const vector = (get("SNYK_CVSS_VECTOR") ?? "") || null;
      if (score === null && vector === null) {
        issue.cvss = null;
      } else {
        const version = vector ? parseCvssVector(vector).version ?? "3.1" : "3.1";
        const entry = { source: "Snyk", version, score, vector, level: null };
        issue.cvss = pickCvss([entry]).primary;
      }
    }
    if (has("NVD_SCORE")) issue.nvdScore = parseNumber(get("NVD_SCORE"));
    if (has("NVD_SEVERITY")) {
      issue.nvdSeverity = normalizeSeverity(get("NVD_SEVERITY"));
    }
    if (hasExploit) {
      const r = normalizeExploitMaturity(get("EXPLOIT_MATURITY"), get("EXPLOIT_MATURITY_CVSS_V4"));
      issue.exploitMaturity = r.value;
      issue.exploitVocab = r.vocab;
    }
    if (has("CVE")) issue.cve = splitIds(get("CVE"));
    if (has("CWE")) issue.cwe = splitIds(get("CWE"));
    if (has("COMPUTED_FIXABILITY")) issue.fixability = normalizeFixability(get("COMPUTED_FIXABILITY"));
    if (has("FIXED_IN_AVAILABLE")) issue.fixedInAvailable = parseBool(get("FIXED_IN_AVAILABLE"));
    if (has("FIXED_IN_VERSION")) issue.fixedInVersion = flattenJsonList(get("FIXED_IN_VERSION"));
    if (has("SEMVER_VULNERABLE_RANGE")) {
      issue.semverVulnerableRange = flattenJsonList(get("SEMVER_VULNERABLE_RANGE"));
    }
    if (has("EXISTS_IN_DIRECT_DEPENDENCY")) {
      issue.existsInDirectDependency = parseBool(get("EXISTS_IN_DIRECT_DEPENDENCY"));
    }
    if (has("REACHABILITY")) issue.reachability = normalizeReachability(get("REACHABILITY"));
    if (has("PACKAGE_NAME_AND_VERSION")) issue.packageNameAndVersion = packageNameAndVersion;
    if (has("FILE_PATH")) issue.filePath = filePath;
    if (hasCodeRegion) {
      const raw = (get("CODE_REGION_DISPLAY_VALUE") ?? get("CODE_REGION") ?? "").trim();
      issue.codeRegion = raw ? { raw, ...parseRegion(raw) } : null;
    }
    if (has("COMMIT_ID")) issue.commitId = (get("COMMIT_ID") ?? "") || null;
    if (has("FIRST_INTRODUCED")) issue.firstIntroduced = parseSnykTimestamp(get("FIRST_INTRODUCED"));
    if (has("LAST_RESOLVED")) issue.lastResolved = parseSnykTimestamp(get("LAST_RESOLVED"));
    if (has("VULNERABILITY_PUBLICATION_DATE")) {
      issue.vulnerabilityPublicationDate = parseSnykTimestamp(get("VULNERABILITY_PUBLICATION_DATE"));
    }
    if (has("UPDATED_AT")) issue.updatedAt = parseSnykTimestamp(get("UPDATED_AT"));
    if (has("DELETED_AT")) issue.deletedAt = deletedAt;
    if (has("ISSUE_URL")) issue.issueUrl = issueUrl;
    if (has("ASSET_FINDING_ID")) issue.assetFindingId = assetFindingId;
    if (has("VULN_DB_URL")) issue.vulnDbUrl = (get("VULN_DB_URL") ?? "") || null;
    if (has("ISSUE_TYPE")) issue.issueType = (get("ISSUE_TYPE") ?? "") || null;
    if (has("ISSUE_SUB_TYPE")) issue.issueSubType = (get("ISSUE_SUB_TYPE") ?? "") || null;
    if (has("JIRA_ISSUES") || has("LATEST_JIRA_ISSUE")) {
      issue.jiraIssues = splitIds(get("JIRA_ISSUES") ?? get("LATEST_JIRA_ISSUE"));
    }
    if (has("INTRODUCTION_CATEGORY")) {
      issue.introductionCategory = (get("INTRODUCTION_CATEGORY") ?? "") || null;
    }
    if (has("IS_CISA_KEV")) issue.isCisaKev = parseBool(get("IS_CISA_KEV"));
    if (has("LAST_INTRODUCED")) issue.lastIntroduced = parseSnykTimestamp(get("LAST_INTRODUCED"));
    if (has("LAST_IGNORED")) issue.lastIgnored = parseSnykTimestamp(get("LAST_IGNORED"));
    if (hasAsset) {
      const a = {
        id: (get("ASSET_ID") ?? "") || null,
        name: (get("ASSET_NAME") ?? "") || null,
        type: (get("ASSET_TYPE") ?? "") || null,
        klass: (get("ASSET_CLASS") ?? "") || null,
        url: (get("ASSET_LINK") ?? "") || null
      };
      issue.asset = a.id || a.name ? a : null;
    }
    if (opts.retainRaw) issue.raw = fields;
    return { ok: true, issue, keyStrength: identity.strength };
  };
}
function parseRegion(raw) {
  try {
    const o = JSON.parse(raw);
    const start = o["start"]?.line;
    const end = o["end"]?.line;
    return {
      ...typeof start === "number" ? { startLine: start } : {},
      ...typeof end === "number" ? { endLine: end } : {}
    };
  } catch {
    const m = /^(\d+)/.exec(raw);
    return m?.[1] ? { startLine: Number(m[1]) } : {};
  }
}

// snyk_report/lib/ingest/csv-file.mts
async function isGzip(path) {
  const fh = await open(path, "r");
  try {
    const buf = Buffer.alloc(2);
    const { bytesRead } = await fh.read(buf, 0, 2, 0);
    return bytesRead === 2 && buf[0] === 31 && buf[1] === 139;
  } finally {
    await fh.close();
  }
}
function looksLikeXml(first) {
  return first.trimStart().startsWith("<");
}
async function ingestCsvFile(path, opts) {
  const gz = await isGzip(path);
  const raw = createReadStream(path);
  const stream = gz ? raw.pipe(createGunzip()) : raw;
  return ingestCsvStream(stream, opts);
}
async function ingestCsvStream(stream, opts) {
  let header = null;
  let normalize = null;
  const issues = [];
  const seen = /* @__PURE__ */ new Set();
  const problems = [];
  const dropped = { deleted: 0, unparseable: 0, duplicate: 0, filtered: 0 };
  let rowsRead = 0;
  let weakKeyCollisions = 0;
  let keyStrength = "strong";
  for await (const rec of csvRecords(stream)) {
    if (!header) {
      const first = rec.fields[0] ?? "";
      if (looksLikeXml(first)) {
        throw new Error(
          "That file is XML, not CSV. An expired Export API signed link returns an S3 <Error> document -- re-fetch the export result to mint a fresh URL."
        );
      }
      header = canonicaliseHeader(rec.fields);
      normalize = makeExportNormalizer(header, {
        source: opts.source,
        includeDeleted: opts.includeDeleted,
        retainRaw: opts.retainRaw ?? false,
        ...opts.defaultOrg ? { defaultOrg: opts.defaultOrg } : {}
      });
      continue;
    }
    rowsRead++;
    const result = normalize(rec.fields, rec.line);
    if (!result.ok) {
      dropped[result.reason]++;
      if (result.detail && problems.length < 20) problems.push(result.detail);
      continue;
    }
    if (result.keyStrength === "strong") {
      if (seen.has(result.issue.issueKey)) {
        dropped.duplicate++;
        continue;
      }
    } else {
      keyStrength = "weak";
      if (seen.has(result.issue.issueKey)) weakKeyCollisions++;
    }
    seen.add(result.issue.issueKey);
    issues.push(result.issue);
  }
  if (!header) throw new Error("The CSV is empty -- no header row found.");
  return {
    issues,
    summary: {
      header,
      availability: exportAvailability(header, opts.source),
      rowsRead,
      dropped,
      unknownColumns: header.unknown,
      problems,
      keyStrength,
      weakKeyCollisions,
      noFindings: issues.length === 0
    }
  };
}

// snyk_report/lib/ingest/export-api.mts
import { Readable } from "node:stream";
import { createGunzip as createGunzip2 } from "node:zlib";

// snyk_report/lib/regions.mts
var REGIONS = [
  { key: "us", label: "SNYK-US-01 (app.snyk.io)", url: "https://api.snyk.io" },
  { key: "us02", label: "SNYK-US-02 (app.us.snyk.io)", url: "https://api.us.snyk.io" },
  { key: "eu", label: "SNYK-EU-01 (app.eu.snyk.io)", url: "https://api.eu.snyk.io" },
  { key: "au", label: "SNYK-AU-01 (app.au.snyk.io)", url: "https://api.au.snyk.io" },
  { key: "gov", label: "SNYK-GOV-01 (app.snykgov.io)", url: "https://api.snykgov.io" }
];
var REST_VERSION = "2024-10-15";
function resolveRegion(input) {
  const key2 = input.trim().toLowerCase();
  const match = REGIONS.find((r) => r.key === key2);
  if (match) return match.url;
  if (/^https?:\/\//i.test(input)) return input.replace(/\/+$/, "");
  return null;
}
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
function redactUrl(url) {
  try {
    const u = new URL(url);
    return u.search ? `${u.origin}${u.pathname}?<signed>` : `${u.origin}${u.pathname}`;
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
  async get(path, params = {}) {
    const url = new URL(path.startsWith("http") ? path : `${this.baseUrl}${path}`);
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
  async post(path, body) {
    const url = new URL(path.startsWith("http") ? path : `${this.baseUrl}${path}`);
    if (!url.searchParams.has("version")) url.searchParams.set("version", REST_VERSION);
    return request(url.toString(), {
      method: "POST",
      headers: this.#headers("application/vnd.api+json"),
      body: JSON.stringify(body)
    });
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
  async *paginate(path, params = {}, opts = {}) {
    const maxPages = opts.maxPages ?? 2e4;
    let url = this.#absolute(path, params);
    const seenCursors = /* @__PURE__ */ new Set();
    for (let page2 = 1; url && page2 <= maxPages; page2++) {
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
  #absolute(path, params) {
    const url = new URL(path.startsWith("http") ? path : `${this.baseUrl}${path}`);
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
async function fetchSigned(url) {
  const res = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
  if (!res.ok) {
    throw new Error(
      `Could not download the export file (${res.status}) from ${redactUrl(url)}. Signed links expire 60 minutes after they are minted; re-fetch the export result to get fresh ones.`
    );
  }
  return res;
}

// snyk_report/lib/ingest/export-api.mts
function validateFilters(f) {
  const problems = [];
  if (!f.introducedFrom && !f.updatedFrom) {
    problems.push(
      "The Export API requires at least one date filter (introduced or updated). Pass --since 7d|14d|30d|90d|all."
    );
  }
  for (const [name, v] of [
    ["introduced.from", f.introducedFrom],
    ["introduced.to", f.introducedTo],
    ["updated.from", f.updatedFrom]
  ]) {
    if (v && Number.isNaN(Date.parse(v))) problems.push(`${name} is not a valid date: ${v}`);
  }
  return problems;
}
function buildBody(scope, f) {
  const filters = {};
  if (f.introducedFrom || f.introducedTo) {
    filters["introduced"] = {
      ...f.introducedFrom ? { from: f.introducedFrom } : {},
      ...f.introducedTo ? { to: f.introducedTo } : {}
    };
  }
  if (f.updatedFrom) filters["updated"] = { from: f.updatedFrom };
  if (f.targetDisplayNames?.length) filters["project_target_display_name"] = f.targetDisplayNames;
  if (scope.kind === "groups" && f.orgs?.length) filters["orgs"] = f.orgs;
  return {
    data: {
      type: "resource",
      attributes: {
        formats: ["csv"],
        dataset: "issues",
        // No `columns`: omitting it returns every column. See the file header.
        filters
      }
    }
  };
}
async function startExport(client, scope, filters) {
  const problems = validateFilters(filters);
  if (problems.length) throw new Error(problems.join("\n"));
  const res = await client.post(
    `/rest/${scope.kind}/${scope.id}/export`,
    buildBody(scope, filters)
  );
  if (res.status === 429) {
    throw new Error(
      `Export rate limit reached: the API allows 20 export requests per hour. Retry after ${res.headers["retry-after"] ?? "a while"}, or re-attach to an export you already started with --export-id.`
    );
  }
  if (res.status === 404) {
    throw new Error(
      `No ${scope.kind === "orgs" ? "organisation" : "group"} ${scope.id} is visible to this token. If that id is a ${scope.kind === "orgs" ? "group" : "organisation"}, re-run with ${scope.kind === "orgs" ? "--group" : "--org"} instead. ${describeError(res)}`
    );
  }
  if (res.status === 403) {
    throw new Error(
      `The token is valid but not allowed to export from this ${scope.kind.slice(0, -1)}. Group-scope exports need a group-level token or service account. ${describeError(res)}`
    );
  }
  if (res.status < 200 || res.status >= 300) throw new Error(describeError(res));
  const exportId = res.data?.data?.id;
  if (!exportId) throw new Error(`the API accepted the export but returned no id: ${describeError(res)}`);
  return { exportId, scope };
}
async function waitForExport(client, job, opts = {}) {
  const deadline = Date.now() + (opts.timeoutMs ?? 30 * 6e4);
  const delays = [5e3, 5e3, 1e4, 1e4, 2e4, 3e4];
  let i = 0;
  let lastStatus = "";
  for (; ; ) {
    if (Date.now() > deadline) {
      throw new Error(
        `The export was still ${lastStatus || "running"} after the timeout. It is not lost: re-attach with --export-id ${job.exportId}. Results are kept for three days.`
      );
    }
    await new Promise((r) => setTimeout(r, delays[Math.min(i++, delays.length - 1)]));
    const status = await client.get(
      `/rest/${job.scope.kind}/${job.scope.id}/jobs/export/${job.exportId}`
    );
    const state = (status.data?.attributes?.status ?? "").toUpperCase();
    if (state !== lastStatus) {
      log.dim(`export ${job.exportId}: ${state.toLowerCase() || "pending"}`);
      lastStatus = state;
    }
    if (state === "ERROR") {
      throw new Error(`Snyk reported the export failed (export id ${job.exportId}).`);
    }
    if (state === "FINISHED") break;
  }
  return fetchExportResult(client, job);
}
async function fetchExportResult(client, job) {
  const result = await client.get(
    `/rest/${job.scope.kind}/${job.scope.id}/export/${job.exportId}`
  );
  const urls = (result.data?.attributes?.results ?? []).map((r) => r.url).filter((u) => Boolean(u));
  if (urls.length === 0) {
    log.warn(
      "the export finished with no files: nothing in this scope matched. Writing a clean report that records the filters which produced it."
    );
  }
  return { urls };
}
function isGzip2(head) {
  return head.length >= 2 && head[0] === 31 && head[1] === 139;
}
async function downloadExport(client, job, result, opts) {
  const issues = [];
  const seen = /* @__PURE__ */ new Set();
  const problems = [];
  const dropped = { deleted: 0, unparseable: 0, duplicate: 0, filtered: 0 };
  let rowsRead = 0;
  let weakKeyCollisions = 0;
  let keyStrength = "strong";
  let header = null;
  let firstColumns = "";
  for (const [index, url] of result.urls.entries()) {
    log.dim(`downloading part ${index + 1} of ${result.urls.length}`);
    let res = await fetchSigned(url).catch(async (err) => {
      log.dim(`${err.message.split(".")[0]} - re-minting signed links`);
      const fresh = await fetchExportResult(client, job);
      const replacement = fresh.urls[index];
      if (!replacement) throw err;
      return fetchSigned(replacement);
    });
    const buf = new Uint8Array(await res.arrayBuffer());
    if (buf.length && buf[0] === 60) {
      throw new Error(
        `The export download returned an XML error document rather than CSV (${redactUrl(url)}). The signed link had probably expired.`
      );
    }
    const body = isGzip2(buf) ? Readable.from([Buffer.from(buf)]).pipe(createGunzip2()) : Readable.from([Buffer.from(buf)]);
    let normalize = null;
    let partHeader = null;
    for await (const rec of csvRecords(body)) {
      if (!partHeader) {
        partHeader = canonicaliseHeader(rec.fields);
        const signature = partHeader.columns.join("|");
        if (header === null) {
          header = partHeader;
          firstColumns = signature;
        } else if (signature !== firstColumns) {
          throw new Error(
            `Export part ${index + 1} has a different column set from part 1. Refusing to merge them, because misaligned columns would corrupt every row.`
          );
        }
        normalize = makeExportNormalizer(partHeader, {
          source: "export-api",
          includeDeleted: opts.includeDeleted,
          retainRaw: false
        });
        continue;
      }
      rowsRead++;
      const out = normalize(rec.fields, rec.line);
      if (!out.ok) {
        dropped[out.reason]++;
        if (out.detail && problems.length < 20) problems.push(out.detail);
        continue;
      }
      if (out.keyStrength === "strong") {
        if (seen.has(out.issue.issueKey)) {
          dropped.duplicate++;
          continue;
        }
      } else {
        keyStrength = "weak";
        if (seen.has(out.issue.issueKey)) weakKeyCollisions++;
      }
      seen.add(out.issue.issueKey);
      issues.push(out.issue);
    }
  }
  if (!header) {
    return {
      issues: [],
      summary: {
        header: canonicaliseHeader([]),
        availability: exportAvailability(canonicaliseHeader([]), "export-api"),
        rowsRead: 0,
        dropped,
        unknownColumns: [],
        problems,
        keyStrength: "strong",
        weakKeyCollisions: 0,
        noFindings: true
      }
    };
  }
  return {
    issues,
    summary: {
      header,
      availability: exportAvailability(header, "export-api"),
      rowsRead,
      dropped,
      unknownColumns: header.unknown,
      problems,
      keyStrength,
      weakKeyCollisions,
      noFindings: issues.length === 0
    }
  };
}
var SINCE_CHOICES = [
  { value: "7d", label: "Last 7 days" },
  { value: "14d", label: "Last 14 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
  { value: "all", label: "All time" }
];
function sinceToFilters(preset) {
  if (preset === "all") return { introducedFrom: "1970-01-01T00:00:00Z" };
  const days = Number(preset.replace("d", ""));
  const from = new Date(Date.now() - days * 864e5);
  return { introducedFrom: `${from.toISOString().slice(0, 19)}Z` };
}
function describeSince(preset) {
  return SINCE_CHOICES.find((c2) => c2.value === preset)?.label ?? preset;
}

// snyk_report/lib/ingest/tests-api.mts
var SAFE_ID = /^[A-Za-z0-9_-]+$/;
function validId(value, label) {
  if (!value || !SAFE_ID.test(value)) {
    throw new Error(`${label} must contain only letters, digits, '-' or '_' (got: ${JSON.stringify(value)})`);
  }
  return value;
}
async function startCodeTest(client, orgId, resource) {
  orgId = validId(orgId, "--org");
  const scmResource = {
    type: "scm",
    repo_url: resource.repoUrl,
    integration_id: resource.integrationId,
    file_patterns: resource.filePatterns ?? []
  };
  if (resource.ref) scmResource["ref"] = resource.ref;
  if (resource.commit) scmResource["commit"] = resource.commit;
  const res = await client.post(`/rest/orgs/${orgId}/tests`, {
    data: {
      type: "tests",
      attributes: {
        resources: [{ type: "base", resource: scmResource }],
        config: { scan_config: { sast: {} } }
      }
    }
  });
  if (res.status === 422) {
    const codes = new Set((res.data.errors ?? []).map((e) => e.code));
    if (codes.has("SNYK-TARGET-0002")) {
      throw new Error(
        `SNYK-TARGET-0002 -- more than one imported target matches (${resource.integrationId}, ${resource.repoUrl}).
  List them: GET /rest/orgs/${orgId}/targets?url=${resource.repoUrl}
  Then deactivate/merge the duplicates in the Snyk UI under Snyk admin -> Projects -> Targets.`
      );
    }
  }
  if (res.status === 429) {
    throw new Error(
      `Scan rate limit reached: 15 test creates/sec per org, 30/sec org-wide. Retry after ${res.headers["retry-after"] ?? "a while"}.`
    );
  }
  if (res.status < 200 || res.status >= 300) throw new Error(describeError(res));
  const jobId = res.data.data?.id;
  if (!jobId) throw new Error(`the API accepted the scan but returned no test_jobs id: ${describeError(res)}`);
  return jobId;
}
var IN_PROGRESS_STATUSES = /* @__PURE__ */ new Set(["pending", "in_progress", "started", "accepted", "running"]);
var SUCCESS_STATUSES = /* @__PURE__ */ new Set(["succeeded", "completed", "finished"]);
function extractTestId(body) {
  return body.data?.relationships?.test?.data?.id ?? body.data?.relationships?.tests?.data?.id ?? body.data?.attributes?.test_id ?? body.data?.attributes?.testId;
}
async function waitForCodeTest(client, orgId, jobId, opts = {}) {
  orgId = validId(orgId, "--org");
  jobId = validId(jobId, "--job-id");
  const deadline = Date.now() + (opts.timeoutMs ?? 10 * 6e4);
  const delays = [5e3, 5e3, 5e3, 1e4, 1e4, 2e4];
  let i = 0;
  let lastStatus = "";
  for (; ; ) {
    const body = await client.get(`/rest/orgs/${orgId}/test_jobs/${jobId}`);
    const attrs = body.data?.attributes ?? {};
    const status = attrs.status || attrs.state?.execution || "";
    if (status !== lastStatus) {
      log.dim(`test_job ${jobId}: ${status || "pending"}`);
      lastStatus = status;
    }
    if (!IN_PROGRESS_STATUSES.has(status)) {
      const stateErrors = attrs.state?.errors ?? [];
      const erroredOut = status === "errored" || stateErrors.length > 0;
      const testId = extractTestId(body);
      if (erroredOut || !testId) {
        throw new Error(
          `test_job ${jobId} ${erroredOut ? "errored" : "finished with no test id"} (status: ${status || "unknown"}): ${JSON.stringify(body)}`
        );
      }
      if (status === "failed") {
        log.dim(`test_job ${jobId} status is 'failed' (a policy threshold was breached) -- findings are still available`);
      } else if (!SUCCESS_STATUSES.has(status)) {
        log.dim(`test_job ${jobId} reached unrecognised terminal status '${status}' but returned a test id -- continuing`);
      }
      return testId;
    }
    if (Date.now() > deadline) {
      throw new Error(
        `test_job ${jobId} was still '${status}' after the timeout. It is not lost: re-run with --job-id ${jobId} to keep waiting.`
      );
    }
    await new Promise((r) => setTimeout(r, delays[Math.min(i++, delays.length - 1)]));
  }
}
async function fetchTestComponents(client, orgId, testId) {
  orgId = validId(orgId, "--org");
  testId = validId(testId, "--test-id");
  const body = await client.get(`/rest/orgs/${orgId}/tests/${testId}`);
  const map = /* @__PURE__ */ new Map();
  for (const c2 of body.data?.attributes?.components ?? []) {
    if (c2.key) map.set(c2.key, { assetId: c2.asset_id ?? "", projectId: c2.project_id ?? "" });
  }
  return map;
}
function testsApiAvailability() {
  const carried = ["cwe", "filePath", "codeRegion", "dataflow", "asset", "project", "assetFindingId", "commitId"];
  const absent = [
    ["group", "The Tests v2 test resource does not report group membership."],
    ["score", "Tests v2 findings carry no computed risk score."],
    ["riskFactors", "Tests v2 findings carry no risk factors list."],
    ["cvss", "A Snyk Code rule finding has no CVSS assessment -- CVSS applies to CVE-based vulnerabilities."],
    ["cvssV4", "Same as CVSS v3: not applicable to a code rule finding."],
    ["cvssAll", "Same as CVSS v3: not applicable to a code rule finding."],
    ["nvdScore", "Snyk Code rules are not NVD entries."],
    ["nvdSeverity", "Snyk Code rules are not NVD entries."],
    ["epssScore", "EPSS scores CVE-based vulnerabilities; a code rule finding has no CVE."],
    ["epssPercentile", "EPSS scores CVE-based vulnerabilities; a code rule finding has no CVE."],
    ["exploitMaturity", "Exploit maturity is an Open Source concept; Tests v2 findings do not carry it."],
    ["exploitVocab", "Exploit maturity is an Open Source concept; Tests v2 findings do not carry it."],
    ["cve", "Snyk Code rules are not CVE-based."],
    ["fixability", "A source-code finding has no dependency upgrade path."],
    ["fixedInAvailable", "A source-code finding has no dependency upgrade path."],
    ["fixedInVersion", "A source-code finding has no dependency upgrade path."],
    ["semverVulnerableRange", "A source-code finding has no dependency version range."],
    ["existsInDirectDependency", "A source-code finding is not a dependency."],
    ["reachability", "Not returned by this API version for SAST findings."],
    ["packageNameAndVersion", "A source-code finding has no package."],
    ["firstIntroduced", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["lastResolved", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["vulnerabilityPublicationDate", "Snyk Code rules are not published advisories with a disclosure date."],
    ["updatedAt", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["deletedAt", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["issueUrl", "Tests v2 findings carry no browsable Snyk UI link, only the technical key used to dedupe."],
    ["vulnDbUrl", "Not applicable to a Snyk Code rule finding."],
    ["issueType", "Not returned by this API version."],
    ["issueSubType", "Not returned by this API version."],
    ["jiraIssues", "Not returned by this API version."],
    ["introductionCategory", "Not returned by this API version."],
    ["isCisaKev", "CISA KEV tracks CVE-based vulnerabilities; a code rule finding has no CVE."],
    ["lastIntroduced", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["lastIgnored", "A Tests v2 scan is a point-in-time result; it carries no historical timestamps."],
    ["raw", "The raw finding is not retained by this ingestion path."]
  ];
  return makeAvailability("tests-api", [
    ...carried.map(
      (k) => [k, { state: "carried", reason: "carried", note: "" }]
    ),
    ...absent.map(
      ([k, note]) => [k, { state: "absent", reason: "source-limitation", note }]
    )
  ]);
}
async function ingestTestsApiFindings(client, orgId, testId, components, opts) {
  orgId = validId(orgId, "--org");
  testId = validId(testId, "--test-id");
  const issues = [];
  const seen = /* @__PURE__ */ new Set();
  const dropped = { deleted: 0, unparseable: 0, duplicate: 0, filtered: 0 };
  const problems = [];
  let rowsRead = 0;
  for await (const finding of client.paginate(`/rest/orgs/${orgId}/tests/${testId}/findings`)) {
    rowsRead++;
    const a = finding.attributes ?? {};
    if (a.finding_type !== "sast") {
      dropped.filtered++;
      continue;
    }
    const key2 = a.key || finding.id;
    const severity = normalizeSeverity(a.rating?.severity);
    if (!key2 || !severity) {
      dropped.unparseable++;
      if (problems.length < 20) problems.push(`finding ${finding.id ?? "?"}: missing key or unrecognised severity`);
      continue;
    }
    const issueKey = `tests-api:${key2}`;
    if (seen.has(issueKey)) {
      dropped.duplicate++;
      continue;
    }
    seen.add(issueKey);
    const locations = a.locations ?? [];
    const primary = locations.find((l) => l.type === "source") ?? locations[0];
    const cwe = (a.problems ?? []).filter((p) => p.source === "cwe" && p.id).map((p) => p.id);
    const rule = (a.problems ?? []).find((p) => p.source === "snyk_code_rule");
    const flow = (a.evidence ?? []).find((e) => e.source === "execution_flow")?.flow ?? [];
    const dataflow = flow.map((s) => ({
      file: s.file_path ?? "",
      fromLine: s.from_line ?? null,
      fromColumn: s.from_column ?? null,
      toLine: s.to_line ?? null,
      toColumn: s.to_column ?? null
    }));
    const comp = a.component_key ? components.get(a.component_key) : void 0;
    const issue = {
      source: "tests-api",
      issueKey,
      problemId: rule?.id || key2,
      title: a.title || rule?.id || "Snyk Code finding",
      severity,
      status: "open",
      // findings are excluded once suppressed; everything returned is live
      product: "code",
      org: opts.org,
      cwe: cwe.length ? cwe : null,
      filePath: primary?.file_path ?? null,
      codeRegion: primary ? {
        raw: `${primary.from_line ?? ""}:${primary.from_column ?? ""}-${primary.to_line ?? ""}:${primary.to_column ?? ""}`,
        ...primary.from_line != null ? { startLine: primary.from_line } : {},
        ...primary.to_line != null ? { endLine: primary.to_line } : {},
        ...primary.from_column != null ? { startColumn: primary.from_column } : {},
        ...primary.to_column != null ? { endColumn: primary.to_column } : {}
      } : null,
      dataflow: dataflow.length ? dataflow : null,
      assetFindingId: key2,
      commitId: opts.commit ?? null,
      asset: comp?.assetId ? { id: comp.assetId } : null,
      project: comp?.projectId ? { id: comp.projectId } : null
    };
    issues.push(issue);
  }
  const header = {
    columns: ["PROBLEM_ID", "PROBLEM_TITLE", "ISSUE_SEVERITY", "CWE", "FILE_PATH", "CODE_REGION", "DATAFLOW"],
    index: /* @__PURE__ */ new Map([
      ["PROBLEM_ID", 0],
      ["PROBLEM_TITLE", 1],
      ["ISSUE_SEVERITY", 2],
      ["CWE", 3],
      ["FILE_PATH", 4],
      ["CODE_REGION", 5],
      ["DATAFLOW", 6]
    ]),
    unknown: []
  };
  return {
    issues,
    summary: {
      header,
      availability: testsApiAvailability(),
      rowsRead,
      dropped,
      unknownColumns: [],
      problems,
      // `key` is Snyk's own stable aggregation key (see attributes.key in the
      // findings response), never a synthesised fallback.
      keyStrength: "strong",
      weakKeyCollisions: 0
    }
  };
}

// snyk_report/lib/interactive.mts
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

// snyk_report/lib/render/theme.mts
var SEV = {
  critical: { color: "#AB1A1A", letter: "C", tint: "#FDE8E9", label: "Critical" },
  high: { color: "#CE501B", letter: "H", tint: "#FDEADE", label: "High" },
  medium: { color: "#D68000", letter: "M", tint: "#FDF1DA", label: "Medium" },
  low: { color: "#88879E", letter: "L", tint: "#F1F1F3", label: "Low" }
};
var RAMP = ["#3E1E93", "#6F00DD", "#8F3CE8", "#C481F3", "#DDB6F8", "#F0E1FC", "#5B26C8"];
function seriesColor(i) {
  return RAMP[i % RAMP.length];
}
var NEUTRAL_CHIP = { bg: "#F4F4F6", fg: "#4A4A52", border: "#DEDEE2" };
var REACH = {
  reachable: { bg: "#FDE8E9", fg: "#8C0615", border: "#F2C7CB" },
  "potentially-reachable": { bg: "#FDF1DA", fg: "#8A5300", border: "#F0DCB0" },
  "not-reachable": NEUTRAL_CHIP,
  "no-path-found": NEUTRAL_CHIP,
  "not-applicable": { bg: "#F4F4F6", fg: "#6B6B72", border: "#DEDEE2" }
};
var reachChip = (v) => REACH[v] ?? NEUTRAL_CHIP;
var C = {
  ink: "#14121A",
  body: "#2F2F36",
  muted: "#4A4A52",
  subtle: "#6B6B72",
  faint: "#9A9AA0",
  line: "#E4E3E8",
  lineSoft: "#EDEDEF",
  lineFaint: "#F4F4F6",
  surface: "#FAFAFB",
  paper: "#FFFFFF",
  canvas: "#E9E8ED",
  coverInk: "#0B0613",
  accent: "#6F00DD",
  accentHover: "#8F3CE8",
  accentDeep: "#3E1E93",
  accentDark: "#5B1BAF",
  accentTint: "#F3E9FE",
  accentWash: "#FBF8FE",
  accentBorder: "#C9A6F5",
  success: "#00875A",
  successDeep: "#00734A",
  successDot: "#00A86B",
  dangerDeep: "#8C0615"
};
var FONT_SANS = '"Geist", "Inter", system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
var FONT_MONO = 'ui-monospace, "SFMono-Regular", "Geist Mono", Menlo, Consolas, monospace';
var GRAD_FIRE = "linear-gradient(90deg, #6F00DD 0%, #E501FB 45%, #FF8904 100%)";

// snyk_report/lib/render/parts.mts
function esc(v) {
  return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
var fmt = (n) => n.toLocaleString("en-GB");
function pct(part, total) {
  if (!total) return "0%";
  return `${(part / total * 100).toFixed(1)}%`;
}
function day(t) {
  if (!t) return "";
  if (!Number.isFinite(t.ms)) return t.raw;
  return new Date(t.ms).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric"
  });
}
function dayOf(i, k) {
  const r = read(i, k);
  return r.state === "present" ? day(r.value) : "";
}
var PRODUCT_LABEL = {
  "open-source": "Snyk Open Source",
  code: "Snyk Code",
  container: "Snyk Container",
  iac: "Snyk IaC",
  secrets: "Snyk Secrets",
  custom: "Custom",
  unknown: "Unattributed"
};
var PRODUCT_SHORT = {
  "open-source": "SCA",
  code: "SAST",
  container: "Container",
  iac: "IaC",
  secrets: "Secrets",
  custom: "Custom",
  unknown: "\u2014"
};
var productLabel = (p) => PRODUCT_LABEL[p] ?? p;
var productShort = (p) => PRODUCT_SHORT[p] ?? p;
var kebabLabel = (v) => v.replace(/-/g, " ").replace(/^./, (c2) => c2.toUpperCase());
var statusLabel = (v) => v === "resolved" ? "Fixed" : kebabLabel(v);
function sevBadge(s, size = "sm") {
  const cls = size === "lg" ? " sev-badge--lg" : size === "md" ? " sev-badge--md" : "";
  return `<span class="sev-badge${cls} sv-${s}">${SEV[s].letter}</span>`;
}
var sevInline = (s) => `<span style="display:inline-flex;align-items:center;gap:5px">${sevBadge(s)}${SEV[s].label}</span>`;
function brandMark(logo) {
  return logo ? `<img class="cv-logo" src="${esc(logo)}" alt="Snyk">` : '<span class="cv-wordmark">snyk</span>';
}
function donut(slices, centreLabel = "Total") {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const circ = 2 * Math.PI * 42;
  let offset = 0;
  let arcs = "";
  for (const s of slices) {
    if (s.value <= 0) continue;
    const len = circ * s.value / total;
    arcs += `<circle cx="52" cy="52" r="42" stroke="${s.color}" stroke-dasharray="${len.toFixed(2)} ${circ.toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}"></circle>`;
    offset += len;
  }
  return `<svg width="104" height="104" viewBox="0 0 104 104" role="img" aria-label="${esc(centreLabel)}"><circle cx="52" cy="52" r="42" fill="none" stroke="#F1F1F3" stroke-width="15"></circle><g transform="rotate(-90 52 52)" stroke-width="15" fill="none">${arcs}</g><text x="52" y="49" text-anchor="middle" font-size="9" fill="${C.subtle}">${esc(centreLabel)}</text><text x="52" y="63" text-anchor="middle" font-size="15" font-weight="700" fill="${C.ink}">${fmt(total)}</text></svg>`;
}
function donutCard(title, slices) {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const rows = slices.map(
    (s) => `<div class="row"><span class="sw" style="background:${s.color}"></span><span class="l">${esc(s.label)}</span><span class="v">${fmt(s.value)} &middot; ${pct(s.value, total)}</span></div>`
  ).join("");
  return `<div class="pad avoid-break"><div class="lbl">${esc(title)}</div>
    <div class="chartrow">${donut(slices)}<div class="legend">${rows}</div></div></div>`;
}
function barList(rows, total) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  const body = rows.map((r, n) => {
    const cap = r.caption ?? (total ? `${fmt(r.value)} \xB7 ${pct(r.value, total)}` : fmt(r.value));
    return `<div><div class="bar__top"><span>${esc(r.label)}</span><span class="v">${esc(cap)}</span></div>
        <div class="bar__track"><div class="bar__fill" style="width:${(r.value / max * 100).toFixed(1)}%;
        background:${r.color ?? seriesColor(n)}"></div></div></div>`;
  }).join("");
  return `<div class="bars">${body}</div>`;
}
var card = (title, bodyHtml, cls = "") => `<div class="card avoid-break ${cls}"><div class="card__h">${esc(title)}</div>${bodyHtml}</div>`;
function kv(pairs, variant = "") {
  const cls = variant ? ` kv--${variant}` : "";
  return `<div class="kv${cls}">${pairs.map(([k, v]) => `<div class="k">${esc(k)}</div><div>${v}</div>`).join("")}</div>`;
}
var runHead = (left, right) => `<div class="rh"><span>${esc(left)}</span><span>${esc(right)}</span></div>`;
var runFoot = (left, right) => `<div class="rf"><span>${esc(left)}</span><span>${esc(right)}</span></div>`;
var refOf = (index) => `VULN-${String(index + 1).padStart(3, "0")}`;
var anchorOf = (index) => `detail-${refOf(index).toLowerCase()}`;
function locationShort(i) {
  const pkg = read(i, "packageNameAndVersion");
  if (pkg.state === "present") return pkg.value;
  const fp = read(i, "filePath");
  if (fp.state !== "present") return "";
  const base = fp.value.split("/").slice(-1)[0] ?? fp.value;
  const region = read(i, "codeRegion");
  const line = region.state === "present" ? region.value.startLine : null;
  return line ? `${base}:${line}` : base;
}
var ECOSYSTEMS = [
  { match: /docker|container|image/i, eco: { code: "DKR", label: "Docker", color: "#1D63ED" } },
  { match: /npm|pnpm|yarn|javascript|node/i, eco: { code: "NPM", label: "npm", color: "#C12127" } },
  { match: /maven|gradle|\bjava\b/i, eco: { code: "MVN", label: "Maven", color: "#B0713B" } },
  { match: /golang|gomodules|govendor|\bgo\b/i, eco: { code: "GO", label: "Go", color: "#00A0C6" } },
  { match: /pip|pipenv|poetry|python/i, eco: { code: "PIP", label: "Python", color: "#3670A0" } },
  { match: /rubygems|ruby/i, eco: { code: "GEM", label: "Ruby", color: "#9B111E" } },
  { match: /nuget|paket|\.net/i, eco: { code: "NET", label: ".NET", color: "#512BD4" } },
  { match: /composer|php/i, eco: { code: "PHP", label: "PHP", color: "#4F5B93" } },
  { match: /swift|cocoapods/i, eco: { code: "POD", label: "CocoaPods", color: "#EE3322" } },
  { match: /hex|elixir/i, eco: { code: "HEX", label: "Hex", color: "#6E4A7E" } },
  { match: /cargo|rust/i, eco: { code: "CRA", label: "Cargo", color: "#B7410E" } },
  { match: /terraform|cloudformation|kubernetes|helm|iac/i, eco: { code: "IAC", label: "IaC", color: "#7B42BC" } },
  { match: /secret/i, eco: { code: "KEY", label: "Secrets", color: "#B8860B" } },
  { match: /static application|sast|code/i, eco: { code: "SAST", label: "Code", color: "#6F00DD" } }
];
function ecosystemOf(type) {
  const t = (type ?? "").trim();
  if (!t) return { code: "?", label: "Unknown", color: "#8A8A8E" };
  for (const { match, eco } of ECOSYSTEMS) if (match.test(t)) return eco;
  return { code: t.slice(0, 3).toUpperCase(), label: t.replace(/\s*\(.*$/, ""), color: "#8A8A8E" };
}
function ecoBadge(type) {
  const e = ecosystemOf(type);
  return `<span class="eco" style="background:${e.color}" title="${esc(e.label)}">${esc(e.code)}</span>`;
}

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
    const picked = /* @__PURE__ */ new Set();
    let bad = false;
    for (const part of answer.split(",").map((p) => p.trim()).filter(Boolean)) {
      const range = /^(\d+)\s*-\s*(\d+)$/.exec(part);
      if (range) {
        const lo = Number(range[1]);
        const hi = Number(range[2]);
        if (lo < 1 || hi > choices.length || lo > hi) bad = true;
        else for (let i = lo; i <= hi; i++) picked.add(i);
        continue;
      }
      const n = Number(part);
      if (!Number.isInteger(n) || n < 1 || n > choices.length) bad = true;
      else picked.add(n);
    }
    if (!bad && picked.size > 0) return [...picked].sort((a, b) => a - b).map((i) => choices[i - 1].value);
    stderr.write(c.yellow("  could not read that selection\n"));
  }
}

// snyk_report/lib/interactive.mts
async function connect(opts) {
  let baseUrl = null;
  if (opts.region) {
    baseUrl = resolveRegion(opts.region);
    if (!baseUrl) {
      throw new Error(
        `unknown --region ${opts.region}. Use one of: ${REGIONS.map((r) => r.key).join(", ")}, or a full https:// URL.`
      );
    }
  } else if (isInteractive()) {
    baseUrl = await choose(
      "Which Snyk region is your account in?",
      REGIONS.map((r) => ({ value: r.url, label: r.label, hint: r.url }))
    );
  } else {
    throw new Error("--region is required when not running interactively");
  }
  let token = (opts.token ?? process.env["SNYK_TOKEN"] ?? "").trim();
  if (!token) {
    if (!isInteractive()) {
      throw new Error(
        "no API token. Set SNYK_TOKEN in the environment, or run this in a terminal to be prompted for one."
      );
    }
    log.dim("SNYK_TOKEN is not set; asking instead (export it to skip this next time)");
    token = (await askSecret(
      `API token for ${describeRegion(baseUrl)} (get one at ${appUrlFor(baseUrl)}/account):`
    )).trim();
    if (!token) throw new Error("no token entered");
  } else {
    log.dim("using the token from SNYK_TOKEN");
  }
  const client = new SnykClient(baseUrl, token);
  log.step(`Connecting to ${describeRegion(baseUrl)}`);
  const me = await client.detectAuth();
  const whoami = me.email ? `${me.name} <${me.email}>` : me.name;
  log.info(`authenticated as ${c.bold(whoami)} ${c.dim(`(${client.scheme} scheme)`)}`);
  return { client, baseUrl, regionLabel: describeRegion(baseUrl), whoami };
}
var list = (v) => {
  const parts = (v ?? "").split(",").map((p) => p.trim()).filter(Boolean);
  return parts.length ? parts : void 0;
};
var BACK_WORDS = /* @__PURE__ */ new Set(["back", "b", "list", "cancel", "q"]);
async function askUntilResolved(question, resolve3) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const answer = await ask(`${question} (or "back" for the list)`);
    if (!answer) continue;
    if (BACK_WORDS.has(answer.trim().toLowerCase())) return null;
    try {
      return await resolve3(answer);
    } catch (err) {
      log.warn(err instanceof Error ? err.message : String(err));
    }
  }
  log.warn("too many attempts; returning to the list");
  return null;
}
async function selectScope(conn, opts) {
  const client = conn.client;
  if (opts.org) {
    const org = await resolveOrg(client, opts.org);
    const targetNames2 = opts.target ? await resolveTargets(client, org.id, list(opts.target) ?? []) : void 0;
    return {
      scope: { kind: "orgs", id: org.id, label: `Organisation ${org.name}` },
      orgIds: void 0,
      targetNames: targetNames2,
      projectNames: list(opts.project)
    };
  }
  if (opts.group) {
    return {
      scope: { kind: "groups", id: opts.group, label: `Group ${opts.group}` },
      orgIds: void 0,
      targetNames: list(opts.target),
      projectNames: list(opts.project)
    };
  }
  log.step("Finding what this token can see");
  const groups = await tryList("groups", () => listGroups(client)) ?? [];
  let scope;
  let orgIds;
  let orgForNarrowing = null;
  if (groups.length === 0) {
    log.dim("no groups visible (an org-scoped token cannot list them); listing organisations");
    const orgs = await tryList("organisations", () => listOrgs(client)) ?? [];
    if (orgs.length === 0) throw new Error("this token can see no groups and no organisations");
    const org = await choose(
      "Which organisation?",
      orgs.map((o) => ({ value: o, label: o.name, hint: o.id }))
    );
    orgForNarrowing = org;
    scope = { kind: "orgs", id: org.id, label: `Organisation ${org.name}` };
  } else {
    const group2 = await choose(
      "Which group?",
      groups.map((g) => ({ value: g, label: g.name, hint: g.id }))
    );
    const orgs = await tryList("organisations", () => listOrgsInGroup(client, group2.id)) ?? [];
    const WHOLE_GROUP = Symbol("whole-group");
    const BY_NAME = Symbol("by-name");
    for (; ; ) {
      const picked = await choose(
        "Which organisation?",
        [
          {
            value: WHOLE_GROUP,
            label: c.bold(`Everything in ${group2.name}`),
            hint: `${orgs.length} organisations, one export`
          },
          {
            value: BY_NAME,
            label: c.bold("Type an organisation name or ID..."),
            hint: "validated against Snyk before use"
          },
          ...orgs.map((o) => ({
            value: o,
            label: o.name,
            hint: o.id
          }))
        ]
      );
      if (picked === BY_NAME) {
        const typed = await askUntilResolved(
          "Organisation name or UUID",
          (v) => resolveOrg(client, v, orgs)
        );
        if (!typed) continue;
        orgForNarrowing = typed;
        scope = { kind: "orgs", id: typed.id, label: `Organisation ${typed.name}` };
      } else if (picked === WHOLE_GROUP) {
        scope = { kind: "groups", id: group2.id, label: `Group ${group2.name}` };
        if (orgs.length > 1) {
          const chosen = await chooseMany(
            "Limit to particular organisations?",
            orgs.map((o) => ({ value: o.id, label: o.name, hint: o.id })),
            { allLabel: "all", defaultAll: true }
          );
          orgIds = chosen.length === orgs.length ? void 0 : chosen;
        }
      } else {
        orgForNarrowing = picked;
        scope = { kind: "orgs", id: picked.id, label: `Organisation ${picked.name}` };
      }
      break;
    }
  }
  let targetNames;
  let projectNames;
  if (orgForNarrowing && isInteractive()) {
    const targets = await tryList("targets", () => listTargets(client, orgForNarrowing.id)) ?? [];
    if (targets.length > 1) {
      const TYPE_IN = "\0__type__";
      for (; ; ) {
        const chosen = await chooseMany(
          `Which targets in ${orgForNarrowing.name}?`,
          [
            { value: TYPE_IN, label: c.bold("Type target name(s)..."), hint: "comma separated" },
            ...targets.map((t) => ({ value: t.name, label: t.name, hint: t.hint }))
          ],
          { allLabel: "all", defaultAll: true }
        );
        if (chosen.includes(TYPE_IN)) {
          const typed = await askUntilResolved(
            "Target name(s), comma separated",
            (v) => resolveTargets(client, orgForNarrowing.id, v.split(","), targets)
          );
          if (!typed) continue;
          targetNames = typed;
        } else if (chosen.length !== targets.length) {
          targetNames = chosen;
        }
        break;
      }
    }
  }
  if (opts.target) targetNames = list(opts.target);
  if (opts.project) projectNames = list(opts.project);
  return { scope, orgIds, targetNames, projectNames };
}
async function selectSince(preset) {
  if (preset) {
    const value = preset.trim().toLowerCase();
    if (!SINCE_CHOICES.some((c2) => c2.value === value)) {
      throw new Error(`unknown --since ${preset}. Use 7d, 14d, 30d, 90d or all.`);
    }
    return value;
  }
  if (!isInteractive()) return "all";
  return choose(
    "Issues introduced within which period?",
    SINCE_CHOICES.map((c2) => ({ value: c2.value, label: c2.label }))
  );
}
async function selectSeverities(spec, counts) {
  if (spec) {
    const wanted = spec.split(",").map((s) => s.trim().toLowerCase());
    if (wanted.includes("all")) return [...SEVERITIES];
    const bad = wanted.filter((w) => !SEVERITIES.includes(w));
    if (bad.length) throw new Error(`unknown --severity value(s): ${bad.join(", ")}`);
    return SEVERITIES.filter((s) => wanted.includes(s));
  }
  if (!isInteractive()) return [...SEVERITIES];
  const present = counts ? SEVERITIES.filter((s) => counts[s] > 0) : [...SEVERITIES];
  if (present.length === 0) return [...SEVERITIES];
  if (present.length === 1) {
    log.dim(`only ${present[0]}-severity issues remain; including them all`);
    return present;
  }
  const chosen = await chooseMany(
    "Which severities?",
    present.map((s) => ({
      value: s,
      label: s[0].toUpperCase() + s.slice(1),
      ...counts ? { hint: counts[s].toLocaleString() } : {}
    })),
    { allLabel: "all", defaultAll: true }
  );
  return chosen.length ? chosen : present;
}
async function selectFormats(spec) {
  if (spec) return spec.split(",").map((f) => f.trim().toLowerCase()).filter(Boolean);
  if (!isInteractive()) return ["html"];
  const chosen = await chooseMany(
    "Which output formats?",
    [
      { value: "pdf", label: "PDF" },
      { value: "html", label: "HTML" },
      { value: "csv", label: "CSV" },
      { value: "json", label: "JSON" }
    ],
    { allLabel: "all" }
  );
  return chosen.length ? chosen : ["html"];
}
async function askOutputPath(fallback) {
  if (!isInteractive()) return fallback;
  return await ask("Output file basename", fallback) || fallback;
}
async function selectSource() {
  return choose("Where should the vulnerability data come from?", [
    {
      value: "api",
      label: "Pull it from Snyk now",
      hint: "needs an API token; returns every field"
    },
    {
      value: "csv",
      label: "Use a CSV I already exported",
      hint: "Reports tab download, or a saved export"
    }
  ]);
}
function humanSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
function expandHome(p) {
  return p.startsWith("~/") ? join(homedir(), p.slice(2)) : p;
}
async function findLocalCsvs() {
  try {
    const names = await readdir(process.cwd());
    const out = [];
    for (const name of names.filter((n) => /[.]csv([.]gz)?$/i.test(n)).slice(0, 20)) {
      const path = resolve(name);
      try {
        const info = await stat(path);
        if (info.isFile()) out.push({ path, name, size: humanSize(info.size) });
      } catch {
      }
    }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  } catch {
    return [];
  }
}
async function askCsvPath() {
  const here = await findLocalCsvs();
  const OTHER = "\0__other__";
  for (; ; ) {
    let answer;
    if (here.length > 0) {
      const picked = await choose("Which file?", [
        ...here.map((f) => ({ value: f.path, label: f.name, hint: f.size })),
        { value: OTHER, label: "A file somewhere else..." }
      ]);
      if (picked !== OTHER) return picked;
      answer = await ask("Path to the CSV");
    } else {
      answer = await ask("Path to the Snyk CSV export");
    }
    const path = expandHome(answer.trim().replace(/^["']|["']$/g, ""));
    if (!path) continue;
    try {
      const info = await stat(path);
      if (info.isFile()) return resolve(path);
      log.warn(`${path} is a directory, not a file`);
    } catch {
      log.warn(`no such file: ${path}`);
    }
  }
}
var PRODUCT_ALIASES = {
  sca: "open-source",
  "open-source": "open-source",
  opensource: "open-source",
  oss: "open-source",
  sast: "code",
  code: "code",
  container: "container",
  containers: "container",
  iac: "iac",
  infrastructure: "iac",
  secrets: "secrets",
  secret: "secrets",
  custom: "custom",
  unknown: "unknown"
};
function parseProducts(spec) {
  const wanted = spec.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  if (wanted.length === 0 || wanted.includes("all")) return "all";
  const out = [];
  const bad = [];
  for (const w of wanted) {
    const p = PRODUCT_ALIASES[w];
    if (p) out.push(p);
    else bad.push(w);
  }
  if (bad.length) {
    throw new Error(
      `unknown --product value(s): ${bad.join(", ")}. Use sca, sast, container, iac, secrets, or all.`
    );
  }
  return out;
}
async function selectProducts(spec, available) {
  const all = available.map((a) => a.product);
  if (spec) {
    const parsed = parseProducts(spec);
    return parsed === "all" ? all : parsed;
  }
  if (!isInteractive() || available.length < 2) return all;
  const chosen = await chooseMany(
    "Which scanners?",
    available.map((a) => ({
      value: a.product,
      label: `${productShort(a.product)} \u2014 ${productLabel(a.product)}`,
      hint: a.total.toLocaleString()
    })),
    { allLabel: "all", defaultAll: true }
  );
  return chosen.length ? chosen : all;
}
async function selectDetailDepth(spec, total, wantsPdf) {
  if (spec) {
    const t = spec.trim().toLowerCase();
    if (t === "all") return total;
    const n = Number(t);
    if (!Number.isFinite(n) || n < 0) {
      throw new Error(`--top must be a number or "all", got: ${spec}`);
    }
    return n;
  }
  if (!isInteractive()) return Math.min(25, total);
  const pdfNote = (n) => wantsPdf ? `about ${n.toLocaleString()} extra PDF pages` : `${n.toLocaleString()} pages of HTML`;
  const options = [
    { value: 25, label: "Top 25 by risk", hint: pdfNote(Math.min(25, total)) },
    { value: 100, label: "Top 100 by risk", hint: pdfNote(Math.min(100, total)) },
    { value: total, label: `Every finding (${total.toLocaleString()})`, hint: pdfNote(total) }
  ].filter((o, i, arr) => o.value <= total && arr.findIndex((x) => x.value === o.value) === i);
  if (options.length <= 1) return total;
  return choose("How many findings get a full detail page?", options);
}
async function selectStatuses(spec, counts) {
  const ALL = ["open", "resolved", "ignored"];
  if (spec) {
    const wanted = spec.split(",").map((x) => x.trim().toLowerCase());
    if (wanted.includes("all")) return ALL;
    const bad = wanted.filter((w) => !ALL.includes(w));
    if (bad.length) {
      throw new Error(`unknown --status value(s): ${bad.join(", ")}. Use open, resolved, ignored or all.`);
    }
    return ALL.filter((s) => wanted.includes(s));
  }
  const present = ALL.filter((s) => counts[s] > 0);
  if (!isInteractive() || present.length < 2) return present.length ? present : ALL;
  const n = (s) => counts[s].toLocaleString();
  const options = [
    { value: ["open"], label: "Open issues only", hint: `${n("open")} outstanding` }
  ];
  if (counts.resolved > 0) {
    options.push({
      value: ["open", "resolved"],
      label: "Open and already-fixed issues",
      hint: `${n("open")} open + ${n("resolved")} fixed, shown as Fixed`
    });
  }
  options.push({
    value: present,
    label: "Everything, including ignored",
    hint: present.map((s) => `${n(s)} ${s}`).join(" + ")
  });
  return choose("Which issues should the report cover?", options);
}

// snyk_report/lib/render/css.mts
var sevRules = Object.keys(SEV).map(
  (s) => `.sv-${s}{background:${SEV[s].color}}
.tint-${s}{background:${SEV[s].tint}}
.fg-${s}{color:${SEV[s].color}}`
).join("\n");
var CSS = `
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
*,*::before,*::after{box-sizing:border-box}
body{
  margin:0;background:${C.canvas};color:${C.ink};
  font-family:${FONT_SANS};-webkit-font-smoothing:antialiased;
}
a{color:${C.accent};text-decoration:none;border-bottom:1px solid rgba(111,0,221,.25)}
a:hover{color:${C.accentHover};border-bottom-color:${C.accentHover}}

/* ---- page frame ---------------------------------------------------- */
.report{display:flex;flex-direction:column;align-items:center;gap:20px;padding:24px 0 60px}
.page{
  position:relative;width:210mm;min-height:296mm;background:${C.paper};
  box-shadow:0 2px 10px rgba(11,6,19,.14);padding:11mm 9mm 9mm;
  display:flex;flex-direction:column;
}
.page--cover{padding:0}
.page--flow{min-height:0}

.rh{display:flex;justify-content:space-between;align-items:center;
    border-bottom:1px solid ${C.line};padding-bottom:8px;margin-bottom:9mm}
.rh span,.rf span{font-family:${FONT_MONO};font-size:10px;letter-spacing:.14em;
    text-transform:uppercase;color:${C.subtle}}
.rf{margin-top:auto;padding-top:6mm;display:flex;justify-content:space-between}
.rf span{font-size:9.5px;letter-spacing:.06em}

/* ---- cover ---------------------------------------------------------- */
.cv-hero{position:relative;background:${C.coverInk};color:#fff;padding:18mm 14mm 14mm;overflow:hidden}
.cv-glow{position:absolute;inset:0;background:radial-gradient(120% 120% at 100% 0%,
    rgba(111,0,221,.6) 0%,rgba(42,15,102,.34) 45%,rgba(11,6,19,0) 78%)}
.cv-top{position:relative;display:flex;justify-content:space-between;align-items:flex-start}
.cv-logo{height:24px;width:auto;display:block}
.cv-wordmark{font-size:27px;font-weight:700;letter-spacing:-.045em;color:#fff;line-height:1;display:block}
.cv-id{font-family:${FONT_MONO};font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;
    color:rgba(255,255,255,.6);text-align:right;line-height:1.8}
.cv-h1{position:relative;margin:24mm 0 0;font-size:36px;line-height:1.12;
    letter-spacing:-.025em;font-weight:700;max-width:15ch}
.cv-sub{position:relative;margin:14px 0 0;font-size:14px;line-height:1.55;
    color:rgba(255,255,255,.72);max-width:56ch}
.cv-rule{position:relative;height:2px;background:${GRAD_FIRE};margin:20mm 0 0}
.cv-body{padding:12mm 14mm 0;flex:1}
.cv-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10mm 12mm}
.cv-grid .v{font-size:15px;font-weight:600;line-height:1.45}
.cv-grid .v small{font-weight:400;color:${C.muted};font-size:13px}
.cv-foot{padding:0 14mm 12mm;display:flex;justify-content:space-between}
.cv-foot span{font-family:${FONT_MONO};font-size:9.5px;letter-spacing:.06em;
    text-transform:uppercase;color:${C.subtle}}
.confid{margin:10mm 0 0;font-size:10.5px;line-height:1.65;color:${C.subtle};
    border-top:1px solid ${C.line};padding-top:10px}

/* ---- typography ----------------------------------------------------- */
h2.sec{margin:0 0 4px;font-size:22px;font-weight:700;letter-spacing:-.02em}
h3.sub{margin:6mm 0 8px;font-size:14px;font-weight:600}
p.lede{margin:0 0 7mm;font-size:12.5px;line-height:1.6;color:${C.muted};max-width:82ch}
.eyebrow{font-family:${FONT_MONO};font-size:9px;letter-spacing:.14em;
    text-transform:uppercase;color:${C.subtle};margin-bottom:6px}
.lbl{font-size:10px;letter-spacing:.1em;text-transform:uppercase;color:${C.subtle};
    font-weight:600;margin-bottom:4px}
.mono{font-family:${FONT_MONO};font-size:11px;overflow-wrap:anywhere}
.muted{color:${C.subtle}}
.faint{color:${C.faint}}
.num{text-align:right;font-variant-numeric:tabular-nums}

/* ---- cards ---------------------------------------------------------- */
.card{border:1px solid ${C.line};border-radius:8px;overflow:hidden;margin-bottom:5mm}
.card--mt{margin-top:12mm}
.card__h{background:${C.surface};border-bottom:1px solid ${C.line};padding:9px 14px;
    font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:${C.muted}}
.card__b{padding:14px}
.pad{border:1px solid ${C.line};border-radius:8px;padding:14px 16px}
.split{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6mm;margin-bottom:6mm}
.kv{display:grid;grid-template-columns:150px minmax(0,1fr);gap:9px 16px;font-size:12px;line-height:1.55}
.kv--tight{grid-template-columns:120px minmax(0,1fr);gap:8px 12px;font-size:12px;line-height:1.5}
.kv--narrow{grid-template-columns:78px minmax(0,1fr);gap:7px 10px;font-size:11.5px;line-height:1.45}
.kv .k{color:${C.subtle}}

.note{border:1px solid ${C.line};border-radius:8px;padding:14px 16px}
.note--purple{border-left:3px solid ${C.accent};background:${C.accentWash}}
.note--danger{border-left:3px solid ${SEV.critical.color};background:#FEFAFA}
.note--good{border-left:3px solid ${C.success};background:#FAFDFB}
.note__t{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;margin-bottom:6px}
.note--purple .note__t{color:${C.accentDark}}
.note--danger .note__t{color:${C.dangerDeep}}
.note p{margin:0;font-size:12.5px;line-height:1.65;color:${C.body}}

/* ---- stats ---------------------------------------------------------- */
.glance{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}
.glance>div{padding:14px;border-right:1px solid ${C.lineSoft}}
.glance>div:last-child{border-right:0}
.glance .n{font-size:26px;font-weight:700;letter-spacing:-.03em}
.glance .l{font-size:11px;color:${C.subtle};margin-top:2px}
.bigrow{display:flex;gap:10mm;align-items:flex-start;margin-bottom:7mm;flex-wrap:wrap}
.big .l{font-size:11px;color:${C.subtle};margin-bottom:2px}
.big .n{font-size:40px;font-weight:700;letter-spacing:-.04em;line-height:1}
.tiles{flex:1;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;min-width:260px}
.tile{border-radius:8px;padding:10px 12px}
.tile .t{display:flex;align-items:center;gap:6px;font-size:11.5px;font-weight:500}
.tile .n{font-size:26px;font-weight:700;letter-spacing:-.03em;margin-top:6px}

.sev-badge{display:inline-flex;width:16px;height:16px;border-radius:4px;color:#fff;
    font-size:10px;font-weight:700;align-items:center;justify-content:center;flex:none}
.sev-badge--lg{width:24px;height:24px;border-radius:6px;font-size:13px}
.sev-badge--md{width:17px;height:17px}
${sevRules}

.legend{flex:1;display:flex;flex-direction:column;gap:6px;font-size:11.5px;min-width:0}
.legend .row{display:grid;grid-template-columns:9px minmax(0,1fr) auto;
    align-items:center;gap:7px;line-height:1.3}
.legend .sw{width:9px;height:9px;border-radius:2px}
.legend .l{min-width:0}
/* Never break a figure. A count and a percentage split over two lines is
   unreadable, and it is the one thing here that must stay scannable. */
.legend .v{color:${C.muted};font-variant-numeric:tabular-nums;
    white-space:nowrap;text-align:right}
/* The donut gives up 12px so the legend can hold "Open Source" on one line
   inside a half-width card. */
.chartrow{display:flex;align-items:center;gap:12px}
.chartrow>svg{width:92px;height:92px;flex:none}

.bars{display:flex;flex-direction:column;gap:10px;font-size:12px}
.bar__top{display:flex;justify-content:space-between;margin-bottom:5px;gap:10px}
.bar__top .v{color:${C.muted};font-variant-numeric:tabular-nums;flex:none}
.bar__track{height:6px;border-radius:999px;background:#F1F1F3}
.bar__fill{height:6px;border-radius:999px}

.dot{width:7px;height:7px;border-radius:999px;display:inline-block;flex:none}
.pill{display:inline-flex;align-items:center;gap:5px;border:1px solid ${C.line};
    border-radius:999px;padding:2px 9px 2px 3px;background:${C.paper};font-size:12px}
.pill--plain{border-radius:6px;padding:3px 9px;font-size:11.5px;gap:6px}
.tag{display:inline-block;border:1px solid ${C.line};border-radius:4px;padding:2px 7px;
    font-size:10.5px;color:${C.muted};background:${C.surface}}
.reach{display:inline-block;border-radius:999px;padding:2px 9px;font-size:11px;font-weight:600}

/* ---- tables --------------------------------------------------------- */
table{width:100%;border-collapse:collapse;font-size:12px}
thead th{text-align:left;padding:8px 10px;border-bottom:1.5px solid ${C.ink};
    font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:${C.muted};font-weight:600}
tbody td{padding:7px 10px;border-bottom:1px solid ${C.lineFaint};vertical-align:top}
.card table thead th{border-bottom:1px solid ${C.lineSoft};padding:8px 14px}
.card table tbody td{padding:7px 14px}
th.num,td.num{text-align:right;font-variant-numeric:tabular-nums}

/* Ecosystem badge. Fixed width so a column of them lines up, and monospace
   so a 2-char and a 4-char code sit at the same optical weight. */
.eco{display:inline-flex;align-items:center;justify-content:center;
  min-width:30px;height:15px;padding:0 4px;border-radius:3px;color:#fff;
  font-family:${FONT_MONO};font-size:8.5px;font-weight:700;letter-spacing:.04em;
  vertical-align:middle;flex:none}
/* Top-aligned, not centred: a project name that wraps to three lines would
   otherwise leave its badge floating in the middle of the cell, detached
   from the line it labels. */
.eco-row{display:inline-flex;align-items:flex-start;gap:7px;min-width:0}
.eco-row .eco{margin-top:1px}
/* On screen the register scrolls inside one viewport-height pane with a
   sticky header, so 9,000 rows are browsable without an endless page. In
   print the pane is unset entirely and the table paginates as before -- a
   fixed-height scroller would otherwise clip everything below the fold and
   silently drop most of the register from the PDF. */
/* The contents list of detail pages, same treatment as the register: a
   scroll pane on screen, released for print. Without it, --top all puts
   thousands of contents lines ahead of the report. */
.toc__scroll{max-height:46vh;overflow:auto}
.toc__more{padding:8px 0 0;font-size:11px;color:${C.subtle}}
.print-only{display:none}
@media print{
  .toc__scroll{max-height:none;overflow:visible}
  .print-only{display:block}
  /* Paper cannot scroll, so the tail is hidden rather than printed. */
  .toc__scroll[data-print-limit] .toc__s:nth-of-type(n+61){display:none}
}
.reg-scroll{max-height:72vh;overflow:auto;border:1px solid ${C.line};border-radius:8px}
.reg-scroll .reg{margin:0}
.reg thead th{position:sticky;top:0;z-index:2;background:${C.paper};
  box-shadow:inset 0 -2px 0 ${C.ink}}
@media print{
  .reg-scroll{max-height:none;overflow:visible;border:0;border-radius:0}
  .reg thead th{position:static;box-shadow:none}
}
.reg{table-layout:fixed;font-size:11.5px}
.reg th{cursor:pointer;line-height:1.3;padding:8px 7px}
.reg td{padding:8px 7px}
/* A reference is one token. Letting VULN-001 break after the hyphen made
   every row two lines tall for no reason. */
.reg .ref{font-family:${FONT_MONO};font-size:10.5px;color:${C.accent};white-space:nowrap}
.reg .ttl{font-weight:600;line-height:1.4;overflow-wrap:anywhere}
.reg .loc{font-family:${FONT_MONO};font-size:10.5px;font-weight:400;color:${C.subtle};
    margin-top:2px;overflow-wrap:anywhere}
.reg .ids{font-family:${FONT_MONO};font-size:10.5px;color:${C.muted};line-height:1.5;overflow-wrap:anywhere}
/* Break a long target at a slash or hyphen, never mid-word: "snyk-abhay/
   snyk-" then "bulk" is harder to read than a slightly narrower column. */
.reg .proj{font-family:${FONT_MONO};font-size:10.5px;color:${C.muted};
  word-break:normal;overflow-wrap:normal}
/* Wrap between identifiers, never inside one. nowrap stopped CVE-2024-38475
   breaking mid-token, but a cell holding "CWE-20, CWE-502" then overflowed
   into the neighbouring column and printed on top of it. Breaking at the
   space gives both. */
.reg .ids{font-family:${FONT_MONO};font-size:10.5px;white-space:normal}
.reg .id1{white-space:nowrap}
/* Belt and braces: a fixed-layout cell must clip rather than paint over the
   column beside it, whatever ends up inside. */
.reg td{overflow:hidden}
.idx-row:hover{background:${C.accentWash}}

/* ---- table of contents ---------------------------------------------- */
.toc{display:flex;flex-direction:column;gap:2px;font-size:13px}
.toc__r{display:flex;align-items:baseline;gap:10px;padding:7px 0;border-bottom:1px dotted #D8D8DA}
.toc__r .n{width:26px;color:${C.accent};font-family:${FONT_MONO};font-size:11px;flex:none}
.toc__r .t{font-weight:600}
.toc__r .sp{flex:1}
.toc__r .p{font-variant-numeric:tabular-nums;color:${C.muted};flex:none}
.toc__s{display:flex;align-items:baseline;gap:10px;padding:6px 0 6px 36px;
    border-bottom:1px dotted ${C.lineSoft};font-size:12.5px}
.toc__s .t{color:${C.body};overflow-wrap:anywhere}
.toc__s .r{color:${C.faint};font-family:${FONT_MONO};font-size:10.5px;flex:none}

/* ---- finding detail -------------------------------------------------- */
/* A full hairline border. The three-sided rule was only ever three-sided
   because the severity bar supplied the top edge; without it the card was
   open along the top. */
/* A finding is a block, not a sheet. break-inside:avoid keeps it whole, so
   Chrome fits two or three short findings on a printed page and gives a long
   one the space it needs. A finding taller than a page still breaks, which is
   the correct fallback -- browsers ignore avoid when honouring it is
   impossible. */
.fd{break-inside:avoid;page-break-inside:avoid;padding-bottom:6mm;margin-bottom:6mm;
  border-bottom:1px solid ${C.lineSoft}}
.fd:last-child{border-bottom:0;margin-bottom:0}
.fd-ref{font-family:${FONT_MONO};font-size:9px;letter-spacing:.14em;text-transform:uppercase;
  color:${C.subtle};margin-bottom:5px}
.fd-hd{border:1px solid ${C.line};border-radius:8px;overflow:hidden;margin-bottom:2.5mm}
/* No severity-coloured rule across the top, and no chip beside the title.
   A 3px bar in a warning colour reads as an alert banner rather than a
   document, and it competed with the two other things already carrying that
   colour. Severity is stated once, in the rightmost metric cell, where it is
   a fact among facts. The extra breathing room is what replaces it. */
/* The title zone carries a severity wash -- the same tints the chips and
   table rows use, so a reader learns one colour language, not two.
   A wash rather than the old 3px bar: the bar read as an alert banner and
   shouted at the same volume for every severity, whereas a tint is felt
   before it is read and still lets Critical look worse than Medium.
   Only this zone is tinted. Carrying it through the metrics strip and the
   blocks below would swamp the page in colour and make the numbers harder
   to read, which is the opposite of the point. */
.fd-hd__t{padding:16px 16px 13px;border-bottom:1px solid rgba(11,6,19,.06)}
/* One step deeper than the shared chip/row tints, and scoped to this zone.
   At full-page size the lighter wash read as "slightly off-white" rather
   than as a severity; a header the reader is meant to judge at a glance
   needs a step in value, not only in hue. Chips and table rows keep the
   lighter tokens, where a stronger fill would fight the text. */
.fd-hd__t.tint-critical{background:#F9D3D6}
.fd-hd__t.tint-high{background:#FBDCC8}
.fd-hd__t.tint-medium{background:#FCE9C4}
.fd-hd__t.tint-low{background:#ECECEF}
.fd-hd h3{margin:0;font-size:17.5px;font-weight:700;letter-spacing:-.015em;
    line-height:1.25;overflow-wrap:anywhere}
.fd-crumbs{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:9px;font-size:11px;
    color:${C.subtle};font-family:${FONT_MONO};letter-spacing:.06em;text-transform:uppercase}
.fd-crumbs .sep{color:#D8D8DA}
.fd-crumbs .hi{color:${C.accent}}
.fd-metrics{display:grid;background:#fff}
/* Values sit on a common baseline. Grid already equalises cell heights, so
   making each cell a column and pushing the value down means a label that
   wraps to two lines (EXPLOIT MATURITY) no longer drops its value below the
   values either side of it. */
.fd-metrics>div{padding:7px 12px;border-right:1px solid ${C.lineSoft};min-width:0;
    display:flex;flex-direction:column}
.fd-metrics>div:last-child{border-right:0}
.fd-metrics .k{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:${C.subtle}}
.fd-metrics .v{font-size:14px;font-weight:700;margin-top:auto;padding-top:3px}
.fd-metrics .v--sm{font-size:12.5px;font-weight:600}
.fd-cols{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(0,1fr);gap:5mm;margin-bottom:3mm}
/* Severity moved into the header metrics, so the attribute list spans the
   full width and its pairs flow into two columns instead of one long run. */
.fd-attrs{margin-bottom:3mm}
/* Four grid tracks, so pairs place as label,value,label,value and flow two
   per row. The CSS multi-column property cannot do this, because .kv is
   itself a grid container. NB: no backticks in here -- this whole stylesheet
   is a template literal, and one would end it. */
.fd-attrs .kv--narrow{grid-template-columns:78px minmax(0,1fr) 78px minmax(0,1fr);
  column-gap:8mm}
.fd-sev{display:inline-flex;align-items:center;gap:6px}
.fd-pkg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))}
.fd-pkg>div{padding:11px 13px;border-right:1px solid ${C.lineSoft};min-width:0}
.fd-pkg>div:last-child{border-right:0}
.fd-pkg .k{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:${C.subtle};margin-bottom:3px}
.fd-pkg .v{font-family:${FONT_MONO};font-size:11.5px;overflow-wrap:anywhere;line-height:1.45}
.fd-2col{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:6mm}
.fd-2col ul{margin:0;padding-left:16px;font-size:11.5px;line-height:1.6;color:${C.muted}}
.fd-rem ol{margin:0;padding-left:17px;font-size:12px;line-height:1.5;color:${C.body};
    display:flex;flex-direction:column;gap:4px}

/* ---- register controls (screen only) --------------------------------- */
/* Two stacked rows: search plus dropdowns, then the toggle chips. Cramming
   all of it onto one line pushed the search box down to a stub. */
.ctl__r{display:flex;gap:8px;align-items:center;width:100%;flex-wrap:wrap}
.sel{border:1px solid #D8D8DA;border-radius:6px;padding:7px 9px;font:inherit;font-size:12px;
  background:#fff;color:${C.ink};max-width:230px;flex:0 1 auto;cursor:pointer}
.sel:focus{outline:2px solid rgba(111,0,221,.3);outline-offset:1px}
/* A hairline between the severity group and the status group, so two sets of
   toggles do not read as one long undifferentiated row of buttons. */
.ctl__sep{width:1px;align-self:stretch;background:${C.line};margin:0 3px}
.ctl{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;
    padding:10px 12px;border:1px solid ${C.line};border-radius:8px;background:${C.surface};margin-bottom:2.5mm}
.ctl input{flex:1 1 220px;min-width:0;border:1px solid #D8D8DA;border-radius:6px;padding:7px 11px;
    font-size:12.5px;font-family:inherit;background:${C.paper};color:${C.ink}}
.ctl input::placeholder{color:${C.faint}}
.ctl input:focus{outline:2px solid rgba(111,0,221,.3);outline-offset:1px}
.ctl__g{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid #D8D8DA;background:${C.paper};
    color:${C.muted};border-radius:6px;padding:5px 10px;font-size:12px;font-weight:500;
    font-family:inherit;cursor:pointer}
.btn:hover{background:${C.lineFaint}}
.btn[aria-pressed="true"]{background:${C.accentTint};color:${C.accentDeep};border-color:${C.accentBorder}}
.btn .c{color:${C.subtle};font-variant-numeric:tabular-nums}

/* ---- print ----------------------------------------------------------- */
/* Every printed sheet gets its own margin.
   This was margin:0, with the white space drawn by .page's padding instead.
   That works only while a section fits on one sheet: padding applies at the
   start and end of the element, so a section spanning several pages had
   NOTHING between its continuation pages and the paper edge -- the register,
   the contents list and the detail flow were all cropped mid-content.
   The page box is the only thing that repeats per sheet, so the margin
   belongs here. */
@page{size:A4}
/* Margins and the running header/footer are emitted per report by
   pageBoxCss() in html.mts, which needs the report's own title and holder
   strings; only the sheet size is static enough to live here. */
@media print{
  body{background:${C.paper}}
  .no-print{display:none!important}
  /* Block, not flex: as a centred flex item a width:auto .page would
     shrink-to-fit its own content and every sheet would end up a
     different width. As a block it fills the page box exactly. */
  .report{display:block;gap:0;padding:0}
  /* The page box now provides the margin, so the on-screen sheet padding
     must not be added on top of it or every page is inset twice. */
  /* width too: the on-screen sheet is a fixed 210mm, but in print the page
     box is already 190mm wide after its margins, so leaving 210mm here
     overflows the printable area and Chrome clips ~10mm off the right. */
  .page{box-shadow:none!important;margin:0!important;padding:0!important;
    width:auto!important;min-height:0!important;break-after:page;break-inside:auto}
  .page:last-of-type{break-after:auto}
  /* The page-box running header/footer replace these in print; leaving
     both would print the section header twice on a section's first sheet. */
  .rh,.rf{display:none!important}
  .avoid-break{break-inside:avoid}
  a{color:${C.ink};border-bottom:0}
  a[href]:after{content:""}
  thead{display:table-header-group}
  tr{break-inside:avoid}
  h1,h2,h3,h4{break-after:avoid}
  p,li{orphans:3;widows:3}
}
`;

// snyk_report/lib/render/html.mts
function listOf(items) {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}
function coverPage(ctx) {
  const { data, meta } = ctx;
  const uniq = new Set(data.issues.map((i) => i.problemId)).size;
  const tiles = [
    { n: fmt(data.total), l: "Issues reported" },
    { n: fmt(uniq), l: "Unique vulnerabilities", color: C.accent },
    { n: fmt(data.bySeverity.critical), l: "Critical", color: SEV.critical.color }
  ];
  if (ctx.has("fixability")) {
    const fixable = data.issues.filter((i) => {
      const f = read(i, "fixability");
      return f.state === "present" && (f.value === "fixable" || f.value === "partially-fixable");
    }).length;
    tiles.push({ n: pct(fixable, data.total), l: "Have a fix available" });
  } else if (data.cisaKevCount !== null) {
    tiles.push({ n: fmt(data.cisaKevCount), l: "In CISA KEV", color: SEV.critical.color });
  } else {
    tiles.push({ n: fmt(data.bySeverity.high), l: "High", color: SEV.high.color });
  }
  const idBlock = [
    meta.reportId ? `<div>${esc(meta.reportId)}</div>` : "",
    `<div>${esc(ctx.classification)}</div>`
  ].join("");
  const products = data.byProduct.map((p) => productLabel(p.product));
  const subtitle = meta.subtitle ?? `Consolidated ${esc(listOf(products))} findings across ${fmt(data.byProject.length || data.byOrg.length)} ${data.byProject.length ? "project" : "organisation"}${(data.byProject.length || data.byOrg.length) === 1 ? "" : "s"}.`;
  const pairs = [
    ["Prepared for", esc(meta.preparedFor ?? ctx.holder), ""],
    ["Prepared by", esc(meta.preparedBy ?? "snyk-auto-report"), esc(meta.sourceLabel)],
    [
      "Scope",
      esc(meta.scope),
      `${fmt(data.byProject.length)} project${data.byProject.length === 1 ? "" : "s"}`
    ],
    [
      "Period covered",
      esc(meta.period ?? meta.dataAsOf ?? "Point-in-time snapshot"),
      `Generated ${esc(meta.generatedAt)}`
    ]
  ];
  return `<section class="page page--cover" data-page="cover">
  <div class="cv-hero">
    <div class="cv-glow"></div>
    <div class="cv-top">
      ${brandMark(meta.logo)}
      <div class="cv-id">${idBlock}</div>
    </div>
    <h1 class="cv-h1">${esc(meta.title)}</h1>
    <p class="cv-sub">${subtitle}</p>
    <div class="cv-rule"></div>
  </div>
  <div class="cv-body">
    <div class="cv-grid">
      ${pairs.map(
    ([k, v, sub]) => `<div><div class="eyebrow">${esc(k)}</div><div class="v">${v}${sub ? `<br><small>${sub}</small>` : ""}</div></div>`
  ).join("")}
    </div>
    ${card(
    "Report at a glance",
    `<div class="glance">${tiles.map(
      (t) => `<div><div class="n"${t.color ? ` style="color:${t.color}"` : ""}>${t.n}</div><div class="l">${esc(t.l)}</div></div>`
    ).join("")}</div>`,
    "card--mt"
  )}
    <p class="confid">Confidential. This document contains unremediated vulnerability detail,
      including package versions and file paths, and is restricted to ${esc(ctx.holder)} and its
      authorised security personnel. Figures are a point-in-time snapshot of the data source named
      above and will drift as branches advance and scans re-run.</p>
  </div>
  <div class="cv-foot"><span>${esc(ctx.classification)} \u2014 ${esc(ctx.holder)}</span><span>Page 1</span></div>
</section>`;
}
function detailsPage(ctx) {
  const { data, meta } = ctx;
  const sevPills = SEVERITIES.filter((s) => data.bySeverity[s] > 0).map(
    (s) => `<span class="pill">${sevBadge(s)}${SEV[s].label}<span class="muted" style="font-variant-numeric:tabular-nums">${fmt(data.bySeverity[s])}</span></span>`
  ).join("");
  const st = data.byStatus;
  const statusText = ["open", "resolved", "ignored"].filter((k) => st[k] > 0).map((k) => `${statusLabel(k)} ${fmt(st[k])}`).join(" \xB7 ");
  const filtered = card(
    "Filtered by",
    `<div class="card__b">${kv([
      ["Severity", `<div class="ctl__g">${sevPills}</div>`],
      ["Issue status", esc(statusText || "none reported")],
      ["Scanners", esc(data.byProduct.map((p) => productLabel(p.product)).join(", "))],
      ["Filters applied", esc(meta.filters || "none")],
      [
        "Results limited to",
        data.detailTruncatedTo === null ? `all ${fmt(data.total)} issues listed in the register \xB7 detailed write-ups for the top ${fmt(data.topRisks.length)} by risk score` : `register capped at ${fmt(data.detailTruncatedTo)} of ${fmt(data.total)} \xB7 detailed write-ups for the top ${fmt(data.topRisks.length)} by risk score`
      ]
    ])}</div>`
  );
  const inputRows = [
    ["Data source", esc(meta.sourceLabel)],
    ...meta.sourceDetail ? [["Source", `<span class="mono">${esc(meta.sourceDetail)}</span>`]] : [],
    ["Organisations", esc(data.byOrg.map((o) => o.label).join(", ") || "\u2014")]
  ];
  if (meta.region) inputRows.push(["Region", esc(meta.region)]);
  if (meta.dataAsOf) inputRows.push(["Data as of", esc(meta.dataAsOf)]);
  inputRows.push(["Generated", esc(meta.generatedAt)]);
  const d = meta.dropped;
  const volumeRows = [
    ["Rows read", fmt(meta.rowsRead)],
    ["Deleted", fmt(d.deleted)],
    ["Unparseable", fmt(d.unparseable)],
    ["Duplicates collapsed", fmt(d.duplicate)],
    ["Issues reported", `<b>${fmt(data.total)}</b>`]
  ];
  const inputs = card(
    "Report inputs",
    `<div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr))">
      <div style="padding:14px;border-right:1px solid ${C.lineSoft}">${kv(inputRows, "tight")}</div>
      <div style="padding:14px">${kv(volumeRows, "tight")}</div>
    </div>`
  );
  const scope = ctx.has("project") ? projectsCard(ctx) : orgsCard(ctx);
  return page(
    ctx,
    "report-details",
    `<h2 class="sec">Report Details</h2>
     <p class="lede">Parameters, coverage and filters used to produce this report. Every value
       below comes from the data source itself or from the flags this run was given.</p>
     ${filtered}${inputs}${scope}`,
    "Page 2"
  );
}
function projectsCard(ctx) {
  const rows = [...ctx.data.byProject].sort((a, b) => b.total - a.total).slice(0, 14).map((g) => {
    const sample = ctx.data.issues.find((i) => (i.project?.id ?? i.project?.name) === g.key);
    const type = sample?.project?.type ?? "";
    const target = sample?.project?.targetDisplayName ?? "";
    const eco = ecosystemOf(type);
    return `<tr>
        <td><span class="eco-row">${ecoBadge(type)}<span class="mono">${esc(g.label)}</span></span></td>
        <td class="muted">${esc(eco.label)}</td>
        <td class="mono muted">${esc(target)}</td>
        <td class="num"><b>${fmt(g.total)}</b></td></tr>`;
  }).join("");
  const more = ctx.data.byProject.length > 14 ? `<div style="padding:8px 14px;font-size:11px;color:${C.subtle}">
         and ${fmt(ctx.data.byProject.length - 14)} more \u2014 the full list is in the CSV output.</div>` : "";
  return card(
    "Projects in scope",
    `<table><thead><tr><th>Project</th><th>Type</th><th>Target</th><th class="num">Issues</th></tr></thead>
     <tbody>${rows}</tbody></table>${more}`
  );
}
function orgsCard(ctx) {
  const rows = ctx.data.byOrg.map(
    (g) => `<tr><td class="mono">${esc(g.label)}</td>` + SEVERITIES.map((s) => `<td class="num">${g.bySeverity[s] || ""}</td>`).join("") + `<td class="num"><b>${fmt(g.total)}</b></td></tr>`
  ).join("");
  return card(
    "Organisations in scope",
    `<table><thead><tr><th>Organisation</th>
     ${SEVERITIES.map((s) => `<th class="num">${SEV[s].label}</th>`).join("")}
     <th class="num">Total</th></tr></thead><tbody>${rows}</tbody></table>
     <div style="padding:8px 14px;font-size:11px;color:${C.subtle}">
       This data source carried no project column, so scope is shown by organisation.</div>`
  );
}
function tocPage(ctx) {
  const sections = [
    ["01", "Report Details", "2"],
    ["02", "Table of Contents", "3"],
    ["03", "Executive Summary", "4"],
    ["04", "Findings Index", "5"],
    ["05", "Findings Register", "6"]
  ];
  const rows = sections.map(
    ([n, t, p]) => `<div class="toc__r"><span class="n">${n}</span><span class="t">${esc(t)}</span>
         <span class="sp"></span><span class="p">${p}</span></div>`
  ).join("");
  const detailRows = ctx.data.topRisks.map((i, n) => {
    const idx = ctx.refIndex.get(i.issueKey) ?? n;
    return `<div class="toc__s">${sevBadge(i.severity)}
        <span class="t"><a href="#${anchorOf(idx)}">${esc(i.title)}</a></span>
        <span class="r">${refOf(idx)}</span><span class="sp"></span>
        <span class="p">Detail ${n + 1}</span></div>`;
  }).join("");
  const PRINT_TOC_LIMIT = 60;
  const over = ctx.data.topRisks.length - PRINT_TOC_LIMIT;
  const printNote = over > 0 ? `<div class="toc__more print-only">and ${fmt(over)} more detail
         page${over === 1 ? "" : "s"} \u2014 every issue is listed in the register, section 05.</div>` : "";
  const details = `<div class="toc__scroll"${over > 0 ? ` data-print-limit="${PRINT_TOC_LIMIT}"` : ""}>${detailRows}</div>${printNote}`;
  return page(
    ctx,
    "contents",
    `<h2 class="sec" style="margin-bottom:8mm">Table of Contents</h2>
     <div class="toc">${rows}
       <div class="toc__r" style="padding-top:12px"><span class="n">06</span>
         <span class="t">Vulnerability Details</span><span class="sp"></span>
         <span class="p">${fmt(ctx.data.topRisks.length)} page${ctx.data.topRisks.length === 1 ? "" : "s"}</span></div>
       ${details}
       <div class="toc__r" style="padding-top:12px"><span class="n">07</span>
         <span class="t">Appendix \u2014 methodology, glossary and data coverage</span>
         <span class="sp"></span><span class="p">end</span></div>
     </div>
     <div class="note note--purple avoid-break" style="margin-top:10mm">
       <div class="note__t">How to read this report</div>
       <p>Section 04 gives the distribution of issues across scanners, severity, status and
         project. Section 05 is the register of every issue this report covers; each row carries
         the reference used throughout. Section 06 devotes a page to each of the highest-risk
         issues. Section 07 records exactly which fields this data source could and could not
         carry \u2014 read it before concluding that a blank means "clean".</p>
     </div>`,
    "Page 3"
  );
}
function execPage(ctx) {
  const { data } = ctx;
  const uniq = new Set(data.issues.map((i) => i.problemId)).size;
  const tiles = SEVERITIES.map(
    (s) => `<div class="tile tint-${s}"><div class="t">${sevBadge(s, "md")}${SEV[s].label}</div>
       <div class="n">${fmt(data.bySeverity[s])}</div></div>`
  ).join("");
  const top = data.topRisks.slice(0, 4);
  const topList = top.length ? `<div class="note note--danger avoid-break" style="margin-bottom:7mm">
        <div class="note__t">Highest-risk issues</div>
        <p style="margin:0 0 12px;font-size:11.5px;color:${C.subtle}">Ranked by this tool's risk
          score \u2014 severity first, then whichever of exploit maturity, KEV listing, reachability,
          fix availability and CVSS this data source carried.</p>
        <ol style="margin:0;padding-left:18px;display:flex;flex-direction:column;gap:10px;
          font-size:12.5px;line-height:1.55">
          ${top.map((i) => {
    const where = locationShort(i);
    const proj = i.project?.name ?? "";
    const tail = [proj, where].filter(Boolean).join(" \xB7 ");
    return `<li><strong>${esc(i.title)}</strong>${tail ? ` \u2014 <span class="mono">${esc(tail)}</span>` : ""} <span class="muted">(${esc(SEV[i.severity].label)}, ${esc(productLabel(i.product))})</span></li>`;
  }).join("")}
        </ol></div>` : "";
  return page(
    ctx,
    "executive-summary",
    `<h2 class="sec">Executive Summary</h2>
     <p class="lede">Issues as reported by the data source named on page 2. Severity is Snyk's
       effective severity, which already reflects any organisation policy override; it is never
       re-derived from CVSS here.</p>
     <div class="bigrow">
       <div class="big"><div class="l">Issues reported</div><div class="n">${fmt(data.total)}</div></div>
       <div class="big"><div class="l">Unique vulns</div>
         <div class="n" style="color:${C.accent}">${fmt(uniq)}</div></div>
       <div class="tiles">${tiles}</div>
     </div>
     ${topList}
     <div class="split">${statusPanel(ctx)}${signalPanel(ctx)}</div>
     ${fixPanel(ctx)}`,
    "Page 4"
  );
}
function cleanBill(ctx) {
  const { data, meta } = ctx;
  const filtered = meta.rowsRead > 0 && data.total === 0 && meta.sourceHadFindings;
  if (filtered) {
    return `<div class="note note--good"><div class="note__t">Nil return</div>
      <p>No issue matched the filters recorded on the previous page. The data was read
      successfully and did contain findings; none of them meet these criteria. This is a
      statement about the filter, not about the estate.</p></div>`;
  }
  const scanned = ctx.scannersRequested.length ? ctx.scannersRequested : ["open-source", "code", "container", "iac", "secrets"];
  const lines = scanned.map(
    (p) => `<li><b>${esc(productLabel(p))}</b> \u2014 no ${esc(productShort(p))} findings</li>`
  ).join("");
  return `<div class="note note--good"><div class="note__t">Clean \u2014 no vulnerabilities found</div>
    <p>The data for this scope was read successfully and contains no findings at all.</p>
    <ul style="margin:8px 0 0;padding-left:18px;font-size:12.5px;line-height:1.7">${lines}</ul>
    <p style="margin-top:10px"><b>Not covered:</b> DAST. Snyk API &amp; Web is a separate
    platform that this report cannot read, so this result says nothing about dynamic testing.
    Anything outside the filters on the previous page is likewise out of scope.</p></div>`;
}
function statusPanel(ctx) {
  const st = ctx.data.byStatus;
  const rows = [
    ["Open", fmt(st.open)],
    ["Fixed", fmt(st.resolved)],
    ["Ignored", fmt(st.ignored)]
  ];
  if (ctx.data.cisaKevCount !== null) {
    rows.push([
      "In CISA KEV",
      `<span style="color:${SEV.critical.color}">${fmt(ctx.data.cisaKevCount)}</span>`
    ]);
  }
  const body = rows.map(
    ([k, v], n) => `<div style="display:flex;justify-content:space-between${n === rows.length - 1 && ctx.data.cisaKevCount !== null ? `;border-top:1px solid ${C.lineSoft};padding-top:9px` : ""}"><span>${esc(k)}</span><span style="font-weight:600">${v}</span></div>`
  ).join("");
  const caveat = st.resolved || st.ignored ? `<p style="margin:10px 0 0;font-size:11px;color:${C.subtle}">Totals include resolved and
         ignored issues. Re-run with <span class="mono">--status open</span> to exclude them.</p>` : "";
  return `<div class="pad avoid-break"><div class="lbl">Status</div>
    <div style="display:flex;flex-direction:column;gap:9px;font-size:12.5px">${body}</div>${caveat}</div>`;
}
function signalPanel(ctx) {
  const blocks = [];
  if (ctx.has("exploitMaturity")) {
    const counts = /* @__PURE__ */ new Map();
    for (const i of ctx.data.issues) {
      const e = read(i, "exploitMaturity");
      if (e.state === "present") {
        const l = exploitMaturityLabel(e.value, ctx.cvss4);
        counts.set(l, (counts.get(l) ?? 0) + 1);
      }
    }
    const rows = [...counts].sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }));
    if (rows.length) blocks.push(`<div class="lbl">Exploit maturity</div>${barList(rows, ctx.data.total)}`);
  }
  if (ctx.has("reachability")) {
    const counts = /* @__PURE__ */ new Map();
    for (const i of ctx.data.issues) {
      const r = read(i, "reachability");
      if (r.state === "present") counts.set(r.value, (counts.get(r.value) ?? 0) + 1);
    }
    const rows = [...counts].sort((a, b) => b[1] - a[1]).map(([k, value]) => ({ label: statusLabel(k), value, color: reachChip(k).fg }));
    if (rows.length) {
      blocks.push(
        `<div class="lbl" style="margin-top:14px">Reachability</div>${barList(rows, ctx.data.total)}`
      );
    }
  }
  if (!blocks.length) {
    return `<div class="pad avoid-break"><div class="lbl">Exploitability signals</div>
      <p style="margin:0;font-size:12px;line-height:1.6;color:${C.body}">This data source carried
        no exploit-maturity, reachability or EPSS column, so no exploitability signal can be shown.
        That is a gap in the export, <strong>not</strong> a finding that nothing is exploitable.
        Section 07 lists every field in this position.</p></div>`;
  }
  return `<div class="pad avoid-break">${blocks.join("")}</div>`;
}
function fixPanel(ctx) {
  const { data } = ctx;
  const facts = [];
  if (ctx.has("fixability")) {
    const fixable = data.issues.filter((i) => {
      const f = read(i, "fixability");
      return f.state === "present" && f.value === "fixable";
    });
    const critHigh = fixable.filter((i) => i.severity === "critical" || i.severity === "high");
    if (fixable.length) {
      facts.push(
        `<li><strong>${fmt(fixable.length)}</strong> issue${fixable.length === 1 ? " has" : "s have"}
         a supported fix, of which <strong>${fmt(critHigh.length)}</strong> are critical or high.</li>`
      );
    }
  }
  if (ctx.has("fixedInVersion")) {
    const byPkg = /* @__PURE__ */ new Map();
    for (const i of data.issues) {
      const p = read(i, "packageNameAndVersion");
      const f = read(i, "fixedInVersion");
      if (p.state === "present" && f.state === "present") {
        const name = p.value.split("@")[0] ?? p.value;
        byPkg.set(name, (byPkg.get(name) ?? 0) + 1);
      }
    }
    const top = [...byPkg].sort((a, b) => b[1] - a[1]).slice(0, 3);
    for (const [name, n] of top) {
      if (n < 2) continue;
      facts.push(
        `<li>Upgrading <span class="mono">${esc(name)}</span> closes
         <strong>${fmt(n)}</strong> issues in one change.</li>`
      );
    }
  }
  if (data.cisaKevCount) {
    facts.push(
      `<li><strong>${fmt(data.cisaKevCount)}</strong> issue${data.cisaKevCount === 1 ? " is" : "s are"}
       in CISA's Known Exploited Vulnerabilities catalogue \u2014 confirmed exploited in the wild.</li>`
    );
  }
  const worst = data.byProject[0];
  if (worst && worst.bySeverity.critical) {
    facts.push(
      `<li><span class="mono">${esc(worst.label)}</span> carries the most critical issues
       (<strong>${fmt(worst.bySeverity.critical)}</strong> of ${fmt(worst.total)} in that project).</li>`
    );
  }
  if (!facts.length) return "";
  return `<div class="note note--good avoid-break">
    <div class="note__t" style="color:${C.successDeep}">Where the fixes are</div>
    <ol style="margin:0;padding-left:18px;font-size:12.5px;line-height:1.7;color:${C.body}">
      ${facts.join("")}</ol>
    <p style="margin:10px 0 0;font-size:11px;color:${C.subtle}">Derived arithmetically from the
      figures above. This is not a remediation plan and does not account for your release process
      or asset criticality.</p></div>`;
}
function statsPage(ctx) {
  const { data } = ctx;
  const byProduct = data.byProduct.map((p, n) => ({
    // "Snyk " on every row of a card headed "By scanner" is noise, and it is
    // the reason the labels needed two lines. Dropped here only; the full
    // product name is still used everywhere else.
    label: productLabel(p.product).replace(/^Snyk /, ""),
    value: p.total,
    color: seriesColor(n)
  }));
  const bySeverity = SEVERITIES.filter((s) => data.bySeverity[s] > 0).map((s) => ({
    label: SEV[s].label,
    value: data.bySeverity[s],
    color: SEV[s].color
  }));
  const statusRows = ["open", "resolved", "ignored"].filter((k) => data.byStatus[k] > 0).map((k, n) => ({ label: statusLabel(k), value: data.byStatus[k], color: seriesColor(n) }));
  const projectRows = [...data.byProject].sort((a, b) => b.total - a.total).slice(0, 6).map((g, n) => ({ label: g.label, value: g.total, color: seriesColor(n) }));
  return page(
    ctx,
    "statistics",
    `<h2 class="sec">Findings Index</h2>
     ${data.total === 0 ? cleanBill(ctx) : `<p class="lede">Distribution of the ${fmt(data.total)} reported issues across
            scanners, severity, status and project.</p>`}
     <div class="split">${donutCard("By scanner", byProduct)}${donutCard("By severity", bySeverity)}</div>
     <div class="split">
       <div class="pad avoid-break"><div class="lbl">By status</div>
         ${barList(statusRows, data.total)}</div>
       <div class="pad avoid-break"><div class="lbl">Top projects</div>
         ${projectRows.length ? barList(projectRows, data.total) : `<p style="margin:0;font-size:12px;color:${C.body}">${data.total === 0 ? "No findings, so no projects to rank." : "This data source carried no project column."}</p>`}</div>
     </div>
     ${topTypesCard(ctx)}`,
    "Page 5"
  );
}
function topTypesCard(ctx) {
  const byProblem = /* @__PURE__ */ new Map();
  for (const i of ctx.data.issues) {
    let a = byProblem.get(i.problemId);
    if (!a) {
      const cwe = read(i, "cwe");
      a = {
        title: i.title,
        cwe: cwe.state === "present" ? cwe.value[0] ?? "" : "",
        count: 0,
        worst: i.severity
      };
      byProblem.set(i.problemId, a);
    }
    a.count++;
    if (SEVERITIES.indexOf(i.severity) < SEVERITIES.indexOf(a.worst)) a.worst = i.severity;
  }
  const top = [...byProblem.values()].sort((x, y) => y.count - x.count).slice(0, 8);
  if (!top.length) return "";
  const max = top[0].count;
  const rows = top.map(
    (t, n) => `<tr><td class="num" style="width:30px;color:${C.faint}">${n + 1}</td>
         <td>${esc(t.title)}</td>
         <td class="mono muted" style="width:88px">${esc(t.cwe)}</td>
         <td style="width:230px"><div style="display:flex;align-items:center;gap:8px">
           <div style="flex:1;height:8px;border-radius:3px;background:#F1F1F3;overflow:hidden">
             <div style="height:8px;width:${(t.count / max * 100).toFixed(1)}%;
               background:${SEV[t.worst].color}"></div></div>
           <span style="width:34px;text-align:right;font-variant-numeric:tabular-nums;font-weight:600">
             ${fmt(t.count)}</span></div></td></tr>`
  ).join("");
  return card(
    `Most frequent vulnerabilities (top ${top.length})`,
    `<table><tbody>${rows}</tbody></table>`
  );
}
function idList(ids) {
  return ids.map((v) => `<span class="id1">${esc(v)}</span>`).join(" ");
}
function targetOf(i) {
  const t = i.project?.targetDisplayName;
  if (t) return t;
  const name = i.project?.name ?? "";
  const cut = name.indexOf(":");
  return cut > 0 ? name.slice(0, cut) : name;
}
function registerCols(ctx) {
  const cols = [
    {
      key: "ref",
      label: "Ref",
      width: "60px",
      sort: (_i) => 0,
      cell: (_i, idx) => `<span class="ref">${refOf(idx)}</span>`
    },
    {
      key: "sev",
      label: "Severity",
      width: "68px",
      sort: (i) => -SEVERITIES.indexOf(i.severity),
      cell: (i) => sevInline(i.severity)
    },
    {
      key: "title",
      label: "Issue",
      width: "auto",
      sort: (i) => i.title.toLowerCase(),
      cell: (i, idx) => {
        const hasDetail = idx < ctx.data.topRisks.length;
        const t = esc(i.title);
        return `<div class="ttl">${hasDetail ? `<a href="#${anchorOf(idx)}">${t}</a>` : t}</div>`;
      }
    }
  ];
  if (ctx.has("cwe")) {
    cols.push({
      key: "cwe",
      label: "CWE",
      width: "64px",
      sort: (i) => {
        const v = read(i, "cwe");
        return v.state === "present" ? v.value[0] ?? "" : "";
      },
      cell: (i) => {
        const v = read(i, "cwe");
        return v.state === "present" ? `<span class="ids">${idList(v.value)}</span>` : "";
      }
    });
  }
  if (ctx.has("cvss")) {
    cols.push({
      key: "cvss",
      label: "CVSS",
      width: "44px",
      num: true,
      sort: (i) => {
        const v = read(i, "cvss");
        return v.state === "present" ? v.value.score : -1;
      },
      cell: (i) => {
        const v = read(i, "cvss");
        return v.state === "present" ? `<b>${v.value.score}</b>` : "";
      }
    });
  }
  if (ctx.has("project")) {
    cols.push({
      key: "target",
      label: "Target",
      width: "146px",
      sort: (i) => targetOf(i).toLowerCase(),
      cell: (i) => `<span class="proj">${esc(targetOf(i))}</span>`
    });
  }
  cols.push({
    key: "product",
    label: "Product",
    width: "62px",
    sort: (i) => i.product,
    cell: (i) => `<span class="muted">${esc(productShort(i.product))}</span>`
  });
  cols.push({
    key: "status",
    label: "Status",
    width: "52px",
    sort: (i) => i.status,
    cell: (i) => `<span class="tag">${esc(statusLabel(i.status))}</span>`
  });
  return cols;
}
function registerPage(ctx) {
  const { data } = ctx;
  const cols = registerCols(ctx);
  const rows = data.detailIssues;
  const chips = SEVERITIES.filter((s) => data.bySeverity[s] > 0).map(
    (s) => `<button type="button" class="btn" data-f="sev" data-v="${s}" aria-pressed="true">
         ${sevBadge(s)}<span>${SEV[s].label}</span>
         <span class="c">${fmt(data.bySeverity[s])}</span></button>`
  ).join("");
  const statusChips = ["open", "resolved", "ignored"].filter((st) => data.byStatus[st] > 0).map(
    (st) => `<button type="button" class="btn" data-f="status" data-v="${st}" aria-pressed="true">
         <span>${esc(statusLabel(st))}</span>
         <span class="c">${fmt(data.byStatus[st])}</span></button>`
  ).join("");
  const productOpts = data.byProduct.map((p) => `<option value="${esc(p.product)}">${esc(productLabel(p.product))} (${fmt(p.total)})</option>`).join("");
  const targetCounts = /* @__PURE__ */ new Map();
  for (const i of rows) {
    const t = targetOf(i);
    if (t) targetCounts.set(t, (targetCounts.get(t) ?? 0) + 1);
  }
  const targetOpts = [...targetCounts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([t, n]) => `<option value="${esc(t)}">${esc(t)} (${fmt(n)})</option>`).join("");
  const selects = `<select id="reg-product" class="sel" aria-label="Filter by product"><option value="">All products</option>${productOpts}</select>` + (targetCounts.size > 1 ? `<select id="reg-target" class="sel" aria-label="Filter by target"><option value="">All targets (${fmt(targetCounts.size)})</option>${targetOpts}</select>` : "");
  const head = cols.map(
    (c2) => `<th data-key="${c2.key}" style="width:${c2.width}${c2.num ? ";text-align:right" : ""}">${esc(c2.label)}<span class="arrow"></span></th>`
  ).join("");
  const body = rows.map((i, idx) => {
    const cve = read(i, "cve");
    const cwe = read(i, "cwe");
    const hay = [
      i.title,
      i.problemId,
      i.project?.name,
      targetOf(i),
      productShort(i.product),
      i.status,
      locationShort(i),
      refOf(idx),
      cve.state === "present" ? cve.value.join(" ") : "",
      cwe.state === "present" ? cwe.value.join(" ") : ""
    ].filter(Boolean).join(" ").toLowerCase();
    const sorts = cols.map((c2) => ` data-s-${c2.key}="${esc(c2.key === "ref" ? idx : c2.sort(i))}"`).join("");
    return `<tr class="idx-row" data-sev="${i.severity}" data-status="${esc(i.status)}" data-product="${esc(i.product)}" data-target="${esc(targetOf(i))}" data-hay="${esc(hay)}"${sorts}>${cols.map((c2) => `<td${c2.num ? ' class="num"' : ""}>${c2.cell(i, idx)}</td>`).join("")}</tr>`;
  }).join("");
  const omitted = data.total - rows.length;
  const capNote = omitted ? `<div class="note avoid-break" style="margin-top:6mm;background:${C.surface};
        font-size:11.5px;line-height:1.6;color:${C.muted}">
        The remaining <strong>${fmt(omitted)}</strong> issues are omitted from this register by
        <span class="mono">--max-detail-rows</span>. The CSV and JSON outputs are always complete.</div>` : `<div class="note avoid-break" style="margin-top:6mm;background:${C.surface};
        font-size:11.5px;line-height:1.6;color:${C.muted}">
        Every one of the <strong>${fmt(data.total)}</strong> reported issues is listed above.
        Snyk's own PDF export truncates this table at 50 rows; this one is uncapped.</div>`;
  return page(
    ctx,
    "register",
    `<h2 class="sec">Findings Register</h2>
     ${data.total === 0 ? `<div class="note note--good"><div class="note__t">Nil return</div>
            <p>Nothing to register: no issue matched the selected filters.</p></div>` : `<p class="lede">Every issue this report covers, ordered worst-first by risk score.
            The first ${fmt(data.topRisks.length)}
            reference${data.topRisks.length === 1 ? "" : "s"} link to a detail page in
            section 06.</p>`}
     <div class="ctl no-print">
       <div class="ctl__r">
         <input type="search" id="reg-q"
           placeholder="Search issue, CVE, CWE, target, project or package"
           aria-label="Search the findings register">
         ${selects}
       </div>
       <div class="ctl__g">${chips}${statusChips ? `<span class="ctl__sep"></span>${statusChips}` : ""}
         <button type="button" class="btn" id="reg-reset">Reset filters</button></div>
     </div>
     <div class="reg-scroll"><table class="reg" id="reg"><thead><tr>${head}</tr></thead>
       <tbody>${body}</tbody></table></div>
     <p class="no-print" id="reg-count" style="font-size:11.5px;color:${C.subtle};margin:12px 0 0"></p>
     ${capNote}`,
    "Findings register",
    "page--flow"
  );
}
function findingPage(ctx, i, n) {
  const idx = ctx.refIndex.get(i.issueKey) ?? n;
  const ref = refOf(idx);
  const sev = SEV[i.severity];
  const cve = read(i, "cve");
  const cwe = read(i, "cwe");
  const crumbs = [
    `<span>${esc(productLabel(i.product))}</span>`,
    cwe.state === "present" ? `<span class="sep">|</span><span class="hi">${esc(cwe.value.join(", "))}</span>` : "",
    cve.state === "present" ? `<span class="sep">|</span><span class="hi">${esc(cve.value.join(", "))}</span>` : "",
    `<span class="sep">|</span><span>${ref}</span>`
  ].join("");
  const metrics = [];
  const cvss = read(i, "cvss");
  if (cvss.state === "present") {
    metrics.push({ k: `CVSS v${cvss.value.version}`, v: String(cvss.value.score) });
  }
  metrics.push({ k: "Risk score", v: String(Math.round(riskScore(i, ctx.a))), tint: true });
  const em = read(i, "exploitMaturity");
  if (em.state === "present") {
    metrics.push({ k: "Exploit maturity", v: esc(exploitMaturityLabel(em.value, ctx.cvss4)), small: true });
  }
  metrics.push({ k: "Status", v: esc(statusLabel(i.status)), small: true });
  const fixv = read(i, "fixedInVersion");
  const fixa = read(i, "fixability");
  if (fixv.state === "present") metrics.push({ k: "Fixed in", v: esc(fixv.value), small: true });
  else if (fixa.state === "present") {
    metrics.push({ k: "Fixability", v: esc(kebabLabel(fixa.value)), small: true });
  }
  metrics.push({
    k: "Severity",
    v: `<span class="fd-sev">${sevBadge(i.severity, "md")}<span>${SEV[i.severity].label}</span></span>`
  });
  const metricHtml = metrics.map(
    (m) => `<div><div class="k">${esc(m.k)}</div><div class="v${m.small ? " v--sm" : ""}"${m.tint ? ` style="color:${sev.color}"` : ""}>${m.v}</div></div>`
  ).join("");
  return `<article class="fd" data-page="finding-detail" id="${anchorOf(idx)}">
  <div class="fd-ref">${esc(`Vulnerability detail \xB7 ${ref}`)}</div>
  <div class="fd-hd">
    <div class="fd-hd__t tint-${i.severity}">
      <h3>${esc(i.title)}</h3>
      <div class="fd-crumbs">${crumbs}</div>
    </div>
    <div class="fd-metrics" style="grid-template-columns:repeat(${metrics.length},minmax(0,1fr))">
      ${metricHtml}</div>
  </div>
  ${attributesBlock(ctx, i)}
  ${packageBlock(ctx, i)}
  ${codeBlock(i)}
  ${remediationBlock(ctx, i)}
  ${classificationBlock(i)}
</article>`;
}
function attributesBlock(ctx, i) {
  const pairs = [];
  if (ctx.has("project")) {
    pairs.push(["Project", `<span class="mono">${esc(i.project?.name ?? "")}</span>`]);
    const t = i.project?.targetDisplayName;
    if (t) pairs.push(["Target", `<span class="mono">${esc(t)}</span>`]);
  }
  pairs.push(["Organisation", esc(i.org.name ?? i.org.id)]);
  if (i.group?.name) pairs.push(["Group", esc(i.group.name)]);
  pairs.push(["Snyk problem id", `<span class="mono">${esc(i.problemId)}</span>`]);
  const intro = dayOf(i, "firstIntroduced");
  if (intro) pairs.push(["Introduced", esc(intro)]);
  const upd = dayOf(i, "updatedAt");
  if (upd) pairs.push(["Last updated", esc(upd)]);
  const kev = read(i, "isCisaKev");
  if (kev.state === "present") {
    pairs.push([
      "CISA KEV",
      kev.value ? `<span style="color:${SEV.critical.color};font-weight:600">Yes \u2014 exploited in the wild</span>` : "No"
    ]);
  }
  const epss = read(i, "epssScore");
  if (epss.state === "present") {
    const p = read(i, "epssPercentile");
    pairs.push([
      "EPSS",
      `${(epss.value * 100).toFixed(2)}%${p.state === "present" ? ` <span class="muted">(${(p.value * 100).toFixed(0)}th pct)</span>` : ""}`
    ]);
  }
  const notes = [];
  const score = read(i, "score");
  if (score.state === "present") notes.push(`Snyk priority score ${score.value}`);
  const rf = read(i, "riskFactors");
  if (rf.state === "present") notes.push(`Risk factors: ${rf.value.join(", ")}`);
  return `<div class="fd-attrs">
    <div class="lbl">Issue attributes</div>
    ${kv(pairs, "narrow")}
    ${notes.length ? `<p style="margin:10px 0 0;font-size:11.5px;color:${C.subtle}">${esc(notes.join(" \xB7 "))}</p>` : ""}
  </div>`;
}
function packageBlock(ctx, i) {
  const pkg = read(i, "packageNameAndVersion");
  if (pkg.state !== "present") return "";
  const fixed = read(i, "fixedInVersion");
  const reach = read(i, "reachability");
  const direct = read(i, "existsInDirectDependency");
  const range = read(i, "semverVulnerableRange");
  const cvss = read(i, "cvss");
  const cells = [
    `<div><div class="k">Package</div><div class="v">${esc(pkg.value)}</div></div>`,
    `<div><div class="k">Fixed in</div><div class="v" style="color:${C.successDeep}">${fixed.state === "present" ? esc(fixed.value) : '<span class="faint">not stated</span>'}</div></div>`
  ];
  if (direct.state === "present") {
    cells.push(
      `<div><div class="k">Dependency</div><div class="v">${direct.value ? "Direct" : "Transitive"}</div></div>`
    );
  }
  if (reach.state === "present") {
    const c2 = reachChip(reach.value);
    cells.push(
      `<div><div class="k">Reachability</div><span class="reach" style="background:${c2.bg};
       color:${c2.fg};border:1px solid ${c2.border}">${esc(kebabLabel(reach.value))}</span></div>`
    );
  }
  const tail = [];
  if (range.state === "present") {
    tail.push(["Vulnerable range", `<span class="mono">${esc(range.value)}</span>`]);
  }
  if (cvss.state === "present" && cvss.value.vector) {
    tail.push([
      "CVSS vector",
      `<span class="mono">${esc(cvss.value.vector)}</span> <span class="muted">(${esc(
        cvss.value.source
      )})</span>`
    ]);
  }
  return `<div class="card avoid-break">
    <div class="card__h">Affected package</div>
    <div class="fd-pkg" style="grid-template-columns:repeat(${cells.length},minmax(0,1fr))">
      ${cells.join("")}</div>
    ${tail.length ? `<div style="border-top:1px solid ${C.lineSoft};padding:11px 13px">
           ${kv(tail, "tight")}</div>` : ""}
  </div>`;
}
function codeBlock(i) {
  const fp = read(i, "filePath");
  if (fp.state !== "present") return "";
  const r = read(i, "codeRegion");
  const pairs = [["File", `<span class="mono">${esc(fp.value)}</span>`]];
  if (r.state === "present") {
    const v = r.value;
    const lines = v.startLine != null ? `${v.startLine}${v.endLine != null && v.endLine !== v.startLine ? `\u2013${v.endLine}` : ""}` : "";
    const colsTxt = v.startColumn != null ? `${v.startColumn}${v.endColumn != null && v.endColumn !== v.startColumn ? `\u2013${v.endColumn}` : ""}` : "";
    if (lines) pairs.push(["Line", esc(lines)]);
    if (colsTxt) pairs.push(["Column", esc(colsTxt)]);
  }
  const commit = read(i, "commitId");
  if (commit.state === "present") pairs.push(["Commit", `<span class="mono">${esc(commit.value)}</span>`]);
  const flow = read(i, "dataflow");
  const flowHtml = flow.state === "present" ? dataflowList(flow.value) : "";
  const note = flow.state === "present" ? "" : `<p style="margin:10px 0 0;font-size:11px;color:${C.subtle}">The source excerpt and traced data
      flow are shown in the Snyk UI; this data source does not carry them, so they cannot be
      reproduced here.</p>`;
  return `<div class="card avoid-break"><div class="card__h">Code location</div>
    <div class="card__b">${kv(pairs, "tight")}${flowHtml}${note}</div></div>`;
}
function dataflowList(steps) {
  const rows = steps.map((s, idx) => {
    const isEnd = idx === 0 || idx === steps.length - 1;
    const loc = s.fromLine == null ? "" : `:${s.fromLine}${s.toLine != null && s.toLine !== s.fromLine ? `\u2013${s.toLine}` : ""}`;
    return `<div style="display:flex;align-items:center;gap:8px;padding:4px 0;
        border-bottom:1px dashed ${C.lineSoft}">
        <span style="flex:0 0 18px;height:18px;border-radius:50%;display:flex;align-items:center;
          justify-content:center;font-size:10px;font-weight:700;color:#fff;
          background:${isEnd ? C.accent : C.subtle}">${idx + 1}</span>
        <span class="mono" style="font-size:11px">${esc(s.file)}${esc(loc)}</span></div>`;
  }).join("");
  return `<div style="margin-top:10px"><div class="lbl" style="margin-bottom:6px">
      Source &rarr; Sink data flow (${steps.length} step${steps.length === 1 ? "" : "s"})</div>
    ${rows}</div>`;
}
function remediationBlock(ctx, i) {
  const steps = [];
  const fixed = read(i, "fixedInVersion");
  const pkg = read(i, "packageNameAndVersion");
  const fixa = read(i, "fixability");
  const direct = read(i, "existsInDirectDependency");
  if (fixed.state === "present" && pkg.state === "present") {
    const name = pkg.value.split("@")[0] ?? pkg.value;
    steps.push(
      `Upgrade <span class="mono">${esc(name)}</span> to <span class="mono">${esc(fixed.value)}</span> or later.`
    );
    if (direct.state === "present" && !direct.value) {
      steps.push(
        "This is a transitive dependency, so the upgrade usually means bumping the parent package or adding an override in the manifest."
      );
    }
  } else if (fixa.state === "present") {
    const map = {
      fixable: "A supported fix is available \u2014 see the Snyk issue page for the upgrade path.",
      "partially-fixable": "Partially fixable: some paths to this vulnerability have a fix and some do not.",
      "no-supported-fix": "No supported fix is published. Mitigate, or remove the dependency.",
      unfixable: "No fix is available. Mitigate at the application or network layer."
    };
    steps.push(map[fixa.value] ?? kebabLabel(fixa.value));
  }
  if (i.product === "code") {
    steps.push("Snyk Code findings need a source change; there is no upgrade path.");
  }
  const url = read(i, "issueUrl");
  if (url.state === "present") {
    steps.push(`Triage or ignore this finding in Snyk: <a href="${esc(url.value)}">open the issue</a>.`);
  }
  if (!steps.length) return "";
  return `<div class="fd-rem" style="margin-bottom:2.5mm">
    <div class="lbl">Remediation</div>
    <div class="note note--good avoid-break" style="padding:10px 12px">
      <ol>${steps.map((s) => `<li>${s}</li>`).join("")}</ol></div></div>`;
}
function classificationBlock(i) {
  const cwe = read(i, "cwe");
  const cve = read(i, "cve");
  const rows = [];
  if (cwe.state === "present") {
    rows.push([
      "CWE",
      cwe.value.map(
        (w) => `<a href="https://cwe.mitre.org/data/definitions/${esc(w.replace(/\D/g, ""))}.html">${esc(w)}</a>`
      ).join(", ")
    ]);
  }
  if (cve.state === "present") {
    rows.push([
      "CVE",
      cve.value.map((v) => `<a href="https://nvd.nist.gov/vuln/detail/${esc(v)}">${esc(v)}</a>`).join(", ")
    ]);
  }
  const t = read(i, "issueType");
  if (t.state === "present") rows.push(["Issue type", esc(t.value)]);
  const nvd = read(i, "nvdScore");
  if (nvd.state === "present") rows.push(["NVD score", String(nvd.value)]);
  const refs = [];
  const url = read(i, "issueUrl");
  if (url.state === "present") refs.push(`<a href="${esc(url.value)}">Snyk issue</a>`);
  const vdb = read(i, "vulnDbUrl");
  if (vdb.state === "present") refs.push(`<a href="${esc(vdb.value)}">Snyk Vulnerability DB</a>`);
  if (cve.state === "present") {
    for (const v of cve.value) refs.push(`<a href="https://nvd.nist.gov/vuln/detail/${esc(v)}">NVD ${esc(v)}</a>`);
  }
  if (!rows.length && !refs.length) return "";
  return `<div class="fd-2col">
    <div class="avoid-break"><div class="lbl">Classification</div>
      ${rows.length ? kv(rows, "narrow") : `<p class="muted" style="font-size:11.5px;margin:0">Not classified in this export.</p>`}</div>
    <div class="avoid-break"><div class="lbl">References</div>
      ${refs.length ? `<ul>${refs.map((r) => `<li>${r}</li>`).join("")}</ul>` : `<p class="muted" style="font-size:11.5px;margin:0">This export carried no issue URL.</p>`}</div></div>`;
}
var GLOSSARY = [
  [
    "Effective severity",
    "Snyk's severity for the issue in your organisation, after any policy override. This report never re-derives severity from CVSS, so the two can legitimately disagree."
  ],
  [
    "Risk score",
    "Computed by this tool, not by Snyk. Severity dominates; exploit maturity, CISA KEV listing, reachability, direct-dependency status, fixability and CVSS act as tie-breakers, and any of those the data source did not carry contributes nothing at all rather than zero. It is not Snyk's Priority Score."
  ],
  [
    "CISA KEV",
    "CISA's Known Exploited Vulnerabilities catalogue \u2014 confirmed exploited in the wild, and for US federal bodies a binding remediation deadline."
  ],
  [
    "EPSS",
    "Exploit Prediction Scoring System: the modelled probability that a vulnerability will be exploited in the next 30 days."
  ],
  [
    "Exploit maturity",
    'Whether working exploit code is known. Snyk uses two vocabularies; the CVSS v4 one collapses "no known exploit" and "no data" into a single "not defined", so a report built from that vocabulary genuinely cannot distinguish them.'
  ],
  [
    "Reachability",
    'Whether a call path exists from your code to the vulnerable function. "No path found" means none was detected by this analysis, which is weaker than proving none exists.'
  ],
  [
    "Direct / transitive",
    "A direct dependency is declared in your manifest; a transitive one is pulled in by another package and usually requires upgrading the parent."
  ],
  [
    "Unique vulnerabilities",
    "Distinct Snyk problem ids. One vulnerable package affecting eight projects is eight issues but one unique vulnerability."
  ]
];
function appendixPage(ctx) {
  const { data, meta } = ctx;
  const missing = absentFields(ctx.a);
  const sevRows = SEVERITIES.map(
    (s) => `<tr><td style="vertical-align:top"><span style="display:inline-flex;align-items:center;gap:6px">
       ${sevBadge(s)}${SEV[s].label}</span></td>
       <td style="line-height:1.5;color:${C.body}">${esc(SEV_NOTE[s])}</td></tr>`
  ).join("");
  const glossRows = GLOSSARY.map(
    ([t, d2]) => `<tr><td style="vertical-align:top;font-weight:600">${esc(t)}</td>
       <td style="line-height:1.5;color:${C.body}">${esc(d2)}</td></tr>`
  ).join("");
  const coverage = missing.length ? `<div class="note avoid-break" style="background:${C.accentWash};border-left:3px solid ${C.accent}">
        <div class="note__t" style="color:${C.accentDark}">
          ${missing.length} field${missing.length === 1 ? "" : "s"} not carried by this data source</div>
        <p style="margin:0 0 8px">They are omitted from the tables above rather than drawn as blank
          cells, because a blank cell reads as "Snyk found nothing here" when the truth is that
          nobody asked.</p>
        <ul style="margin:0;padding-left:18px;font-size:12px;line-height:1.6;color:${C.body}">
          ${missing.map((f) => `<li><b>${esc(f.key)}</b> \u2014 ${esc(f.note)}</li>`).join("")}</ul></div>` : `<p style="font-size:12px;color:${C.body}">Every modelled field was carried by this data source.</p>`;
  const d = meta.dropped;
  const prov = [
    ["Data source", esc(meta.sourceLabel)],
    ...meta.sourceDetail ? [["Source", `<span class="mono">${esc(meta.sourceDetail)}</span>`]] : [],
    ["Scope", esc(meta.scope)],
    ["Filters applied", esc(meta.filters || "none")],
    ["Rows read", fmt(meta.rowsRead)],
    [
      "Rows excluded",
      `${fmt(d.deleted)} deleted, ${fmt(d.unparseable)} unparseable, ${fmt(d.duplicate)} duplicate`
    ],
    ["Issues reported", fmt(data.total)],
    ["Ranking used", esc(data.rankingInputsUsed.join(", ") || "severity only")],
    [
      "Ranking could not use",
      esc(data.rankingInputsUnavailable.join(", ") || "nothing \u2014 all signals available")
    ],
    ["CVSS policy", "Snyk source preferred, v3.1 quoted, v4.0 carried separately"],
    ["Generated", esc(meta.generatedAt)]
  ];
  return page(
    ctx,
    "appendix",
    `<h2 class="sec">Appendix</h2>

     <h3 class="sub">A \xB7 Methodology</h3>
     <p style="margin:0 0 8px;font-size:12px;line-height:1.55;color:${C.body}">This report is
       generated from a Snyk data export, not from a scan run by this tool. Every figure is a
       count of what the export contained at the moment it was produced. No manual penetration
       testing, business-logic review or runtime exploitation was performed.</p>
     <p style="margin:0 0 8px;font-size:12px;line-height:1.55;color:${C.body}">Rows are
       de-duplicated only when the export carries a Snyk-assigned per-finding identifier
       (<span class="mono">ASSET_FINDING_ID</span> or <span class="mono">ISSUE_URL</span>). Without
       one, findings are counted as they appear and nothing is collapsed, because dropping a real
       finding from a security report is worse than listing one twice.</p>
     <p style="margin:0 0 8px;font-size:12px;line-height:1.55;color:${C.body}">The register is
       ordered by the risk score defined in section B, and the detail pages cover the highest-scoring
       ${fmt(data.topRisks.length)}. Any signal the export did not carry is excluded from that score
       entirely rather than scored as zero, so ranking degrades to severity-only instead of quietly
       treating unknown as benign.</p>

     <h3 class="sub">B \xB7 Glossary</h3>
     <table><thead><tr><th style="width:150px">Term</th><th>Definition</th></tr></thead>
       <tbody>${sevRows}${glossRows}</tbody></table>

     <h3 class="sub">C \xB7 Data coverage</h3>
     ${coverage}

     <h3 class="sub">D \xB7 Provenance</h3>
     ${card("How this report was produced", `<div class="card__b">${kv(prov)}</div>`)}

     <p style="margin:8mm 0 0;font-size:10.5px;line-height:1.6;color:${C.subtle};
       border-top:1px solid ${C.line};padding-top:12px">
       ${esc(ctx.classification)} \u2014 ${esc(ctx.holder)}. Generated by snyk-auto-report on
       ${esc(meta.generatedAt)} from ${esc(meta.sourceLabel)}.</p>`,
    "Appendix",
    "page--flow"
  );
}
var SEV_NOTE = {
  critical: "CVSS 9.0\u201310.0. Typically remote, unauthenticated and leading to full compromise of the service or its data.",
  high: "CVSS 7.0\u20138.9. Significant impact on confidentiality, integrity or availability, usually with a precondition.",
  medium: "CVSS 4.0\u20136.9. Limited impact, or meaningful exploitation barriers such as authentication or local access.",
  low: "CVSS 0.1\u20133.9. Minimal direct impact; hardening and defence-in-depth items."
};
function pageBoxCss(ctx) {
  const title = cssString(ctx.meta.title);
  const holder = cssString(ctx.holder);
  const mark = cssString(ctx.classification);
  const face = `font-family:${FONT_MONO};font-size:7.5pt;letter-spacing:.08em;color:${C.subtle}`;
  return `@page{
  margin:17mm 10mm 15mm;
  @top-left{content:${title};${face};vertical-align:bottom;padding-bottom:3mm}
  @top-right{content:${holder};${face};vertical-align:bottom;padding-bottom:3mm}
  @bottom-left{content:${mark};${face};vertical-align:top;padding-top:3mm}
  @bottom-right{content:"Page " counter(page);${face};vertical-align:top;padding-top:3mm}
}
/* The cover bleeds to the paper edge, so it has no margin for a box to sit
   in; blank them explicitly rather than relying on the zero margin. */
@page :first{
  margin:0;
  @top-left{content:""} @top-right{content:""}
  @bottom-left{content:""} @bottom-right{content:""}
}`;
}
function cssString(v) {
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, " ")}"`;
}
function page(ctx, id, bodyHtml, footRight, cls = "") {
  return `<section class="page ${cls}" data-page="${id}">
  ${runHead(ctx.meta.title, ctx.holder)}
  ${bodyHtml}
  ${runFoot(`${ctx.classification} \u2014 ${ctx.holder}`, footRight)}
</section>`;
}
var SCRIPT = String.raw`
(function () {
  var table = document.getElementById('reg');
  if (!table) return;
  var q = document.getElementById('reg-q');
  var reset = document.getElementById('reg-reset');
  var count = document.getElementById('reg-count');
  var product = document.getElementById('reg-product');
  var target = document.getElementById('reg-target');
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var chips = Array.prototype.slice.call(document.querySelectorAll('.btn[data-f]'));
  var sortKey = null, sortDir = -1;

  // One "off" set per chip group, so severity and status filter
  // independently. A single shared set would make de-selecting High also
  // silently affect the status toggles.
  var off = { sev: Object.create(null), status: Object.create(null) };

  function apply() {
    var term = (q && q.value || '').trim().toLowerCase();
    var wantProduct = product ? product.value : '';
    var wantTarget = target ? target.value : '';
    var shown = 0;

    rows.forEach(function (r) {
      var ok =
        !off.sev[r.getAttribute('data-sev')] &&
        !off.status[r.getAttribute('data-status')] &&
        (!wantProduct || r.getAttribute('data-product') === wantProduct) &&
        (!wantTarget || r.getAttribute('data-target') === wantTarget) &&
        (!term || (r.getAttribute('data-hay') || '').indexOf(term) !== -1);
      r.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });

    if (count) {
      count.textContent =
        shown === rows.length
          ? 'Showing all ' + rows.length + ' listed issues.'
          : 'Showing ' + shown + ' of ' + rows.length + ' listed issues.';
    }
  }

  function sortBy(key) {
    if (!key) return;
    if (sortKey === key) sortDir = -sortDir; else { sortKey = key; sortDir = -1; }
    var num = rows.every(function (r) {
      var v = r.getAttribute('data-s-' + key);
      return v !== null && v !== '' && !isNaN(Number(v));
    });
    rows.sort(function (a, b) {
      var x = a.getAttribute('data-s-' + key) || '', y = b.getAttribute('data-s-' + key) || '';
      if (num) { x = Number(x); y = Number(y); }
      return x < y ? sortDir : x > y ? -sortDir : 0;
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th) {
      var a = th.querySelector('.arrow');
      if (a) a.textContent = th.getAttribute('data-key') === key ? (sortDir === -1 ? ' \u2193' : ' \u2191') : '';
    });
  }

  Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th) {
    th.addEventListener('click', function () { sortBy(th.getAttribute('data-key')); });
  });

  chips.forEach(function (b) {
    b.addEventListener('click', function () {
      var group = b.getAttribute('data-f');
      var value = b.getAttribute('data-v');
      off[group][value] = !off[group][value];
      b.setAttribute('aria-pressed', off[group][value] ? 'false' : 'true');
      apply();
    });
  });

  if (q) q.addEventListener('input', apply);
  if (product) product.addEventListener('change', apply);
  if (target) target.addEventListener('change', apply);

  if (reset) reset.addEventListener('click', function () {
    if (q) q.value = '';
    if (product) product.value = '';
    if (target) target.value = '';
    off = { sev: Object.create(null), status: Object.create(null) };
    chips.forEach(function (b) { b.setAttribute('aria-pressed', 'true'); });
    apply();
  });

  apply();
})();
`;
function renderHtml(data, availability, meta) {
  const refIndex = /* @__PURE__ */ new Map();
  data.detailIssues.forEach((i, n) => {
    if (!refIndex.has(i.issueKey)) refIndex.set(i.issueKey, n);
  });
  const cvss4 = data.issues.some((i) => {
    const v = read(i, "exploitVocab");
    return v.state === "present" && (v.value === "cvss4" || v.value === "merged");
  });
  const ctx = {
    data,
    a: availability,
    meta,
    holder: meta.preparedFor?.trim() || data.byOrg[0]?.label || meta.orgLabel?.trim() || "this organisation",
    classification: meta.classification?.trim() || "Confidential",
    has: (k) => stateOf(availability, k) !== "absent",
    cvss4,
    refIndex,
    scannersRequested: meta.scannersRequested ?? []
  };
  const details = data.topRisks.length ? page(
    ctx,
    "finding-details",
    `<h2 class="sec">Vulnerability Details</h2>
         <p class="lede">One entry per finding, worst-first. Entries are kept whole: a finding
           is never split across a page break, so short ones share a page.</p>
         ${data.topRisks.map((i, n) => findingPage(ctx, i, n)).join("\n")}`,
    "Vulnerability details",
    "page--flow"
  ) : "";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(meta.title)} \u2014 Snyk Vulnerability Report</title>
<style>${CSS}</style>
<style>${pageBoxCss(ctx)}</style></head>
<body><div class="report">
${coverPage(ctx)}
${detailsPage(ctx)}
${tocPage(ctx)}
${execPage(ctx)}
${statsPage(ctx)}
${registerPage(ctx)}
${details}
${appendixPage(ctx)}
</div>
<script>${SCRIPT}</script>
</body></html>`;
}

// snyk_report/lib/render/pdf.mts
import { spawn } from "node:child_process";
import { access, constants, stat as stat2, unlink } from "node:fs/promises";
import { pathToFileURL } from "node:url";
var CANDIDATES = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/microsoft-edge",
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
];
async function findChrome() {
  const fromEnv = process.env["CHROME_PATH"];
  if (fromEnv) {
    try {
      await access(fromEnv, constants.X_OK);
      return fromEnv;
    } catch {
    }
  }
  for (const p of CANDIDATES) {
    try {
      await access(p, constants.X_OK);
      return p;
    } catch {
    }
  }
  return null;
}
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
async function sizeOf(path) {
  try {
    return (await stat2(path)).size;
  } catch {
    return 0;
  }
}
async function exportPdf(htmlPath, pdfPath, opts = {}) {
  const chrome = await findChrome();
  if (!chrome) {
    return {
      ok: false,
      reason: "No Chrome, Chromium or Edge found. The HTML is written and its print stylesheet is tuned for A4 -- open it and use Print > Save as PDF, or set CHROME_PATH."
    };
  }
  await unlink(pdfPath).catch(() => {
  });
  const timeout = opts.timeoutMs ?? 3e5;
  const child = spawn(
    chrome,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-sandbox",
      "--no-first-run",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-dev-shm-usage",
      "--run-all-compositor-stages-before-draw",
      "--no-pdf-header-footer",
      "--virtual-time-budget=20000",
      `--print-to-pdf=${pdfPath}`,
      pathToFileURL(htmlPath).href
    ],
    { stdio: ["ignore", "ignore", "pipe"] }
  );
  let stderr2 = "";
  child.stderr?.on("data", (d) => {
    if (stderr2.length < 4e3) stderr2 += d.toString();
  });
  let exited = false;
  child.on("exit", () => {
    exited = true;
  });
  const deadline = Date.now() + timeout;
  let lastSize = -1;
  let stable = 0;
  while (Date.now() < deadline && !exited) {
    const size = await sizeOf(pdfPath);
    stable = size > 0 && size === lastSize ? stable + 1 : 0;
    lastSize = size;
    if (stable >= 2) break;
    await sleep2(500);
  }
  if (!exited) {
    child.kill("SIGTERM");
    await Promise.race([new Promise((r) => child.once("exit", r)), sleep2(1e4)]);
    if (!exited) child.kill("SIGKILL");
  }
  if (await sizeOf(pdfPath) > 0) return { ok: true };
  return { ok: false, reason: stderr2.trim().slice(0, 400) || "Chrome produced no PDF" };
}

// snyk_report/snyk-auto-report.mts
var HELP = `
snyk-auto-report -- complete HTML / PDF / CSV vulnerability reports from Snyk data

  --csv <file>          a Snyk CSV export (Reports tab download or Export API result)
  --out <basename>      output basename (default: snyk-report)
  --format <list>       html,pdf,csv,json          (default: html)
  --title <text>        report title
  --subtitle <text>     cover strapline (default: derived from the scanners present)
  --prepared-for <text> customer name on the cover and in every running header
  --prepared-by <text>  author line on the cover (default: snyk-auto-report)
  --report-id <text>    document reference for the cover (omitted when not given)
  --classification <t>  document marking (default: Confidential)
  --logo <file>         image for the cover lockup, inlined as a data URI
                        (the design system's own wordmark PNG is corrupt, so
                        the cover falls back to a text mark without this)
  --period <text>       period covered, for the cover
  --include-deleted     keep issues Snyk has marked deleted (default: excluded,
                        which is what the Snyk Reports UI does)
  --status <list>       open,resolved,ignored or all. Asked for interactively.
                        Including "resolved" prints already-fixed findings and
                        marks them Fixed, for a "found and since remediated"
                        report.
  --top <n|all>         issues given a full detail page, worst-first (default: 25).
                        "all" writes one page per finding; on a large org that is
                        thousands of PDF pages, so prefer HTML for that.
  --max-detail-rows <n> cap the findings register. CSV and JSON stay complete.
                        A 9,000-issue org renders a ~340-page register uncapped.
  -h, --help

Pull straight from the Snyk API instead of a file:
  --from-api            use the Export API. With no other flags this walks you
                        through region, group, org, target, period and severity.
  --region <r>          us | us02 | eu | au | gov, or a full https:// URL
  --org <uuid|name>     organisation scope, by UUID or name. Validated against
                        Snyk; an unknown value is an error, not an empty report.
  --group <uuid>        group scope (skips the picker)
  --target <list>       target names, comma separated. Each is checked against
                        the organisation; any miss fails the run.
  --project <list>      project names, filtered after download
  --since <p>           7d | 14d | 30d | 90d | all   (the API requires a period)
  --severity <list>     critical,high,medium,low or all
  --product <list>      sca,sast,container,iac,secrets or all
                        (which scanners to include; asked for interactively)
  --export-id <id>      re-attach to an export already running or finished.
                        Results live for 3 days; use this after a timeout
                        rather than spending another of your 20 exports/hour.
  --export-timeout <m>  minutes to wait for the job (default: 30)

Or run a fresh Snyk Code scan directly and report on just that (also Tests
v2 API; useful to target one repo without an Export API run first):
  --from-tests-api      run a new scan instead of reading an existing result
  --org <uuid|name>     organisation to scan in, by UUID or name (required; no group scope)
  --repo-url <url>      e.g. https://github.com/your-org/your-repo
  --integration-id <id> SCM integration id: GET /v1/org/{org_id}/integrations
  --ref <name>          branch to scan
  --commit <sha>        commit SHA to scan (preferred -- the resolved SHA for
                        a --ref-only scan is not surfaced back afterwards)
  --file-patterns <list> restrict the scan to matching paths
  --job-id <id>         resume polling an existing test_jobs id
  --test-id <id>        skip scanning; report on a tests id you already have
  --scan-timeout <m>    minutes to wait for the scan (default: 10)

  The token comes from SNYK_TOKEN, or a hidden prompt. It is never written to
  disk and never sent anywhere but your chosen Snyk region.
`;
function fail(msg) {
  log.error(msg);
  process.exit(1);
}
async function main() {
  const { values } = parseArgs({
    options: {
      csv: { type: "string" },
      "from-api": { type: "boolean", default: false },
      region: { type: "string" },
      org: { type: "string" },
      group: { type: "string" },
      target: { type: "string" },
      project: { type: "string" },
      since: { type: "string" },
      severity: { type: "string" },
      product: { type: "string" },
      "export-id": { type: "string" },
      "export-timeout": { type: "string", default: "30" },
      "from-tests-api": { type: "boolean", default: false },
      "repo-url": { type: "string" },
      "integration-id": { type: "string" },
      ref: { type: "string" },
      commit: { type: "string" },
      "file-patterns": { type: "string" },
      "job-id": { type: "string" },
      "test-id": { type: "string" },
      "scan-timeout": { type: "string", default: "10" },
      "no-dataflow": { type: "boolean", default: false },
      // No parseArgs defaults for options that gate an interactive question.
      // A default is indistinguishable from the user having typed the value,
      // so the guard `!values.x` is never true and the prompt is dead code.
      // This bit --format and then --top; the fallbacks live at the point of
      // use instead, where they only affect the non-interactive path.
      out: { type: "string" },
      // No parseArgs default. A default here is indistinguishable from the
      // user having passed --format, so `!values.format` was never true and
      // the interactive format question could never fire. The html fallback
      // is applied further down instead, where it only affects the
      // non-interactive path.
      format: { type: "string" },
      title: { type: "string" },
      subtitle: { type: "string" },
      "prepared-for": { type: "string" },
      "prepared-by": { type: "string" },
      "report-id": { type: "string" },
      classification: { type: "string" },
      period: { type: "string" },
      logo: { type: "string" },
      "include-deleted": { type: "boolean", default: false },
      status: { type: "string" },
      "max-detail-rows": { type: "string" },
      top: { type: "string" },
      help: { type: "boolean", short: "h", default: false }
    },
    allowPositionals: false
  });
  if (values.help) {
    process.stderr.write(`${HELP}
`);
    return 0;
  }
  const useTestsApi = values["from-tests-api"];
  const apiFlags = ["region", "org", "group", "since", "export-id", "target"];
  let useApi = !useTestsApi && (values["from-api"] || apiFlags.some((f) => values[f] !== void 0));
  if (useTestsApi && (useApi || values.csv)) {
    fail("pass --from-tests-api on its own, not together with --csv or --from-api.");
  }
  if (useApi && values.csv) fail("pass either --csv or --from-api, not both.");
  if (useTestsApi && !values["test-id"] && !values["job-id"] && !(values["repo-url"] && values["integration-id"])) {
    fail("--from-tests-api needs --test-id, or --job-id, or --repo-url plus --integration-id.");
  }
  if (useTestsApi && !values["test-id"] && !values["job-id"] && !values.ref && !values.commit) {
    fail("--from-tests-api with --repo-url needs --ref and/or --commit.");
  }
  if (useTestsApi && !values.org) {
    fail("--from-tests-api needs --org <org_id> (the Tests API has no group scope).");
  }
  let csvPathFromPrompt;
  if (!useApi && !useTestsApi && !values.csv) {
    if (!isInteractive()) {
      fail("nothing to report on. Pass --csv <file>, --from-api or --from-tests-api, or --help for usage.");
    }
    const source = await selectSource();
    if (source === "api") useApi = true;
    else csvPathFromPrompt = await askCsvPath();
  }
  try {
    await selectSeverities(values.severity ?? "all");
    await selectSince(values.since ?? "all");
    parseProducts(values.product ?? "all");
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  let sourceLabel;
  let sourceDetail;
  let outcome;
  let scopeLabel = null;
  let periodLabel = "all time";
  let regionLabel = null;
  let severities = [...SEVERITIES];
  let apiClient = null;
  let projectFilter;
  let formatSpec = values.format;
  if (useApi) {
    const conn = await connect({ region: values.region, token: process.env["SNYK_TOKEN"] });
    regionLabel = conn.regionLabel;
    apiClient = conn.client;
    const selection = await selectScope(conn, {
      group: values.group,
      org: values.org,
      target: values.target,
      project: values.project
    });
    scopeLabel = selection.scope.label;
    projectFilter = selection.projectNames;
    const since = await selectSince(values.since);
    periodLabel = describeSince(since);
    const filters = {
      ...sinceToFilters(since),
      ...selection.orgIds ? { orgs: selection.orgIds } : {},
      ...selection.targetNames ? { targetDisplayNames: selection.targetNames } : {}
    };
    outcome = await runExport(
      conn.client,
      selection.scope,
      filters,
      values["export-id"],
      Number(values["export-timeout"]) || 30,
      values["include-deleted"]
    );
    sourceLabel = "Snyk Export API";
    sourceDetail = `${selection.scope.label} - ${conn.regionLabel}`;
  } else if (useTestsApi) {
    const conn = await connect({ region: values.region, token: process.env["SNYK_TOKEN"] });
    regionLabel = conn.regionLabel;
    const org = await resolveOrg(conn.client, values.org);
    const orgId = org.id;
    scopeLabel = `Organisation ${org.name}`;
    periodLabel = "point-in-time scan";
    outcome = await runTestsApiScan(conn.client, orgId, {
      repoUrl: values["repo-url"],
      integrationId: values["integration-id"],
      ref: values.ref,
      commit: values.commit,
      filePatterns: values["file-patterns"],
      jobId: values["job-id"],
      testId: values["test-id"],
      scanTimeoutMs: (Number(values["scan-timeout"]) || 10) * 6e4
    });
    sourceLabel = "Snyk Code Tests API (source\u2192sink dataflow)";
    sourceDetail = `${scopeLabel} - ${conn.regionLabel}`;
  } else {
    const csvPath = csvPathFromPrompt ?? resolve2(values.csv);
    log.step(`Reading ${csvPath}`);
    outcome = await ingestCsvFile(csvPath, {
      source: "csv",
      includeDeleted: values["include-deleted"]
    });
    sourceLabel = "Snyk CSV export";
    sourceDetail = csvPath;
  }
  const { issues, summary } = outcome;
  const d = summary.dropped;
  log.info(
    `${summary.rowsRead.toLocaleString()} rows read, ${issues.length.toLocaleString()} issues kept`
  );
  if (d.deleted) log.dim(`${d.deleted.toLocaleString()} deleted (use --include-deleted to keep)`);
  if (d.duplicate) log.dim(`${d.duplicate.toLocaleString()} duplicate rows collapsed`);
  if (d.unparseable) {
    log.warn(`${d.unparseable.toLocaleString()} rows could not be parsed`);
    for (const p of summary.problems.slice(0, 3)) log.dim(p);
  }
  if (summary.unknownColumns.length) {
    log.dim(`unrecognised columns kept but unused: ${summary.unknownColumns.join(", ")}`);
  }
  if (summary.keyStrength === "weak") {
    log.dim(
      "no ASSET_FINDING_ID or ISSUE_URL column, so findings have no Snyk-assigned id; nothing was de-duplicated"
    );
    if (summary.weakKeyCollisions) {
      log.dim(
        `${summary.weakKeyCollisions.toLocaleString()} rows share a synthesised key and were all kept (they may or may not be true duplicates)`
      );
    }
  }
  const productTotals = /* @__PURE__ */ new Map();
  for (const i of issues) productTotals.set(i.product, (productTotals.get(i.product) ?? 0) + 1);
  const wantProducts = await selectProducts(
    values.product,
    [...productTotals].map(([product, total]) => ({ product, total })).sort((a, b) => b.total - a.total)
  );
  let kept = issues;
  if (wantProducts.length && wantProducts.length < productTotals.size) {
    const want = new Set(wantProducts);
    const before = kept.length;
    kept = kept.filter((i) => want.has(i.product));
    log.dim(`scanners ${wantProducts.join(",")} kept ${fmt2(kept.length)} of ${fmt2(before)}`);
  }
  severities = await selectSeverities(values.severity, countBySeverity(kept));
  const statusCounts = { open: 0, resolved: 0, ignored: 0 };
  for (const i of kept) statusCounts[i.status]++;
  let wantStatuses;
  try {
    wantStatuses = await selectStatuses(values.status, statusCounts);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  if (wantStatuses.length < 3) {
    const want = new Set(wantStatuses);
    const before = kept.length;
    kept = kept.filter((i) => want.has(i.status));
    if (kept.length !== before) {
      log.dim(`status ${wantStatuses.join(",")} kept ${fmt2(kept.length)} of ${fmt2(before)}`);
    }
  }
  if (severities.length < SEVERITIES.length) {
    const wanted = new Set(severities);
    const before = kept.length;
    kept = kept.filter((i) => wanted.has(i.severity));
    log.dim(`severity ${severities.join(",")} kept ${kept.length} of ${before}`);
  }
  if (projectFilter?.length) {
    const wanted = new Set(projectFilter.map((p2) => p2.toLowerCase()));
    const before = kept.length;
    kept = kept.filter((i) => {
      const name = i.project?.name ?? i.project?.targetDisplayName ?? "";
      return wanted.has(name.toLowerCase());
    });
    log.dim(`project filter kept ${kept.length} of ${before}`);
    if (kept.length === 0) {
      log.warn("no issue matched those project names; check the spelling against the report");
    }
  }
  if (kept.length === 0) {
    if (issues.length === 0) {
      if (!summary.noFindings && summary.rowsRead === 0 && summary.header.columns.length === 0) {
        fail("the data source was empty -- no header, no rows. Nothing was scanned.");
      }
      log.info(c.green("no vulnerabilities in the supplied data \u2014 writing a clean report"));
    } else {
      log.warn(
        `no issue matches those filters (${fmt2(issues.length)} were read). Writing a nil-return report that records the filters and states the result.`
      );
    }
  }
  if (!values.format && isInteractive()) {
    formatSpec = (await selectFormats(void 0)).join(",");
  }
  const formats = new Set(
    (formatSpec ?? "html").split(",").map((f) => f.trim().toLowerCase()).filter(Boolean)
  );
  for (const f of formats) {
    if (!["html", "pdf", "csv", "json"].includes(f)) fail(`unknown --format value: ${f}`);
  }
  const wantHtml = formats.has("html");
  if (formats.has("pdf")) formats.add("html");
  const maxDetail = values["max-detail-rows"] ? Number(values["max-detail-rows"]) : void 0;
  if (maxDetail !== void 0 && !Number.isFinite(maxDetail)) {
    fail("--max-detail-rows must be a number");
  }
  let topN;
  try {
    topN = await selectDetailDepth(values.top, kept.length, formats.has("pdf"));
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  const data = buildReport(kept, summary.availability, {
    topN,
    ...maxDetail === void 0 ? {} : { maxDetailRows: maxDetail }
  });
  if (formats.has("pdf") && data.topRisks.length > 250) {
    log.warn(
      `${fmt2(data.topRisks.length)} detail pages requested. That is roughly ${fmt2(data.topRisks.length)} PDF pages and can take many minutes to render. Lower --top, or drop pdf from --format and use the scrollable HTML.`
    );
  }
  if (formats.has("pdf")) {
    const pages = 5 + Math.ceil(data.detailIssues.length / 15) + data.topRisks.length + 1;
    if (pages > 250) {
      log.warn(
        `${data.total.toLocaleString()} issues will render roughly ${pages.toLocaleString()} A4 pages. Use --max-detail-rows to cap the register and --top to cap the detail pages; CSV and JSON stay complete.`
      );
    }
  }
  if (data.cisaKevCount) {
    log.info(c.red(`${data.cisaKevCount} issue(s) in CISA's Known Exploited Vulnerabilities catalogue`));
  }
  if (data.total > 0 && data.rankingInputsUnavailable.length) {
    log.warn(
      `ranking could not use: ${data.rankingInputsUnavailable.join(", ")} (not carried by this data source)`
    );
  }
  let logo = null;
  if (values.logo) {
    const p = resolve2(values.logo);
    const ext = p.slice(p.lastIndexOf(".") + 1).toLowerCase();
    const mime = ext === "svg" ? "image/svg+xml" : ext === "jpg" || ext === "jpeg" ? "image/jpeg" : `image/${ext}`;
    try {
      logo = `data:${mime};base64,${(await readFile(p)).toString("base64")}`;
    } catch {
      fail(`could not read --logo ${p}`);
    }
  }
  const meta = {
    title: values.title ?? "Snyk vulnerability report",
    preparedFor: values["prepared-for"] ?? null,
    generatedAt: (/* @__PURE__ */ new Date()).toLocaleString(void 0, { dateStyle: "long", timeStyle: "short" }),
    sourceLabel,
    sourceDetail,
    scope: scopeLabel ?? describeScope(issues),
    // From the examined set, not the filtered one, so a nil return still
    // names the organisation it examined.
    orgLabel: [...new Set(issues.map((i) => i.org.name ?? i.org.id))].join(", ") || void 0,
    scannersRequested: wantProducts,
    sourceHadFindings: issues.length > 0,
    filters: [
      `period: ${periodLabel}`,
      `severity: ${severities.length === 4 ? "all" : severities.join(", ")}`,
      `scanners: ${wantProducts.length === new Set(issues.map((i) => i.product)).size ? "all" : wantProducts.join(", ")}`,
      values["include-deleted"] ? "including deleted issues" : "excluding deleted issues",
      `status: ${wantStatuses.length === 3 ? "all" : wantStatuses.join(", ")}`,
      ...projectFilter ? [`projects: ${projectFilter.join(", ")}`] : []
    ].join("; "),
    ...regionLabel ? { region: regionLabel } : {},
    rowsRead: summary.rowsRead,
    dropped: summary.dropped,
    // Absent keys rather than nulls: the renderer omits the cover's report-id
    // line entirely when none was given, instead of printing an empty label.
    ...values.subtitle === void 0 ? {} : { subtitle: values.subtitle },
    ...values["prepared-by"] === void 0 ? {} : { preparedBy: values["prepared-by"] },
    ...values["report-id"] === void 0 ? {} : { reportId: values["report-id"] },
    ...values.classification === void 0 ? {} : { classification: values.classification },
    ...values.period === void 0 ? {} : { period: values.period },
    ...logo === null ? {} : { logo }
  };
  const chosenOut = values.out ?? (isInteractive() ? await askOutputPath("snyk-report") : "snyk-report");
  const base = resolve2(chosenOut);
  await mkdir(dirname(base), { recursive: true });
  const written = [];
  if (formats.has("html")) {
    const html = renderHtml(data, summary.availability, meta);
    await writeFile(`${base}.html`, html, "utf8");
    if (wantHtml) written.push(`${base}.html`);
  }
  if (formats.has("csv")) {
    await writeFile(`${base}.csv`, toCsvReport(kept), "utf8");
    written.push(`${base}.csv`);
  }
  if (formats.has("json")) {
    await writeFile(`${base}.json`, `${JSON.stringify({ meta, issues: kept }, null, 2)}
`, "utf8");
    written.push(`${base}.json`);
  }
  if (formats.has("pdf")) {
    log.step("Rendering PDF");
    const r = await exportPdf(`${base}.html`, `${base}.pdf`);
    if (r.ok) written.push(`${base}.pdf`);
    else log.warn(r.reason ?? "PDF export failed");
    if (!wantHtml) {
      if (r.ok) {
        await rm(`${base}.html`, { force: true });
      } else {
        log.info(`HTML kept at ${base}.html \u2014 open it and print to PDF`);
        written.push(`${base}.html`);
      }
    }
  }
  log.blank();
  const counts = SEVERITIES.filter((s) => data.bySeverity[s]).map((s) => `${data.bySeverity[s]} ${s}`).join(", ");
  log.info(
    data.total === 0 ? issues.length === 0 ? `${c.bold("0")} issues \u2014 clean report written` : `${c.bold("0")} issues \u2014 nothing matched the filters (nil-return report written)` : `${c.bold(fmt2(data.total))} issues \u2014 ${counts}`
  );
  for (const f of written) log.info(c.green(f));
  return 0;
}
async function runExport(client, scope, filters, existingId, timeoutMinutes, includeDeleted) {
  let job = existingId ? { exportId: existingId, scope } : void 0;
  if (job) {
    log.step(`Re-attaching to export ${job.exportId}`);
  } else {
    log.step(`Requesting an export of ${scope.label}`);
    job = await startExport(client, scope, filters);
    log.info(`export id ${c.bold(job.exportId)} ${c.dim("(--export-id to re-attach)")}`);
  }
  const result = existingId ? await fetchExportResult(client, job) : await waitForExport(client, job, { timeoutMs: timeoutMinutes * 6e4 });
  log.step(`Downloading ${result.urls.length} file(s)`);
  return downloadExport(client, job, result, { includeDeleted });
}
async function runTestsApiScan(client, orgId, opts) {
  let testId = opts.testId;
  if (!testId) {
    let jobId = opts.jobId;
    if (!jobId) {
      const resource = {
        repoUrl: opts.repoUrl,
        integrationId: opts.integrationId,
        ...opts.ref ? { ref: opts.ref } : {},
        ...opts.commit ? { commit: opts.commit } : {},
        ...opts.filePatterns ? { filePatterns: opts.filePatterns.split(",").map((p) => p.trim()).filter(Boolean) } : {}
      };
      log.step(`Starting a Snyk Code scan of ${resource.repoUrl} (${opts.ref ?? opts.commit})`);
      jobId = await startCodeTest(client, orgId, resource);
      log.info(`test_job id ${c.bold(jobId)} ${c.dim("(--job-id to resume)")}`);
    }
    log.step("Waiting for the scan to finish");
    testId = await waitForCodeTest(client, orgId, jobId, { timeoutMs: opts.scanTimeoutMs });
  }
  log.info(`test id ${c.bold(testId)} ${c.dim("(--test-id to re-report without rescanning)")}`);
  log.step("Fetching findings");
  const components = await fetchTestComponents(client, orgId, testId);
  return ingestTestsApiFindings(client, orgId, testId, components, {
    org: { id: orgId },
    commit: opts.commit ?? null
  });
}
function fmt2(n) {
  return n.toLocaleString();
}
function describeScope(issues) {
  const orgs = new Set(issues.map((i) => i.org.name ?? i.org.id));
  if (orgs.size === 1) return `Organisation: ${[...orgs][0]}`;
  return `${orgs.size} organisations`;
}
function toCsvReport(issues) {
  const head = [
    "SEVERITY",
    "PROBLEM_ID",
    "TITLE",
    "PRODUCT",
    "STATUS",
    "ORG",
    "PROJECT",
    "PACKAGE_OR_FILE",
    "CVSS",
    "EPSS",
    "EXPLOIT_MATURITY",
    "FIXED_IN",
    "ISSUE_URL",
    "DATAFLOW"
  ];
  const v = (i, k) => {
    const r = read(i, k);
    if (r.state === "unsupported") return "n/a";
    if (r.state === "empty") return "";
    return typeof r.value === "object" ? JSON.stringify(r.value) : String(r.value);
  };
  const flowOf = (i) => {
    const r = read(i, "dataflow");
    if (r.state === "unsupported") return "n/a";
    if (r.state === "empty") return "";
    return r.value.map((s) => `${s.file}:${s.fromLine ?? "?"}`).join(" -> ");
  };
  const lines = [toCsvLine(head)];
  for (const i of issues) {
    const cvss = read(i, "cvss");
    const epss = read(i, "epssScore");
    lines.push(
      toCsvLine([
        i.severity,
        i.problemId,
        i.title,
        i.product,
        i.status,
        i.org.name ?? i.org.id,
        i.project?.name ?? ("project" in i ? "" : "n/a"),
        v(i, "packageNameAndVersion") || v(i, "filePath"),
        cvss.state === "present" ? cvss.value.score : cvss.state === "unsupported" ? "n/a" : "",
        epss.state === "present" ? epss.value : epss.state === "unsupported" ? "n/a" : "",
        v(i, "exploitMaturity"),
        v(i, "fixedInVersion"),
        v(i, "issueUrl"),
        flowOf(i)
      ])
    );
  }
  return `${lines.join("\n")}
`;
}
try {
  const code = await main();
  closePrompts();
  process.exit(code);
} catch (err) {
  closePrompts();
  if (err instanceof InputClosedError || err?.message === "cancelled") {
    log.info("cancelled");
    process.exit(130);
  }
  log.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
