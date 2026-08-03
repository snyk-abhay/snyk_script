#!/usr/bin/env node
/**
 * snyk-bulk-import
 *
 * A small, dependency-free CLI that bulk-imports repos into a Snyk org from
 * GitHub, GitHub Enterprise, GitLab.com or a privately hosted GitLab — then
 * writes the onboarding status of every repo back into the input file.
 *
 * Flow:
 *   1. Pick the Snyk region
 *   2. Pick the SCM (GitHub / GitLab) and, if self-hosted, its base URL
 *   3. Collect both API keys (Snyk + SCM)
 *   4. Verify the Snyk key
 *   5. Verify the SCM key
 *   6. Pick the Snyk org
 *   7. Pick the SCM integration in Snyk
 *   8. Choose the repos: whole group/org, typed names, or a CSV/TXT file
 *   9. Compare against what is already onboarded in Snyk
 *  10. Check each repo on the SCM (for GitLab this resolves the project id)
 *  11. Kick off the imports
 *  12. Wait for the import jobs to finish
 *  13. Write status back into the file + print a summary
 *
 * Run:
 *   node tools/snyk-bulk-import.mts --file repos.csv
 *   npx tsx tools/snyk-bulk-import.mts --file repos.csv     (Node < 22.18)
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { stdin, stdout } from 'node:process';

// ---------------------------------------------------------------------------
// Types & constants
// ---------------------------------------------------------------------------

interface Region {
  key: string;
  label: string;
  url: string;
}

/** One row of the input file. Non-repo rows are preserved so we can rewrite. */
interface FileRow {
  raw: string;
  kind: 'repo' | 'passthrough' | 'invalid';
  owner?: string;
  name?: string;
  branch?: string;
  /** Status read from the file on a previous run, if any. */
  previousStatus?: string;
  /** Result of this run. */
  result?: RowResult;
  reason?: string;
  /** Repo already came from the SCM API, so it needs no extra check. */
  verified?: boolean;
  /** GitLab only — the numeric project id the import API needs. */
  projectId?: number;
}

interface RowResult {
  status: Status;
  projects: number;
  message: string;
  pollingUrl?: string;
  at: string;
}

type Status =
  | 'IMPORTED'
  | 'PARTIAL'
  | 'FAILED'
  | 'NOT_FOUND'
  | 'SKIPPED'
  | 'QUEUED';

interface SnykOrg {
  id: string;
  name: string;
  slug?: string;
  group?: { id: string; name: string } | null;
}

interface ImportedProject {
  projectUrl?: string;
  success: boolean;
  targetFile?: string;
  projectId?: string;
  userMessage?: string;
}

interface PollResponse {
  id: string;
  status: string;
  logs: { name: string; status: string; projects: ImportedProject[] }[];
}

interface ApiResponse<T> {
  status: number;
  headers: Record<string, string>;
  data: T;
  requestId?: string;
}

const REGIONS: Region[] = [
  { key: 'us', label: 'SNYK-US-01 (default)', url: 'https://api.snyk.io' },
  { key: 'us02', label: 'SNYK-US-02', url: 'https://api.us.snyk.io' },
  { key: 'eu', label: 'SNYK-EU-01', url: 'https://api.eu.snyk.io' },
  { key: 'au', label: 'SNYK-AU-01', url: 'https://api.au.snyk.io' },
];

/** The Snyk web app URL for an API base URL — used to point at the token page. */
export function appUrlFor(apiBaseUrl: string): string {
  return apiBaseUrl.replace('//api.', '//app.');
}

/** The GitHub token page for an API base URL (handles GHE at /api/v3). */
export function githubTokenPage(apiUrl: string): string {
  if (/api\.github\.com/.test(apiUrl)) return 'https://github.com/settings/tokens';
  return `${apiUrl.replace(/\/api\/v3\/?$/, '')}/settings/tokens`;
}

/** Accept a GitLab host with or without a trailing slash or /api/v4 suffix. */
export function normaliseGitlabUrl(input: string): string {
  let url = input.trim().replace(/\/+$/, '');
  url = url.replace(/\/api\/v4$/, '');
  if (!/^https?:\/\//.test(url)) url = `https://${url}`;
  return url;
}

/** GitLab REST API base for a host URL. */
export function gitlabApiUrl(hostUrl: string): string {
  return `${normaliseGitlabUrl(hostUrl)}/api/v4`;
}

/** The GitLab personal access token page for a host URL. */
export function gitlabTokenPage(hostUrl: string): string {
  return `${normaliseGitlabUrl(hostUrl)}/-/user_settings/personal_access_tokens`;
}

/** Integration names in Snyk, per SCM. */
const GITHUB_INTEGRATIONS = ['github', 'github-enterprise', 'github-cloud-app'];
const GITLAB_INTEGRATIONS = ['gitlab'];

/** Columns this tool owns in a CSV file. */
const STATUS_COLUMNS = ['status', 'projects', 'imported_at', 'details'];

/** Version of the Snyk REST API used to list existing targets. */
const REST_VERSION = '2024-10-15';

const POLL_INTERVAL_MS = Number(process.env.SNYK_BULK_IMPORT_POLL_MS) || 15_000;
const POLL_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

type ScmKind = 'github' | 'gitlab';

interface Options {
  file?: string;
  /** Which SCM the repos live in. */
  scm?: ScmKind;
  /** Base URL of a self-hosted GitLab, e.g. https://gitlab.mycorp.com */
  gitlabUrl?: string;
  /** GitHub org / GitLab group to discover repos from. */
  githubOrg?: string;
  /** Comma-separated repo list given on the command line. */
  repos?: string;
  /** Where to write the status CSV when repos did not come from a file. */
  outputFile?: string;
  org?: string;
  integration?: string;
  region?: string;
  githubUrl: string;
  concurrency: number;
  out: string;
  dryRun: boolean;
  poll: boolean;
  force: boolean;
  /** Import every repo, including the ones already onboarded in Snyk. */
  all: boolean;
  includeArchived: boolean;
  skipScmCheck: boolean;
  yes: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Options {
  const opts: Options = {
    githubUrl: process.env.GITHUB_API_URL?.trim() || 'https://api.github.com',
    concurrency: 5,
    out: 'snyk-import-results',
    dryRun: false,
    poll: true,
    force: false,
    all: false,
    includeArchived: false,
    skipScmCheck: false,
    yes: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;

    const eq = arg.indexOf('=');
    const flag = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
    const inline = eq === -1 ? undefined : arg.slice(eq + 1);
    const value = (): string => {
      if (inline !== undefined) return inline;
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) {
        fail(`Flag --${flag} expects a value`);
      }
      return v;
    };

    switch (flag) {
      case 'file':
        opts.file = value();
        break;
      case 'scm': {
        const v = value().toLowerCase();
        if (v !== 'github' && v !== 'gitlab') {
          fail('--scm must be either "github" or "gitlab"');
        }
        opts.scm = v;
        break;
      }
      case 'gitlab-url':
        opts.gitlabUrl = normaliseGitlabUrl(value());
        opts.scm ??= 'gitlab';
        break;
      case 'github-org':
      case 'gitlab-group':
      case 'group':
        opts.githubOrg = value();
        break;
      case 'repos':
        opts.repos = value();
        break;
      case 'output-file':
        opts.outputFile = value();
        break;
      case 'org':
        opts.org = value();
        break;
      case 'integration':
        opts.integration = value();
        break;
      case 'region':
        opts.region = value();
        break;
      case 'github-url':
        opts.githubUrl = value().replace(/\/+$/, '');
        break;
      case 'out':
        opts.out = value();
        break;
      case 'concurrency':
        opts.concurrency = Number(value());
        if (!Number.isFinite(opts.concurrency) || opts.concurrency < 1) {
          fail('--concurrency must be a positive number');
        }
        break;
      case 'dry-run':
        opts.dryRun = true;
        break;
      case 'no-poll':
        opts.poll = false;
        break;
      case 'force':
        opts.force = true;
        break;
      case 'all':
        opts.all = true;
        break;
      case 'include-archived':
        opts.includeArchived = true;
        break;
      case 'skip-github-check':
      case 'skip-scm-check':
        opts.skipScmCheck = true;
        break;
      case 'yes':
      case 'y':
        opts.yes = true;
        break;
      case 'help':
      case 'h':
        opts.help = true;
        break;
      default:
        fail(`Unknown flag: --${flag}. Run with --help to see all options.`);
    }
  }

  return opts;
}

const HELP = `
snyk-bulk-import — bulk import GitHub / GitLab repos into a Snyk org and record the status

Usage:
  node tools/snyk-bulk-import.mts                          (fully interactive)
  node tools/snyk-bulk-import.mts --github-org my-org      (discover from GitHub)
  node tools/snyk-bulk-import.mts --gitlab-url https://gitlab.mycorp.com --gitlab-group my-group
  node tools/snyk-bulk-import.mts --file repos.csv         (import from a file)
  node tools/snyk-bulk-import.mts --repos a/b,a/c          (import a few by name)

Which SCM (asked interactively if not given):
  --scm <github|gitlab>  Where the repos live. Default: github.
  --gitlab-url <url>     Base URL of your GitLab, e.g. https://gitlab.mycorp.com
                         (implies --scm gitlab; defaults to https://gitlab.com).
                         The API base /api/v4 is added for you.
  --github-url <url>     GitHub API base (default: https://api.github.com).
                         For GitHub Enterprise use https://<host>/api/v3

Where the repos come from (pick one; you are asked if you pick none):
  --github-org <name>    Read every repo in this GitHub org/user.
  --gitlab-group <path>  Read every project in this GitLab group, including
                         subgroups (alias of --github-org; --group works too).
                         Either way the tool then shows how many are already
                         onboarded in Snyk and lets you import only the pending
                         ones, or all of them.
  --file <path>          CSV or TXT file listing the repos.
  --repos <a/b,a/c>      Comma-separated repo names. With a group/org set you
                         can use bare names: --github-org my-org --repos api,web

Options:
  --all                  Import every repo, including ones already onboarded in
                         Snyk (default: only the pending ones).
  --include-archived     Include archived repos when discovering (default: skip).
  --output-file <path>   Status CSV to write when repos did not come from a file
                         (default: snyk-import-<org>-<timestamp>.csv).
  --org <orgId>          Snyk org UUID. Prompted if omitted.
  --integration <id>     Snyk GitHub integration UUID. Prompted if omitted.
  --region <key|url>     One of: us, us02, eu, au — or a full Snyk API base URL.
  --github-url <url>     GitHub API base (default: https://api.github.com).
                         For GHE use https://<host>/api/v3
  --concurrency <n>      Parallel import requests (default: 5).
  --out <dir>            Where to write the run report (default: snyk-import-results).
  --force                Re-import rows already marked IMPORTED in the file.
  --skip-scm-check       Do not verify each repo against the SCM API.
                         GitHub only — GitLab needs the API to resolve project ids.
  --dry-run              Show what would be imported, then exit.
  --no-poll              Kick off imports without waiting for them to finish.
  --yes                  Skip the confirmation prompt.
  --help                 Show this message.

Environment:
  SNYK_TOKEN               Snyk API token (prompted if not set)
  GITHUB_TOKEN / GH_TOKEN  GitHub PAT     (prompted if not set)
  GITLAB_TOKEN             GitLab PAT     (prompted if not set)
  GITLAB_URL               Default GitLab host
  GITHUB_API_URL           Default GitHub API base

Where to get the API keys:
  Snyk    https://app.snyk.io/account  (or app.eu / app.au / app.us for other regions)
          Avatar bottom-left > Account settings > Auth Token > "click to show".
          Tokens are region-specific; a US token will not work on EU or AU.
          For automation use a Service Account token with the Org Admin role.
  GitHub  https://github.com/settings/tokens  (GHE: https://<host>/settings/tokens)
          Developer settings > Personal access tokens > Tokens (classic) >
          Generate new token, scopes: repo + read:org. If the org uses SAML SSO,
          click "Configure SSO" next to the token and authorize it.
          Only used to pre-check repos — skip it with --skip-scm-check.
  GitLab  https://<your-gitlab>/-/user_settings/personal_access_tokens
          Add a token with the read_api scope. Required for GitLab: the Snyk
          import API needs each project's numeric id, read from the GitLab API.

Input file — TXT (one repo per line, # comments and blank lines ignored):
  owner/repo
  owner/repo@main

Input file — CSV (header required, owner+name or a single repo column):
  repo,branch
  my-org/my-service,main

After a run the tool writes the status back into the same file:
  repo,branch,status,projects,imported_at,details
  my-org/my-service,main,IMPORTED,4,2026-07-31T10:12:00.000Z,"4 project(s) imported"
`;

// ---------------------------------------------------------------------------
// Console helpers
// ---------------------------------------------------------------------------

const useColour = Boolean(stdout.isTTY);
const c = {
  bold: (s: string) => (useColour ? `[1m${s}[0m` : s),
  dim: (s: string) => (useColour ? `[2m${s}[0m` : s),
  green: (s: string) => (useColour ? `[32m${s}[0m` : s),
  red: (s: string) => (useColour ? `[31m${s}[0m` : s),
  yellow: (s: string) => (useColour ? `[33m${s}[0m` : s),
};

function fail(message: string): never {
  console.error(c.red(`\nError: ${message}\n`));
  process.exit(1);
}

let stepNumber = 0;
function step(title: string): void {
  console.log(`\n${c.bold(`Step ${++stepNumber}:`)} ${title}`);
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

let rl: readline.Interface | undefined;

function getReadline(): readline.Interface {
  if (!rl) rl = readline.createInterface({ input: stdin, output: stdout });
  return rl;
}

function closeReadline(): void {
  rl?.close();
  rl = undefined;
}

function ask(question: string): Promise<string> {
  if (!stdin.isTTY) {
    fail(
      `Need input for "${question.trim()}" but the terminal is not interactive. Pass it as a flag instead.`,
    );
  }
  return new Promise((resolve) =>
    getReadline().question(question, (a) => resolve(a.trim())),
  );
}

/** Prompt without echoing what is typed — used for API tokens. */
function askSecret(question: string): Promise<string> {
  if (!stdin.isTTY) {
    fail(`A token is required but the terminal is not interactive: ${question.trim()}`);
  }
  return new Promise((resolve) => {
    const iface = getReadline() as readline.Interface & {
      _writeToOutput?: (s: string) => void;
    };
    const original = iface._writeToOutput;
    iface._writeToOutput = function (str: string) {
      stdout.write(str.includes(question) ? question : '*');
    };
    iface.question(question, (answer) => {
      iface._writeToOutput = original;
      stdout.write('\n');
      resolve(answer.trim());
    });
  });
}

/** Numbered menu — the user picks 1, 2, 3... */
async function choose<T>(
  title: string,
  items: T[],
  render: (item: T) => string,
): Promise<T> {
  if (items.length === 0) fail(`Nothing to choose from for: ${title}`);
  if (items.length === 1) {
    console.log(`  ${title} ${render(items[0])} ${c.dim('(only option)')}`);
    return items[0];
  }

  console.log(`\n  ${title}`);
  items.forEach((item, i) => console.log(`    ${i + 1}) ${render(item)}`));

  for (;;) {
    const answer = await ask(`  Select [1-${items.length}]: `);
    const index = Number(answer);
    if (Number.isInteger(index) && index >= 1 && index <= items.length) {
      return items[index - 1];
    }
    console.log(c.yellow(`  Enter a number between 1 and ${items.length}.`));
  }
}

async function confirm(question: string): Promise<boolean> {
  return /^y(es)?$/i.test(await ask(`${question} [y/N]: `));
}

// ---------------------------------------------------------------------------
// CSV helpers (minimal, quote-aware)
// ---------------------------------------------------------------------------

export function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      out.push(field.trim());
      field = '';
    } else {
      field += ch;
    }
  }
  out.push(field.trim());
  return out;
}

export function toCsvLine(fields: string[]): string {
  return fields
    .map((f) => {
      const v = f ?? '';
      return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
    })
    .join(',');
}

// ---------------------------------------------------------------------------
// Input file: parse
// ---------------------------------------------------------------------------

interface ParsedFile {
  format: 'csv' | 'txt';
  rows: FileRow[];
  /** CSV only: the header fields, already extended with the status columns. */
  header?: string[];
  /** CSV only: index of the columns we read repo info from. */
  columns?: { repo?: number; owner?: number; name?: number; branch?: number };
  eol: string;
}

/**
 * Parse "owner/repo", "owner/repo@branch" or a clone URL.
 *
 * GitLab projects can be nested several levels deep (group/subgroup/project),
 * so `nested` allows more than two path segments and treats everything before
 * the last one as the namespace.
 */
function splitRepoRef(
  value: string,
  nested = false,
): { owner: string; name: string; branch?: string } | undefined {
  let text = value.trim();
  if (!text) return undefined;

  // Tolerate a full clone / browse URL.
  const url = text.match(
    /^(?:https?:\/\/|git@)[^/:]+[/:](.+?)(?:\.git)?(?:@([^/@]+))?$/,
  );
  if (url) {
    const pathPart = url[1];
    const branch = url[2];
    const segments = pathPart.split('/').filter(Boolean);
    if (segments.length >= 2 && (nested || segments.length === 2)) {
      return {
        owner: segments.slice(0, -1).join('/'),
        name: segments[segments.length - 1].replace(/\.git$/, ''),
        branch,
      };
    }
    return undefined;
  }

  let branch: string | undefined;
  const at = text.lastIndexOf('@');
  if (at > 0) {
    branch = text.slice(at + 1).trim() || undefined;
    text = text.slice(0, at).trim();
  }

  const parts = text.split('/').filter(Boolean);
  if (parts.length < 2) return undefined;
  if (!nested && parts.length !== 2) return undefined;

  return {
    owner: parts.slice(0, -1).join('/'),
    name: parts[parts.length - 1].replace(/\.git$/, ''),
    branch,
  };
}

export function parseInputFile(
  contents: string,
  filePath: string,
  nested = false,
): ParsedFile {
  const eol = contents.includes('\r\n') ? '\r\n' : '\n';
  const lines = contents.split(/\r?\n/);
  // Drop a single trailing empty line produced by the final newline.
  if (lines.length && lines[lines.length - 1] === '') lines.pop();

  const isCsv =
    path.extname(filePath).toLowerCase() === '.csv' ||
    /^\s*(repo|owner)\s*,/i.test(lines.find((l) => l.trim() && !l.startsWith('#')) ?? '');

  return isCsv ? parseCsv(lines, eol, nested) : parseTxt(lines, eol, nested);
}

function parseCsv(lines: string[], eol: string, nested: boolean): ParsedFile {
  const rows: FileRow[] = [];
  let header: string[] | undefined;
  let columns: ParsedFile['columns'] = {};
  let statusIndex = -1;

  for (const raw of lines) {
    const trimmed = raw.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      rows.push({ raw, kind: 'passthrough' });
      continue;
    }

    if (!header) {
      header = splitCsvLine(raw).map((h) => h.trim());
      const lower = header.map((h) => h.toLowerCase());
      columns = {
        repo: firstIndex(lower, ['repo', 'repository', 'full_name', 'url']),
        owner: firstIndex(lower, ['owner', 'org', 'organisation', 'organization']),
        name: firstIndex(lower, ['name', 'repo_name', 'slug']),
        branch: firstIndex(lower, ['branch', 'default_branch', 'ref']),
      };
      statusIndex = lower.indexOf('status');
      if (columns.repo === undefined && columns.owner === undefined) {
        fail(
          'CSV header must contain a "repo" column (owner/repo) or "owner" + "name" columns.',
        );
      }
      // Make sure our status columns exist exactly once, at the end.
      for (const col of STATUS_COLUMNS) {
        if (!lower.includes(col)) header.push(col);
      }
      rows.push({ raw, kind: 'passthrough' });
      continue;
    }

    const fields = splitCsvLine(raw);
    const ref =
      columns.repo !== undefined && fields[columns.repo]
        ? splitRepoRef(fields[columns.repo], nested)
        : columns.owner !== undefined &&
            columns.name !== undefined &&
            fields[columns.owner] &&
            fields[columns.name]
          ? {
              owner: fields[columns.owner],
              name: fields[columns.name],
              branch: undefined,
            }
          : undefined;

    if (!ref) {
      rows.push({ raw, kind: 'invalid', reason: 'could not read a repo from this row' });
      continue;
    }

    const branch =
      (columns.branch !== undefined ? fields[columns.branch] : undefined) ||
      ref.branch ||
      undefined;

    rows.push({
      raw,
      kind: 'repo',
      owner: ref.owner,
      name: ref.name,
      branch,
      previousStatus: statusIndex >= 0 ? fields[statusIndex] : undefined,
    });
  }

  if (!header) fail('CSV file is empty — expected a header row.');
  return { format: 'csv', rows, header, columns, eol };
}

function firstIndex(haystack: string[], needles: string[]): number | undefined {
  for (const needle of needles) {
    const i = haystack.indexOf(needle);
    if (i >= 0) return i;
  }
  return undefined;
}

function parseTxt(lines: string[], eol: string, nested: boolean): ParsedFile {
  const rows: FileRow[] = [];

  for (const raw of lines) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      rows.push({ raw, kind: 'passthrough' });
      continue;
    }

    // A previous run appends "  # STATUS ..." — strip it before parsing.
    const hash = trimmed.indexOf('#');
    const repoPart = hash >= 0 ? trimmed.slice(0, hash).trim() : trimmed;
    const comment = hash >= 0 ? trimmed.slice(hash + 1).trim() : '';
    const previousStatus = comment.split(/\s+/)[0] || undefined;

    // Tolerate "owner,repo,branch" inside a .txt file.
    const ref = repoPart.includes(',')
      ? (() => {
          const [owner, name, branch] = repoPart.split(',').map((p) => p.trim());
          return owner && name ? { owner, name, branch: branch || undefined } : undefined;
        })()
      : splitRepoRef(repoPart, nested);

    if (!ref) {
      rows.push({ raw, kind: 'invalid', reason: `could not parse "${trimmed}"` });
      continue;
    }

    rows.push({
      raw,
      kind: 'repo',
      owner: ref.owner,
      name: ref.name,
      branch: ref.branch,
      previousStatus,
    });
  }

  return { format: 'txt', rows, eol };
}

// ---------------------------------------------------------------------------
// Input file: write status back
// ---------------------------------------------------------------------------

export function renderFile(parsed: ParsedFile): string {
  const out: string[] = [];

  if (parsed.format === 'csv') {
    const header = parsed.header!;
    const lower = header.map((h) => h.toLowerCase());
    const at = {
      status: lower.indexOf('status'),
      projects: lower.indexOf('projects'),
      imported_at: lower.indexOf('imported_at'),
      details: lower.indexOf('details'),
    };

    let headerWritten = false;
    for (const row of parsed.rows) {
      if (row.kind !== 'repo') {
        if (!headerWritten && row.raw.trim() && !row.raw.trim().startsWith('#')) {
          out.push(toCsvLine(header));
          headerWritten = true;
        } else {
          out.push(row.raw);
        }
        continue;
      }

      const fields = splitCsvLine(row.raw);
      while (fields.length < header.length) fields.push('');

      // Record the branch we actually imported when the row did not name one.
      const branchColumn = parsed.columns?.branch;
      if (branchColumn !== undefined && row.branch && !fields[branchColumn]) {
        fields[branchColumn] = row.branch;
      }

      if (row.result) {
        fields[at.status] = row.result.status;
        fields[at.projects] = String(row.result.projects);
        fields[at.imported_at] = row.result.at;
        fields[at.details] = row.result.message;
      }
      out.push(toCsvLine(fields));
    }
    return out.join(parsed.eol) + parsed.eol;
  }

  // TXT: keep the repo reference, replace the trailing status comment.
  for (const row of parsed.rows) {
    if (row.kind !== 'repo' || !row.result) {
      out.push(row.raw);
      continue;
    }
    const ref = `${row.owner}/${row.name}${row.branch ? `@${row.branch}` : ''}`;
    const r = row.result;
    out.push(
      `${ref}  # ${r.status} | projects=${r.projects} | ${r.at} | ${r.message.replace(/\s+/g, ' ')}`,
    );
  }
  return out.join(parsed.eol) + parsed.eol;
}

function writeFileAtomic(filePath: string, contents: string): void {
  const tmp = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, contents);
  fs.renameSync(tmp, filePath);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function backoff(attempt: number): number {
  return Math.min(60_000, 2 ** attempt * 1000 + Math.floor(Math.random() * 1000));
}

async function request<T = any>(
  url: string,
  init: { method: 'GET' | 'POST'; headers: Record<string, string>; body?: unknown },
): Promise<ApiResponse<T>> {
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        method: init.method,
        headers: init.headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
      });
    } catch (error: any) {
      lastError = error;
      if (attempt === MAX_ATTEMPTS) break;
      await sleep(backoff(attempt));
      continue;
    }

    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));

    const text = await res.text();
    let data: any = text;
    if (text && headers['content-type']?.includes('json')) {
      try {
        data = JSON.parse(text);
      } catch {
        /* keep the raw text */
      }
    }

    if ((res.status === 429 || res.status >= 500) && attempt < MAX_ATTEMPTS) {
      const retryAfter = Number(headers['retry-after']);
      const wait = Number.isFinite(retryAfter) ? retryAfter * 1000 : backoff(attempt);
      console.log(
        c.dim(`  ${res.status} from API, retrying in ${Math.round(wait / 1000)}s...`),
      );
      await sleep(wait);
      continue;
    }

    return {
      status: res.status,
      headers,
      data,
      requestId: headers['snyk-request-id'] || headers['x-request-id'],
    };
  }

  const cause = (lastError as any)?.cause;
  throw new Error(
    `Could not reach ${new URL(url).origin} after ${MAX_ATTEMPTS} attempts` +
      `: ${cause?.code ?? cause?.message ?? lastError?.message ?? 'unknown network error'}` +
      '. Check the URL, your network and any proxy / self-signed certificate settings' +
      ' (NODE_EXTRA_CA_CERTS, HTTPS_PROXY).',
  );
}

function snykRequest<T = any>(
  token: string,
  method: 'GET' | 'POST',
  url: string,
  body?: unknown,
): Promise<ApiResponse<T>> {
  return request<T>(url, {
    method,
    headers: {
      Authorization: `token ${token}`,
      'Content-Type': 'application/json',
      'User-Agent': 'snyk-bulk-import',
    },
    body,
  });
}

function githubRequest<T = any>(
  token: string,
  url: string,
): Promise<ApiResponse<T>> {
  return request<T>(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'snyk-bulk-import',
    },
  });
}

/** Turn any API response into one readable line. */
function describeError(res: ApiResponse<any>): string {
  const body = res.data;
  const message =
    (body && typeof body === 'object' && (body.message || body.error)) ||
    body?.errors?.[0]?.detail ||
    (typeof body === 'string' && body.trim().slice(0, 300)) ||
    'no response body';
  const reqId = res.requestId ? ` (snyk-request-id: ${res.requestId})` : '';
  return `HTTP ${res.status}: ${message}${reqId}`;
}

// ---------------------------------------------------------------------------
// Snyk API
// ---------------------------------------------------------------------------

async function verifySnykToken(
  baseUrl: string,
  token: string,
): Promise<{ username?: string; email?: string }> {
  const res = await snykRequest(token, 'GET', `${baseUrl}/v1/user/me`);
  if (res.status === 401) {
    fail(
      `Snyk token rejected (401).\n` +
        `  Snyk tokens are region-specific — this one must come from ${appUrlFor(baseUrl)}/account.\n` +
        `  If your org is in a different region, re-run and pick that region at step 1.`,
    );
  }
  if (res.status !== 200) {
    fail(`Could not verify the Snyk token. ${describeError(res)}`);
  }
  return res.data ?? {};
}

async function listOrgs(baseUrl: string, token: string): Promise<SnykOrg[]> {
  const res = await snykRequest<{ orgs: SnykOrg[] }>(token, 'GET', `${baseUrl}/v1/orgs`);
  if (res.status !== 200) fail(`Could not list orgs. ${describeError(res)}`);
  return res.data.orgs ?? [];
}

async function listIntegrations(
  baseUrl: string,
  token: string,
  orgId: string,
): Promise<Record<string, string>> {
  const res = await snykRequest<Record<string, string>>(
    token,
    'GET',
    `${baseUrl}/v1/org/${orgId}/integrations`,
  );
  if (res.status !== 200) {
    fail(`Could not list integrations for org ${orgId}. ${describeError(res)}`);
  }
  return res.data ?? {};
}

async function importRepo(
  baseUrl: string,
  token: string,
  orgId: string,
  integrationId: string,
  row: FileRow,
  opts: Options,
): Promise<string> {
  const target = buildImportTarget(opts, row);

  const res = await snykRequest(
    token,
    'POST',
    `${baseUrl}/v1/org/${orgId}/integrations/${integrationId}/import`,
    { target },
  );

  if (res.status !== 201) throw new Error(describeError(res));

  const location = res.headers['location'] || (res.data as any)?.location;
  if (!location) throw new Error('Import accepted but no polling URL was returned');
  return location.startsWith('http') ? location : `${baseUrl}${location}`;
}

async function pollJob(token: string, pollingUrl: string): Promise<ImportedProject[]> {
  const deadline = Date.now() + POLL_TIMEOUT_MS;

  for (;;) {
    const res = await snykRequest<PollResponse>(token, 'GET', pollingUrl);
    if (res.status !== 200) throw new Error(describeError(res));

    if (res.data.status === 'complete') {
      return (res.data.logs ?? []).flatMap((log) => log.projects ?? []);
    }
    if (Date.now() > deadline) {
      throw new Error(
        `Timed out after ${POLL_TIMEOUT_MS / 60000} min (last status: ${res.data.status})`,
      );
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

async function verifyGithubToken(
  apiUrl: string,
  token: string,
): Promise<{ login: string; scopes?: string }> {
  const res = await githubRequest<{ login: string }>(token, `${apiUrl}/user`);
  if (res.status === 401) {
    fail(
      `GitHub token rejected (401).\n` +
        `  Generate a new one at ${githubTokenPage(apiUrl)} with the "repo" and "read:org" scopes,\n` +
        `  or re-run with --skip-github-check to import without the GitHub pre-check.`,
    );
  }
  if (res.status !== 200) {
    fail(`Could not verify the GitHub token against ${apiUrl}. ${describeError(res)}`);
  }
  return { login: res.data.login, scopes: res.headers['x-oauth-scopes'] };
}

interface RepoCheck {
  ok: boolean;
  defaultBranch?: string;
  archived?: boolean;
  message?: string;
  /** GitLab only — the numeric project id. */
  projectId?: number;
}

async function checkRepo(
  apiUrl: string,
  token: string,
  owner: string,
  name: string,
): Promise<RepoCheck> {
  const res = await githubRequest<any>(token, `${apiUrl}/repos/${owner}/${name}`);
  if (res.status === 200) {
    return {
      ok: true,
      defaultBranch: res.data.default_branch,
      archived: Boolean(res.data.archived),
    };
  }
  if (res.status === 404) {
    return { ok: false, message: 'not found on GitHub, or the token cannot see it' };
  }
  if (res.status === 403) {
    return { ok: false, message: 'GitHub denied access (403) — check token scopes / SSO' };
  }
  return { ok: false, message: describeError(res) };
}

interface GithubRepo {
  owner: string;
  name: string;
  branch: string;
  archived: boolean;
  /** GitLab only — the numeric project id the Snyk import API needs. */
  projectId?: number;
}

/** `<url>; rel="next"` → url */
export function nextLink(linkHeader?: string): string | undefined {
  if (!linkHeader) return undefined;
  for (const part of linkHeader.split(',')) {
    const match = part.match(/<([^>]+)>\s*;\s*rel="next"/);
    if (match) return match[1];
  }
  return undefined;
}

/** Every repo in a GitHub org — falls back to a user account if the org 404s. */
async function listGithubRepos(
  apiUrl: string,
  token: string,
  owner: string,
): Promise<GithubRepo[]> {
  const repos: GithubRepo[] = [];
  let url: string | undefined = `${apiUrl}/orgs/${owner}/repos?per_page=100&type=all`;
  let triedUserFallback = false;

  while (url) {
    const res: ApiResponse<any> = await githubRequest(token, url);

    if (res.status === 404 && !triedUserFallback) {
      // Not an org — maybe a personal account.
      triedUserFallback = true;
      url = `${apiUrl}/users/${owner}/repos?per_page=100&type=all`;
      continue;
    }
    if (res.status !== 200) {
      fail(`Could not list repos for "${owner}" on GitHub. ${describeError(res)}`);
    }
    if (!Array.isArray(res.data)) {
      fail(`Unexpected response listing repos for "${owner}".`);
    }

    for (const repo of res.data) {
      repos.push({
        owner: repo.owner?.login ?? owner,
        name: repo.name,
        branch: repo.default_branch ?? '',
        archived: Boolean(repo.archived),
      });
    }
    if (stdout.isTTY) stdout.write(`\r  Fetched ${repos.length} repos from GitHub...`);
    url = nextLink(res.headers['link']);
  }

  if (stdout.isTTY) stdout.write(`\r${' '.repeat(45)}\r`);
  return repos;
}

// ---------------------------------------------------------------------------
// GitLab API (works the same for gitlab.com and a self-hosted install)
// ---------------------------------------------------------------------------

function gitlabRequest<T = any>(token: string, url: string): Promise<ApiResponse<T>> {
  return request<T>(url, {
    method: 'GET',
    headers: {
      'PRIVATE-TOKEN': token,
      Accept: 'application/json',
      'User-Agent': 'snyk-bulk-import',
    },
  });
}

async function verifyGitlabToken(
  apiUrl: string,
  token: string,
): Promise<{ login: string; scopes?: string }> {
  const res = await gitlabRequest<{ username: string; name: string }>(
    token,
    `${apiUrl}/user`,
  );
  if (res.status === 401 || res.status === 403) {
    fail(
      `GitLab token rejected (${res.status}).\n` +
        `  Create a personal access token with the "read_api" scope at\n` +
        `  ${gitlabTokenPage(apiUrl.replace(/\/api\/v4$/, ''))}`,
    );
  }
  if (res.status !== 200) {
    fail(`Could not verify the GitLab token against ${apiUrl}. ${describeError(res)}`);
  }
  return { login: res.data.username || res.data.name };
}

function toGitlabRepo(project: any): GithubRepo {
  const fullPath: string = project.path_with_namespace ?? '';
  const lastSlash = fullPath.lastIndexOf('/');
  return {
    owner: lastSlash > 0 ? fullPath.slice(0, lastSlash) : '',
    name: lastSlash > 0 ? fullPath.slice(lastSlash + 1) : fullPath,
    branch: project.default_branch ?? '',
    archived: Boolean(project.archived),
    projectId: project.id,
  };
}

/** Every project in a GitLab group (including subgroups), or a user namespace. */
async function listGitlabProjects(
  apiUrl: string,
  token: string,
  group: string,
  includeArchived: boolean,
): Promise<GithubRepo[]> {
  const projects: GithubRepo[] = [];
  const encoded = encodeURIComponent(group);
  const archivedParam = includeArchived ? '' : '&archived=false';

  let url: string | undefined =
    `${apiUrl}/groups/${encoded}/projects?include_subgroups=true&per_page=100${archivedParam}`;
  let triedUserFallback = false;

  while (url) {
    const res: ApiResponse<any> = await gitlabRequest(token, url);

    if (res.status === 404 && !triedUserFallback) {
      // Not a group — maybe a personal namespace.
      triedUserFallback = true;
      url = `${apiUrl}/users/${encoded}/projects?per_page=100${archivedParam}`;
      continue;
    }
    if (res.status !== 200) {
      fail(`Could not list projects for "${group}" on GitLab. ${describeError(res)}`);
    }
    if (!Array.isArray(res.data)) {
      fail(`Unexpected response listing projects for "${group}".`);
    }

    res.data.forEach((p: any) => projects.push(toGitlabRepo(p)));
    if (stdout.isTTY) stdout.write(`\r  Fetched ${projects.length} projects from GitLab...`);

    // GitLab paginates with an x-next-page header holding the next page number.
    const nextPage = res.headers['x-next-page'];
    const base: string = url.split('&page=')[0];
    url = nextPage ? `${base}&page=${nextPage}` : undefined;
  }

  if (stdout.isTTY) stdout.write(`\r${' '.repeat(48)}\r`);
  return projects;
}

/** Resolve one "group/sub/project" path to its numeric id and default branch. */
async function checkGitlabProject(
  apiUrl: string,
  token: string,
  fullPath: string,
): Promise<RepoCheck> {
  const res = await gitlabRequest<any>(
    token,
    `${apiUrl}/projects/${encodeURIComponent(fullPath)}`,
  );
  if (res.status === 200) {
    return {
      ok: true,
      defaultBranch: res.data.default_branch,
      archived: Boolean(res.data.archived),
      projectId: res.data.id,
    };
  }
  if (res.status === 404) {
    return { ok: false, message: 'not found on GitLab, or the token cannot see it' };
  }
  if (res.status === 403) {
    return { ok: false, message: 'GitLab denied access (403) — check the token scopes' };
  }
  return { ok: false, message: describeError(res) };
}

// ---------------------------------------------------------------------------
// SCM dispatch — one entry point per operation, GitHub or GitLab
// ---------------------------------------------------------------------------

/** The API base URL for the configured SCM. */
function scmApiUrl(opts: Options): string {
  return opts.scm === 'gitlab' ? gitlabApiUrl(opts.gitlabUrl!) : opts.githubUrl;
}

function scmLabel(opts: Options): string {
  return opts.scm === 'gitlab' ? 'GitLab' : 'GitHub';
}

/** What a group of repos is called in each SCM, for prompts. */
function scmGroupLabel(opts: Options): string {
  return opts.scm === 'gitlab' ? 'GitLab group (or username)' : 'GitHub org (or user)';
}

function verifyScmToken(
  opts: Options,
  token: string,
): Promise<{ login: string; scopes?: string }> {
  return opts.scm === 'gitlab'
    ? verifyGitlabToken(scmApiUrl(opts), token)
    : verifyGithubToken(opts.githubUrl, token);
}

function listScmRepos(
  opts: Options,
  token: string,
  group: string,
): Promise<GithubRepo[]> {
  return opts.scm === 'gitlab'
    ? listGitlabProjects(scmApiUrl(opts), token, group, opts.includeArchived)
    : listGithubRepos(opts.githubUrl, token, group);
}

function checkScmRepo(
  opts: Options,
  token: string,
  owner: string,
  name: string,
): Promise<RepoCheck> {
  return opts.scm === 'gitlab'
    ? checkGitlabProject(scmApiUrl(opts), token, `${owner}/${name}`)
    : checkRepo(opts.githubUrl, token, owner, name);
}

/**
 * The `target` the Snyk import API expects. GitHub takes owner/name/branch;
 * GitLab takes the numeric project id and a branch.
 */
function buildImportTarget(opts: Options, row: FileRow): Record<string, unknown> {
  if (opts.scm === 'gitlab') {
    if (row.projectId === undefined) {
      throw new Error(
        'GitLab imports need the numeric project id, which could not be resolved',
      );
    }
    const target: Record<string, unknown> = { id: row.projectId };
    if (row.branch) target.branch = row.branch;
    return target;
  }

  const target: Record<string, unknown> = { owner: row.owner!, name: row.name! };
  if (row.branch) target.branch = row.branch;
  return target;
}

/** Repos already onboarded in the Snyk org, as a set of "owner/repo". */
async function listSnykTargets(
  baseUrl: string,
  token: string,
  orgId: string,
): Promise<Set<string>> {
  const found = new Set<string>();
  let url: string | undefined =
    `${baseUrl}/rest/orgs/${orgId}/targets?version=${REST_VERSION}&limit=100`;

  while (url) {
    const res: ApiResponse<any> = await snykRequest(token, 'GET', url);
    if (res.status !== 200) {
      console.log(
        c.yellow(
          `  Could not list what is already in Snyk (${describeError(res)}).` +
            ' Continuing — nothing will be treated as already onboarded.',
        ),
      );
      return new Set();
    }

    for (const target of res.data?.data ?? []) {
      const displayName: string | undefined = target?.attributes?.display_name;
      if (displayName) found.add(displayName.toLowerCase());
    }

    const link: string | undefined = res.data?.links?.next;
    url = link
      ? link.startsWith('http')
        ? link
        : `${baseUrl}${link.startsWith('/') ? '' : '/'}${link}`
      : undefined;
  }

  return found;
}

// ---------------------------------------------------------------------------
// Concurrency pool
// ---------------------------------------------------------------------------

async function pool<T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      await worker(items[index], index);
    }
  });
  await Promise.all(runners);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(HELP);
    return;
  }

  console.log(c.bold('\nSnyk bulk repo importer'));

  // --- Step 1: region -------------------------------------------------------
  step('Choose your Snyk region');
  let baseUrl: string;
  if (opts.region) {
    const match = REGIONS.find((r) => r.key === opts.region!.toLowerCase());
    baseUrl = match ? match.url : opts.region.replace(/\/+$/, '');
    if (!/^https?:\/\//.test(baseUrl)) {
      fail(`--region must be one of ${REGIONS.map((r) => r.key).join(', ')} or a full URL`);
    }
    console.log(`  Using ${baseUrl}`);
  } else {
    baseUrl = (await choose('Which Snyk region?', REGIONS, (r) => `${r.label} — ${r.url}`))
      .url;
  }

  // --- Step 2: which SCM ----------------------------------------------------
  step('Choose where your repos live');
  await chooseScm(opts);
  const scm = scmLabel(opts);

  // --- Step 3: collect both keys -------------------------------------------
  step('Enter your API keys');
  const envSnykToken = process.env.SNYK_TOKEN?.trim();
  const envScmToken =
    opts.scm === 'gitlab'
      ? (process.env.GITLAB_TOKEN || process.env.CI_JOB_TOKEN)?.trim()
      : (process.env.GITHUB_TOKEN || process.env.GH_TOKEN)?.trim();
  const needsScmToken = !envScmToken && !opts.skipScmCheck;

  // Only explain where to get the keys if we are actually going to ask for one.
  if (!envSnykToken || needsScmToken) {
    printTokenHelp(opts, baseUrl, !envSnykToken, needsScmToken);
  }

  let snykToken = envSnykToken;
  if (snykToken) {
    console.log(c.dim('  Snyk token  : from SNYK_TOKEN'));
  } else {
    snykToken = await askSecret('  Snyk API token   : ');
  }
  if (!snykToken) {
    fail(
      `A Snyk API token is required. Copy it from ${appUrlFor(baseUrl)}/account and either paste it here or export SNYK_TOKEN.`,
    );
  }

  const scmTokenEnvName = opts.scm === 'gitlab' ? 'GITLAB_TOKEN' : 'GITHUB_TOKEN';
  let scmToken = envScmToken;
  if (scmToken) {
    console.log(c.dim(`  ${scm} token: from ${scmTokenEnvName}`));
  } else if (opts.skipScmCheck) {
    console.log(c.dim(`  ${scm} token: skipped (--skip-scm-check)`));
  } else if (!stdin.isTTY) {
    fail(
      `No ${scm} token and no terminal to ask on. Export ${scmTokenEnvName}` +
        (opts.scm === 'gitlab' ? '.' : ', or pass --skip-scm-check to import without the GitHub pre-check.'),
    );
  } else {
    scmToken = await askSecret(`  ${scm} token${' '.repeat(Math.max(0, 9 - scm.length))}: `);
    if (!scmToken && opts.scm === 'gitlab') {
      fail(
        'GitLab imports need a GitLab token — the numeric project id can only be read from the GitLab API.',
      );
    }
    if (!scmToken) {
      console.log(
        c.yellow(`  No ${scm} token given — repos will not be pre-checked on ${scm}.`),
      );
    }
  }

  // --- Step 4: verify Snyk auth --------------------------------------------
  step('Verify the Snyk API key');
  const me = await verifySnykToken(baseUrl, snykToken);
  console.log(
    `  ${c.green('✓')} Snyk authenticated as ${c.bold(me.username || me.email || 'unknown user')}`,
  );

  // --- Step 5: verify SCM auth ---------------------------------------------
  step(`Verify the ${scm} API key`);
  if (opts.skipScmCheck || !scmToken) {
    if (opts.scm === 'gitlab') {
      fail('A GitLab token is required — GitLab imports cannot skip the SCM check.');
    }
    console.log(c.yellow(`  Skipped — repos will not be pre-checked on ${scm}.`));
    opts.skipScmCheck = true;
  } else {
    const who = await verifyScmToken(opts, scmToken);
    console.log(`  ${c.green('✓')} ${scm} authenticated as ${c.bold(who.login)}`);
    console.log(c.dim(`    ${scmApiUrl(opts)}`));
    if (who.scopes !== undefined) {
      console.log(c.dim(`    scopes: ${who.scopes || '(fine-grained token)'}`));
    }
  }

  // --- Step 5: org ----------------------------------------------------------
  step('Select the target Snyk organization');
  let orgId = opts.org;
  if (orgId) {
    console.log(`  Org: ${orgId}`);
  } else {
    const orgs = await listOrgs(baseUrl, snykToken);
    if (orgs.length === 0) fail('This token has no access to any Snyk orgs.');
    orgId = (
      await choose(
        `Which org? (${orgs.length} available)`,
        orgs,
        (o) => `${o.name}${o.group ? ` ${c.dim(`[${o.group.name}]`)}` : ''} ${c.dim(o.id)}`,
      )
    ).id;
  }

  // --- Step 7: integration --------------------------------------------------
  step(`Select the ${scm} integration in Snyk`);
  let integrationId = opts.integration;
  if (integrationId) {
    console.log(`  Integration: ${integrationId}`);
  } else {
    const wanted = opts.scm === 'gitlab' ? GITLAB_INTEGRATIONS : GITHUB_INTEGRATIONS;
    const integrations = await listIntegrations(baseUrl, snykToken, orgId);
    const available = Object.entries(integrations)
      .filter(([name, id]) => wanted.includes(name) && Boolean(id))
      .map(([name, id]) => ({ name, id }));
    if (available.length === 0) {
      fail(
        `No ${scm} integration is configured on org ${orgId}. Set one up in Snyk under Settings > Integrations first.`,
      );
    }
    integrationId = (
      await choose('Which integration?', available, (i) => `${i.name} ${c.dim(i.id)}`)
    ).id;
  }

  // --- Step 7: where do the repos come from --------------------------------
  step('Choose the repos to import');
  const { parsed, filePath, sourceLabel } = await collectRepos(opts, scmToken);

  const repoRows = parsed.rows.filter((r) => r.kind === 'repo');
  const invalidRows = parsed.rows.filter((r) => r.kind === 'invalid');
  invalidRows.forEach((r) => console.log(c.yellow(`  Ignoring row — ${r.reason}`)));
  if (repoRows.length === 0) fail(`No usable repos found in ${sourceLabel}.`);

  // --- Step 8: compare against what is already in Snyk ----------------------
  step('Compare with what is already onboarded in Snyk');
  const snykTargets = await listSnykTargets(baseUrl, snykToken, orgId);

  // Work out the buckets before asking anything, so the counts are accurate.
  const seen = new Set<string>();
  const duplicateRows: FileRow[] = [];
  const previouslyImportedRows: FileRow[] = [];
  const onboardedRows: FileRow[] = [];
  const pendingRows: FileRow[] = [];

  for (const row of repoRows) {
    const key = `${row.owner}/${row.name}@${row.branch ?? ''}`.toLowerCase();
    if (seen.has(key)) {
      duplicateRows.push(row);
      continue;
    }
    seen.add(key);

    if (row.previousStatus?.toUpperCase() === 'IMPORTED' && !opts.force) {
      previouslyImportedRows.push(row);
    } else if (snykTargets.has(`${row.owner}/${row.name}`.toLowerCase())) {
      onboardedRows.push(row);
    } else {
      pendingRows.push(row);
    }
  }

  console.log(`\n  Source                    : ${sourceLabel}`);
  console.log(`  Repos in the list         : ${c.bold(String(repoRows.length))}`);
  if (duplicateRows.length) {
    console.log(`  Duplicate entries         : ${duplicateRows.length}`);
  }
  if (previouslyImportedRows.length) {
    console.log(`  Marked IMPORTED already   : ${previouslyImportedRows.length}`);
  }
  console.log(`  Already onboarded in Snyk : ${c.green(String(onboardedRows.length))}`);
  console.log(`  Pending to onboard        : ${c.bold(String(pendingRows.length))}`);

  // Decide whether to import only the pending repos, or everything.
  let importAll = opts.all;
  if (!importAll && stdin.isTTY && !opts.yes) {
    if (pendingRows.length === 0 && onboardedRows.length > 0) {
      const answer = await choose(
        'Every repo is already onboarded. What now?',
        [
          { key: 'stop', label: 'Stop — nothing to do' },
          { key: 'all', label: `Re-import all ${onboardedRows.length} repos anyway` },
        ],
        (o) => o.label,
      );
      if (answer.key === 'stop') {
        console.log(c.green('\nNothing to import. Done.'));
        return;
      }
      importAll = true;
    } else if (onboardedRows.length > 0) {
      const answer = await choose(
        'What do you want to import?',
        [
          { key: 'pending', label: `Only the pending repos (${pendingRows.length})` },
          {
            key: 'all',
            label: `All repos (${pendingRows.length + onboardedRows.length}) — re-imports the ${onboardedRows.length} already onboarded`,
          },
          { key: 'stop', label: 'Cancel' },
        ],
        (o) => o.label,
      );
      if (answer.key === 'stop') {
        console.log('Cancelled — nothing was imported.');
        return;
      }
      importAll = answer.key === 'all';
    }
  }

  // Apply the decision to the rows.
  const now = () => new Date().toISOString();
  duplicateRows.forEach((row) => {
    row.result = {
      status: 'SKIPPED',
      projects: 0,
      message: 'duplicate of an earlier entry',
      at: now(),
    };
  });
  previouslyImportedRows.forEach((row) => {
    row.result = {
      status: 'SKIPPED',
      projects: 0,
      message: 'already imported in a previous run',
      at: now(),
    };
  });
  if (!importAll) {
    onboardedRows.forEach((row) => {
      row.result = {
        status: 'SKIPPED',
        projects: 0,
        message: 'already onboarded in this Snyk org',
        at: now(),
      };
    });
  }

  const pending = importAll ? [...pendingRows, ...onboardedRows] : pendingRows;
  if (pending.length === 0) {
    if (repoRows.some((r) => r.kind === 'repo' && r.result)) {
      writeFileAtomic(filePath, renderFile(parsed));
      console.log(`  Statuses written to ${filePath}.`);
    }
    console.log(c.green('\nNothing left to import. Done.'));
    return;
  }
  console.log(`\n  ${c.bold(String(pending.length))} repo(s) selected for import.`);

  // --- Step 10: check repos on the SCM -------------------------------------
  step(`Check the repos on ${scm}`);
  let importable = pending;
  const needsCheck = pending.filter((r) => !r.verified || r.projectId === undefined);
  if (opts.skipScmCheck) {
    console.log(c.dim('  Skipped.'));
  } else if (needsCheck.length === 0) {
    console.log(c.dim(`  Not needed — the list came straight from the ${scm} API.`));
  } else {
    if (opts.scm === 'gitlab') {
      console.log(c.dim('  Resolving GitLab project ids (needed by the import API)...'));
    }
    let checked = 0;
    await pool(needsCheck, 10, async (row) => {
      const check = await checkScmRepo(opts, scmToken!, row.owner!, row.name!);
      checked++;
      if (!check.ok) {
        row.result = {
          status: 'NOT_FOUND',
          projects: 0,
          message: check.message ?? `unavailable on ${scm}`,
          at: new Date().toISOString(),
        };
        console.log(`  ${c.red('✗')} ${row.owner}/${row.name}: ${check.message}`);
        return;
      }
      if (check.archived) {
        console.log(c.yellow(`  ! ${row.owner}/${row.name} is archived — importing anyway`));
      }
      if (!row.branch && check.defaultBranch) row.branch = check.defaultBranch;
      if (check.projectId !== undefined) row.projectId = check.projectId;
    });
    importable = pending.filter((r) => !r.result);
    console.log(
      `  ${c.green('✓')} ${importable.length - (pending.length - needsCheck.length)}/${checked} repos reachable on ${scm}.`,
    );
    if (importable.length === 0) {
      writeFileAtomic(filePath, renderFile(parsed));
      fail(`None of the repos could be reached on ${scm}. Statuses written to ${filePath}.`);
    }
  }

  // --- Step 9: confirm ------------------------------------------------------
  step('Review');
  importable
    .slice(0, 10)
    .forEach((r) => console.log(`  - ${r.owner}/${r.name}${r.branch ? `@${r.branch}` : ''}`));
  if (importable.length > 10) {
    console.log(c.dim(`  ...and ${importable.length - 10} more`));
  }
  console.log(
    `\n  Importing ${c.bold(String(importable.length))} repos into org ${orgId} (concurrency ${opts.concurrency}).`,
  );

  if (opts.dryRun) {
    console.log(c.yellow('\nDry run — nothing was imported and the file was not modified.'));
    return;
  }
  if (!opts.yes && stdin.isTTY && !(await confirm('  Proceed?'))) {
    console.log('Aborted — the file was not modified.');
    return;
  }
  closeReadline();

  // --- Step 10: import ------------------------------------------------------
  step('Kick off the imports');
  let queuedCount = 0;
  await pool(importable, opts.concurrency, async (row) => {
    const label = `${row.owner}/${row.name}`;
    try {
      const pollingUrl = await importRepo(
        baseUrl,
        snykToken!,
        orgId!,
        integrationId!,
        row,
        opts,
      );
      row.result = {
        status: 'QUEUED',
        projects: 0,
        message: 'import job queued',
        pollingUrl,
        at: new Date().toISOString(),
      };
      console.log(
        `  ${c.green('✓')} queued ${label} ${c.dim(`(${++queuedCount}/${importable.length})`)}`,
      );
    } catch (error: any) {
      row.result = {
        status: 'FAILED',
        projects: 0,
        message: error.message,
        at: new Date().toISOString(),
      };
      console.log(`  ${c.red('✗')} ${label}: ${error.message}`);
    }
  });

  // Persist early: if polling is interrupted we still know what was queued.
  writeFileAtomic(filePath, renderFile(parsed));

  const queued = importable.filter((r) => r.result?.pollingUrl);
  console.log(`\n  ${queued.length}/${importable.length} import jobs accepted by Snyk.`);

  // --- Step 11: poll --------------------------------------------------------
  if (opts.poll && queued.length > 0) {
    step('Wait for the import jobs to finish');
    console.log(c.dim(`  Polling every ${POLL_INTERVAL_MS / 1000}s (timeout ${POLL_TIMEOUT_MS / 60000} min)...`));

    let polled = 0;
    await pool(queued, Math.min(10, opts.concurrency), async (row) => {
      const label = `${row.owner}/${row.name}`;
      try {
        const projects = await pollJob(snykToken!, row.result!.pollingUrl!);
        const ok = projects.filter((p) => p.success);
        const bad = projects.filter((p) => !p.success);
        row.result = {
          ...row.result!,
          status: ok.length === 0 ? 'FAILED' : bad.length ? 'PARTIAL' : 'IMPORTED',
          projects: ok.length,
          message:
            ok.length === 0
              ? bad[0]?.userMessage || 'no projects were created (no supported manifests found?)'
              : `${ok.length} project(s) imported${bad.length ? `, ${bad.length} failed` : ''}`,
          at: new Date().toISOString(),
        };
        const mark = row.result.status === 'IMPORTED' ? c.green('✓') : c.yellow('!');
        console.log(
          `  ${mark} ${label}: ${row.result.message} ${c.dim(`(${++polled}/${queued.length})`)}`,
        );
      } catch (error: any) {
        row.result = {
          ...row.result!,
          status: 'FAILED',
          message: error.message,
          at: new Date().toISOString(),
        };
        console.log(`  ${c.red('✗')} ${label}: ${error.message}`);
      }
    });
  }

  // --- Step 12: write status back + summary --------------------------------
  step('Write the statuses back and summarise');
  writeFileAtomic(filePath, renderFile(parsed));
  console.log(`  Updated ${c.bold(filePath)} with a status for every repo.`);

  const report = writeReport(opts.out, {
    baseUrl,
    orgId,
    integrationId,
    file: filePath,
    rows: repoRows,
  });
  console.log(`  Wrote run report ${report}`);

  printSummary(repoRows, invalidRows.length);
}

/**
 * Ask which SCM the repos live in, and for a self-hosted install, its base URL.
 * GitHub Enterprise and self-hosted GitLab both just need a different API base.
 */
async function chooseScm(opts: Options): Promise<void> {
  if (!opts.scm) {
    if (!stdin.isTTY) {
      opts.scm = 'github';
    } else {
      const picked = await choose(
        'Where do your repos live?',
        [
          { key: 'github' as ScmKind, hosted: false, label: 'GitHub.com' },
          { key: 'github' as ScmKind, hosted: true, label: 'GitHub Enterprise (self-hosted)' },
          { key: 'gitlab' as ScmKind, hosted: false, label: 'GitLab.com' },
          { key: 'gitlab' as ScmKind, hosted: true, label: 'GitLab self-hosted / private' },
        ],
        (o) => o.label,
      );
      opts.scm = picked.key;

      if (picked.hosted && picked.key === 'github' && !process.env.GITHUB_API_URL) {
        const host = await ask('  GitHub Enterprise URL (e.g. https://github.mycorp.com): ');
        if (!host) fail('A GitHub Enterprise URL is required.');
        const clean = host.trim().replace(/\/+$/, '').replace(/\/api\/v3$/, '');
        opts.githubUrl = `${/^https?:\/\//.test(clean) ? clean : `https://${clean}`}/api/v3`;
      }
      if (picked.key === 'gitlab' && !opts.gitlabUrl) {
        opts.gitlabUrl = picked.hosted
          ? await ask('  GitLab URL (e.g. https://gitlab.mycorp.com): ')
          : 'https://gitlab.com';
        if (!opts.gitlabUrl) fail('A GitLab URL is required.');
        opts.gitlabUrl = normaliseGitlabUrl(opts.gitlabUrl);
      }
    }
  }

  if (opts.scm === 'gitlab') {
    opts.gitlabUrl ??= normaliseGitlabUrl(
      process.env.GITLAB_URL || process.env.CI_SERVER_URL || 'https://gitlab.com',
    );
    console.log(`  GitLab : ${opts.gitlabUrl}`);
    console.log(c.dim(`  API    : ${gitlabApiUrl(opts.gitlabUrl)}`));
  } else {
    console.log(`  GitHub : ${opts.githubUrl}`);
  }
}

/** Directory this script lives in — used to suggest the bundled examples. */
const scriptDir = path.dirname(fileURLToPath(import.meta.url));

/** CSV/TXT files sitting in a directory, for the "which file?" menu. */
function listRepoFilesIn(dir: string): string[] {
  try {
    return fs
      .readdirSync(dir)
      .filter((f) => /\.(csv|txt)$/i.test(f) && !f.startsWith('.'))
      .filter((f) => {
        try {
          return fs.statSync(path.join(dir, f)).isFile();
        } catch {
          return false;
        }
      })
      .sort()
      .slice(0, 10);
  } catch {
    return [];
  }
}

/** Explain a bad path, and point at the file they probably meant. */
function explainMissingFile(given: string): void {
  const resolved = path.resolve(given);

  if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
    console.log(c.red(`  "${given}" is a directory, not a file.`));
    const inside = listRepoFilesIn(resolved);
    if (inside.length) {
      console.log(c.dim('    it contains:'));
      inside.forEach((f) => console.log(c.dim(`      ${path.join(given, f)}`)));
    }
    return;
  }

  console.log(c.red(`  Could not find "${given}"`));
  console.log(c.dim(`    looked for : ${resolved}`));
  console.log(c.dim(`    working dir: ${process.cwd()}`));

  const base = path.basename(given);
  const suggestions = [
    path.join(process.cwd(), 'tools', base),
    path.join(scriptDir, base),
  ].filter((p, i, arr) => arr.indexOf(p) === i && fs.existsSync(p));

  suggestions.forEach((s) => {
    // Show a short relative path when it is below the working directory,
    // otherwise the absolute one — "../../../.." helps nobody.
    const rel = path.relative(process.cwd(), s);
    const display = rel && !rel.startsWith('..') ? rel : s;
    console.log(c.yellow(`    did you mean: ${display}`));
  });
}

/** Ask for a repo file, offering the CSV/TXT files in the current directory. */
async function promptForInputFile(): Promise<string> {
  const candidates = listRepoFilesIn(process.cwd());
  if (candidates.length > 0) {
    const picked = await choose(
      'Which file?',
      [
        ...candidates.map((f) => ({ key: f, label: f })),
        { key: '', label: 'Type a different path' },
      ],
      (o) => o.label,
    );
    if (picked.key) return picked.key;
  }
  return ask('  Path to the CSV/TXT file: ');
}

/** Turn whatever --file was given into a readable file, re-prompting if needed. */
async function resolveInputFile(given: string | undefined): Promise<string> {
  let candidate = given;

  for (;;) {
    if (candidate) {
      const resolved = path.resolve(candidate);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) return candidate;
      explainMissingFile(candidate);
      if (!stdin.isTTY) {
        fail('Could not read the repo file. Pass a valid path with --file.');
      }
      console.log('');
    }
    candidate = await promptForInputFile();
    if (!candidate) {
      fail('A repo file is required — pass one with --file.');
    }
  }
}

/**
 * Works out where the repo list comes from — a file, the GitHub API, or names
 * typed on the command line — and returns it as a parsed file we can write
 * statuses back into.
 */
async function collectRepos(
  opts: Options,
  scmToken: string | undefined,
): Promise<{ parsed: ParsedFile; filePath: string; sourceLabel: string }> {
  const scm = scmLabel(opts);
  type SourceKey = 'file' | 'github' | 'list';

  // A --file that cannot be read should not lock us into file mode — explain
  // the problem and let the user pick a source instead.
  if (opts.file) {
    const resolved = path.resolve(opts.file);
    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
      explainMissingFile(opts.file);
      if (!stdin.isTTY) {
        fail('Could not read the repo file. Pass a valid path with --file.');
      }
      opts.file = undefined;
      console.log('');
    }
  }

  let source: SourceKey;
  if (opts.file) source = 'file';
  else if (opts.repos) source = 'list';
  else if (opts.githubOrg) source = 'github';
  else {
    const groupWordForMenu = opts.scm === 'gitlab' ? 'group (incl. subgroups)' : 'org';
    source = (
      await choose(
        'Where should the repo list come from?',
        [
          {
            key: 'github' as SourceKey,
            label: `Every repo in a ${scm} ${groupWordForMenu} (read from ${scm})`,
          },
          { key: 'list' as SourceKey, label: 'Repo names I type in (comma separated)' },
          { key: 'file' as SourceKey, label: 'A CSV / TXT file' },
        ],
        (o) => o.label,
      )
    ).key;
  }

  // --- from a file ---------------------------------------------------------
  if (source === 'file') {
    const filePath = await resolveInputFile(opts.file);
    const parsed = parseInputFile(
      fs.readFileSync(filePath, 'utf8'),
      filePath,
      opts.scm === 'gitlab',
    );
    const count = parsed.rows.filter((r) => r.kind === 'repo').length;
    console.log(`  Read ${c.bold(String(count))} repos from ${filePath} (${parsed.format.toUpperCase()})`);
    return { parsed, filePath, sourceLabel: filePath };
  }

  // --- from the SCM API ----------------------------------------------------
  if (!scmToken || opts.skipScmCheck) {
    fail(
      `Reading repos from ${scm} needs a ${scm} token. Set ${
        opts.scm === 'gitlab' ? 'GITLAB_TOKEN' : 'GITHUB_TOKEN'
      }, or use --file instead.`,
    );
  }

  const groupWord = opts.scm === 'gitlab' ? 'group' : 'org';
  let discovered: GithubRepo[];
  let label: string;
  let slug: string;

  if (source === 'github') {
    const group = opts.githubOrg ?? (await ask(`  ${scmGroupLabel(opts)} name: `));
    if (!group) {
      fail(
        `A ${scm} ${groupWord} name is required (${
          opts.scm === 'gitlab' ? '--gitlab-group' : '--github-org'
        }).`,
      );
    }

    console.log(`  Reading repos from ${scm} ${groupWord} "${group}"...`);
    const all = await listScmRepos(opts, scmToken, group);
    if (all.length === 0) {
      fail(`No repos found for "${group}" — check the name and your token's access.`);
    }

    const archived = all.filter((r) => r.archived);
    const kept = opts.includeArchived ? all : all.filter((r) => !r.archived);
    console.log(`  Found ${c.bold(String(all.length))} repos on ${scm}.`);
    if (archived.length) {
      const note = opts.includeArchived
        ? 'included'
        : 'skipped — use --include-archived to keep them';
      console.log(c.dim(`  ${archived.length} of them are archived (${note}).`));
    }
    discovered = kept;
    label = `${scm} ${groupWord} ${group}`;
    slug = group.replace(/[^a-zA-Z0-9._-]+/g, '-');
  } else {
    const raw =
      opts.repos ??
      (await ask(
        `  Repo names, comma separated (${
          opts.scm === 'gitlab' ? 'group/project' : 'owner/repo'
        }, or just the name if you give a ${groupWord}): `,
      ));
    const entries = raw
      .split(',')
      .map((e) => e.trim())
      .filter(Boolean);
    if (entries.length === 0) fail('No repo names were given.');

    let group = opts.githubOrg;
    if (!group && entries.some((e) => !e.includes('/'))) {
      group = await ask(`  ${scm} ${groupWord} for the names without one: `);
      if (!group) {
        fail(
          `A ${groupWord} is required — use ${
            opts.scm === 'gitlab' ? 'group/project' : 'owner/repo'
          }, or pass ${opts.scm === 'gitlab' ? '--gitlab-group' : '--github-org'}.`,
        );
      }
    }

    discovered = entries.map((entry) => {
      const ref = entry.includes('/')
        ? splitRepoRef(entry, opts.scm === 'gitlab')
        : { owner: group!, name: entry, branch: undefined };
      if (!ref) fail(`Could not read a repo from "${entry}".`);
      return {
        owner: ref.owner,
        name: ref.name,
        branch: ref.branch ?? '',
        archived: false,
      };
    });
    console.log(`  ${c.bold(String(discovered.length))} repo(s) given.`);
    label = `${discovered.length} repo name(s) from the command line`;
    slug = (group ?? 'repos').replace(/[^a-zA-Z0-9._-]+/g, '-');
  }

  // Turn the discovered repos into a CSV so status write-back works the same.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filePath = opts.outputFile ?? `snyk-import-${slug}-${stamp}.csv`;
  const csv =
    'repo,branch\n' +
    discovered.map((r) => toCsvLine([`${r.owner}/${r.name}`, r.branch])).join('\n') +
    '\n';

  const parsed = parseInputFile(csv, filePath, opts.scm === 'gitlab');
  // These came from the SCM API (or were typed deliberately), so the per-repo
  // existence check only needs to run for the typed ones. Discovered GitLab
  // projects already carry the numeric id the import API needs.
  parsed.rows
    .filter((r) => r.kind === 'repo')
    .forEach((r, i) => {
      r.verified = source === 'github';
      r.projectId = discovered[i]?.projectId;
    });

  console.log(c.dim(`  Statuses will be written to ${filePath}`));
  return { parsed, filePath, sourceLabel: label };
}

/** Printed just before the token prompts so nobody has to go hunting. */
export function printTokenHelp(
  opts: Options,
  snykApiUrl: string,
  needSnyk: boolean,
  needScm: boolean,
): void {
  const appUrl = appUrlFor(snykApiUrl);
  console.log(c.dim('  Where to get these keys:'));

  if (needSnyk) {
    console.log(`
  ${c.bold('Snyk API token')} — ${c.bold(`${appUrl}/account`)}
    1. Log in to Snyk and make sure you are in the right region (the URL above).
    2. Click your avatar / name at the bottom-left, then "Account settings".
    3. Under "Auth Token" (General), click "click to show" and copy the value.
    Notes:
      - The token is tied to that region. A US token will NOT work on EU or AU.
      - A personal token uses your own permissions. For automation, prefer a
        Service Account token: Group or Org settings > Service accounts >
        Create, role "Org Admin" (needed to import), then copy the token once —
        it is only shown at creation time.`);
  }

  if (needScm && opts.scm === 'gitlab') {
    const host = normaliseGitlabUrl(opts.gitlabUrl ?? 'https://gitlab.com');
    console.log(`
  ${c.bold('GitLab token')} — ${c.bold(gitlabTokenPage(host))}
    1. Open ${host} and go to your avatar > Edit profile > Access tokens.
       (On older GitLab: ${host}/-/profile/personal_access_tokens)
    2. Add a new token with the ${c.bold('read_api')} scope. Set an expiry, then create.
    3. Copy the token (glpat-...) — GitLab only shows it once.
    Notes:
      - A group access token or project access token with read_api works too,
        as long as it can see every project you want to import.
      - This token is used to list your projects and to resolve each project's
        numeric id, which the Snyk import API requires for GitLab. It cannot
        be skipped for GitLab the way it can for GitHub.
      - The import itself runs through the GitLab integration already set up
        in Snyk, so Snyk needs its own network access to ${host}.
      - Self-signed certificate? export NODE_EXTRA_CA_CERTS=/path/to/ca.pem`);
  }

  if (needScm && opts.scm !== 'gitlab') {
    const tokenPage = githubTokenPage(opts.githubUrl);
    console.log(`
  ${c.bold('GitHub token')} — ${c.bold(tokenPage)}
    1. GitHub > Settings > Developer settings > Personal access tokens.
    2. "Tokens (classic)" > Generate new token (classic).
    3. Tick the scopes: ${c.bold('repo')} and ${c.bold('read:org')}. Set an expiry, then generate.
    4. Copy the token (ghp_...) — GitHub only shows it once.
    Notes:
      - A fine-grained token also works: give it access to the repos you are
        importing with Repository permissions > Metadata: Read-only.
      - If your GitHub org enforces SAML SSO, click "Configure SSO" next to the
        new token and authorize it for that org, or every repo returns 404.
      - This token is only used to check the repos exist before importing. The
        import itself runs through the GitHub integration already set up in Snyk.
      - Skip this step entirely with --skip-github-check.`);
  }

  const scmEnv = opts.scm === 'gitlab' ? 'GITLAB_TOKEN' : 'GITHUB_TOKEN';
  console.log(
    c.dim(
      `\n  Tip: export SNYK_TOKEN=... and ${scmEnv}=... to skip these prompts next time.\n`,
    ),
  );
}

function countBy(rows: FileRow[], status: Status): number {
  return rows.filter((r) => r.result?.status === status).length;
}

function printSummary(rows: FileRow[], invalidCount: number): void {
  const imported = countBy(rows, 'IMPORTED');
  const partial = countBy(rows, 'PARTIAL');
  const failed = countBy(rows, 'FAILED');
  const notFound = countBy(rows, 'NOT_FOUND');
  const skipped = countBy(rows, 'SKIPPED');
  const queuedOnly = countBy(rows, 'QUEUED');
  const projects = rows.reduce((sum, r) => sum + (r.result?.projects ?? 0), 0);

  console.log(`\n${c.bold('Summary')}`);
  console.log(`  Repos in the list  : ${rows.length}`);
  if (invalidCount) console.log(`  Unparseable rows   : ${c.yellow(String(invalidCount))}`);
  console.log(`  ${c.green('IMPORTED')}           : ${imported}`);
  if (partial) console.log(`  ${c.yellow('PARTIAL')}            : ${partial}`);
  if (queuedOnly) console.log(`  QUEUED (not polled): ${queuedOnly}`);
  if (skipped) console.log(`  SKIPPED            : ${skipped}`);
  if (notFound) console.log(`  ${c.red('NOT_FOUND')}          : ${notFound}`);
  if (failed) console.log(`  ${c.red('FAILED')}             : ${failed}`);
  console.log(`  Snyk projects made : ${projects}`);

  const problems = rows.filter(
    (r) => r.result && ['FAILED', 'NOT_FOUND'].includes(r.result.status),
  );
  if (problems.length) {
    console.log(`\n${c.bold('Needs attention')}`);
    problems
      .slice(0, 20)
      .forEach((r) =>
        console.log(`  ${c.red('✗')} ${r.owner}/${r.name} — ${r.result!.message}`),
      );
    if (problems.length > 20) console.log(c.dim(`  ...and ${problems.length - 20} more`));
    console.log(
      c.dim('\n  Fix the cause, then re-run the same command — IMPORTED rows are skipped automatically.'),
    );
    process.exitCode = 1;
  } else {
    console.log(c.green('\nAll done.'));
  }
}

function writeReport(
  outDir: string,
  payload: {
    baseUrl: string;
    orgId: string;
    integrationId: string;
    file: string;
    rows: FileRow[];
  },
): string {
  fs.mkdirSync(outDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportPath = path.join(outDir, `import-${stamp}.json`);

  fs.writeFileSync(
    reportPath,
    JSON.stringify(
      {
        ranAt: new Date().toISOString(),
        snykApi: payload.baseUrl,
        orgId: payload.orgId,
        integrationId: payload.integrationId,
        inputFile: path.resolve(payload.file),
        repos: payload.rows.map((r) => ({
          repo: `${r.owner}/${r.name}`,
          branch: r.branch,
          status: r.result?.status ?? 'UNKNOWN',
          projects: r.result?.projects ?? 0,
          details: r.result?.message,
          pollingUrl: r.result?.pollingUrl,
        })),
      },
      null,
      2,
    ),
  );
  return reportPath;
}

// Set SNYK_BULK_IMPORT_LIB=1 to import the helpers above without running the CLI.
if (process.env.SNYK_BULK_IMPORT_LIB !== '1') {
  main()
    .catch((error) => {
      console.error(c.red(`\nUnexpected error: ${error?.message ?? error}`));
      if (process.env.DEBUG) console.error(error);
      process.exitCode = 1;
    })
    .finally(closeReadline);
}
