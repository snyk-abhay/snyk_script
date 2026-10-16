#!/usr/bin/env node
/**
 * snyk-auto-report -- a complete, uncapped vulnerability report from your own
 * Snyk data.
 *
 * WHY THIS EXISTS
 * ---------------
 * Snyk's Reports tab caps PDF table exports at the first 50 rows. For anyone
 * with a real backlog, the document that goes to an auditor or a customer
 * security review is truncated to the point of being useless, and the CSV
 * alternative is a spreadsheet, not a report. This produces the whole thing.
 *
 * WHAT IT WILL NOT DO
 * -------------------
 * It will not show you a blank column and let you read it as "clean". Every
 * ingestion path carries a different subset of Snyk's fields, so the report
 * distinguishes "Snyk had nothing to report" from "this data source cannot
 * tell you", and says which is which. See lib/model.mts.
 *
 * STATUS: the CSV, Export API, Issues REST and Tests v2 (dataflow) paths are
 * all implemented.
 *
 * USAGE
 *   node snyk_report/snyk-auto-report.mts --csv issues.csv --format html,pdf
 *   node snyk_report/snyk-auto-report.mts --csv issues.csv --out audit --title "Q3 review"
 *   node snyk_report/snyk-auto-report.mts --from-issues-api --region us --org <id>
 *       --target owner/repo     (live data, for a scan that just finished)
 *   node snyk_report/snyk-auto-report.mts --from-tests-api --org <id> \
 *       --repo-url https://github.com/org/repo --integration-id <id> --ref main
 */

import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { buildReport, countBySeverity } from './lib/aggregate/build.mts';
// import { mergeAvailability } from './lib/availability.mts'; // see disabled dataflow block
import { listTargets, resolveOrg, tryList } from './lib/discover.mts';
import { ingestCsvFile } from './lib/ingest/csv-file.mts';
import type { IngestOutcome } from './lib/ingest/csv-file.mts';
import {
  downloadExport,
  describeSince,
  isIsoDate,
  fetchExportResult,
  sinceToFilters,
  startExport,
  waitForExport,
} from './lib/ingest/export-api.mts';
import type { ExportFilters, ExportScope } from './lib/ingest/export-api.mts';
import { ingestIssuesApi } from './lib/ingest/issues-api.mts';
import { checkExportFreshness } from './lib/freshness.mts';
import { ingestCliResults, runCliScans } from './lib/ingest/cli-scan.mts';
import { attachSourceContext } from './lib/source-context.mts';
import { enrichIssueDetails } from './lib/ingest/enrich-details.mts';
import { REGIONS, describeRegion, resolveRegion } from './lib/regions.mts';
import {
  fetchTestComponents,
  ingestTestsApiFindings,
  startCodeTest,
  waitForCodeTest,
} from './lib/ingest/tests-api.mts';
import type { CodeTestResource } from './lib/ingest/tests-api.mts';
import {
  askCsvPath,
  askOutputPath,
  askScanFolder,
  askSourcePath,
  selectCliScans,
  connect,
  selectSource,
  selectDetailDepth,
  selectFormats,
  selectProducts,
  selectScope,
  selectSeverities,
  selectStatuses,
  selectSince,
} from './lib/interactive.mts';
import { InputClosedError, closePrompts, isInteractive } from './lib/prompt.mts';
import { parseProducts } from './lib/interactive.mts';
import type { IssueStatus, Product, Severity } from './lib/model.mts';
import { log, c } from './lib/log.mts';
import type { SnykClient } from './lib/http.mts';
import { toCsvLine } from './lib/csv.mts';
import { read, SEVERITIES } from './lib/model.mts';
import type { Issue } from './lib/model.mts';
import { renderHtml } from './lib/render/html.mts';
import type { ReportMeta } from './lib/render/html.mts';
import { exportPdf } from './lib/render/pdf.mts';

const HELP = `
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
  --since <p>           7d | 14d | 30d | 90d | 180d | 365d | 2y | all, or a start
                        date YYYY-MM-DD   (the API requires a period)
  --until <date>        end date YYYY-MM-DD, inclusive (Export API only)
  --severity <list>     critical,high,medium,low or all
  --product <list>      sca,sast,container,iac,secrets or all
                        (which scanners to include; asked for interactively)
  --export-id <id>      re-attach to an export already running or finished.
                        Results live for 3 days; use this after a timeout
                        rather than spending another of your 20 exports/hour.
  --export-timeout <m>  minutes to wait for the job (default: 30)

  The Export API reads Snyk's reporting store, which refreshes about every
  2 hours, so a scan that just finished may not be in it yet. Each run checks
  recently tested projects against the export and warns when they disagree.

Or read live results (Issues REST API) -- use this right after a scan:
  --from-issues-api     read the live issue store the project page uses.
                        Takes the same --region, --org, --group, --target,
                        --project and --since flags as --from-api. Carries
                        Snyk Code data flows; does not carry EPSS, CISA KEV,
                        computed fixability or deleted issues.
  --no-dataflow         skip Snyk Code data flows (smaller, faster responses)
  --no-details          do not fetch Snyk's description, remediation advice and
                        code flow for the findings that get a detail page. By
                        default, with an API token, they are read back from the
                        Issues API (one request per project) because the CSV
                        and Export API carry none of that text.

Or scan a local folder with the Snyk CLI, and report on that:
  --from-cli            run "snyk code test" and "snyk test --all-projects" in
                        --path, then build the report. Every Code finding gets
                        its data flow with the actual code at each step.
                        Uses the CLI's own login (snyk auth) or SNYK_TOKEN.
  --path <dir>          folder to scan (default: the current folder). With any
                        other source, a local checkout to read the code at each
                        data-flow step from.
  --product <list>      sast and/or sca: which of the two scans to run
  --org <id|slug>       passed to the CLI as --org (default: the CLI's org)
  --region <r>          sets the CLI's API region (default: the CLI's config)
  --cli-results <list>  skip scanning; report on SARIF / snyk test --json files
                        you already have, comma separated
  --scan-timeout <m>    minutes each scan may take (default: 10)

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

function fail(msg: string): never {
  log.error(msg);
  process.exit(1);
}

async function main(): Promise<number> {
  const { values } = parseArgs({
    options: {
      csv: { type: 'string' },
      'from-api': { type: 'boolean', default: false },
      region: { type: 'string' },
      org: { type: 'string' },
      group: { type: 'string' },
      target: { type: 'string' },
      project: { type: 'string' },
      since: { type: 'string' },
      until: { type: 'string' },
      severity: { type: 'string' },
      product: { type: 'string' },
      'export-id': { type: 'string' },
      'export-timeout': { type: 'string', default: '30' },
      'from-issues-api': { type: 'boolean', default: false },
      'from-cli': { type: 'boolean', default: false },
      path: { type: 'string' },
      'cli-results': { type: 'string' },
      'from-tests-api': { type: 'boolean', default: false },
      'repo-url': { type: 'string' },
      'integration-id': { type: 'string' },
      ref: { type: 'string' },
      commit: { type: 'string' },
      'file-patterns': { type: 'string' },
      'job-id': { type: 'string' },
      'test-id': { type: 'string' },
      'scan-timeout': { type: 'string', default: '10' },
      'no-dataflow': { type: 'boolean', default: false },
      'no-details': { type: 'boolean', default: false },
      // No parseArgs defaults for options that gate an interactive question.
      // A default is indistinguishable from the user having typed the value,
      // so the guard `!values.x` is never true and the prompt is dead code.
      // This bit --format and then --top; the fallbacks live at the point of
      // use instead, where they only affect the non-interactive path.
      out: { type: 'string' },
      // No parseArgs default. A default here is indistinguishable from the
      // user having passed --format, so `!values.format` was never true and
      // the interactive format question could never fire. The html fallback
      // is applied further down instead, where it only affects the
      // non-interactive path.
      format: { type: 'string' },
      title: { type: 'string' },
      subtitle: { type: 'string' },
      'prepared-for': { type: 'string' },
      'prepared-by': { type: 'string' },
      'report-id': { type: 'string' },
      classification: { type: 'string' },
      period: { type: 'string' },
      logo: { type: 'string' },
      'include-deleted': { type: 'boolean', default: false },
      status: { type: 'string' },
      'max-detail-rows': { type: 'string' },
      top: { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    allowPositionals: false,
  });

  if (values.help) {
    process.stderr.write(`${HELP}\n`);
    return 0;
  }

  const useTestsApi = values['from-tests-api'];
  let useIssuesApi = values['from-issues-api'];
  let useCli = values['from-cli'] || values['cli-results'] !== undefined;

  if (useCli) {
    const others = [
      values.csv && '--csv',
      values['from-api'] && '--from-api',
      useIssuesApi && '--from-issues-api',
      useTestsApi && '--from-tests-api',
    ].filter(Boolean);
    if (others.length) fail(`pass --from-cli on its own, not together with ${others.join(', ')}.`);
    // These select data already in Snyk. A CLI run scans --path instead, so
    // accepting them would suggest a narrowing that never happens.
    for (const f of ['group', 'target', 'project', 'since', 'until', 'export-id'] as const) {
      if (values[f] !== undefined) fail(`--${f} does not apply to --from-cli, which scans --path.`);
    }
  }
  if (useIssuesApi && useTestsApi) fail('pass either --from-issues-api or --from-tests-api, not both.');
  if (useIssuesApi && (values['from-api'] || values.csv)) {
    fail('pass --from-issues-api on its own, not together with --csv or --from-api.');
  }
  if (values.until !== undefined) {
    if (!isIsoDate(values.until)) fail(`--until ${values.until} is not a date. Use YYYY-MM-DD.`);
    if (useIssuesApi) fail('--until applies to the Export API only; the Issues API has no end-date filter.');
  }
  if (useIssuesApi && values['export-id']) {
    fail('--export-id re-attaches to an Export API job; it has no meaning with --from-issues-api.');
  }

  // Any API-shaped flag implies --from-api, so people do not have to pass
  // both --org and --from-api to mean the obvious thing. The other sources
  // are excluded from this heuristic: they take --org too, and that must not
  // silently redirect the run into the Export API branch.
  const apiFlags = ['region', 'org', 'group', 'since', 'until', 'export-id', 'target'] as const;
  let useApi =
    !useTestsApi &&
    !useIssuesApi &&
    !useCli &&
    (values['from-api'] || apiFlags.some((f) => values[f] !== undefined));

  if (useTestsApi && (useApi || values.csv)) {
    fail('pass --from-tests-api on its own, not together with --csv or --from-api.');
  }
  if (useApi && values.csv) fail('pass either --csv or --from-api, not both.');
  if (useTestsApi && !values['test-id'] && !values['job-id'] && !(values['repo-url'] && values['integration-id'])) {
    fail('--from-tests-api needs --test-id, or --job-id, or --repo-url plus --integration-id.');
  }
  if (useTestsApi && !values['test-id'] && !values['job-id'] && !values.ref && !values.commit) {
    fail('--from-tests-api with --repo-url needs --ref and/or --commit.');
  }
  if (useTestsApi && !values.org) {
    fail('--from-tests-api needs --org <org_id> (the Tests API has no group scope).');
  }

  // Nothing specified. In a terminal, ask -- someone running this for the
  // first time should not have to read --help to get started. In a script,
  // there is nobody to ask, so say what to pass.
  let csvPathFromPrompt: string | undefined;
  if (!useApi && !useTestsApi && !useIssuesApi && !useCli && !values.csv) {
    if (!isInteractive()) {
      fail(
        'nothing to report on. Pass --csv <file>, --from-api, --from-issues-api, --from-cli or ' +
          '--from-tests-api, or --help for usage.',
      );
    }
    const source = await selectSource();
    if (source === 'api') useApi = true;
    else if (source === 'issues-api') useIssuesApi = true;
    else if (source === 'cli') useCli = true;
    else csvPathFromPrompt = await askCsvPath();
  }
  if (useIssuesApi && values['include-deleted']) {
    log.warn('--include-deleted has no effect here: the Issues API never returns deleted issues.');
  }

  // Validate every cheap string spec before doing anything expensive. Failing
  // on a typo after reading a 12MB CSV, or worse after spending one of 20
  // hourly exports, is a bad trade for a check that costs nothing.
  try {
    await selectSeverities(values.severity ?? 'all');
    await selectSince(values.since ?? 'all');
    parseProducts(values.product ?? 'all');
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  let sourceLabel: string;
  let sourceDetail: string;
  let outcome: IngestOutcome;
  let scopeLabel: string | null = null;
  let periodLabel = 'all time';
  let regionLabel: string | null = null;
  let severities: Severity[] = [...SEVERITIES];
  // Only the Export API path has a live token+client to run a dataflow
  // rescan with; CSV has neither, and Tests v2 already carries its own flow.
  let apiClient: SnykClient | null = null;
  let projectFilter: string[] | undefined;
  // Recorded so a zero-findings report can still say WHAT it examined. With
  // no rows the data names nothing, so the scope has to come from the request.
  let targetFilter: string[] | undefined;
  let scopeOrgIds: string[] | undefined;
  let formatSpec = values.format;
  let dataAsOf: string | null = null;
  let freshness: string | null = null;
  // Where to read code from for data-flow steps: the scanned folder on the
  // CLI path, --path on any other.
  let codeRoot: string | null = values.path ? resolve(values.path) : null;
  // Asked during a CLI run instead of after it; see selectCliScans().
  let productSpec = values.product;
  let examinedTargetsFromSource: string[] | undefined;

  if (useApi || useIssuesApi) {
    const conn = await connect({ region: values.region, token: process.env['SNYK_TOKEN'] });
    regionLabel = conn.regionLabel;
    apiClient = conn.client;

    const selection = await selectScope(conn, {
      group: values.group,
      org: values.org,
      target: values.target,
      project: values.project,
    });
    scopeLabel = selection.scope.label;
    projectFilter = selection.projectNames;
    targetFilter = selection.targetNames;
    // Org scope puts the org in scope.id; group scope carries the orgs here.
    scopeOrgIds = selection.orgIds ?? (selection.scope.kind === 'orgs' ? [selection.scope.id] : undefined);

    const since = await selectSince(values.since);
    const until = values.until;
    if (until && since !== 'all' && /^\d{4}-/.test(since) && until < since) {
      fail(`--until ${until} is before --since ${since}.`);
    }
    periodLabel = describeSince(since, until);
    sourceDetail = `${selection.scope.label} - ${conn.regionLabel}`;

    if (useIssuesApi) {
      log.step(`Reading live issues for ${selection.scope.label}`);
      outcome = await ingestIssuesApi(conn.client, {
        scope: selection.scope,
        orgIds: selection.orgIds,
        targetNames: selection.targetNames,
        // "All time" needs no date here: unlike the export, this endpoint
        // does not demand one.
        createdAfter: since === 'all' ? undefined : sinceToFilters(since).introducedFrom,
        includeCodeFlows: !values['no-dataflow'],
      });
      sourceLabel = 'Snyk Issues API (live)';
      dataAsOf = `Live issue data, read ${new Date().toLocaleString(undefined, {
        dateStyle: 'long',
        timeStyle: 'short',
      })}`;
    } else {
      const filters: ExportFilters = {
        ...sinceToFilters(since, until),
        ...(selection.orgIds ? { orgs: selection.orgIds } : {}),
        ...(selection.targetNames ? { targetDisplayNames: selection.targetNames } : {}),
      };

      outcome = await runExport(
        conn.client,
        selection.scope,
        filters,
        values['export-id'],
        Number(values['export-timeout']) || 30,
        values['include-deleted']!,
      );
      sourceLabel = 'Snyk Export API';

      // The export lags new scans by up to ~2 hours and never says so. Catch
      // the "I just scanned, why is it missing" case here, before the report
      // goes out describing the state before the scan.
      freshness = await checkExportFreshness(conn.client, {
        scope: selection.scope,
        orgIds: selection.orgIds,
        targetNames: selection.targetNames,
        exported: outcome.issues,
        allTime: since === 'all' && !until,
      });
    }
  } else if (useTestsApi) {
    const conn = await connect({ region: values.region, token: process.env['SNYK_TOKEN'] });
    regionLabel = conn.regionLabel;
    // --org accepts a name as well as a UUID here too, same as the Export
    // API path: an unresolvable org would otherwise fail deep inside the
    // Tests v2 POST with a bare 404 instead of naming the actual problem.
    const org = await resolveOrg(conn.client, values.org!);
    const orgId = org.id;
    scopeLabel = `Organisation ${org.name}`;
    periodLabel = 'point-in-time scan';

    outcome = await runTestsApiScan(conn.client, orgId, {
      repoUrl: values['repo-url'],
      integrationId: values['integration-id'],
      ref: values.ref,
      commit: values.commit,
      filePatterns: values['file-patterns'],
      jobId: values['job-id'],
      testId: values['test-id'],
      scanTimeoutMs: (Number(values['scan-timeout']) || 10) * 60_000,
    });
    sourceLabel = 'Snyk Code Tests API (source→sink dataflow)';
    sourceDetail = `${scopeLabel} - ${conn.regionLabel}`;
  } else if (useCli) {
    // --path, or ask, or the current folder: the scan and the code shown
    // for every data-flow step both come from here.
    const dir = values.path
      ? resolve(values.path)
      : isInteractive() && !values['cli-results']
        ? await askScanFolder()
        : process.cwd();
    codeRoot = dir;
    scopeLabel = `Local folder ${basename(dir)}`;
    periodLabel = 'point-in-time scan';
    sourceLabel = 'Snyk CLI scan';
    sourceDetail = dir;
    examinedTargetsFromSource = [basename(dir)];

    let apiUrl: string | undefined;
    if (values.region) {
      const url = resolveRegion(values.region);
      if (!url) fail(`unknown --region ${values.region}. Use one of: ${REGIONS.map((r) => r.key).join(', ')}.`);
      apiUrl = url;
      regionLabel = describeRegion(url);
    }

    if (values['cli-results']) {
      const files = values['cli-results'].split(',').map((f) => resolve(f.trim())).filter(Boolean);
      log.step(`Reading ${files.length} CLI result file(s)`);
      outcome = await ingestCliResults(files, { dir, org: values.org });
    } else {
      // Products decide which scans run at all, not just what is kept after.
      const wanted = parseProducts(values.product ?? 'all');
      let scans = {
        code: wanted === 'all' || wanted.includes('code'),
        openSource: wanted === 'all' || wanted.includes('open-source'),
      };
      if (!values.product && isInteractive()) {
        scans = await selectCliScans();
        productSpec = [scans.code && 'sast', scans.openSource && 'sca'].filter(Boolean).join(',');
      }
      if (!scans.code && !scans.openSource) {
        fail('--from-cli runs Snyk Code (sast) and Open Source (sca) scans; --product names neither.');
      }
      const run = await runCliScans({
        dir,
        code: scans.code,
        openSource: scans.openSource,
        org: values.org,
        apiUrl,
        timeoutMs: (Number(values['scan-timeout']) || 10) * 60_000,
      });
      try {
        outcome = await ingestCliResults(run.files, { dir, ran: scans, org: values.org });
      } finally {
        await run.cleanup();
      }
      sourceLabel = `Snyk CLI ${run.version} scan`;
    }
  } else {
    const csvPath = csvPathFromPrompt ?? resolve(values.csv!);
    log.step(`Reading ${csvPath}`);
    outcome = await ingestCsvFile(csvPath, {
      source: 'csv',
      includeDeleted: values['include-deleted']!,
    });
    sourceLabel = 'Snyk CSV export';
    sourceDetail = csvPath;
  }

  // DISABLED FOR NOW (2026-09-11) -- the auto dataflow enrichment below is
  // commented out at Abhay's request so --from-api stays quiet and fast.
  //
  // It was not merely noisy, it was failing: waitForCodeTest() rejected every
  // finished job with "finished with no test id". The terminal response does
  // carry the id -- it is data.id, with data.type "tests" -- so extractTestId()
  // is looking in the wrong place. Every scan therefore cost its full runtime
  // and then threw, and the run logged a wall of JSON for nothing.
  //
  // Re-enabling means fixing extractTestId() in lib/ingest/tests-api.mts first.
  // --no-dataflow is still accepted so existing scripts do not break; on this
  // path it has nothing to turn off. It now only skips Code data flows on
  // --from-issues-api, and the --from-tests-api path still carries dataflow
  // directly.

  // // Export API SAST issues never carry a dataflow -- attach one automatically
  // // rather than making that a separate command. One Tests v2 scan per
  // // distinct (repo, branch), matched back onto the existing issues; anything
  // // that cannot be resolved to a scannable GitHub repo is skipped and
  // // counted, never guessed at. --csv has no client to scan with, and
  // // --from-tests-api already carries the flow directly.
  // if (useApi && apiClient && !values['no-dataflow']) {
  //   const sastCount = outcome.issues.filter((i) => i.product === 'code').length;
  //   if (sastCount > 0) {
  //     log.step(`Attaching Source→Sink dataflow to ${fmt2(sastCount)} SAST issue(s) (--no-dataflow to skip)`);
  //     const enrich = await enrichSastWithDataflow(apiClient, outcome.issues, {
  //       scanTimeoutMs: (Number(values['scan-timeout']) || 10) * 60_000,
  //     });
  //     outcome = {
  //       issues: enrich.issues,
  //       summary: {
  //         ...outcome.summary,
  //         availability:
  //           enrich.matched > 0
  //             ? mergeAvailability([outcome.summary.availability, enrich.availability])
  //             : outcome.summary.availability,
  //       },
  //     };
  //     log.info(
  //       `dataflow: ${fmt2(enrich.matched)} issue(s) matched across ${fmt2(enrich.targetsScanned)} target(s)` +
  //         (enrich.targetsSkipped
  //           ? `; ${fmt2(enrich.targetsSkipped)} SAST issue(s) skipped (no resolvable GitHub repo + branch)`
  //           : '') +
  //         (enrich.targetsFailed.length ? `; ${fmt2(enrich.targetsFailed.length)} target(s) failed` : ''),
  //     );
  //   }
  // }

  // Show the code. No API returns it, so this needs the source on disk --
  // and on the API paths, someone to say where it is.
  if (!codeRoot && isInteractive() && outcome.issues.some((i) => read(i, 'dataflow').state === 'present')) {
    codeRoot = await askSourcePath();
  }
  if (codeRoot) {
    const ctx = await attachSourceContext(outcome.issues, codeRoot);
    outcome = { ...outcome, issues: ctx.issues };
    if (ctx.enriched) log.dim(`code shown for ${fmt2(ctx.enriched)} finding(s) from ${codeRoot}`);
    if (ctx.missing.length) {
      log.warn(
        `${fmt2(ctx.missing.length)} file(s) named by Snyk are not in ${codeRoot} ` +
          `(e.g. ${ctx.missing.slice(0, 3).join(', ')}); is it the same repository and commit?`,
      );
    }
  }

  const { issues, summary } = outcome;



  const d = summary.dropped;
  log.info(
    `${summary.rowsRead.toLocaleString()} rows read, ${issues.length.toLocaleString()} issues kept`,
  );
  if (d.deleted) log.dim(`${d.deleted.toLocaleString()} deleted (use --include-deleted to keep)`);
  if (d.duplicate) log.dim(`${d.duplicate.toLocaleString()} duplicate rows collapsed`);
  if (d.unparseable) {
    log.warn(`${d.unparseable.toLocaleString()} rows could not be parsed`);
    for (const p of summary.problems.slice(0, 3)) log.dim(p);
  }
  if (summary.unknownColumns.length) {
    log.dim(`unrecognised columns kept but unused: ${summary.unknownColumns.join(', ')}`);
  }
  if (summary.keyStrength === 'weak') {
    log.dim(
      'no ASSET_FINDING_ID or ISSUE_URL column, so findings have no Snyk-assigned id; ' +
        'nothing was de-duplicated',
    );
    if (summary.weakKeyCollisions) {
      log.dim(
        `${summary.weakKeyCollisions.toLocaleString()} rows share a synthesised key and were ` +
          `all kept (they may or may not be true duplicates)`,
      );
    }
  }
  // Asked after the summary above, so the operator picks with real counts in
  // front of them. Scanners FIRST, then severities -- because the severities
  // that exist depend on the scanners chosen. Asked the other way round, a
  // SAST-only report offers Critical (which SAST never produces here) and
  // dead-ends on an empty selection four questions in.
  const productTotals = new Map<Product, number>();
  for (const i of issues) productTotals.set(i.product, (productTotals.get(i.product) ?? 0) + 1);
  const wantProducts = await selectProducts(
    productSpec,
    [...productTotals]
      .map(([product, total]) => ({ product, total }))
      .sort((a, b) => b.total - a.total),
  );

  let kept = issues;

  if (wantProducts.length && wantProducts.length < productTotals.size) {
    const want = new Set<Product>(wantProducts);
    const before = kept.length;
    kept = kept.filter((i) => want.has(i.product));
    log.dim(`scanners ${wantProducts.join(',')} kept ${fmt2(kept.length)} of ${fmt2(before)}`);
  }

  severities = await selectSeverities(values.severity, countBySeverity(kept));

  const statusCounts: Record<IssueStatus, number> = { open: 0, resolved: 0, ignored: 0 };
  for (const i of kept) statusCounts[i.status]++;

  let wantStatuses: IssueStatus[];
  try {
    wantStatuses = await selectStatuses(values.status, statusCounts);
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  if (wantStatuses.length < 3) {
    const want = new Set<IssueStatus>(wantStatuses);
    const before = kept.length;
    kept = kept.filter((i) => want.has(i.status));
    if (kept.length !== before) {
      log.dim(`status ${wantStatuses.join(',')} kept ${fmt2(kept.length)} of ${fmt2(before)}`);
    }
  }

  // Severity is filtered here rather than in the export request. The API
  // only gained an effective_severity filter in March 2026, after the version
  // this tool pins, so sending it could 400 a request that costs one of 20
  // per hour. Filtering locally is always correct.
  if (severities.length < SEVERITIES.length) {
    const wanted = new Set(severities);
    const before = kept.length;
    kept = kept.filter((i) => wanted.has(i.severity));
    log.dim(`severity ${severities.join(',')} kept ${kept.length} of ${before}`);
  }

  // Projects likewise: the Export API has no project filter, so the docs
  // direct you to post-filter on the project column.
  if (projectFilter?.length) {
    const wanted = new Set(projectFilter.map((p2) => p2.toLowerCase()));
    const before = kept.length;
    kept = kept.filter((i) => {
      const name = i.project?.name ?? i.project?.targetDisplayName ?? '';
      return wanted.has(name.toLowerCase());
    });
    log.dim(`project filter kept ${kept.length} of ${before}`);
    if (kept.length === 0) {
      log.warn('no issue matched those project names; check the spelling against the report');
    }
  }

  if (kept.length === 0) {
    if (issues.length === 0) {
      // A source that parsed fine and simply contained no findings is a
      // clean bill of health, and "we scanned and found nothing" is a
      // report someone genuinely needs. Only a source that yielded no rows
      // AND no header is a data problem.
      // A source that reported "nothing here" is clean. A source that gave
      // us neither a header nor rows AND never said so is malformed, and
      // must not be dressed up as a clean bill of health.
      if (!summary.noFindings && summary.rowsRead === 0 && summary.header.columns.length === 0) {
        fail('the data source was empty -- no header, no rows. Nothing was scanned.');
      }
      log.info(c.green('no vulnerabilities in the supplied data — writing a clean report'));
    } else {
    // Filters excluded everything. That IS the finding -- "no critical SAST
    // issues" is exactly the attestation someone asks a report for -- so it
    // is written, clearly labelled, rather than refused.
      log.warn(
        `no issue matches those filters (${fmt2(issues.length)} were read). ` +
          'Writing a nil-return report that records the filters and states the result.',
      );
    }
  }

  // A clean report is only worth anything if a reader can tell what was
  // examined. When targets were picked by name we already know; when the run
  // covered a whole organisation the data has no rows to name them, so ask
  // the API. Best effort only -- a report that lists no targets is still
  // truthful, one that claims the wrong ones is not.
  let examinedTargets: string[] | undefined = targetFilter ?? examinedTargetsFromSource;
  if (!examinedTargets?.length && issues.length === 0 && apiClient && scopeOrgIds?.length === 1) {
    const found = await tryList('targets', () => listTargets(apiClient!, scopeOrgIds![0]!));
    if (found?.length) examinedTargets = found.map((t) => t.name);
  }

  // Put the chosen target on the cover. On a clean report especially, a
  // cover that says only "Organisation X" leaves the reader unable to tell
  // which repository the document is actually about.
  const scopeWithTargets =
    scopeLabel && targetFilter?.length
      ? `${scopeLabel} - ${
          targetFilter.length === 1 ? targetFilter[0] : `${fmt2(targetFilter.length)} targets`
        }`
      : scopeLabel;

  // Output questions come after the content ones: choosing a format before
  // knowing what -- or how much -- is going into it is the wrong order, and
  // the pdf size warning below needs the answer.
  if (!values.format && isInteractive()) {
    formatSpec = (await selectFormats(undefined)).join(',');
  }

  const formats = new Set(
    (formatSpec ?? 'html')
      .split(',')
      .map((f) => f.trim().toLowerCase())
      .filter(Boolean),
  );
  for (const f of formats) {
    if (!['html', 'pdf', 'csv', 'json'].includes(f)) fail(`unknown --format value: ${f}`);
  }
  // A PDF is rendered from the HTML, so the HTML has to exist -- but only as
  // an intermediate unless it was asked for. Adding it to `formats` and
  // leaving it there meant asking for PDF alone produced two files.
  const wantHtml = formats.has('html');
  if (formats.has('pdf')) formats.add('html');

  const maxDetail = values['max-detail-rows'] ? Number(values['max-detail-rows']) : undefined;
  if (maxDetail !== undefined && !Number.isFinite(maxDetail)) {
    fail('--max-detail-rows must be a number');
  }

  // Asked here rather than only exposed as --top: the guided flow used to
  // hand everyone the default of 25 with no hint that more was possible.
  let topN: number;
  try {
    topN = await selectDetailDepth(values.top, kept.length, formats.has('pdf'));
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }

  const reportOpts = {
    topN,
    ...(maxDetail === undefined ? {} : { maxDetailRows: maxDetail }),
  };
  let data = buildReport(kept, summary.availability, reportOpts);

  // The CSV and Export API carry no description, remedy text or code flow, so
  // a detail page built from them can only say a title and an id. When there
  // is a token, read those back from the Issues API for exactly the findings
  // that get a detail page. Ranking is untouched: only prose and flow are added.
  if (apiClient && !values['no-details'] && data.topRisks.length) {
    const lacking = data.topRisks.filter(
      (i) => read(i, 'description').state !== 'present' || read(i, 'remediationText').state !== 'present',
    );
    if (lacking.length) {
      log.step(`Fetching Snyk's description and remediation for ${fmt2(lacking.length)} detail page(s)`);
      try {
        const enr = await enrichIssueDetails(apiClient, lacking, kept, {
          includeCodeFlows: !values['no-dataflow'],
        });
        if (enr.enriched) {
          kept = enr.issues;
          data = buildReport(kept, summary.availability, reportOpts);
        }
        log.info(
          `details: ${fmt2(enr.enriched)} of ${fmt2(lacking.length)} finding(s) enriched` +
            (enr.unmatched ? `; ${fmt2(enr.unmatched)} had no single matching live issue` : '') +
            (enr.unmatchable ? `; ${fmt2(enr.unmatchable)} had no project or problem id to match on` : '') +
            (enr.failedProjects.length ? `; ${fmt2(enr.failedProjects.length)} project lookup(s) failed` : ''),
        );
      } catch (err) {
        // Best effort: the report is already complete without this layer.
        log.warn(`could not fetch issue details: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  // Detail pages are roughly one page each, so this is the dominant cost of
  // a large PDF -- far more than the register. Warn with a real estimate
  // rather than letting someone discover it after a 20-minute render.
  if (formats.has('pdf') && data.topRisks.length > 250) {
    log.warn(
      `${fmt2(data.topRisks.length)} detail pages requested. That is roughly ` +
        `${fmt2(data.topRisks.length)} PDF pages and can take many minutes to render. ` +
        `Lower --top, or drop pdf from --format and use the scrollable HTML.`,
    );
  }

  // An uncapped register is technically correct and practically unusable, so
  // warn rather than silently producing a 40MB artifact.
  // 5 fixed pages, ~15 register rows to a page, one page per detail write-up,
  // plus the appendix. Rough by design -- it exists to catch "you are about to
  // make a 2,000-page PDF", not to be accurate to the sheet.
  if (formats.has('pdf')) {
    const pages = 5 + Math.ceil(data.detailIssues.length / 15) + data.topRisks.length + 1;
    if (pages > 250) {
      log.warn(
        `${data.total.toLocaleString()} issues will render roughly ` +
          `${pages.toLocaleString()} A4 pages. Use --max-detail-rows to cap the register and ` +
          `--top to cap the detail pages; CSV and JSON stay complete.`,
      );
    }
  }
  if (data.cisaKevCount) {
    log.info(c.red(`${data.cisaKevCount} issue(s) in CISA's Known Exploited Vulnerabilities catalogue`));
  }

  if (data.total > 0 && data.rankingInputsUnavailable.length) {
    log.warn(
      `ranking could not use: ${data.rankingInputsUnavailable.join(', ')} ` +
        `(not carried by this data source)`,
    );
  }

  // Inlined rather than linked: the HTML has to render from a file:// URL on a
  // machine with no network, and the PDF is produced by pointing Chrome at
  // that same file.
  let logo: string | null = null;
  if (values.logo) {
    const p = resolve(values.logo);
    const ext = p.slice(p.lastIndexOf('.') + 1).toLowerCase();
    const mime =
      ext === 'svg' ? 'image/svg+xml' : ext === 'jpg' || ext === 'jpeg' ? 'image/jpeg' : `image/${ext}`;
    try {
      logo = `data:${mime};base64,${(await readFile(p)).toString('base64')}`;
    } catch {
      fail(`could not read --logo ${p}`);
    }
  }

  const meta: ReportMeta = {
    title: values.title ?? 'Snyk vulnerability report',
    preparedFor: values['prepared-for'] ?? null,
    generatedAt: new Date().toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' }),
    sourceLabel,
    sourceDetail,
    // describeScope() reads the issues, so with none it returns
    // "0 organisations" -- true, useless, and alarming on a clean report.
    // Name the file instead; that is what the reader needs to identify.
    scope: scopeWithTargets ?? (issues.length ? describeScope(issues) : (sourceDetail ?? sourceLabel)),
    // From the examined set, not the filtered one, so a nil return still
    // names the organisation it examined.
    // ... and when there are no issues at all, fall back to the scope that
    // was requested. Without this a clean report names no organisation
    // anywhere and the running header reads "this organisation".
    orgLabel:
      [...new Set(issues.map((i) => i.org.name ?? i.org.id))].join(', ') || scopeLabel || undefined,
    scannersRequested: wantProducts,
    ...(examinedTargets?.length ? { scopeTargets: examinedTargets } : {}),
    ...(projectFilter?.length ? { scopeProjects: projectFilter } : {}),
    targetsWereFiltered: Boolean(targetFilter?.length),
    sourceHadFindings: issues.length > 0,
    filters: [
      `period: ${periodLabel}`,
      `severity: ${severities.length === 4 ? 'all' : severities.join(', ')}`,
      `scanners: ${
        wantProducts.length === new Set(issues.map((i) => i.product)).size
          ? 'all'
          : wantProducts.join(', ')
      }`,
      values['include-deleted'] ? 'including deleted issues' : 'excluding deleted issues',
      `status: ${wantStatuses.length === 3 ? 'all' : wantStatuses.join(', ')}`,
      ...(targetFilter?.length ? [`targets: ${targetFilter.join(', ')}`] : []),
      ...(projectFilter ? [`projects: ${projectFilter.join(', ')}`] : []),
    ].join('; '),
    ...(regionLabel ? { region: regionLabel } : {}),
    ...(dataAsOf ? { dataAsOf } : {}),
    ...(freshness ? { freshness } : {}),
    rowsRead: summary.rowsRead,
    dropped: summary.dropped,
    // Absent keys rather than nulls: the renderer omits the cover's report-id
    // line entirely when none was given, instead of printing an empty label.
    ...(values.subtitle === undefined ? {} : { subtitle: values.subtitle }),
    ...(values['prepared-by'] === undefined ? {} : { preparedBy: values['prepared-by'] }),
    ...(values['report-id'] === undefined ? {} : { reportId: values['report-id'] }),
    ...(values.classification === undefined ? {} : { classification: values.classification }),
    ...(values.period === undefined ? {} : { period: values.period }),
    ...(logo === null ? {} : { logo }),
  };


  const chosenOut = values.out ?? (isInteractive() ? await askOutputPath('snyk-report') : 'snyk-report');
  const base = resolve(chosenOut);
  await mkdir(dirname(base), { recursive: true });
  const written: string[] = [];

  if (formats.has('html')) {
    const html = renderHtml(data, summary.availability, meta);
    await writeFile(`${base}.html`, html, 'utf8');
    if (wantHtml) written.push(`${base}.html`);
  }

  if (formats.has('csv')) {
    await writeFile(`${base}.csv`, toCsvReport(kept), 'utf8');
    written.push(`${base}.csv`);
  }

  if (formats.has('json')) {
    // Issues serialise with absent keys still absent, so the honesty of the
    // model survives into anything downstream that reads this file.
    await writeFile(`${base}.json`, `${JSON.stringify({ meta, issues: kept }, null, 2)}\n`, 'utf8');
    written.push(`${base}.json`);
  }

  if (formats.has('pdf')) {
    log.step('Rendering PDF');
    const r = await exportPdf(`${base}.html`, `${base}.pdf`);
    if (r.ok) written.push(`${base}.pdf`);
    else log.warn(r.reason ?? 'PDF export failed');

    if (!wantHtml) {
      if (r.ok) {
        // The HTML was scaffolding for the PDF, not a requested output.
        await rm(`${base}.html`, { force: true });
      } else {
        // Keep it when the render failed: it is the whole report, and its
        // print stylesheet means the operator can still produce the PDF by
        // opening it and printing. Deleting it here would destroy the work.
        log.info(`HTML kept at ${base}.html — open it and print to PDF`);
        written.push(`${base}.html`);
      }
    }
  }

  log.blank();
  const counts = SEVERITIES.filter((s) => data.bySeverity[s])
    .map((s) => `${data.bySeverity[s]} ${s}`)
    .join(', ');
  log.info(
    data.total === 0
      ? issues.length === 0
        ? `${c.bold('0')} issues — clean report written`
        : `${c.bold('0')} issues — nothing matched the filters (nil-return report written)`
      : `${c.bold(fmt2(data.total))} issues — ${counts}`,
  );
  for (const f of written) log.info(c.green(f));
  return 0;
}

/**
 * Drive one export end to end: start (or re-attach), poll, download.
 *
 * Splitting re-attach from start is what makes a timeout survivable. The
 * export id is printed the moment it exists, so a Ctrl-C, a dropped network
 * or a sleeping laptop costs nothing: the same command with --export-id picks
 * the results up again, within the three days Snyk keeps them.
 */
async function runExport(
  client: SnykClient,
  scope: ExportScope,
  filters: ExportFilters,
  existingId: string | undefined,
  timeoutMinutes: number,
  includeDeleted: boolean,
): Promise<IngestOutcome> {
  let job = existingId ? { exportId: existingId, scope } : undefined;

  if (job) {
    log.step(`Re-attaching to export ${job.exportId}`);
  } else {
    log.step(`Requesting an export of ${scope.label}`);
    job = await startExport(client, scope, filters);
    // Printed before the first poll on purpose: if anything goes wrong from
    // here on, this id is what saves one of the 20 exports per hour.
    log.info(`export id ${c.bold(job.exportId)} ${c.dim('(--export-id to re-attach)')}`);
  }

  const result = existingId
    ? await fetchExportResult(client, job)
    : await waitForExport(client, job, { timeoutMs: timeoutMinutes * 60_000 });

  log.step(`Downloading ${result.urls.length} file(s)`);
  return downloadExport(client, job, result, { includeDeleted });
}

export interface TestsApiScanOptions {
  readonly repoUrl: string | undefined;
  readonly integrationId: string | undefined;
  readonly ref: string | undefined;
  readonly commit: string | undefined;
  readonly filePatterns: string | undefined;
  readonly jobId: string | undefined;
  readonly testId: string | undefined;
  readonly scanTimeoutMs: number;
}

/**
 * Drive one Tests v2 scan end to end: start (or resume), poll, then fetch
 * findings with their dataflow.
 *
 * Every one of --job-id/--test-id short-circuits an earlier step, same
 * reasoning as --export-id above: a scan takes real time, so Ctrl-C, a
 * dropped network or a timeout must not mean starting a fresh one.
 */
async function runTestsApiScan(
  client: SnykClient,
  orgId: string,
  opts: TestsApiScanOptions,
): Promise<IngestOutcome> {
  let testId = opts.testId;

  if (!testId) {
    let jobId = opts.jobId;
    if (!jobId) {
      const resource: CodeTestResource = {
        repoUrl: opts.repoUrl!,
        integrationId: opts.integrationId!,
        ...(opts.ref ? { ref: opts.ref } : {}),
        ...(opts.commit ? { commit: opts.commit } : {}),
        ...(opts.filePatterns
          ? { filePatterns: opts.filePatterns.split(',').map((p) => p.trim()).filter(Boolean) }
          : {}),
      };
      log.step(`Starting a Snyk Code scan of ${resource.repoUrl} (${opts.ref ?? opts.commit})`);
      jobId = await startCodeTest(client, orgId, resource);
      // Printed before the first poll on purpose, same reasoning as the
      // export id above: this is what --job-id resumes with if anything
      // goes wrong from here on.
      log.info(`test_job id ${c.bold(jobId)} ${c.dim('(--job-id to resume)')}`);
    }
    log.step('Waiting for the scan to finish');
    testId = await waitForCodeTest(client, orgId, jobId, { timeoutMs: opts.scanTimeoutMs });
  }
  log.info(`test id ${c.bold(testId)} ${c.dim('(--test-id to re-report without rescanning)')}`);

  log.step('Fetching findings');
  const components = await fetchTestComponents(client, orgId, testId);
  return ingestTestsApiFindings(client, orgId, testId, components, {
    org: { id: orgId },
    commit: opts.commit ?? null,
  });
}

/** Thousands separators, for operator-facing messages. */
function fmt2(n: number): string {
  return n.toLocaleString();
}

function describeScope(issues: readonly Issue[]): string {
  const orgs = new Set(issues.map((i) => i.org.name ?? i.org.id));
  if (orgs.size === 1) return `Organisation: ${[...orgs][0]}`;
  return `${orgs.size} organisations`;
}

/** Flat CSV of the normalised issues -- consistent regardless of input path. */
function toCsvReport(issues: readonly Issue[]): string {
  const head = [
    'SEVERITY',
    'PROBLEM_ID',
    'TITLE',
    'PRODUCT',
    'STATUS',
    'ORG',
    'PROJECT',
    'PACKAGE_OR_FILE',
    'CVSS',
    'EPSS',
    'EXPLOIT_MATURITY',
    'FIXED_IN',
    'ISSUE_URL',
    'DATAFLOW',
  ];
  // "n/a" is deliberately distinct from an empty cell: it means this ingestion
  // path could not carry the field, not that the value was blank.
  const v = (i: Issue, k: Parameters<typeof read>[1]): string => {
    const r = read(i, k);
    if (r.state === 'unsupported') return 'n/a';
    if (r.state === 'empty') return '';
    return typeof r.value === 'object' ? JSON.stringify(r.value) : String(r.value);
  };

  // Source -> Sink, flattened to one cell: "file:line -> file:line -> ...".
  // Only the Tests v2 API carries this at all; every other source is 'n/a'.
  const flowOf = (i: Issue): string => {
    const r = read(i, 'dataflow');
    if (r.state === 'unsupported') return 'n/a';
    if (r.state === 'empty') return '';
    return r.value.map((s) => `${s.file}:${s.fromLine ?? '?'}`).join(' -> ');
  };

  const lines = [toCsvLine(head)];
  for (const i of issues) {
    const cvss = read(i, 'cvss');
    const epss = read(i, 'epssScore');
    lines.push(
      toCsvLine([
        i.severity,
        i.problemId,
        i.title,
        i.product,
        i.status,
        i.org.name ?? i.org.id,
        i.project?.name ?? (('project' in i) ? '' : 'n/a'),
        v(i, 'packageNameAndVersion') || v(i, 'filePath'),
        cvss.state === 'present' ? cvss.value.score : cvss.state === 'unsupported' ? 'n/a' : '',
        epss.state === 'present' ? epss.value : epss.state === 'unsupported' ? 'n/a' : '',
        v(i, 'exploitMaturity'),
        v(i, 'fixedInVersion'),
        v(i, 'issueUrl'),
        flowOf(i),
      ]),
    );
  }
  return `${lines.join('\n')}\n`;
}

try {
  const code = await main();
  closePrompts();
  process.exit(code);
} catch (err) {
  closePrompts();
  if (err instanceof InputClosedError || (err as Error)?.message === 'cancelled') {
    log.info('cancelled');
    process.exit(130);
  }
  log.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
}
