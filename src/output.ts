// DFGHR-10: job summary rendering, fail-on threshold evaluation, and canonical artifact serialization.
import { canonicalJson, type DepsReportBody } from '@summationai/security-checks';
import type { BaselineRunResult } from './runner.ts';

export const FAIL_ON_LEVELS = ['critical', 'high', 'moderate', 'low'] as const;
export type FailOnLevel = (typeof FAIL_ON_LEVELS)[number];
export type DisplaySeverity = FailOnLevel | 'unknown';

export const SETUP_PAGE_URL = 'https://agent.cloud/security/github/setup';

const SEVERITY_RANK: Record<DisplaySeverity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  unknown: 0,
};

export interface SummaryFinding {
  lockfile: string;
  findingId: string;
  package: string;
  version: string;
  advisory: string;
  severity: DisplaySeverity;
  fixVersion: string | null;
}

export function parseFailOn(raw: string | undefined): FailOnLevel | null {
  const value = (raw ?? '').trim().toLowerCase();
  if (!value) return null;
  if ((FAIL_ON_LEVELS as readonly string[]).includes(value)) return value as FailOnLevel;
  throw new Error(`Invalid fail-on value "${value}": expected one of ${FAIL_ON_LEVELS.join(', ')}, or empty.`);
}

export function toDisplaySeverity(normalized: string | undefined): DisplaySeverity {
  const s = (normalized ?? '').toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium' || s === 'moderate') return 'moderate';
  if (s === 'low') return 'low';
  return 'unknown';
}

function escapeCell(value: string): string {
  return value.replace(/[|\\`<>[\]]/g, (ch) => `\\${ch}`).replace(/\r?\n/g, ' ');
}

export function extractFindings(reports: readonly DepsReportBody[]): SummaryFinding[] {
  const out: SummaryFinding[] = [];
  for (const body of reports) {
    const factsByFinding = new Map(body.extension.fix_facts.map((f) => [f.finding_id, f]));
    const obsById = new Map(body.observations.map((o) => [o.observation_id, o]));

    for (const finding of body.findings) {
      const fact = factsByFinding.get(finding.finding_id);
      const sourceObs = finding.observation_ids
        .map((id) => (typeof id === 'string' ? obsById.get(id) : undefined))
        .filter((o): o is Extract<(typeof body.observations)[number], { kind: 'source_observation' }> => o?.kind === 'source_observation');

      let pkg = fact?.package ?? null;
      let ver = fact?.installed ?? null;
      let highest: DisplaySeverity = 'unknown';

      for (const obs of sourceObs) {
        if ((!pkg || !ver) && obs.occurrence.kind === 'dependency') {
          pkg ??= obs.occurrence.package;
          ver ??= obs.occurrence.version;
        }
        const sev = toDisplaySeverity(obs.severity.normalized);
        if (SEVERITY_RANK[sev] > SEVERITY_RANK[highest]) highest = sev;
      }

      const advisory =
        finding.aliases.find((a) => a.startsWith('GHSA-')) ??
        finding.aliases[0] ??
        sourceObs[0]?.source_id ??
        finding.finding_id;

      out.push({
        lockfile: body.lockfile.path,
        findingId: finding.finding_id,
        package: pkg ?? 'unknown',
        version: ver ?? 'unknown',
        advisory,
        severity: highest,
        fixVersion: fact?.candidate ?? fact?.fixed_version ?? null,
      });
    }
  }
  return out.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.lockfile.localeCompare(b.lockfile) ||
      a.package.localeCompare(b.package) ||
      a.advisory.localeCompare(b.advisory),
  );
}

export function evaluateFailOn(
  findings: readonly SummaryFinding[],
  failOn: FailOnLevel | null,
): { failed: boolean; matchingCount: number; message: string | null } {
  if (!failOn) return { failed: false, matchingCount: 0, message: null };
  const threshold = SEVERITY_RANK[failOn];
  const matching = findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold);
  if (!matching.length) return { failed: false, matchingCount: 0, message: null };
  return {
    failed: true,
    matchingCount: matching.length,
    message: `${matching.length} dependency finding${matching.length === 1 ? '' : 's'} met or exceeded fail-on=${failOn}.`,
  };
}

export function renderSummary(result: BaselineRunResult): string {
  const findings = extractFindings(result.reports);
  const lines: string[] = ['## agent.cloud Dependency Baseline', ''];

  const details: string[] = [
    `${result.reports.length} lockfile${result.reports.length === 1 ? '' : 's'} analyzed`,
    `${findings.length} finding${findings.length === 1 ? '' : 's'}`,
  ];
  const unavailableHosts = [...new Set(result.summary.unavailable.map((u) => u.host))];
  if (unavailableHosts.length) details.push(`unavailable: ${unavailableHosts.join(', ')}`);
  if (result.summary.skipped.length) details.push(`${result.summary.skipped.length} skipped`);
  if (result.summary.holds.length) details.push(`${result.summary.holds.length} held`);

  lines.push(`Coverage: **${result.coverage}** (${details.join('; ')}).`, '');

  if (result.summary.unavailable.length) {
    lines.push(
      `Source unavailable (${unavailableHosts.join(', ')}): report is **incomplete**.`,
      '',
    );
  }

  if (findings.length > 0) {
    lines.push(
      '| Lockfile | Package | Version | Advisory | Severity | Fix version |',
      '| --- | --- | --- | --- | --- | --- |',
    );
    for (const f of findings) {
      lines.push(
        `| ${escapeCell(f.lockfile)} | ${escapeCell(f.package)} | ${escapeCell(f.version)} | ${escapeCell(f.advisory)} | ${escapeCell(f.severity)} | ${escapeCell(f.fixVersion ?? 'none')} |`,
      );
    }
    lines.push('');
  } else if (result.coverage === 'none') {
    lines.push('No supported `package-lock.json` files were found to analyze.', '');
  } else if (result.coverage !== 'incomplete') {
    lines.push('No known advisories matched the checked dependencies.', '');
  }

  // DFGHR-11: private/unchecked entries remain visible in the customer's own job summary.
  const unchecked: { lockfile: string; entry: string; reason: string }[] = [];
  for (const body of result.reports) {
    for (const item of body.extension.not_checked.entries) {
      unchecked.push({ lockfile: body.lockfile.path, entry: item.entry, reason: item.reason });
    }
  }
  if (unchecked.length > 0) {
    lines.push(`Unchecked dependencies (${unchecked.length}):`);
    for (const item of unchecked.slice(0, 50)) {
      lines.push(`- ${escapeCell(item.lockfile)}: \`${escapeCell(item.entry)}\` (${escapeCell(item.reason)})`);
    }
    if (unchecked.length > 50) {
      lines.push(`- ... and ${unchecked.length - 50} more`);
    }
    lines.push('');
  }

  // DFGHR-10: the summary ends with one line on what agent.cloud adds and the setup page's link.
  lines.push(
    `agent.cloud adds exploitability proofs and automated fix pull requests: [Set up agent.cloud](${SETUP_PAGE_URL}).`,
  );
  return `${lines.join('\n')}\n`;
}

export function serializeArtifact(result: BaselineRunResult): string {
  // Canonicalize each section and each report body individually so multi-lockfile runs (up to 25 lockfiles)
  // never exceed canonicalJson's single-report 10 MiB / 300,000-node guard while preserving exact canonical order.
  const reportsJson = `[${result.reports.map((body) => canonicalJson(body)).join(',')}]`;
  return `{${[
    `"coverage":${canonicalJson(result.coverage)}`,
    `"profile":${canonicalJson(result.profile)}`,
    `"reports":${reportsJson}`,
    `"schema":${canonicalJson(result.schema)}`,
    `"sources":${canonicalJson(result.sources)}`,
    `"summary":${canonicalJson(result.summary)}`,
  ].join(',')}}`;
}
