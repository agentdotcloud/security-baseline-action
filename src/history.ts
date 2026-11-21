// DFGHR-22: once sending is on, a workflow_dispatch run with send-history: true also sends the reports the repository's
// earlier runs still keep in their agentcloud-baseline artifacts, read with the job's own token (actions: read).
// What it sends is each earlier run's agentcloud-report.json, byte for byte: the body that run sent or would have sent.
import { parseReportJson } from '@summationai/security-checks';
import { REPORT_MAX_BYTES, type RunEnvelope } from './agentcloud.ts';

/** The file in an agentcloud-baseline artifact that holds the body POST /security/github/runner/reports takes. */
export const REPORT_FILE = 'agentcloud-report.json';
/** How many of the repository's artifacts the action lists at most. */
export const HISTORY_LIST_MAX = 300;

export interface BaselineArtifact {
  id: number;
  /** The workflow run that uploaded it. */
  runId: string;
  /** That run's commit. */
  headSha: string;
  createdAt: string;
  expired: boolean;
}

export interface EarlierReport {
  runId: string;
  createdAt: string;
  json: string;
  reports: number;
}

export interface HistoryCollection {
  /** Oldest first, so the newest report is still the newest revision once all are sent. */
  send: EarlierReport[];
  /** How many earlier runs were left out, and why. */
  left: { other_commit: number; no_report: number; unreadable: number; invalid: number; over_limit: number };
}

export interface HistorySource {
  list(): Promise<BaselineArtifact[]>;
  read(artifact: BaselineArtifact): Promise<Buffer | null>;
}

/** How many lockfile reports an earlier artifact's report holds, or null when it isn't sendable for this repository and run. */
function sendableCount(bytes: Buffer, artifact: BaselineArtifact, current: RunEnvelope): { reports: number } | null {
  if (bytes.byteLength > REPORT_MAX_BYTES) return null;
  let parsed: unknown;
  try {
    parsed = parseReportJson(bytes);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const { envelope, reports } = parsed as { envelope?: Record<string, unknown>; reports?: unknown };
  if (
    !envelope ||
    envelope.repository_id !== current.repository_id ||
    envelope.repository_owner_id !== current.repository_owner_id ||
    envelope.head_sha !== artifact.headSha ||
    envelope.workflow_run_id !== artifact.runId ||
    !Array.isArray(reports) ||
    reports.length === 0
  ) {
    return null;
  }
  // DFGHR-11: an earlier report goes only if it, too, names no unchecked dependency.
  for (const body of reports as { extension?: { not_checked?: { entries?: unknown } } }[]) {
    const entries = body?.extension?.not_checked?.entries;
    if (!Array.isArray(entries) || entries.length > 0) return null;
  }
  return { reports: reports.length };
}

/**
 * Pick the earlier runs' reports to send: retained (unexpired) artifacts of other runs, one per run, whose report is
 * for this run's commit. Control accepts a report only for the commit the run's OIDC token names (DFGHR-12), so an
 * earlier run at another commit can't be sent from this one. `budget` is how many lockfile reports may go, newest first.
 */
export async function collectEarlierReports(
  source: HistorySource,
  current: RunEnvelope,
  budget: number,
): Promise<HistoryCollection> {
  const left = { other_commit: 0, no_report: 0, unreadable: 0, invalid: 0, over_limit: 0 };
  const newestPerRun = new Map<string, BaselineArtifact>();
  for (const artifact of await source.list()) {
    if (artifact.expired || artifact.runId === current.workflow_run_id || !/^[1-9][0-9]{0,18}$/.test(artifact.runId)) continue;
    const seen = newestPerRun.get(artifact.runId);
    if (!seen || artifact.createdAt > seen.createdAt || (artifact.createdAt === seen.createdAt && artifact.id > seen.id)) {
      newestPerRun.set(artifact.runId, artifact);
    }
  }
  const newestFirst = [...newestPerRun.values()].sort(
    (a, b) => b.createdAt.localeCompare(a.createdAt) || b.id - a.id,
  );

  const chosen: EarlierReport[] = [];
  let remaining = budget;
  for (const artifact of newestFirst) {
    if (artifact.headSha !== current.head_sha) {
      left.other_commit++;
      continue;
    }
    if (remaining <= 0) {
      left.over_limit++;
      continue;
    }
    let bytes: Buffer | null;
    try {
      bytes = await source.read(artifact);
    } catch {
      left.unreadable++;
      continue;
    }
    if (!bytes) {
      left.no_report++;
      continue;
    }
    const ok = sendableCount(bytes, artifact, current);
    if (!ok) {
      left.invalid++;
      continue;
    }
    if (ok.reports > remaining) {
      left.over_limit++;
      continue;
    }
    remaining -= ok.reports;
    chosen.push({ runId: artifact.runId, createdAt: artifact.createdAt, json: bytes.toString('utf8'), reports: ok.reports });
  }
  return { send: chosen.reverse(), left };
}
