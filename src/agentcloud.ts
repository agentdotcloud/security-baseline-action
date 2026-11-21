// DFGHR-11, DFGHR-12, DFGHR-13, DFGHR-15, DFGHR-18, DFGHR-20: everything that talks to agent.cloud's control plane.
// It is used only when sending is on (DFGHR-20), and reaches only the one configured origin on three paths, each
// request carrying a fresh GitHub Actions OIDC token whose audience is that origin (DFGHR-12):
//   GET  /security/github/runner/mode       the repository's mode, asked before scanning (DFGHR-15)
//   POST /security/github/runner/reports    runner mode: the report bodies, never file bytes (DFGHR-11)
//   POST /security/github/runner/lockfiles  agent.cloud mode: the selected lockfiles and sibling package.json files
// Request bodies, limits and answers follow control as built (summationai/agent-cloud PRs 6423 and 6438).
import { canonicalJson, secretInFile, type DepsReportBody } from '@summationai/security-checks';
import type { CheckoutAcquisition, CheckoutSkip } from './checkout.ts';
import { ACTION_VERSION } from './version.ts';

export const DEFAULT_AGENTCLOUD_URL = 'https://agent.cloud';
export const RUNNER_MODE_PATH = '/security/github/runner/mode';
export const RUNNER_REPORTS_PATH = '/security/github/runner/reports';
export const RUNNER_LOCKFILES_PATH = '/security/github/runner/lockfiles';
/** Control refuses a report submission over 1 MiB (DFGHR-11) and a lockfile submission over 38 MiB (DFGHR-15). */
export const REPORT_MAX_BYTES = 1024 * 1024;
export const LOCKFILES_MAX_BYTES = 38 * 1024 * 1024;
/** Control accepts at most 10 lockfile reports per repository an hour, counting each lockfile's report (DFGHR-13). */
export const REPORTS_PER_HOUR = 10;

const RESPONSE_MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 120_000;
const NUMERIC_ID = /^[1-9][0-9]{0,18}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
// Control's lockfile skips: at most 500, each path 1 to 500 characters and reason 1 to 100.
const MAX_SKIPPED = 500;

export type ControlMode = 'runner' | 'agent.cloud';
type ControlPath = typeof RUNNER_MODE_PATH | typeof RUNNER_REPORTS_PATH | typeof RUNNER_LOCKFILES_PATH;

/** The configured control origin: an https:// origin with no credentials, path, query or fragment. */
export function controlOrigin(raw: string | undefined): string {
  const value = (raw ?? '').trim() || DEFAULT_AGENTCLOUD_URL;
  const invalid = new Error(`Invalid agentcloud-url: expected an https:// origin with no path, such as ${DEFAULT_AGENTCLOUD_URL}.`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw invalid;
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw invalid;
  }
  return url.origin;
}

/** DFGHR-11: the run envelope control checks against the OIDC token's repository, owner and commit. */
export interface RunEnvelope {
  repository_id: string;
  repository_owner_id: string;
  head_sha: string;
  workflow_run_id: string;
  action_version: string;
  run_started_at: string;
}

export type EnvelopeResult = { ok: true; envelope: RunEnvelope } | { ok: false; missing: string[] };

/** The envelope from GitHub's own run variables; `startedAt` is when this action started. */
export function envelopeFromEnv(env: Readonly<Record<string, string | undefined>>, startedAt: number): EnvelopeResult {
  const read = (name: string, pattern: RegExp) => {
    const value = env[name]?.trim() ?? '';
    return pattern.test(value) ? value : null;
  };
  const fields = {
    GITHUB_REPOSITORY_ID: read('GITHUB_REPOSITORY_ID', NUMERIC_ID),
    GITHUB_REPOSITORY_OWNER_ID: read('GITHUB_REPOSITORY_OWNER_ID', NUMERIC_ID),
    GITHUB_SHA: read('GITHUB_SHA', GIT_SHA),
    GITHUB_RUN_ID: read('GITHUB_RUN_ID', NUMERIC_ID),
  };
  const missing = Object.entries(fields).filter(([, v]) => v === null).map(([k]) => k);
  if (missing.length) return { ok: false, missing };
  return {
    ok: true,
    envelope: {
      repository_id: fields.GITHUB_REPOSITORY_ID!,
      repository_owner_id: fields.GITHUB_REPOSITORY_OWNER_ID!,
      head_sha: fields.GITHUB_SHA!,
      workflow_run_id: fields.GITHUB_RUN_ID!,
      action_version: ACTION_VERSION,
      run_started_at: new Date(startedAt).toISOString(),
    },
  };
}

/** DFGHR-11: a report body as sent. Unchecked dependencies stay only as counts per reason, never by name. */
export function sendableReport(body: DepsReportBody): DepsReportBody {
  const nc = body.extension.not_checked;
  return {
    ...body,
    extension: { ...body.extension, not_checked: { total: nc.total, by_reason: { ...nc.by_reason }, entries: [] } },
  };
}

/**
 * DFGHR-11, DFGHR-22: the bytes POST /security/github/runner/reports takes, `{envelope, reports}`. The artifact keeps
 * these same bytes as agentcloud-report.json, so a later upload or send-history sends exactly what this run would.
 * Each part is canonical JSON on its own, as serializeArtifact does, so 25 lockfiles never hit one document's caps.
 */
export function serializeReportPayload(envelope: RunEnvelope, reports: readonly DepsReportBody[]): string {
  return `{"envelope":${canonicalJson(envelope)},"reports":[${reports.map((b) => canonicalJson(sendableReport(b))).join(',')}]}`;
}

export interface LockfilesPayload {
  json: string;
  lockfiles: number;
  /** Selected lockfiles held back because their bytes look like they hold a credential. */
  withheld: string[];
}

/**
 * DFGHR-15: the bytes POST /security/github/runner/lockfiles takes: every lockfile DFBASE-8 selected (DFBASE's worker
 * parses them itself) with its sibling package.json, plus what the selection passed over. A file whose bytes look like
 * they hold a credential is never sent: a lockfile is listed as skipped instead, and a sibling is marked unreadable.
 */
export function buildLockfilesPayload(acquired: CheckoutAcquisition, envelope: RunEnvelope): LockfilesPayload {
  const skipped: CheckoutSkip[] = [...acquired.selectionSkipped];
  const withheld: string[] = [];
  const lockfiles: Record<string, unknown>[] = [];
  for (const lock of acquired.selected) {
    if (secretInFile(lock.bytes)) {
      withheld.push(lock.path);
      skipped.push({ path: lock.path, reason: 'credential_shaped_content' });
      continue;
    }
    let unreadable = lock.packageJsonUnreadable;
    let packageJson: { path: string; content_base64: string } | null = null;
    if (lock.packageJson) {
      if (secretInFile(lock.packageJson.bytes)) unreadable = true;
      else packageJson = { path: lock.packageJson.path, content_base64: lock.packageJson.bytes.toString('base64') };
    }
    lockfiles.push({
      path: lock.path,
      content_base64: lock.bytes.toString('base64'),
      package_json: packageJson,
      ...(unreadable ? { package_json_unreadable: true } : {}),
    });
  }
  const inputs: Record<string, number> = {};
  for (const [name, count] of Object.entries(acquired.other)) if (name.length <= 100) inputs[name] = count;
  const { run_started_at: _started, ...lockEnvelope } = envelope; // control's lockfile envelope has no run_started_at
  const json = JSON.stringify({
    envelope: lockEnvelope,
    lockfiles,
    skipped: skipped
      .filter((s) => s.path.length >= 1 && s.path.length <= 500 && s.reason.length >= 1 && s.reason.length <= 100)
      .slice(0, MAX_SKIPPED),
    inputs_not_analyzed: inputs,
  });
  return { json, lockfiles: lockfiles.length, withheld };
}

export interface ControlRefusal {
  /** The HTTP status, or 0 when no answer came. */
  status: number;
  code: string;
  message: string;
  fix: string;
}

export type ControlAnswer<T> = { ok: true; status: number; body: T } | { ok: false; refusal: ControlRefusal };

export interface ModeAnswer {
  mode: ControlMode;
  repository?: string;
  repository_id?: string;
}

export interface ReportReceipt {
  id?: string;
  repeated?: boolean;
  reports?: { report_id: string; revision: number; digest: string; path: string }[];
}

export interface LockfilesReceipt {
  id?: string;
  repeated?: boolean;
  queued?: boolean;
  lockfiles?: number;
}

/** What a person can do about each refusal. Control's own `fix`, when an answer carries one, comes first. */
export function fixFor(code: string, status: number, origin: string): string {
  switch (code) {
    case 'runner.oidc_unavailable':
      return 'Give the job `permissions: id-token: write`, as workflow/agentcloud-baseline.yml does.';
    case 'runner.unauthenticated':
      return `Check that agentcloud-url is the agent.cloud this repository uses (${origin}), that the job has \`id-token: write\`, and that the run is for the commit it checked out.`;
    case 'runner.not_installed':
      return `Install the agent.cloud GitHub App on this repository from ${origin}/security/github/setup, and run the workflow on the default branch.`;
    case 'runner.mode_runner':
      return 'Nothing to do: agent.cloud has this repository in runner mode now, so the next run sends its report instead.';
    case 'runner.rate_limited':
      return `Nothing to do: agent.cloud accepts at most ${REPORTS_PER_HOUR} reports per repository an hour, and the next run sends again.`;
    case 'runner.report_invalid':
    case 'runner.lockfiles_invalid':
      return "Update this action to the commit agent.cloud's setup page pins; if it already is, tell agent.cloud with this run's log.";
    case 'runner.too_large':
      return 'Nothing to send in this run: the job summary and the agentcloud-baseline artifact still have the whole result.';
    case 'runner.stale_run':
      return 'Nothing to do: a newer run already sent this repository\'s lockfiles.';
    case 'runner.unreachable':
      return `Check that this runner can reach ${origin} over HTTPS; the next run tries again.`;
    case 'runner.redirect':
    case 'runner.not_found':
      return `Check agentcloud-url: ${origin} doesn't take runner reports at ${RUNNER_REPORTS_PATH}.`;
    default:
      return status >= 500
        ? 'Nothing to do: agent.cloud had a problem, and the next run tries again.'
        : `Check agentcloud-url (${origin}) and that this action is the version agent.cloud's setup page pins.`;
  }
}

/**
 * One line for the log, such as "Sending this run's report to agent.cloud failed: runner.rate_limited (HTTP 429). …
 * Fix: …". Text from control is kept to one line without control characters, so it can't start a workflow command.
 */
export function describeRefusal(attempt: string, refusal: ControlRefusal): string {
  const status = refusal.status ? `HTTP ${refusal.status}` : 'no answer';
  return `${attempt} failed: ${refusal.code} (${status}). ${refusal.message} Fix: ${refusal.fix}`;
}

const oneLine = (value: unknown, max = 500): string =>
  String(value ?? '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, max);

async function readBounded(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (reader) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.byteLength;
    if (size > RESPONSE_MAX_BYTES) {
      await reader.cancel();
      return '';
    }
    chunks.push(next.value);
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

const sleep = (ms: number) => (ms > 0 ? new Promise<void>((resolve) => setTimeout(resolve, ms)) : Promise.resolve());

export interface ControlClientOptions {
  origin: string;
  /** DFGHR-12: a GitHub Actions OIDC token for this audience. Asked for again on every request: they expire in minutes. */
  getIdToken: (audience: string) => Promise<string>;
  fetch?: typeof fetch;
  /** Wait before the one retry of a request that got no answer or a 5xx. */
  baseBackoffMs?: number;
  timeoutMs?: number;
}

export interface ControlClient {
  origin: string;
  mode(): Promise<ControlAnswer<ModeAnswer>>;
  sendReport(json: string): Promise<ControlAnswer<ReportReceipt>>;
  sendLockfiles(json: string): Promise<ControlAnswer<LockfilesReceipt>>;
}

export function createControlClient(options: ControlClientOptions): ControlClient {
  const origin = controlOrigin(options.origin);
  const fetcher = options.fetch ?? globalThis.fetch;
  const backoff = options.baseBackoffMs ?? 1000;
  const timeoutMs = options.timeoutMs ?? TIMEOUT_MS;
  const refuse = (status: number, code: string, message: string, fix?: string): { ok: false; refusal: ControlRefusal } => ({
    ok: false,
    refusal: { status, code, message: oneLine(message), fix: oneLine(fix) || fixFor(code, status, origin) },
  });

  async function request<T>(method: 'GET' | 'POST', path: ControlPath, body?: string): Promise<ControlAnswer<T>> {
    const url = new URL(path, origin);
    // DFGHR-18: only the configured origin, only these paths, never a redirect's target.
    if (url.origin !== origin || url.pathname !== path || url.search) throw new Error('runner.agentcloud_origin_refused');
    for (let attempt = 1; ; attempt++) {
      let token: string;
      try {
        token = await options.getIdToken(origin);
      } catch (error) {
        return refuse(0, 'runner.oidc_unavailable', `GitHub didn't give this job an identity token: ${error instanceof Error ? error.message : String(error)}`);
      }
      let res: Response;
      try {
        res = await fetcher(url, {
          method,
          redirect: 'manual',
          signal: AbortSignal.timeout(timeoutMs),
          headers: {
            accept: 'application/json',
            authorization: `Bearer ${token}`,
            'user-agent': `agentcloud-security-baseline-action/${ACTION_VERSION}`,
            ...(body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(body === undefined ? {} : { body }),
        });
      } catch (error) {
        if (attempt < 2) {
          await sleep(backoff);
          continue;
        }
        return refuse(0, 'runner.unreachable', `No answer from ${origin}: ${error instanceof Error ? error.message : String(error)}.`);
      }
      const text = await readBounded(res);
      if (res.status >= 500 && attempt < 2) {
        await sleep(backoff);
        continue;
      }
      const parsed = parseJson(text) as Record<string, unknown> | null;
      if (res.status >= 200 && res.status < 300) {
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return refuse(res.status, 'runner.answer_invalid', `${origin} answered ${path} with something other than a JSON object.`);
        }
        return { ok: true, status: res.status, body: parsed as T };
      }
      if (res.status >= 300 && res.status < 400) {
        return refuse(res.status, 'runner.redirect', `${origin} answered ${path} with a redirect, which this action doesn't follow.`);
      }
      const error = parsed && typeof parsed === 'object' ? (parsed as { error?: Record<string, unknown> }).error : undefined;
      const code = typeof error?.code === 'string' && /^[a-z0-9_.]{1,64}$/.test(error.code)
        ? error.code
        : res.status === 404 ? 'runner.not_found' : `http_${res.status}`;
      const message = typeof error?.message === 'string' ? error.message : `${origin} answered ${path} with HTTP ${res.status}.`;
      return refuse(res.status, code, message, typeof error?.fix === 'string' ? error.fix : undefined);
    }
  }

  return {
    origin,
    async mode() {
      const answer = await request<ModeAnswer>('GET', RUNNER_MODE_PATH);
      if (answer.ok && answer.body.mode !== 'runner' && answer.body.mode !== 'agent.cloud') {
        return refuse(answer.status, 'runner.mode_unknown', `${origin} named a mode this action doesn't know: ${oneLine(answer.body.mode, 40)}.`,
          "Update this action to the commit agent.cloud's setup page pins.");
      }
      return answer;
    },
    sendReport: (json) => request<ReportReceipt>('POST', RUNNER_REPORTS_PATH, json),
    sendLockfiles: (json) => request<LockfilesReceipt>('POST', RUNNER_LOCKFILES_PATH, json),
  };
}
