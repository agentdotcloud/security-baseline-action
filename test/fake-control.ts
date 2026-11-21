// A stand-in for agent.cloud's control plane and for GitHub's OIDC token endpoint, for the action's sending tests.
// The request schemas and checks below are copied from summationai/agent-cloud
// packages/control/src/security-runner-reports.ts at 18a901625 (PRs 6423 and 6438), so a body this fake accepts is
// one control's routes accept before storing anything: the strict report payload (DFGHR-11), the OIDC binding of
// repository, owner, default branch and commit (DFGHR-12), the mode answer (DFGHR-15) and the strict lockfile payload.
import { z } from 'zod';
import {
  DEPS_CHECK_ID,
  DEPS_CHECK_VERSION,
  DEPS_REPORT_LIMITS,
  DepsDiscoveryExtension,
  ReportCoverageComponent,
  ReportDisposition,
  ReportEvidence,
  ReportFinding,
  ReportObservation,
  ReportRecommendation,
  evidenceHash,
  exactPath,
  gitSha,
  joinDepsReport,
  parseReportJson,
  reportHash,
  reportPath,
  type DepsReportBody,
} from '@summationai/security-checks';
import { BASELINE as P, BASELINE_DIGEST } from '../vendor/security-checks/src/baseline-profile.ts';

// ---- copied from control: security-runner-reports.ts ----
const NUMERIC_ID_RE = /^[1-9][0-9]{0,18}$/;
const NumericId = z.string().refine((s) => NUMERIC_ID_RE.test(s) && BigInt(s) <= 9223372036854775807n, 'must be a positive 64-bit integer string');
const ActionVersion = z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9_.:@/-]*$/);
const RunnerReportEnvelope = z.strictObject({
  repository_id: NumericId,
  repository_owner_id: NumericId,
  head_sha: gitSha,
  workflow_run_id: NumericId,
  action_version: ActionVersion,
  run_started_at: z.iso.datetime().optional(),
});
const RunnerBodyEvidence = z.strictObject({
  evidence_id: ReportEvidence.shape.evidence_id,
  sha256: ReportEvidence.shape.sha256,
  bytes: ReportEvidence.shape.bytes,
  media_type: ReportEvidence.shape.media_type,
  classification: ReportEvidence.shape.classification,
  kind: ReportEvidence.shape.kind,
  origin: ReportEvidence.shape.origin,
  captured_at: ReportEvidence.shape.captured_at,
  artifact_id: z.null(),
  git: z.strictObject({ blob: gitSha, path: reportPath }).nullable(),
});
const RunnerDepsBodyComponent = z.strictObject({
  id: ReportCoverageComponent.shape.id,
  version: ReportCoverageComponent.shape.version,
  state: ReportCoverageComponent.shape.state,
  required: z.boolean(),
  reasons: ReportCoverageComponent.shape.reasons,
  pagination_complete: z.boolean(),
  source_revision: ReportCoverageComponent.shape.source_revision,
  retrieved_at: ReportCoverageComponent.shape.retrieved_at,
  baseline_receipt: ReportCoverageComponent.shape.baseline_receipt,
  observation_ids: z.array(ReportCoverageComponent.shape.id).max(DEPS_REPORT_LIMITS.observations),
});
const RunnerDepsReportBody = z.strictObject({
  check: z.strictObject({ id: z.literal(DEPS_CHECK_ID), version: z.literal(DEPS_CHECK_VERSION) }),
  lockfile: z.strictObject({ path: exactPath, git_blob: gitSha, sha256: evidenceHash }),
  observations: z.array(ReportObservation).max(DEPS_REPORT_LIMITS.observations),
  findings: z.array(ReportFinding).max(DEPS_REPORT_LIMITS.findings),
  dispositions: z.array(ReportDisposition).max(DEPS_REPORT_LIMITS.dispositions),
  evidence: z.array(RunnerBodyEvidence).max(DEPS_REPORT_LIMITS.evidence),
  recommendations: z.array(ReportRecommendation).max(DEPS_REPORT_LIMITS.recommendations),
  coverage: z.strictObject({
    state: z.enum(['complete', 'partial']),
    union_status: z.enum(['proven', 'incomplete']),
    components: z.array(RunnerDepsBodyComponent).min(1).max(10),
  }),
  extension: DepsDiscoveryExtension,
});
const RunnerReportPayload = z.strictObject({
  envelope: RunnerReportEnvelope,
  reports: z.array(RunnerDepsReportBody).min(1).max(P.lock.count),
});
const RunnerLockfilesEnvelope = z.strictObject({
  repository_id: NumericId,
  repository_owner_id: NumericId,
  head_sha: gitSha,
  workflow_run_id: NumericId,
  action_version: ActionVersion,
});
const RunnerLockfileSibling = z.strictObject({
  path: exactPath,
  content_base64: z.string().max(Math.ceil((P.lock.package_bytes * 4) / 3) + 8),
});
const RunnerLockfileItem = z.strictObject({
  path: exactPath,
  content_base64: z.string().max(Math.ceil((P.lock.bytes * 4) / 3) + 8),
  package_json: RunnerLockfileSibling.nullable().optional(),
  package_json_unreadable: z.boolean().optional(),
});
const RunnerLockfilesPayload = z.strictObject({
  envelope: RunnerLockfilesEnvelope,
  lockfiles: z.array(RunnerLockfileItem).max(P.lock.count),
  skipped: z.array(z.strictObject({ path: z.string().min(1).max(500), reason: z.string().min(1).max(100) })).max(500).optional(),
  inputs_not_analyzed: z.record(z.string().min(1).max(100), z.number().int().nonnegative()).optional(),
});
export type ReportPayload = z.infer<typeof RunnerReportPayload>;
export type LockfilesPayload = z.infer<typeof RunnerLockfilesPayload>;

type Refusal = { status: 400 | 401 | 403 | 404 | 409 | 413 | 429 | 500 | 503; code: string; message: string };

/** parseRunnerReportPayload's checks: strict schema, lockfile paths, no named unchecked dependency, no proof claims. */
function checkReportPayload(raw: Uint8Array): { ok: true; payload: ReportPayload } | { ok: false; error: Refusal } {
  const invalid = (message: string) => ({ ok: false as const, error: { status: 400 as const, code: 'runner.report_invalid', message } });
  if (raw.byteLength > 1024 * 1024) return { ok: false, error: { status: 413, code: 'runner.too_large', message: 'The report body exceeds the 1 MiB limit (DFGHR-11).' } };
  let json: unknown;
  try {
    json = parseReportJson(raw);
  } catch (e) {
    return invalid(`The report body is not valid report JSON (${(e as Error).message}).`);
  }
  const parsed = RunnerReportPayload.safeParse(json);
  if (!parsed.success) {
    return invalid(`The report body is invalid or contains a disallowed field (DFGHR-11): ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.') || 'root'}: ${i.message}`).join('; ')}.`);
  }
  const seen = new Set<string>();
  for (const body of parsed.data.reports) {
    const path = body.lockfile.path;
    if (path.split('/').at(-1) !== P.lock.filename || body.extension.lockfile.path !== path || seen.has(path)) return invalid(`Lockfile path ${path} is invalid.`);
    seen.add(path);
    const nc = body.extension.not_checked;
    if (nc.entries.length > 0) return invalid('Unchecked dependencies must be reported only as counts per reason, never by name (DFGHR-11).');
    if (Object.values(nc.by_reason).reduce((a, b) => a + b, 0) !== nc.total) return invalid('Unchecked dependency counts do not sum to not_checked.total (DFGHR-11).');
    for (const f of body.findings) {
      if (f.reproduction_receipt_ids.length > 0 || f.assessment.validity !== 'unreviewed' || f.assessment.exposure !== 'unverified' || f.assessment.breaker !== 'not_attempted') {
        return invalid('A runner report cannot claim execution receipts or verified proofs (DFGHR-13, DFRPT-12).');
      }
    }
  }
  return { ok: true, payload: parsed.data };
}
// ---- end of what is copied from control ----

/** An unsigned stand-in for a GitHub Actions OIDC token: control's checks here read its claims only. */
export function fakeIdToken(claims: Record<string, unknown>): string {
  const b64u = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  return `${b64u({ alg: 'RS256', typ: 'JWT', kid: 'fake' })}.${b64u(claims)}.c2lnbmF0dXJl`;
}

function claimsOf(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export interface RunIdentity {
  repositoryId: string;
  ownerId: string;
  sha: string;
  runId: string;
  ref?: string;
}

/** GitHub's token endpoint as the action sees it: a token for whatever audience it asks, naming this run. */
export function fakeOidc(run: RunIdentity) {
  const audiences: string[] = [];
  return {
    audiences,
    async getIdToken(audience: string) {
      audiences.push(audience);
      return fakeIdToken({
        iss: 'https://token.actions.githubusercontent.com',
        aud: audience,
        repository_id: run.repositoryId,
        repository_owner_id: run.ownerId,
        ref: run.ref ?? 'refs/heads/main',
        sha: run.sha,
        run_id: run.runId,
      });
    },
  };
}

export interface ControlRequest {
  method: string;
  path: string;
  authorization: string;
  contentType: string | null;
  redirect: RequestRedirect | undefined;
  body: string;
}

export interface FakeControlOptions {
  origin?: string;
  /** The installed repository control knows, with its default branch. */
  repositoryId: string;
  ownerId: string;
  defaultBranch?: string;
  mode?: 'runner' | 'agent.cloud';
  /** Answer this route with this refusal instead. */
  refuse?: Partial<Record<'mode' | 'reports' | 'lockfiles', Refusal>>;
  /** Answer reports with 429 once this many lockfile reports were accepted, as control's hourly limit does. */
  reportsPerHour?: number;
}

export function fakeControl(options: FakeControlOptions) {
  const origin = options.origin ?? 'https://agent.cloud';
  const requests: ControlRequest[] = [];
  const reports: { raw: string; payload: ReportPayload }[] = [];
  const lockfiles: { raw: string; payload: LockfilesPayload }[] = [];
  const digests = new Set<string>();
  let accepted = 0;
  const reply = (status: number, body: unknown) => Response.json(body, { status });
  const refusal = (r: Refusal) => reply(r.status, { error: { code: r.code, message: r.message } });

  // control's authenticateOidc and matchOidcRepository, on the fake token's claims.
  function authenticate(authorization: string): { claims: Record<string, unknown> } | Refusal {
    const match = /^Bearer\s+(\S+)$/i.exec(authorization);
    const claims = match ? claimsOf(match[1]!) : null;
    if (!claims) return { status: 401, code: 'runner.unauthenticated', message: 'Missing GitHub Actions OIDC Bearer token (DFGHR-12).' };
    if (claims.aud !== origin) return { status: 401, code: 'runner.unauthenticated', message: `The OIDC token audience must be ${origin}.` };
    if (claims.repository_id !== options.repositoryId || claims.repository_owner_id !== options.ownerId) {
      return { status: 403, code: 'runner.not_installed', message: 'This repository does not belong to a ready, unfenced installation of the customer App (DFGHR-12).' };
    }
    if (claims.ref !== `refs/heads/${options.defaultBranch ?? 'main'}`) {
      return { status: 403, code: 'runner.not_installed', message: 'Requests are accepted only from the repository default branch (DFGHR-12).' };
    }
    return { claims };
  }

  async function handle(url: URL, init: RequestInit | undefined): Promise<Response> {
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === 'string' ? init.body : '';
    const method = init?.method ?? 'GET';
    requests.push({ method, path: url.pathname, authorization: headers.get('authorization') ?? '', contentType: headers.get('content-type'), redirect: init?.redirect, body });
    const route = `${method} ${url.pathname}`;
    const name = route === 'GET /security/github/runner/mode' ? 'mode'
      : route === 'POST /security/github/runner/reports' ? 'reports'
      : route === 'POST /security/github/runner/lockfiles' ? 'lockfiles' : null;
    if (!name || url.search) return new Response('Not Found', { status: 404 });
    const auth = authenticate(headers.get('authorization') ?? '');
    if ('status' in auth) return refusal(auth);
    if (options.refuse?.[name]) return refusal(options.refuse[name]!);
    const { claims } = auth;
    if (name === 'mode') {
      return reply(200, { mode: options.mode ?? 'runner', repository: 'sdr_fake', repository_id: options.repositoryId, profile: { id: P.id, revision: P.revision, digest: BASELINE_DIGEST } });
    }
    const raw = Buffer.from(body, 'utf8');
    if (name === 'reports') {
      const checked = checkReportPayload(raw);
      if (!checked.ok) return refusal(checked.error);
      const { envelope } = checked.payload;
      if (claims.repository_id !== envelope.repository_id || claims.repository_owner_id !== envelope.repository_owner_id || claims.sha !== envelope.head_sha) {
        return refusal({ status: 401, code: 'runner.unauthenticated', message: 'The OIDC token repository, owner or commit SHA does not match the report envelope (DFGHR-12).' });
      }
      const digest = reportHash(['runner', options.repositoryId, checked.payload]);
      if (digests.has(digest)) return reply(201, { id: 'srr_fake', producer: 'summation.runner', source: 'runner', repeated: true, reports: [] });
      if (options.reportsPerHour !== undefined && accepted + checked.payload.reports.length > options.reportsPerHour) {
        return refusal({ status: 429, code: 'runner.rate_limited', message: `At most ${options.reportsPerHour} reports per repository an hour are accepted (DFGHR-13).` });
      }
      // storeRunnerReports joins each body into a full DFRPT report; a body that doesn't join is refused.
      for (const report of checked.payload.reports) {
        try {
          joinDepsReport(report as DepsReportBody, {
            report_id: `deps-${reportHash([envelope.repository_id, report.lockfile.path])}`,
            producer: { namespace: 'summation.runner', product: 'github-runner', version: envelope.action_version },
            revision: 1,
            previous_digest: null,
            generated_at: '2026-11-20T12:00:00.000Z',
            profile: { id: P.id, revision: P.revision, digest: BASELINE_DIGEST },
            snapshot: { target_id: 'github.com', repository_id: envelope.repository_id, repository: 'acme/web', sha: envelope.head_sha, scopes: [{ scope_id: 'lockfile', service: 'npm', paths: [report.lockfile.path] }] },
          });
        } catch (e) {
          return refusal({ status: 400, code: 'runner.report_invalid', message: (e as Error).message });
        }
      }
      digests.add(digest);
      accepted += checked.payload.reports.length;
      reports.push({ raw: body, payload: checked.payload });
      return reply(201, { id: `srr_${reports.length}`, producer: 'summation.runner', source: 'runner', label: 'reported by your GitHub runner', repository: 'sdr_fake', repeated: false, reports: [] });
    }
    // lockfiles
    if (raw.byteLength > 38 * 1024 * 1024) return refusal({ status: 413, code: 'runner.too_large', message: 'The lockfile submission exceeds the maximum size limit (DFGHR-15).' });
    let json: unknown;
    try {
      json = JSON.parse(body);
    } catch {
      return refusal({ status: 400, code: 'runner.lockfiles_invalid', message: 'The lockfile submission is not valid JSON (DFGHR-15).' });
    }
    const parsed = RunnerLockfilesPayload.safeParse(json);
    if (!parsed.success) {
      return refusal({ status: 400, code: 'runner.lockfiles_invalid', message: `The lockfile submission is invalid (DFGHR-15): ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.') || 'root'}: ${i.message}`).join('; ')}.` });
    }
    const { envelope } = parsed.data;
    if (claims.repository_id !== envelope.repository_id || claims.repository_owner_id !== envelope.repository_owner_id || claims.sha !== envelope.head_sha) {
      return refusal({ status: 401, code: 'runner.unauthenticated', message: 'The OIDC token repository, owner or commit SHA does not match the lockfile envelope (DFGHR-12).' });
    }
    if ((options.mode ?? 'runner') !== 'agent.cloud') {
      return refusal({ status: 403, code: 'runner.mode_runner', message: 'This repository is in runner mode; lockfiles are accepted only in agent.cloud mode (DFGHR-15).' });
    }
    lockfiles.push({ raw: body, payload: parsed.data });
    return reply(202, { id: `sbi_${lockfiles.length}`, mode: 'agent.cloud', repository: 'sdr_fake', head_sha: envelope.head_sha, lockfiles: parsed.data.lockfiles.length, repeated: false, queued: true });
  }

  return { origin, requests, reports, lockfiles, handle };
}
