// DFGHR-8, DFGHR-9, DFGHR-20: run static.deps locally on each selected package-lock.json in the checkout.
import {
  DepsCheckError,
  staticDeps,
  type DepsIdentityCache,
  type DepsIdentityFacts,
  type DepsReportBody,
  type PublicHTTP,
} from '@summationai/security-checks';
import { BASELINE as P, BASELINE_DIGEST } from '../vendor/security-checks/src/baseline-profile.ts';
import { acquireCheckout, type CheckoutSkip } from './checkout.ts';
import { createRunnerHttp, type RunnerHttpOptions } from './http.ts';

export type SourceName = 'npm-registry' | 'osv';
export type SourceAvailability = 'available' | 'unavailable' | 'not_queried';
export type BaselineCoverageState = 'complete' | 'partial' | 'incomplete' | 'none';

export interface UnavailableLockfile {
  path: string;
  source: SourceName;
  host: 'registry.npmjs.org' | 'api.osv.dev';
  status: 'unavailable';
  reason: string;
}

export interface HeldLockfile {
  path: string;
  reason: string;
  totals?: Record<string, number>;
  limits?: Record<string, number>;
}

export interface BaselineRunResult {
  schema: 'summation.runner/baseline/1';
  profile: { id: typeof P.id; revision: typeof P.revision; digest: typeof BASELINE_DIGEST };
  coverage: BaselineCoverageState;
  sources: {
    registry: { host: 'registry.npmjs.org'; status: SourceAvailability };
    osv: { host: 'api.osv.dev'; status: SourceAvailability };
    dependabot: { status: 'not_selected' };
  };
  reports: DepsReportBody[];
  summary: {
    analysis: BaselineCoverageState;
    selected_lockfiles: string[];
    skipped: CheckoutSkip[];
    holds: HeldLockfile[];
    unavailable: UnavailableLockfile[];
    inputs_not_analyzed: Record<string, number>;
    requests: { registry: number; osv: number };
  };
}

export interface RunBaselineOptions {
  checkoutDir: string;
  now?: () => number;
  signal?: AbortSignal;
  http?: PublicHTTP;
  httpOptions?: RunnerHttpOptions;
}

const SOURCE_HOST: Record<SourceName, 'registry.npmjs.org' | 'api.osv.dev'> = {
  'npm-registry': 'registry.npmjs.org',
  osv: 'api.osv.dev',
};

/** DFGHR-20: sending is off unless the send-report input or AGENTCLOUD_SEND_REPORT variable is explicitly 'true'. */
export function shouldSendReport(
  sendReportInput: string | undefined,
  env: Readonly<Record<string, string | undefined>> = process.env,
): boolean {
  return (
    sendReportInput?.trim().toLowerCase() === 'true' ||
    env.AGENTCLOUD_SEND_REPORT?.trim().toLowerCase() === 'true'
  );
}

function createMemoryIdentityCache(): DepsIdentityCache {
  const entries = new Map<string, DepsIdentityFacts>();
  const key = (name: string, version: string, integrity: string) => JSON.stringify([name, version, integrity]);
  return {
    async get(name, version, integrity) {
      return entries.get(key(name, version, integrity)) ?? null;
    },
    async put(facts) {
      entries.set(key(facts.name, facts.version, facts.integrity), facts);
    },
  };
}

export async function runBaseline(options: RunBaselineOptions): Promise<BaselineRunResult> {
  const now = options.now ?? Date.now;
  const http = options.http ?? createRunnerHttp({ ...options.httpOptions, now, signal: options.signal });
  const acquired = acquireCheckout(options.checkoutDir);
  const cache = createMemoryIdentityCache();

  const admittedInRun = new Set<string>();
  const skipped: CheckoutSkip[] = [...acquired.skipped];
  const holds: HeldLockfile[] = [];
  const unavailable: UnavailableLockfile[] = [];
  const reports: DepsReportBody[] = [];
  const requests = { registry: 0, osv: 0 };

  let registryStatus: SourceAvailability = 'not_queried';
  let osvStatus: SourceAvailability = 'not_queried';
  let partial = false;

  for (const lock of acquired.locks) {
    const admitted: string[] = [];
    for (const pair of [...lock.pairs].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))) {
      if (!admittedInRun.has(pair) && admittedInRun.size === P.identities) break;
      admittedInRun.add(pair);
      admitted.push(pair);
    }

    try {
      // DFGHR-9: run static.deps in the runner's own process with Dependabot omitted (optional per DFBASE-11).
      const result = await staticDeps(
        {
          path: lock.path,
          bytes: lock.bytes,
          git_blob: lock.git_blob,
          sha256: lock.sha256,
          overrides: lock.overrides,
          package_json: lock.package_json,
        },
        {
          http,
          now,
          signal: options.signal,
          cache,
          limits: { max_identities: admitted.length, admitted_identities: new Set(admitted) },
        },
      );
      requests.registry += result.requests.registry;
      requests.osv += result.requests.osv;
      if (result.requests.registry > 0 && registryStatus !== 'unavailable') registryStatus = 'available';
      if (result.requests.osv > 0 && osvStatus !== 'unavailable') osvStatus = 'available';

      if (result.outcome === 'report') {
        reports.push(result.body);
        if (result.body.coverage.state === 'partial') partial = true;
      } else if (result.outcome === 'held') {
        holds.push({ path: lock.path, reason: result.reason, totals: result.totals, limits: result.limits });
      } else {
        skipped.push({ path: lock.path, reason: result.reason });
      }
    } catch (error) {
      if (error instanceof DepsCheckError && error.code === 'deps_check.source_failed' && error.source) {
        // DFGHR-8: an unreachable source is reported unavailable and the report incomplete; the job still passes.
        if (error.source === 'npm-registry') registryStatus = 'unavailable';
        if (error.source === 'osv') osvStatus = 'unavailable';
        unavailable.push({
          path: lock.path,
          source: error.source,
          host: SOURCE_HOST[error.source],
          status: 'unavailable',
          reason: error.message || 'source_unavailable',
        });
        continue;
      }
      throw error;
    }
  }

  let analysis: BaselineCoverageState;
  if (unavailable.length > 0) {
    analysis = 'incomplete';
  } else if (!acquired.locks.length && !holds.length) {
    analysis = 'none';
  } else if (partial || skipped.length || holds.length || Object.keys(acquired.other).length) {
    analysis = 'partial';
  } else {
    analysis = 'complete';
  }

  return {
    schema: 'summation.runner/baseline/1',
    profile: { id: P.id, revision: P.revision, digest: BASELINE_DIGEST },
    coverage: analysis,
    sources: {
      registry: { host: 'registry.npmjs.org', status: registryStatus },
      osv: { host: 'api.osv.dev', status: osvStatus },
      dependabot: { status: 'not_selected' },
    },
    reports,
    summary: {
      analysis,
      selected_lockfiles: acquired.selectedPaths,
      skipped,
      holds,
      unavailable,
      inputs_not_analyzed: acquired.other,
      requests,
    },
  };
}
