// Shared fixtures for the action's tests: checkouts on disk, fake npm and OSV, and a recording ActionRuntime.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ActionRuntime, ArtifactUploadRequest, BaselineArtifact } from '../src/index.ts';

export const NOW = Date.parse('2026-11-20T12:00:00Z');
export const INTEGRITY = 'sha512-Zml4dHVyZQ==';
export const tarball = (name: string, version: string) =>
  `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`;
export const regEntry = (name: string, version: string, extra: Record<string, unknown> = {}) => ({
  version,
  resolved: tarball(name, version),
  integrity: INTEGRITY,
  ...extra,
});
export const osvAdvisory = (id: string, name: string, severity: string, fixedVersion?: string) => ({
  id,
  modified: '2026-11-01T00:00:00Z',
  summary: `${id} in ${name}`,
  aliases: [id],
  affected: [
    {
      package: { ecosystem: 'npm', name },
      ranges: [
        {
          type: 'SEMVER',
          events: fixedVersion ? [{ introduced: '0' }, { fixed: fixedVersion }] : [{ introduced: '0' }],
        },
      ],
    },
  ],
  database_specific: { severity },
});

export function makeCheckout(files: Record<string, unknown>): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'dfghr-action-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, typeof content === 'string' ? content : JSON.stringify(content, null, 2), 'utf8');
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export interface FakeNetworkOptions {
  records?: Record<string, unknown>[];
  privatePackages?: string[];
  registryDown?: boolean;
  osvDown?: boolean;
  manifests?: Record<string, Record<string, unknown>>;
  /** Hosts other than npm and OSV, such as a fake agent.cloud: their requests go here instead of failing the test. */
  others?: Record<string, (url: URL, init: RequestInit | undefined) => Promise<Response>>;
}

export interface FetchCall {
  url: string;
  host: string;
  method: string;
  body?: string;
}

export function makeFakeFetch(opts: FakeNetworkOptions = {}) {
  const calls: FetchCall[] = [];
  const records = opts.records ?? [];
  const fetcher = (async (raw: string | URL | Request, init?: RequestInit) => {
    const url = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
    const body = typeof init?.body === 'string' ? init.body : undefined;
    calls.push({ url: url.href, host: url.hostname, method: init?.method ?? 'GET', body });
    assert.equal(init?.redirect, 'manual', 'redirects must stay manual');

    if (url.hostname === 'registry.npmjs.org') {
      if (opts.registryDown) throw new TypeError('connect ECONNREFUSED registry.npmjs.org');
      const segs = url.pathname.slice(1).split('/').map(decodeURIComponent);
      const [name, version] = segs.length === 3 ? [`${segs[0]}/${segs[1]}`, segs[2]!] : [segs[0]!, segs[1]!];
      if (opts.privatePackages?.includes(name)) return new Response(null, { status: 404 });
      return Response.json({
        name,
        version,
        dist: { tarball: tarball(name, version), integrity: INTEGRITY },
        ...opts.manifests?.[`${name}@${version}`],
      });
    }
    if (url.hostname === 'api.osv.dev') {
      if (opts.osvDown) throw new TypeError('connect ECONNREFUSED api.osv.dev');
      if (url.pathname === '/v1/querybatch') {
        const parsed = JSON.parse(body ?? '{}') as { queries: { package: { name: string }; version: string }[] };
        return Response.json({
          results: parsed.queries.map((q) => ({
            vulns: records
              .filter((r) =>
                (r.affected as { package: { name: string } }[]).some((a) => a.package.name === q.package.name),
              )
              .map((r) => ({ id: r.id, modified: r.modified })),
          })),
        });
      }
      const id = decodeURIComponent(url.pathname.slice('/v1/vulns/'.length));
      const record = records.find((r) => r.id === id);
      return record ? Response.json(record) : new Response(null, { status: 404 });
    }
    const other = opts.others?.[url.hostname];
    if (other) return other(url, init);
    throw new Error(`Unexpected host contacted: ${url.hostname}`);
  }) as typeof fetch;

  return { fetcher, calls };
}

/** The variables GitHub Actions sets that the run envelope reads (DFGHR-11). */
export const RUN = {
  repositoryId: '700100',
  ownerId: '800200',
  sha: 'a'.repeat(40),
  runId: '9001',
};

export function githubEnv(extra: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    GITHUB_REPOSITORY: 'acme/web',
    GITHUB_REPOSITORY_ID: RUN.repositoryId,
    GITHUB_REPOSITORY_OWNER_ID: RUN.ownerId,
    GITHUB_SHA: RUN.sha,
    GITHUB_RUN_ID: RUN.runId,
    GITHUB_EVENT_NAME: 'push',
    ...extra,
  };
}

export interface RuntimeOverrides {
  inputs?: Record<string, string>;
  env?: Record<string, string | undefined>;
  getIdToken?: ActionRuntime['getIdToken'];
  listBaselineArtifacts?: ActionRuntime['listBaselineArtifacts'];
  readArtifactFile?: ActionRuntime['readArtifactFile'];
}

export function makeRuntime(cwd: string, fetcher: typeof fetch, overrides: RuntimeOverrides = {}) {
  const outputs: Record<string, string> = {};
  const summaries: string[] = [];
  const artifacts: ArtifactUploadRequest[] = [];
  const failures: string[] = [];
  const infos: string[] = [];
  const warnings: string[] = [];
  /** Everything the action asked GitHub for beyond the checkout: OIDC tokens and earlier runs' artifacts. */
  const github: { oidc: string[]; lists: string[]; reads: { artifact: BaselineArtifact; token: string; file: string; maxBytes: number }[] } = {
    oidc: [],
    lists: [],
    reads: [],
  };
  const inputs = overrides.inputs ?? {};

  const runtime: ActionRuntime = {
    getInput: (name) => inputs[name] ?? '',
    setOutput: (name, value) => {
      outputs[name] = value;
    },
    setFailed: (message) => {
      failures.push(message);
    },
    info: (message) => {
      infos.push(message);
    },
    warning: (message) => {
      warnings.push(message);
    },
    writeSummary: async (md) => {
      summaries.push(md);
    },
    uploadArtifact: async (req) => {
      artifacts.push(req);
    },
    getIdToken: async (audience) => {
      github.oidc.push(audience);
      if (!overrides.getIdToken) throw new Error('Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable');
      return overrides.getIdToken(audience);
    },
    listBaselineArtifacts: async (token) => {
      github.lists.push(token);
      return overrides.listBaselineArtifacts ? overrides.listBaselineArtifacts(token) : [];
    },
    readArtifactFile: async (artifact, token, file, maxBytes) => {
      github.reads.push({ artifact, token, file, maxBytes });
      return overrides.readArtifactFile ? overrides.readArtifactFile(artifact, token, file, maxBytes) : null;
    },
    env: overrides.env ?? {},
    cwd,
    now: () => NOW,
    httpOptions: { fetch: fetcher, retries: 0, baseBackoffMs: 0 },
  };
  return { runtime, outputs, summaries, artifacts, failures, infos, warnings, github };
}
