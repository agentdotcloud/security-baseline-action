// DFGHR-8, DFGHR-10, DFGHR-20: local static.deps execution, network boundaries, unreachable sources,
// job summary, 30-day artifact upload, fail-on threshold, and opt-in sending switch.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonicalJson, type DepsReportBody } from '@summationai/security-checks';
import {
  ARTIFACT_NAME,
  ARTIFACT_RETENTION_DAYS,
  createRunnerHttp,
  parseFailOn,
  runAction,
  runBaseline,
  serializeArtifact,
  SETUP_PAGE_URL,
  shouldSendReport,
  validatePublicRequest,
  type ActionRuntime,
  type ArtifactUploadRequest,
  type BaselineRunResult,
} from '../src/index.ts';

const NOW = Date.parse('2026-11-20T12:00:00Z');
const INTEGRITY = 'sha512-Zml4dHVyZQ==';
const tarball = (name: string, version: string) =>
  `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`;
const regEntry = (name: string, version: string, extra: Record<string, unknown> = {}) => ({
  version,
  resolved: tarball(name, version),
  integrity: INTEGRITY,
  ...extra,
});
const osvAdvisory = (id: string, name: string, severity: string, fixedVersion?: string) => ({
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

function makeCheckout(files: Record<string, unknown>): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'dfghr-action-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(dir, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, typeof content === 'string' ? content : JSON.stringify(content, null, 2), 'utf8');
  }
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

interface FakeNetworkOptions {
  records?: Record<string, unknown>[];
  privatePackages?: string[];
  registryDown?: boolean;
  osvDown?: boolean;
  manifests?: Record<string, Record<string, unknown>>;
}

function makeFakeFetch(opts: FakeNetworkOptions = {}) {
  const calls: { url: string; host: string; method: string; body?: string }[] = [];
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
    throw new Error(`Unexpected host contacted: ${url.hostname}`);
  }) as typeof fetch;

  return { fetcher, calls };
}

function makeRuntime(
  cwd: string,
  fetcher: typeof fetch,
  overrides: {
    inputs?: Record<string, string>;
    env?: Record<string, string | undefined>;
    onSendReport?: ActionRuntime['onSendReport'];
  } = {},
) {
  const outputs: Record<string, string> = {};
  const summaries: string[] = [];
  const artifacts: ArtifactUploadRequest[] = [];
  const failures: string[] = [];
  const infos: string[] = [];
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
    writeSummary: async (md) => {
      summaries.push(md);
    },
    uploadArtifact: async (req) => {
      artifacts.push(req);
    },
    env: overrides.env ?? {},
    cwd,
    now: () => NOW,
    httpOptions: { fetch: fetcher, retries: 0, baseBackoffMs: 0 },
    onSendReport: overrides.onSendReport,
  };
  return { runtime, outputs, summaries, artifacts, failures, infos };
}

test('DFGHR-8: contacts only registry.npmjs.org and api.osv.dev, sending only DFBASE-9 gated pairs', async () => {
  const checkout = makeCheckout({
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo', dependencies: { 'pub-pkg': '^1.0.0', '@acme/scoped-pub': '^2.0.0', 'priv-pkg': '^1.0.0' } },
        'node_modules/pub-pkg': regEntry('pub-pkg', '1.0.0'),
        'node_modules/@acme/scoped-pub': regEntry('@acme/scoped-pub', '2.0.0'),
        'node_modules/priv-pkg': regEntry('priv-pkg', '1.0.0'),
        'node_modules/internal-mirror': {
          version: '2.0.0',
          resolved: 'https://npm.internal.example/internal-mirror/-/internal-mirror-2.0.0.tgz',
          integrity: INTEGRITY,
        },
        'node_modules/bundled-pkg': regEntry('bundled-pkg', '1.0.0', { inBundle: true }),
      },
    },
  });

  try {
    const net = makeFakeFetch({
      privatePackages: ['priv-pkg'],
      records: [
        osvAdvisory('GHSA-1111-2222-3333', 'pub-pkg', 'HIGH', '1.2.0'),
        osvAdvisory('GHSA-4444-5555-6666', '@acme/scoped-pub', 'MODERATE', '2.1.0'),
      ],
    });
    const result = await runBaseline({
      checkoutDir: checkout.dir,
      now: () => NOW,
      httpOptions: { fetch: net.fetcher, retries: 0, baseBackoffMs: 0 },
    });

    assert.ok(net.calls.length > 0);
    for (const c of net.calls) {
      assert.ok(c.host === 'registry.npmjs.org' || c.host === 'api.osv.dev', `unexpected host ${c.host}`);
    }
    const osvBodies = net.calls.filter((c) => c.url.endsWith('/v1/querybatch')).map((c) => c.body ?? '');
    assert.ok(osvBodies.some((b) => b.includes('pub-pkg')), 'verified public package reaches OSV');
    assert.ok(osvBodies.some((b) => b.includes('@acme/scoped-pub')), 'verified scoped public package reaches OSV');
    for (const b of osvBodies) {
      assert.ok(!b.includes('priv-pkg'), 'unverified private package never sent to OSV');
      assert.ok(!b.includes('internal-mirror'), 'non-public registry package never sent to OSV');
      assert.ok(!b.includes('bundled-pkg'), 'bundled package never sent to OSV');
    }
    assert.ok(
      net.calls.every((c) => !c.url.includes('internal-mirror') && !c.url.includes('bundled-pkg')),
      'held entries are never looked up on npm registry',
    );
    assert.equal(result.reports.length, 1);
    assert.equal(result.reports[0]!.findings.length, 2);
    assert.equal(result.reports[0]!.extension.not_checked.total, 3);
    assert.equal(result.coverage, 'partial');

    // Scoped package URL forms (both encoded and unencoded slash) are accepted; malformed/disallowed URLs are refused.
    for (const good of [
      'https://registry.npmjs.org/%40acme%2Fscoped-pub/2.0.0',
      'https://registry.npmjs.org/@acme%2Fscoped-pub/2.0.0',
      'https://registry.npmjs.org/@acme/scoped-pub/2.0.0',
    ]) {
      assert.equal(validatePublicRequest(good, undefined).origin, 'npm', good);
    }
    const http = createRunnerHttp({ fetch: net.fetcher, retries: 0, baseBackoffMs: 0 });
    for (const bad of [
      'https://agent.cloud/security/github/runner/reports',
      'https://registry.npmjs.org.evil.test/pub-pkg/1.0.0',
      'https://api.osv.dev/v1/querybatch?extra=1',
      'http://registry.npmjs.org/pub-pkg/1.0.0',
      'https://user:pass@registry.npmjs.org/pub-pkg/1.0.0',
      'https://registry.npmjs.org/not-a-scope/pkg/1.0.0',
      'https://registry.npmjs.org/@acme/pkg/extra/1.0.0',
      'https://registry.npmjs.org/%ZZ/1.0.0',
      'https://api.osv.dev/v1/vulns/%ZZ',
      'not a url',
    ]) {
      assert.throws(() => validatePublicRequest(bad, undefined), /runner\.public_origin_refused/, bad);
      await assert.rejects(http.json(bad), /runner\.public_origin_refused/, bad);
    }
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-8: an unreachable npm registry or OSV source reports unavailable and incomplete, and the job still passes', async () => {
  const checkout = makeCheckout({
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo', dependencies: { 'pub-pkg': '^1.0.0' } },
        'node_modules/pub-pkg': regEntry('pub-pkg', '1.0.0'),
      },
    },
  });

  try {
    for (const outage of [
      { label: 'registry', opts: { registryDown: true }, host: 'registry.npmjs.org', source: 'npm-registry' },
      { label: 'osv', opts: { osvDown: true }, host: 'api.osv.dev', source: 'osv' },
    ] as const) {
      const net = makeFakeFetch(outage.opts);
      const { runtime, summaries, artifacts, failures, outputs } = makeRuntime(checkout.dir, net.fetcher);
      const exec = await runAction(runtime);

      assert.equal(exec.failed, false, `${outage.label} outage must not fail the job`);
      assert.deepEqual(failures, [], `${outage.label} outage calls setFailed zero times`);
      assert.equal(exec.result.coverage, 'incomplete', outage.label);
      assert.equal(exec.result.summary.analysis, 'incomplete', outage.label);
      assert.equal(outputs.coverage, 'incomplete', outage.label);
      assert.equal(
        outage.source === 'npm-registry' ? exec.result.sources.registry.status : exec.result.sources.osv.status,
        'unavailable',
        outage.label,
      );
      assert.equal(exec.result.summary.unavailable.length, 1);
      assert.equal(exec.result.summary.unavailable[0]!.host, outage.host);
      assert.equal(exec.result.summary.unavailable[0]!.status, 'unavailable');
      assert.match(summaries[0]!, new RegExp(`incomplete.*${outage.host}|${outage.host}.*incomplete`, 'is'));
      assert.equal(artifacts.length, 1);
      assert.equal(artifacts[0]!.name, ARTIFACT_NAME);
      assert.equal(artifacts[0]!.retentionDays, ARTIFACT_RETENTION_DAYS);
    }
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-10: job summary, 30-day agentcloud-baseline artifact, setup link, and fail-on thresholds', async () => {
  const checkout = makeCheckout({
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'demo',
          dependencies: { 'crit-pkg': '^1.0.0', 'mod-pkg': '^1.0.0', 'low-pkg': '^1.0.0' },
        },
        'node_modules/crit-pkg': regEntry('crit-pkg', '1.0.0'),
        'node_modules/mod-pkg': regEntry('mod-pkg', '1.0.0'),
        'node_modules/low-pkg': regEntry('low-pkg', '1.0.0'),
        'node_modules/priv-only': regEntry('priv-only', '1.0.0'),
      },
    },
  });

  try {
    const records = [
      osvAdvisory('GHSA-aaaa-1111-1111', 'crit-pkg', 'CRITICAL', '1.5.0'),
      osvAdvisory('GHSA-bbbb-2222-2222', 'mod-pkg', 'MODERATE', '1.2.0'),
      osvAdvisory('GHSA-cccc-3333-3333', 'low-pkg', 'LOW'),
    ];

    // 1. Default (fail-on unset): never fails even with critical findings.
    const netDefault = makeFakeFetch({ records, privatePackages: ['priv-only'] });
    const rtDefault = makeRuntime(checkout.dir, netDefault.fetcher);
    const execDefault = await runAction(rtDefault.runtime);

    assert.equal(execDefault.failed, false, 'unset fail-on never fails on findings');
    assert.deepEqual(rtDefault.failures, []);
    assert.equal(rtDefault.outputs['findings-count'], '3');
    assert.equal(rtDefault.outputs['artifact-name'], 'agentcloud-baseline');

    // Artifact check: name, 30-day retention, valid JSON containing exact DepsReportBody.
    assert.equal(rtDefault.artifacts.length, 1);
    assert.equal(rtDefault.artifacts[0]!.name, 'agentcloud-baseline');
    assert.equal(rtDefault.artifacts[0]!.retentionDays, 30);
    const uploaded = JSON.parse(rtDefault.artifacts[0]!.content);
    assert.equal(uploaded.schema, 'summation.runner/baseline/1');
    assert.equal(uploaded.reports.length, 1);
    assert.equal(uploaded.reports[0].findings.length, 3);

    // Summary check: findings columns, coverage line, unchecked private package, final setup line.
    const summary = rtDefault.summaries[0]!;
    assert.match(summary, /Coverage:\s+\*\*partial\*\*/);
    assert.match(summary, /\|\s*package-lock\.json\s*\|\s*crit-pkg\s*\|\s*1\.0\.0\s*\|\s*GHSA-aaaa-1111-1111\s*\|\s*critical\s*\|\s*1\.5\.0\s*\|/);
    assert.match(summary, /\|\s*package-lock\.json\s*\|\s*mod-pkg\s*\|\s*1\.0\.0\s*\|\s*GHSA-bbbb-2222-2222\s*\|\s*moderate\s*\|\s*1\.2\.0\s*\|/);
    assert.match(summary, /\|\s*package-lock\.json\s*\|\s*low-pkg\s*\|\s*1\.0\.0\s*\|\s*GHSA-cccc-3333-3333\s*\|\s*low\s*\|\s*none\s*\|/);
    assert.match(summary, /node_modules\/priv-only/);
    const lastLine = summary.trim().split('\n').at(-1)!;
    assert.match(lastLine, /proofs.*fix pull requests/i);
    assert.ok(lastLine.includes('/security/github/setup'), 'final line includes /security/github/setup');
    assert.ok(lastLine.includes(SETUP_PAGE_URL), 'final line links to the setup page');

    // 2. fail-on thresholds: critical/high/moderate/low.
    const onlyLowCheckout = makeCheckout({
      'package-lock.json': {
        lockfileVersion: 3,
        packages: {
          '': { name: 'low-only', dependencies: { 'mod-pkg': '^1.0.0', 'low-pkg': '^1.0.0' } },
          'node_modules/mod-pkg': regEntry('mod-pkg', '1.0.0'),
          'node_modules/low-pkg': regEntry('low-pkg', '1.0.0'),
        },
      },
    });
    try {
      for (const [level, expectedFailed] of [
        ['critical', false],
        ['high', false],
        ['moderate', true],
        ['low', true],
      ] as const) {
        const net = makeFakeFetch({ records });
        const rt = makeRuntime(onlyLowCheckout.dir, net.fetcher, { inputs: { 'fail-on': level } });
        const exec = await runAction(rt.runtime);
        assert.equal(exec.failed, expectedFailed, `fail-on=${level}`);
        assert.equal(rt.failures.length, expectedFailed ? 1 : 0, `setFailed for fail-on=${level}`);
      }
    } finally {
      onlyLowCheckout.cleanup();
    }

    assert.throws(() => parseFailOn('bogus'), /Invalid fail-on value/);
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-10: serializeArtifact matches canonicalJson for small runs and handles multi-lockfile runs over single-report node limits', async () => {
  const checkout = makeCheckout({
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo', dependencies: { 'pub-pkg': '^1.0.0' } },
        'node_modules/pub-pkg': regEntry('pub-pkg', '1.0.0'),
      },
    },
  });
  try {
    const net = makeFakeFetch({ records: [osvAdvisory('GHSA-aaaa-1111-1111', 'pub-pkg', 'HIGH', '1.2.0')] });
    const small = await runBaseline({
      checkoutDir: checkout.dir,
      now: () => NOW,
      httpOptions: { fetch: net.fetcher, retries: 0, baseBackoffMs: 0 },
    });
    assert.equal(serializeArtifact(small), canonicalJson(small), 'byte-identical to canonicalJson on normal runs');

    // Construct a 20-lockfile aggregate where each individual DepsReportBody stays well under canonicalJson's
    // 300,000-node limit (~20,000 nodes each), while the aggregate (~400,000 nodes) exceeds canonicalJson's limit.
    const baseBody = small.reports[0]!;
    const manyEntries = Array.from({ length: 1000 }, (_, i) => ({
      entry: `node_modules/pkg-${i}`,
      reason: 'public_identity_unverified',
    }));
    const heavyReports: DepsReportBody[] = Array.from({ length: 20 }, (_, idx) => ({
      ...baseBody,
      lockfile: { ...baseBody.lockfile, path: `pkg-${idx}/package-lock.json` },
      extension: {
        ...baseBody.extension,
        lockfile: { ...baseBody.extension.lockfile, path: `pkg-${idx}/package-lock.json` },
        not_checked: { total: manyEntries.length, by_reason: { public_identity_unverified: manyEntries.length }, entries: manyEntries },
      },
    }));
    const big: BaselineRunResult = { ...small, reports: heavyReports };
    // Even if each individual report fits canonicalJson, verify serializeArtifact handles multi-lockfile aggregates
    // over 300,000 JSON nodes (construct 105 reports if 20 wasn't enough to cross 300k nodes).
    const reportsOver300k: DepsReportBody[] = Array.from({ length: 110 }, (_, idx) => heavyReports[idx % heavyReports.length]!);
    const huge: BaselineRunResult = { ...big, reports: reportsOver300k };
    assert.throws(() => canonicalJson(huge), /report_complexity|report_size/, 'aggregate crosses canonicalJson single-report cap');
    const serialized = serializeArtifact(huge);
    const parsed = JSON.parse(serialized) as BaselineRunResult;
    assert.equal(parsed.reports.length, 110);
    assert.equal(parsed.schema, small.schema);
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-20: sending is off by default and contacts no agent.cloud host; input or AGENTCLOUD_SEND_REPORT turns it on', async () => {
  assert.equal(shouldSendReport(undefined, {}), false);
  assert.equal(shouldSendReport('', {}), false);
  assert.equal(shouldSendReport('false', { AGENTCLOUD_SEND_REPORT: 'false' }), false);
  assert.equal(shouldSendReport('1', { AGENTCLOUD_SEND_REPORT: 'yes' }), false);
  assert.equal(shouldSendReport('true', {}), true);
  assert.equal(shouldSendReport('TRUE', {}), true);
  assert.equal(shouldSendReport('false', { AGENTCLOUD_SEND_REPORT: 'true' }), true);
  assert.equal(shouldSendReport(undefined, { AGENTCLOUD_SEND_REPORT: 'true' }), true);

  const checkout = makeCheckout({
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo', dependencies: { 'pub-pkg': '^1.0.0' } },
        'node_modules/pub-pkg': regEntry('pub-pkg', '1.0.0'),
      },
    },
  });
  try {
    // Off by default: no agent.cloud host contacted and onSendReport never called.
    let sendCalls = 0;
    const netOff = makeFakeFetch();
    const rtOff = makeRuntime(checkout.dir, netOff.fetcher, {
      onSendReport: async () => {
        sendCalls++;
      },
    });
    const execOff = await runAction(rtOff.runtime);
    assert.equal(execOff.sendingEnabled, false);
    assert.equal(rtOff.outputs['send-report'], 'false');
    assert.equal(sendCalls, 0);
    assert.ok(
      netOff.calls.every((c) => c.host === 'registry.npmjs.org' || c.host === 'api.osv.dev'),
      'no agent.cloud or other host contacted when sending is off',
    );
    assert.ok(
      netOff.calls.every((c) => !c.host.includes('agent.cloud') && !c.host.includes('ac0.app')),
      'no agent.cloud host contacted',
    );

    // On via send-report input.
    let sendViaInput = 0;
    const rtInput = makeRuntime(checkout.dir, makeFakeFetch().fetcher, {
      inputs: { 'send-report': 'true' },
      onSendReport: async () => {
        sendViaInput++;
      },
    });
    const execInput = await runAction(rtInput.runtime);
    assert.equal(execInput.sendingEnabled, true);
    assert.equal(rtInput.outputs['send-report'], 'true');
    assert.equal(sendViaInput, 1);

    // On via AGENTCLOUD_SEND_REPORT variable.
    let sendViaVar = 0;
    const rtVar = makeRuntime(checkout.dir, makeFakeFetch().fetcher, {
      env: { AGENTCLOUD_SEND_REPORT: 'true' },
      onSendReport: async () => {
        sendViaVar++;
      },
    });
    const execVar = await runAction(rtVar.runtime);
    assert.equal(execVar.sendingEnabled, true);
    assert.equal(rtVar.outputs['send-report'], 'true');
    assert.equal(sendViaVar, 1);
  } finally {
    checkout.cleanup();
  }
});
