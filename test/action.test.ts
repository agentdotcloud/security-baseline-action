// DFGHR-8, DFGHR-10, DFGHR-20: local static.deps execution, network boundaries, unreachable sources,
// job summary, 30-day artifact upload, fail-on threshold, and the opt-in sending switch.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJson, type DepsReportBody } from '@summationai/security-checks';
import {
  ARTIFACT_FILE,
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
  type BaselineRunResult,
} from '../src/index.ts';
import { INTEGRITY, makeCheckout, makeFakeFetch, makeRuntime, NOW, osvAdvisory, regEntry } from './helpers.ts';

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
    const uploaded = JSON.parse(rtDefault.artifacts[0]!.contents[ARTIFACT_FILE]!);
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

test('DFGHR-20: only the send-report input or the AGENTCLOUD_SEND_REPORT variable set to true turns sending on', () => {
  assert.equal(shouldSendReport(undefined, {}), false);
  assert.equal(shouldSendReport('', {}), false);
  assert.equal(shouldSendReport('false', { AGENTCLOUD_SEND_REPORT: 'false' }), false);
  assert.equal(shouldSendReport('1', { AGENTCLOUD_SEND_REPORT: 'yes' }), false);
  assert.equal(shouldSendReport('true', {}), true);
  assert.equal(shouldSendReport('TRUE', {}), true);
  assert.equal(shouldSendReport('false', { AGENTCLOUD_SEND_REPORT: 'true' }), true);
  assert.equal(shouldSendReport(undefined, { AGENTCLOUD_SEND_REPORT: 'true' }), true);
  // send.test.ts proves that with sending off nothing reaches agent.cloud, and what turning it on sends.
});

test('DFBASE-23: scans pnpm-lock.yaml and yarn.lock (Classic v1 and Berry) alongside package-lock.json, covering workspaces without counting them as unlocked', async () => {
  const berrySum = 'b'.repeat(128);
  const checkout = makeCheckout({
    'pnpm-lock.yaml': [
      "lockfileVersion: '9.0'",
      'importers:',
      '  .:',
      '    dependencies:',
      '      pub-pkg:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0',
      '  packages/web:',
      '    dependencies:',
      '      pub-pkg:',
      '        specifier: ^1.0.0',
      '        version: 1.0.0',
      'packages:',
      '  pub-pkg@1.0.0:',
      `    resolution: {integrity: ${INTEGRITY}}`,
      '  priv-pnpm@1.0.0:',
      `    resolution: {integrity: ${INTEGRITY}, tarball: https://npm.internal.example/priv-pnpm/-/priv-pnpm-1.0.0.tgz}`,
      'snapshots:',
      '  pub-pkg@1.0.0: {}',
    ].join('\n'),
    'package.json': { name: 'root-pnpm', private: true },
    'packages/web/package.json': { name: 'web', private: true },
    'services/classic/yarn.lock': [
      '# yarn lockfile v1',
      '"@acme/scoped-pub@^2.0.0":',
      '  version "2.0.0"',
      '  resolved "https://registry.yarnpkg.com/@acme/scoped-pub/-/scoped-pub-2.0.0.tgz#0123456789abcdef0123456789abcdef01234567"',
      `  integrity ${INTEGRITY}`,
    ].join('\n'),
    'services/classic/package.json': { name: 'classic', dependencies: { '@acme/scoped-pub': '^2.0.0' } },
    'services/berry/yarn.lock': [
      '__metadata:',
      '  version: 8',
      '  cacheKey: 10c0',
      '"berry@workspace:.":',
      '  version: 0.0.0-use.local',
      '  resolution: "berry@workspace:."',
      '  dependencies:',
      '    pub-pkg: "npm:^1.0.0"',
      '"pub-pkg@npm:^1.0.0":',
      '  version: 1.0.0',
      '  resolution: "pub-pkg@npm:1.0.0"',
      `  checksum: 10c0/${berrySum}`,
    ].join('\n'),
    'services/berry/package.json': { name: 'berry', dependencies: { 'pub-pkg': '^1.0.0' } },
  });

  try {
    const net = makeFakeFetch({
      records: [
        osvAdvisory('GHSA-1111-2222-3333', 'pub-pkg', 'HIGH', '1.2.0'),
        osvAdvisory('GHSA-4444-5555-6666', '@acme/scoped-pub', 'MODERATE', '2.1.0'),
      ],
    });
    const rt = makeRuntime(checkout.dir, net.fetcher);
    const exec = await runAction(rt.runtime);

    assert.equal(exec.failed, false);
    assert.deepEqual(exec.result.summary.selected_lockfiles, [
      'pnpm-lock.yaml',
      'services/berry/yarn.lock',
      'services/classic/yarn.lock',
    ]);
    assert.deepEqual(exec.result.summary.inputs_not_analyzed, {}, 'neither pnpm-lock.yaml, yarn.lock nor covered workspace package.json is counted as unanalyzed');
    assert.equal(exec.result.reports.length, 3);
    assert.equal(rt.outputs['findings-count'], '3');
    assert.ok(net.calls.every((c) => !c.url.includes('priv-pnpm')), 'private pnpm tarball never looked up on npm or OSV');
    assert.match(rt.summaries[0]!, /pnpm-lock\.yaml/);
    assert.match(rt.summaries[0]!, /services\/classic\/yarn\.lock/);
    assert.match(rt.summaries[0]!, /services\/berry\/yarn\.lock/);
  } finally {
    checkout.cleanup();
  }
});
