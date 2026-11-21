// DFGHR-18: the bundle is one file bundling security-checks; it reaches only zod, semver, node:crypto,
// the action toolkit (@actions/core, @actions/artifact, @actions/github), fetch to the allowed hosts (registry.npmjs.org,
// api.osv.dev and, only when sending is on, the configured agent.cloud origin), and file reads under the checkout.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { importGraph } from '../vendor/security-checks/test/import-graph.ts';
import { bundleAction } from '../scripts/bundle.ts';

const ACTION_SRC = dirname(fileURLToPath(new URL('../src/main.ts', import.meta.url)));
const CHECKS_SRC = dirname(fileURLToPath(new URL('../vendor/security-checks/src/index.ts', import.meta.url)));
const NODE_BUILTINS = new Set([...builtinModules, ...builtinModules.map((b) => `node:${b}`)]);

const ALLOWED_SOURCE_PACKAGES = new Set([
  '@actions/artifact',
  '@actions/core',
  '@actions/github',
  '@summationai/security-checks',
  'node:crypto',
  'node:fs',
  'node:os',
  'node:path',
  'semver',
  'zod',
]);

test('DFGHR-18: source import graph reaches only security-checks, zod, semver, node:crypto, the action toolkit, and checkout file reads', () => {
  for (const entry of ['main.ts', 'index.ts']) {
    const graph = importGraph(join(ACTION_SRC, entry));
    assert.deepEqual(graph.unresolved, [], `${entry} has no unresolved imports`);
    for (const mod of graph.modules) {
      const dir = dirname(mod);
      assert.ok(
        dir === ACTION_SRC || dir === CHECKS_SRC,
        `${entry} must not reach workspace module outside security-baseline-action or security-checks: ${mod}`,
      );
    }
    for (const pkg of graph.packages) {
      assert.ok(ALLOWED_SOURCE_PACKAGES.has(pkg), `${entry} reaches disallowed import: ${pkg}`);
    }
  }
});

test('DFGHR-18: source files reference no host other than registry.npmjs.org, api.osv.dev, and agent.cloud as the default control origin and setup link', () => {
  const urlPattern = /https?:\/\/([a-zA-Z0-9.-]+)/g;
  // output.ts links the setup page; agentcloud.ts holds the default control origin, the only one sending ever reaches.
  const AGENTCLOUD_FILES = new Set(['output.ts', 'agentcloud.ts']);
  const seenAgentCloud = new Set<string>();
  for (const file of readdirSync(ACTION_SRC).filter((f) => f.endsWith('.ts'))) {
    const text = readFileSync(join(ACTION_SRC, file), 'utf8');
    const hosts = [...text.matchAll(urlPattern)].map((m) => m[1]!);
    for (const host of hosts) {
      if (AGENTCLOUD_FILES.has(file)) {
        assert.equal(host, 'agent.cloud', `unexpected host in ${file}: ${host}`);
        seenAgentCloud.add(file);
      } else {
        assert.ok(
          host === 'registry.npmjs.org' || host === 'api.osv.dev',
          `unexpected host literal in ${file}: ${host}`,
        );
      }
    }
  }
  assert.deepEqual([...seenAgentCloud].sort(), ['agentcloud.ts', 'output.ts']);
});

test('DFGHR-18: bundle produces one deterministic self-contained file with only allowed packages and runs standalone', async () => {
  const outDir = mkdtempSync(join(tmpdir(), 'dfghr-bundle-'));
  try {
    const fileA = join(outDir, 'a/index.mjs');
    const fileB = join(outDir, 'b/index.mjs');
    const resA = await bundleAction({ outFile: fileA });
    const resB = await bundleAction({ outFile: fileB });

    assert.deepEqual(readdirSync(join(outDir, 'a')), ['index.mjs'], 'bundle emits exactly one file');
    assert.equal(resA.sha256, resB.sha256, 'bundle build is deterministic');
    assert.ok(resA.bytes > 0);

    // Inspect esbuild metafile: workspace modules must stay strictly inside security-baseline-action/src and security-checks/src.
    const outputs = Object.values(resA.metafile.outputs);
    assert.equal(outputs.length, 1, 'exactly one output file in metafile');
    for (const inputPath of Object.keys(outputs[0]!.inputs)) {
      if (inputPath.includes('node_modules/')) continue;
      const abs = resolve(process.cwd(), inputPath);
      const dir = dirname(abs);
      assert.ok(
        dir === ACTION_SRC || dir === CHECKS_SRC,
        `bundled workspace file outside allowed packages: ${inputPath}`,
      );
    }

    // Direct third-party imports from workspace code must be strictly zod, semver, @actions/core, @actions/artifact.
    const directThirdParty = new Set<string>();
    for (const [inputPath, meta] of Object.entries(resA.metafile.inputs)) {
      if (inputPath.includes('node_modules/')) continue;
      for (const imp of meta.imports) {
        if (imp.path.includes('node_modules/')) directThirdParty.add(imp.original ?? imp.path);
      }
    }
    assert.deepEqual(
      [...directThirdParty].sort(),
      ['@actions/artifact', '@actions/core', '@actions/github', 'semver', 'zod'],
      'direct third-party dependencies bundled from workspace',
    );

    // Every external import remaining in the bundle must be a Node builtin (aside from optional supports-color inside debug).
    const externalImports = [...new Set(outputs[0]!.imports.filter((i) => i.external).map((i) => i.path))];
    for (const ext of externalImports) {
      assert.ok(
        NODE_BUILTINS.has(ext) || ext === 'supports-color',
        `unexpected unbundled external import in dist/index.mjs: ${ext}`,
      );
    }

    // Smoke-run the actual single-file bundle from /tmp (no node_modules in parent dirs) on a real lockfile fixture
    // containing both a vulnerable public package and a private package, intercepting fetch to prove only
    // registry.npmjs.org and api.osv.dev are contacted and the summary table + coverage + setup link are written.
    const work = join(outDir, 'work');
    const summaryFile = join(outDir, 'summary.md');
    const outputFile = join(outDir, 'output.txt');
    const hookFile = join(outDir, 'preload.mjs');
    const fetchLogFile = join(outDir, 'fetches.json');
    execFileSync('mkdir', ['-p', work]);
    const integrity = 'sha512-Zml4dHVyZQ==';
    const pubTarball = 'https://registry.npmjs.org/demo-pub/-/demo-pub-1.0.0.tgz';
    writeFileSync(
      join(work, 'package-lock.json'),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          '': { name: 'smoke', dependencies: { 'demo-pub': '^1.0.0', 'demo-priv': '^1.0.0' } },
          'node_modules/demo-pub': { version: '1.0.0', resolved: pubTarball, integrity },
          'node_modules/demo-priv': {
            version: '1.0.0',
            resolved: 'https://npm.internal.example/demo-priv/-/demo-priv-1.0.0.tgz',
            integrity,
          },
        },
      }),
      'utf8',
    );
    writeFileSync(summaryFile, '', 'utf8');
    writeFileSync(outputFile, '', 'utf8');
    writeFileSync(
      hookFile,
      `import { writeFileSync } from 'node:fs';
const seen = [];
globalThis.fetch = async (raw, init) => {
  const url = new URL(typeof raw === 'string' ? raw : raw instanceof URL ? raw.href : raw.url);
  seen.push({ host: url.hostname, path: url.pathname });
  writeFileSync(${JSON.stringify(fetchLogFile)}, JSON.stringify(seen));
  if (url.hostname === 'registry.npmjs.org') {
    const [, name, version] = url.pathname.split('/').map(decodeURIComponent);
    return Response.json({ name, version, dist: { tarball: 'https://registry.npmjs.org/' + name + '/-/' + name + '-' + version + '.tgz', integrity: ${JSON.stringify(integrity)} } });
  }
  if (url.hostname === 'api.osv.dev' && url.pathname === '/v1/querybatch') {
    const queries = JSON.parse(String(init?.body ?? '{}')).queries ?? [];
    return Response.json({ results: queries.map(q => q.package.name === 'demo-pub' && q.version === '1.0.0' ? { vulns: [{ id: 'GHSA-9999-8888-7777', modified: '2026-11-01T00:00:00Z' }] } : {}) });
  }
  if (url.hostname === 'api.osv.dev' && url.pathname === '/v1/vulns/GHSA-9999-8888-7777') {
    return Response.json({ id: 'GHSA-9999-8888-7777', modified: '2026-11-01T00:00:00Z', summary: 'Demo vuln', aliases: ['GHSA-9999-8888-7777'], affected: [{ package: { ecosystem: 'npm', name: 'demo-pub' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }] }], database_specific: { severity: 'HIGH' } });
  }
  throw new Error('unexpected host: ' + url.hostname);
};
`,
      'utf8',
    );
    // Place a poison supports-color module next to the bundle to prove the restricted require() banner refuses
    // loading anything outside Node built-ins even if a customer's runner has node_modules present (DFGHR-18).
    execFileSync('mkdir', ['-p', join(outDir, 'a/node_modules/supports-color')]);
    writeFileSync(
      join(outDir, 'a/node_modules/supports-color/index.js'),
      `throw new Error('poison external module loaded');\n`,
      'utf8',
    );
    let stderr = '';
    let stdout = '';
    try {
      stdout = execFileSync(process.execPath, ['--import', hookFile, fileA], {
        cwd: work,
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          GITHUB_WORKSPACE: work,
          GITHUB_STEP_SUMMARY: summaryFile,
          GITHUB_OUTPUT: outputFile,
          RUNNER_TEMP: outDir,
        },
      });
    } catch (err: unknown) {
      const e = err as { stdout?: string; stderr?: string };
      stdout = String(e.stdout ?? '');
      stderr = String(e.stderr ?? '');
    }
    // The bundle booted standalone with zero missing modules, queried only registry.npmjs.org and api.osv.dev,
    // wrote the full findings table + coverage + setup link, and only stopped when @actions/artifact checked for
    // live GitHub Actions' ACTIONS_RESULTS_URL runtime token.
    const seenFetches = JSON.parse(readFileSync(fetchLogFile, 'utf8')) as { host: string; path: string }[];
    assert.ok(seenFetches.length > 0, 'bundled action contacted npm and OSV');
    for (const f of seenFetches) {
      assert.ok(f.host === 'registry.npmjs.org' || f.host === 'api.osv.dev', `unexpected fetch host: ${f.host}`);
      assert.ok(!f.path.includes('demo-priv'), 'private package never left runner');
    }
    const summary = readFileSync(summaryFile, 'utf8');
    assert.match(summary, /Coverage:\s+\*\*partial\*\*/);
    assert.match(summary, /\|\s*package-lock\.json\s*\|\s*demo-pub\s*\|\s*1\.0\.0\s*\|\s*GHSA-9999-8888-7777\s*\|\s*high\s*\|\s*1\.2\.0\s*\|/);
    assert.match(summary, /\/security\/github\/setup/);
    assert.doesNotMatch(stdout + stderr, /ERR_MODULE_NOT_FOUND|Cannot find package|unexpected host|poison external module loaded/);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});
