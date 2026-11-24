import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as checks from '../src/index.ts';
import * as primitives from '../src/security-primitives.ts';
import { importGraph, impurities } from './import-graph.ts';
import { CATALOG_NAMES, CREDENTIAL_SHAPES, databaseExample, escapedCredentials, HEX_ESCAPED_CREDENTIAL, SHADOWED_JSON_CREDENTIALS, STORED_ESCAPES, STRAY_QUOTE_CREDENTIAL } from './secret-fixtures.ts';

const src = (name: string) => new URL(`../src/${name}`, import.meta.url);
const packageSrc = dirname(fileURLToPath(src('index.ts')));

test('REPO-14: distinctive token prefixes are caught anywhere alongside escaped credential boundaries', () => {
  for (const { kind, raw, json, jsonKey } of escapedCredentials) {
    assert.equal(checks.secretIn(Buffer.from(raw)), kind);
    for (const encoded of [json, jsonKey]) {
      assert.equal(checks.secretIn(Buffer.from(encoded)), null, 'decoding is required');
      assert.equal(checks.secretInFile(Buffer.from(encoded)), true, kind);
      assert.equal(checks.secretInJson({ embedded: JSON.stringify({ [encoded]: true }) }), true, kind);
    }
  }
  for (const { token, kind, bounded } of CREDENTIAL_SHAPES) assert.equal(checks.secretIn(Buffer.from(`prefix_${token}`)), bounded ? null : kind);
  for (const token of [`agcj_${'A'.repeat(20)}`, `agcrep_${'a'.repeat(47)}`, `agcpv_${'a'.repeat(42)}`]) assert.equal(checks.secretIn(Buffer.from(token)), null);
  for (const catalog of CATALOG_NAMES) for (const escape of ['', ...STORED_ESCAPES]) {
    assert.equal(checks.secretIn(Buffer.from(`${escape}${catalog}.main.orders`)), null);
    assert.equal(checks.secretInFile(Buffer.from(`{"sql":"${escape}${catalog}.main.orders"}`)), false);
  }
});

test('DFINT-30: proof screening sees literal and Unicode-escaped credentials in shadowed duplicate fields', () => {
  for (const text of SHADOWED_JSON_CREDENTIALS) {
    assert.deepEqual(JSON.parse(text), { diagnostic: 'safe' });
    assert.equal(checks.secretInFile(Buffer.from(text)), true);
    assert.equal(checks.secretInJson({ embedded: JSON.stringify({ field: text }) }), true);
  }
  const [literal, encoded] = SHADOWED_JSON_CREDENTIALS;
  assert.ok(checks.secretIn(Buffer.from(literal!)));
  assert.equal(checks.secretIn(Buffer.from(encoded!)), null, 'the raw scan cannot see the encoded prefix');
});

test('DFINT-30: standard escapes are decoded independently of quotes or valid JSON', () => {
  for (const text of [STRAY_QUOTE_CREDENTIAL, HEX_ESCAPED_CREDENTIAL]) {
    assert.equal(checks.secretIn(Buffer.from(text)), null, 'the raw scan alone cannot detect it');
    assert.equal(checks.secretInFile(Buffer.from(text)), true);
    assert.equal(checks.secretInJson({ [text]: text }), true);
    assert.equal(checks.secretInJson(JSON.stringify({ embedded: text })), true);
  }
  const raw = String.raw`unmatched " \uD83D\uDE80\x21\/\"\\\n\r\t\b\f`;
  const decoded = 'unmatched " 🚀!/"\\\n\r\t\b\f';
  assert.equal(checks.secretInFile(Buffer.from(raw), (bytes) => bytes.toString() === decoded ? 'decoded' : null), true);
});

test('DFINT-30: only empty or fixed placeholder database passwords pass proof screening', () => {
  for (const placeholder of ['', 'password', 'postgres', 'changeme', 'example', 'test', 'pass']) {
    assert.equal(checks.secretInFile(Buffer.from(databaseExample(placeholder))), false);
  }
  for (const nonPlaceholder of ['fixture-only', 'password1', 'PASSWORD', 'x'.repeat(300)]) {
    assert.equal(checks.secretInFile(Buffer.from(databaseExample(nonPlaceholder))), true);
  }
  assert.equal(checks.secretInFile(Buffer.from('postgres://app:fixture-only@localhost/app')), true);
});

test('DFBASE-3: the package entry point reaches only zod, semver, node:crypto and files inside the package', () => {
  const graph = importGraph(src('index.ts'));
  assert.deepEqual(graph.packages, ['node:crypto', 'semver', 'zod']);
  assert.deepEqual(graph.unresolved, []);
  assert.deepEqual(graph.modules.filter(m => dirname(m) !== packageSrc), [], 'every module is in packages/security-checks/src');
  assert.deepEqual(graph.modules.map(m => basename(m)), ['index.ts', 'secret-in.ts', 'security-advisories.ts', 'security-deps-check.ts', 'security-deps-facts.ts', 'security-deps-lock.ts', 'security-deps-pnpm.ts', 'security-deps-repair.ts', 'security-deps-yarn.ts', 'security-npm.ts',
    'security-primitives.ts', 'security-report-coverage.ts', 'security-report-json.ts', 'security-report.ts']);
  for (const name of ['secretIn', 'sha256', 'digest', 'screenedJson', 'npmExactVersion', 'parseDepsLock', 'dependentsOf', 'planCandidates', 'classify', 'DEPS_LOCK_VERSION', 'DEPS_FACTS_VERSION',
    'staticDeps', 'joinDepsReport', 'osvMatch', 'queryOsv', 'repairLockEntry', 'buildLockRepair', 'lockEntryDiff', 'renderRepairPullRequest',
    // DFRPT-22: every derivation a producer needs, so none keeps its own copy.
    'canonicalJson', 'reportHash', 'documentDigest', 'occurrenceKey', 'observationKey', 'observationSetDigest', 'sealReport', 'parseSecurityReport', 'validateReportGraph', 'validateReportSet', 'compareSourceUnion', 'SecurityReport'] as const)
    assert.ok(name in checks, `the entry point exports ${name}`);
});

test('DFBASE-3: the pure primitives import only zod, node:crypto and secret-in.ts', () => {
  const graph = importGraph(src('security-primitives.ts'));
  assert.deepEqual(graph.modules.map(m => basename(m)), ['secret-in.ts', 'security-primitives.ts']);
  assert.deepEqual(graph.packages, ['node:crypto', 'zod']);
  assert.deepEqual(graph.unresolved, []);
});

test('DFBASE-3: the lock model and fix facts reach no file, network, process, database or server module', () => {
  for (const name of ['security-deps-lock.ts', 'security-deps-facts.ts']) {
    const graph = importGraph(src(name));
    assert.deepEqual(impurities(graph), [], name);
    assert.deepEqual(graph.unresolved, [], name);
  }
});

test('DFBASE-3: the import scan follows runtime imports and skips only erased type imports (negative controls)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'import-graph-'));
  try {
    await writeFile(join(dir, 'store.ts'), 'export const store = 1;\n');
    await writeFile(join(dir, 'typed.ts'), "import type { store } from './store.ts';\nexport type { store as S } from './store.ts';\nexport type T = import('./store.ts').store;\n");
    assert.deepEqual(impurities(importGraph(join(dir, 'typed.ts'))), []);
    for (const [file, code] of [
      ['inline.ts', "import { type store } from './store.ts';\n"],
      ['reexport.ts', "export { store } from './store.ts';\n"],
      ['dynamic.ts', "export const load = () => import('node:child_process');\n"],
      ['side.ts', "import 'pg';\n"],
      ['server.ts', "import { Hono } from 'hono';\nexport const app = new Hono();\n"],
      ['net.ts', "import { connect } from 'node:net';\nimport http from 'http';\nexport { connect, http };\n"],
      ['files.ts', "import { readFile } from 'node:fs/promises';\nexport { readFile };\n"],
    ] as const) {
      await writeFile(join(dir, file), code);
      assert.notDeepEqual(impurities(importGraph(join(dir, file))), [], file);
    }
    await writeFile(join(dir, 'computed.ts'), "const name = 'node:fs';\nexport const load = () => import(name);\n");
    assert.equal(importGraph(join(dir, 'computed.ts')).unresolved.length, 1);
    await writeFile(join(dir, 'missing.ts'), "export { x } from './nowhere.ts';\n");
    assert.equal(importGraph(join(dir, 'missing.ts')).unresolved.length, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('DFRPT-1, DFINT-29: a report path takes `%` as written, a path that selects a file to acquire still refuses it, and the two agree on every other path', () => {
  const { reportPath, exactPath } = checks;
  const percent = ['docs/4k%20monitor.evidence.json', 'a%2fb', 'a%2Fb', '%', '100%/done.md', 'a/%2e%2e/b', 'a%5cb', 'a%00b'];
  const safe = ['a/b', 'package-lock.json', 'src/a b#c?d.ts', 'docs/日本語.md', '.github/workflows/ci.yml', '...', 'a'.repeat(500)];
  const unsafe = ['', '/a', 'a/', 'a//b', '.', '..', 'a/./b', 'a/../b', '../a', 'a\\b', 'a\u0000b', 'a\nb', 'a\tb', 'a\u001fb', 'a\u007fb', 'a'.repeat(501), `${'a'.repeat(499)}/%`];
  for (const path of percent) {
    assert.equal(reportPath.parse(path), path, `${path}: kept as written, never decoded`);
    assert.throws(() => exactPath.parse(path), /exact repository-relative path required/, `${path}: no file is acquired by a path with % in it`);
  }
  for (const path of safe) assert.deepEqual([reportPath.parse(path), exactPath.parse(path)], [path, path], path);
  for (const path of unsafe) assert.deepEqual([reportPath.safeParse(path).success, exactPath.safeParse(path).success], [false, false], JSON.stringify(path.slice(0, 20)));
});

test('DFBASE-3: the primitives keep the behavior control relied on before they moved', () => {
  assert.equal(primitives.digest({ b: 1, a: [2, 'x'] }), createHash('sha256').update('{"a":[2,"x"],"b":1}').digest('hex'));
  assert.equal(primitives.gitBlob(Buffer.from('hello\n')), 'ce013625030ba8dba906f756967f9e9ca394464a');
  const secret = ['ghp', '_', 'A'.repeat(36)].join(''); // a GitHub token's shape, never a real one
  assert.throws(() => primitives.screenedJson({ value: secret }), (e: unknown) => e instanceof primitives.SecurityWorkError && e.code === 'security.secret');
  assert.throws(() => primitives.screenedJson({ value: 'x'.repeat(64) }, 16), /evidence_oversize/);
  assert.equal(checks.secretIn(Buffer.from(secret)), 'a GitHub token');
});
