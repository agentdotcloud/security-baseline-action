import assert from 'node:assert/strict';
import { basename, dirname } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DEPS_BODY_SCOPE, DEPS_COMPONENTS, DEPS_REPORT_LIMITS, DepsCheckError, DepsDiscoveryExtension, joinDepsReport, staticDeps, type DepsCheckLockfile,
  type DepsCheckResult, type DepsCheckState, type DepsDependabotInput, type DepsIdentityCache, type DepsIdentityFacts, type DepsReportBody, type DepsReportEnvelope } from '../src/security-deps-check.ts';
import type { PublicHTTP } from '../src/security-advisories.ts';
import { gitBlob, sha256 } from '../src/security-primitives.ts';
import { parseSecurityReport } from '../src/security-report.ts';
import { importGraph, impurities } from './import-graph.ts';
import { GHSA_A, GHSA_B, GHSA_C, INTEGRITY, NOW, PATH, advisory, caps, fixed, reg, world, type World } from './deps-world.ts';

function lockfile(packages: Record<string, unknown>, extra: Partial<DepsCheckLockfile> & { lockfileVersion?: number } = {}): DepsCheckLockfile {
  const { lockfileVersion = 3, ...rest } = extra, bytes = Buffer.from(JSON.stringify({ name: 'app', lockfileVersion, requires: true, packages }));
  return { path: PATH, bytes, git_blob: gitBlob(bytes), sha256: sha256(bytes), overrides: { state: 'absent' }, package_json: null, ...rest };
}
const alert = (number: number, name: string, ghsa: string, range: string, patched: string | null, extra: Record<string, unknown> = {}) => ({ number, state: 'open', updated_at: '2026-11-01T00:00:00Z',
  dependency: { package: { ecosystem: 'npm', name }, manifest_path: PATH, scope: 'runtime' }, security_advisory: { ghsa_id: ghsa, cve_id: null, summary: `${ghsa} in ${name}`, severity: 'high' },
  security_vulnerability: { vulnerable_version_range: range, first_patched_version: patched ? { identifier: patched } : null }, ...extra });
const alerts = (list: unknown[], state: DepsDependabotInput['state'] = 'complete', reason: string | null = null): DepsDependabotInput => ({ state, reason, retrieved_at: '2026-11-12T17:59:00Z', alerts: list });

function body(result: DepsCheckResult): DepsReportBody { assert.equal(result.outcome, 'report'); return (result as Extract<DepsCheckResult, { outcome: 'report' }>).body; }
const envelope = (extra: Partial<DepsReportEnvelope> = {}): DepsReportEnvelope => ({ producer: { namespace: 'summation.discovery', product: 'dependency-baseline', version: '1' }, report_id: 'repo-42-lock-1', revision: 1, previous_digest: null,
  generated_at: '2026-11-12T18:00:05Z', snapshot: { target_id: 'github', repository_id: '42', repository: 'acme/app', sha: 'a'.repeat(40), scopes: [{ scope_id: 'lock-1', service: 'repository', paths: [PATH] }] },
  profile: { id: 'discovery-deps-v1', revision: 1, digest: 'b'.repeat(64) }, ...extra });
const component = (b: DepsReportBody, id: string) => b.coverage.components.find(c => c.id === id)!;
const factsOf = (b: DepsReportBody) => Object.fromEntries(b.extension.fix_facts.map(f => [`${f.package}:${b.findings.find(x => x.finding_id === f.finding_id)!.aliases.find(a => a.startsWith('GHSA')) ?? f.finding_id}`, f.class]));

// One root dependency `a@^1.0.0` installed at 1.0.0, with a published fix at 1.0.5: the smallest single_entry_upgrade.
const minimal = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({ '': { name: 'app', dependencies: { a: '^1.0.0' } }, 'node_modules/a': reg('a', '1.0.0'), ...extra });
const A_FIXED = advisory(GHSA_A, 'a', fixed('1.0.5'), { aliases: ['CVE-2026-0001'] });

test('DFBASE-3: the check runs with only injected capabilities and bytes, and two callers get identical findings, IDs and classes', async () => {
  const first = world({ records: [A_FIXED] }), second = world({ records: [A_FIXED] });
  const one = body(await staticDeps(lockfile(minimal()), caps(first.http))), two = body(await staticDeps(lockfile(minimal()), caps(second.http)));
  assert.deepEqual(one, two, 'identical inputs give an identical body');
  assert.equal(one.findings.length, 1);
  assert.match(one.findings[0]!.finding_id, /^deps-[0-9a-f]{32}$/);
  assert.equal(one.extension.fix_facts[0]!.class, 'single_entry_upgrade');
  assert.equal(one.recommendations[0]!.category, 'dependency.single_entry_upgrade');
  assert.deepEqual(first.calls.map(c => new URL(c.url).hostname).filter((h, i, all) => all.indexOf(h) === i).sort(), ['api.osv.dev', 'registry.npmjs.org'], 'only the two fixed public origins');
  // DFBASE-12: the ID comes from the lockfile path, the entry path and the advisory, so another repository or revision gives the same one.
  const joined = [joinDepsReport(one, envelope()), joinDepsReport(one, envelope({ report_id: 'other', revision: 3, previous_digest: 'c'.repeat(64), snapshot: { ...envelope().snapshot, repository_id: '77', repository: 'other/repo', sha: 'd'.repeat(40) } }))];
  assert.equal(joined[0]!.report.findings[0]!.finding_id, joined[1]!.report.findings[0]!.finding_id);
  const elsewhere = body(await staticDeps({ ...lockfile(minimal()), path: 'other/package-lock.json' }, caps(world({ records: [A_FIXED] }).http)));
  assert.notEqual(elsewhere.findings[0]!.finding_id, one.findings[0]!.finding_id, 'another lockfile path is another finding');
});

test('DFBASE-3: the check and the package entry point reach no file, process, network or database module and nothing from packages/control', () => {
  const src = (name: string) => new URL(`../src/${name}`, import.meta.url), packageSrc = dirname(fileURLToPath(src('index.ts')));
  for (const entry of ['security-deps-check.ts', 'index.ts']) {
    const graph = importGraph(src(entry));
    assert.deepEqual(impurities(graph), [], entry);
    assert.deepEqual(graph.unresolved, [], entry);
    assert.deepEqual(graph.packages, ['node:crypto', 'semver', 'zod'], entry);
    assert.deepEqual(graph.modules.filter(m => dirname(m) !== packageSrc), [], `${entry}: every module is inside packages/security-checks/src`);
    assert.ok(!graph.modules.some(m => m.includes('/packages/control/')), `${entry}: nothing from packages/control`);
  }
  assert.ok(importGraph(src('security-deps-check.ts')).modules.map(m => basename(m)).includes('security-report.ts'), 'the join uses the package\'s own report library (DFRPT-22)');
});

test('DFBASE-3: the body names no producer, report ID, revision, snapshot or profile, and one body joins two envelopes into two valid reports', async () => {
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [A_FIXED] }).http)));
  assert.deepEqual(Object.keys(b).sort(), ['check', 'coverage', 'dispositions', 'evidence', 'extension', 'findings', 'lockfile', 'observations', 'recommendations']);
  const text = JSON.stringify(b);
  for (const absent of ['producer', 'report_id', 'revision', 'previous_digest', 'snapshot', 'repository_id', 'content_digest', 'generated_at', 'profile']) assert.ok(!text.includes(`"${absent}":`), `the body has no ${absent}`);
  assert.equal(b.findings[0]!.assessment.profile_digest, null, 'only the envelope knows the profile');
  assert.ok(b.evidence.every(e => !e.git || !('sha' in e.git)), 'only the envelope knows the commit');
  const a = joinDepsReport(b, envelope()), other = envelope({ report_id: 'second', snapshot: { ...envelope().snapshot, sha: 'e'.repeat(40), scopes: [{ scope_id: 'main', service: 'web', paths: [PATH] }] }, profile: { id: 'p', revision: 2, digest: 'f'.repeat(64) } });
  const c = joinDepsReport(b, other);
  for (const [joined, env] of [[a, envelope()], [c, other]] as const) {
    const parsed = parseSecurityReport(joined.bytes, ['summation.discovery']);
    assert.equal(parsed.document_type, 'defensive-security-report');
    assert.equal(parsed.content_digest, joined.report.content_digest);
    assert.equal(joined.report.findings[0]!.assessment.profile_digest, env.profile.digest);
    assert.deepEqual(joined.report.findings[0]!.scope_ids, [env.snapshot.scopes[0]!.scope_id]);
    assert.equal(joined.report.evidence.find(e => e.evidence_id === 'ev-lockfile')!.git!.sha, env.snapshot.sha);
    assert.equal(joined.report.coverage.state, 'complete');
    assert.equal(joined.report.coverage.union_status, 'proven');
    assert.throws(() => parseSecurityReport(joined.bytes, ['summation.secure']), /report_producer_unapproved/);
  }
  assert.deepEqual(a.report.findings.map(f => f.finding_id), c.report.findings.map(f => f.finding_id));
  assert.notEqual(a.report.coverage.components[1]!.mapped_observation_keys[0], c.report.coverage.components[1]!.mapped_observation_keys[0], 'observation keys depend on the snapshot');
  assert.notEqual(a.report.content_digest, c.report.content_digest);
});

test('DFBASE-3: the join refuses a body that does not fit the envelope', async () => {
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [A_FIXED] }).http)));
  const scopes = (paths: string[], more: DepsReportEnvelope['snapshot']['scopes'] = []) => envelope({ snapshot: { ...envelope().snapshot, scopes: [{ scope_id: 'lock-1', service: 'repository', paths }, ...more] } });
  assert.throws(() => joinDepsReport(b, scopes(['other/package-lock.json'])), /deps_report_scope/);
  assert.throws(() => joinDepsReport(b, scopes([PATH, 'x/package-lock.json'])), /deps_report_scope/);
  assert.throws(() => joinDepsReport(b, scopes([PATH], [{ scope_id: 'second', service: 'repository', paths: ['x/package-lock.json'] }])), /deps_report_scope/);
  const moved = structuredClone(b), o = moved.observations[0]!;
  if (o.kind === 'source_observation' && o.occurrence.kind === 'dependency') o.occurrence.entry = 'node_modules/b';
  assert.throws(() => joinDepsReport(moved, envelope()), /deps_report_body_mismatch/, 'an occurrence key that is not derived from its coordinates');
  const unmapped = structuredClone(b); unmapped.coverage.components[1]!.observation_ids = ['obs-unknown'];
  assert.throws(() => joinDepsReport(unmapped, envelope()), /deps_report_body_mismatch/);
  const dropped = structuredClone(b); dropped.coverage.components[1]!.observation_ids = [];
  assert.throws(() => joinDepsReport(dropped, envelope()), /report_union_unproven/, 'the report library still checks the union');
  assert.throws(() => joinDepsReport(b, envelope({ revision: 2 })), /report_revision_chain/);
});

test('DFBASE-3: no cache and no checkpoint sink still completes; a sink\'s saved state resumes without repeating a request', async () => {
  const packages = minimal({ 'node_modules/b': reg('b', '2.0.0'), '': { name: 'app', dependencies: { a: '^1.0.0', b: '^2.0.0' } } });
  const plain = world({ records: [A_FIXED] }), expected = body(await staticDeps(lockfile(packages), caps(plain.http)));
  // Stop the first run after its fourth request, as a crash would, keeping what the sink saved.
  let saved: DepsCheckState | undefined, budget = 4;
  const crashing = world({ records: [A_FIXED] }), limited: PublicHTTP = { async json(url, b, max) { if (budget-- <= 0) throw Error('client_failed'); return crashing.http.json(url, b, max); } };
  await assert.rejects(staticDeps(lockfile(packages), caps(limited, { checkpoint: { save: async s => { saved = structuredClone(s); } } })), (e: DepsCheckError) => e.code === 'deps_check.source_failed');
  assert.ok(saved && Object.keys(saved.identities).length === 2);
  const resumed = world({ records: [A_FIXED] }), result = await staticDeps(lockfile(packages), caps(resumed.http, { checkpoint: { state: saved, save: async () => {} } }));
  assert.deepEqual(body(result), expected, 'the resumed run reports what an uninterrupted one does');
  const repeated = resumed.calls.filter(c => crashing.calls.some(d => d.url === c.url && JSON.stringify(d.body) === JSON.stringify(c.body)));
  assert.deepEqual(repeated, [], 'no request the first run completed is made again');
  assert.equal(crashing.calls.length + resumed.calls.length, plain.calls.length, 'together they make exactly an uninterrupted run\'s requests');
  await assert.rejects(staticDeps(lockfile(minimal()), caps(world().http, { checkpoint: { state: saved, save: async () => {} } })), (e: DepsCheckError) => e.code === 'deps_check.checkpoint_scope');
});

test('DFBASE-3, DFRPT-20: no Dependabot input names that source not_selected, and the report is still complete', async () => {
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [A_FIXED] }).http))), d = component(b, DEPS_COMPONENTS.dependabot);
  assert.deepEqual({ state: d.state, required: d.required, reasons: d.reasons, observation_ids: d.observation_ids, baseline_receipt: d.baseline_receipt }, { state: 'not_selected', required: false, reasons: ['not_supplied'], observation_ids: [], baseline_receipt: null });
  assert.equal(b.coverage.state, 'complete');
  const { report } = joinDepsReport(b, envelope()), joined = report.coverage.components.find(c => c.id === DEPS_COMPONENTS.dependabot)!;
  assert.deepEqual([joined.state, joined.observed_count, joined.mapped_count, joined.missing_count, joined.mapped_observation_keys.length], ['not_selected', 0, 0, 0, 0]);
});

test('DFBASE-9: private, unknown and mismatched identities never reach OSV and are listed as not checked with their reason', async () => {
  const packages = { '': { name: 'app', dependencies: { a: '^1.0.0', secret: '^1.0.0', forged: '^1.0.0', '@corp/internal': '^1.0.0', alias: 'npm:a@1.0.0' } },
    'node_modules/a': reg('a', '1.0.0'), 'node_modules/secret': reg('secret', '1.0.0'), 'node_modules/forged': reg('forged', '1.0.0', { integrity: 'sha512-ZGlmZmVyZW50' }),
    'node_modules/@corp/internal': { version: '1.0.0', resolved: 'https://npm.corp.example/@corp/internal/-/internal-1.0.0.tgz', integrity: INTEGRITY }, 'node_modules/alias': { ...reg('a', '1.0.0'), name: 'a' },
    'node_modules/moved': reg('moved', '1.0.0', { resolved: 'https://registry.npmjs.org/moved/-/moved-9.9.9.tgz' }) };
  const w = world({ private: ['secret'], records: [A_FIXED, advisory(GHSA_B, 'secret', fixed('2.0.0')), advisory(GHSA_C, 'forged', fixed('2.0.0'))] });
  const b = body(await staticDeps(lockfile(packages), caps(w.http)));
  assert.deepEqual(w.osvQueried(), ['a@1.0.0', 'a@1.0.5'], 'only the identity the public registry confirmed, and its verified candidate, are sent to OSV');
  assert.ok(!w.calls.some(c => c.url.includes('corp') || c.url.includes('alias')), 'a held entry is not even looked up');
  assert.deepEqual(b.extension.not_checked, { total: 5, by_reason: { not_approved_public_registry: 1, npm_alias_requires_review: 1, public_identity_mismatch: 2, public_identity_unverified: 1 },
    entries: [{ entry: 'node_modules/@corp/internal', reason: 'not_approved_public_registry' }, { entry: 'node_modules/alias', reason: 'npm_alias_requires_review' }, { entry: 'node_modules/forged', reason: 'public_identity_mismatch' },
      { entry: 'node_modules/moved', reason: 'public_identity_mismatch' }, { entry: 'node_modules/secret', reason: 'public_identity_unverified' }] });
  // DFBASE-15: any entry not checked leaves the required OSV source incomplete, so the report is partial.
  assert.deepEqual([component(b, DEPS_COMPONENTS.osv).state, component(b, DEPS_COMPONENTS.osv).reasons, b.coverage.state, b.coverage.union_status], ['incomplete', ['identities_not_checked'], 'partial', 'proven']);
  assert.equal(joinDepsReport(b, envelope()).report.coverage.state, 'partial');
  assert.deepEqual(b.findings.map(f => f.aliases), [['CVE-2026-0001', GHSA_A]]);
});

test('DFBASE-9, DFBASE-10: a bundled entry and an alias with no name are never looked up, whatever the registry would answer', async () => {
  // The registry here would confirm internal-bundled@1.0.0 exactly as the lock entry states it, and knows internal-shim too.
  const packages = { '': { name: 'app', dependencies: { a: '^1.0.0', host: '^1.0.0', 'internal-shim': '^1.0.0' } },
    'node_modules/a': reg('a', '1.0.0'), 'node_modules/host': reg('host', '1.0.0'),
    'node_modules/host/node_modules/internal-bundled': reg('internal-bundled', '1.0.0', { inBundle: true }), 'node_modules/internal-shim': reg('a', '1.0.0') };
  const w = world({ records: [A_FIXED, advisory(GHSA_B, 'internal-bundled', fixed('2.0.0')), advisory(GHSA_C, 'internal-shim', fixed('2.0.0'))] });
  const b = body(await staticDeps(lockfile(packages), caps(w.http)));
  assert.ok(w.calls.length > 0 && !w.calls.some(c => JSON.stringify(c).includes('internal')), 'neither name is in any registry or OSV request');
  assert.deepEqual(w.calls.filter(c => new URL(c.url).hostname === 'registry.npmjs.org').map(c => c.url).sort(),
    ['https://registry.npmjs.org/a/1.0.0', 'https://registry.npmjs.org/a/1.0.5', 'https://registry.npmjs.org/host/1.0.0']);
  assert.deepEqual(b.extension.not_checked, { total: 2, by_reason: { bundled_dependency: 1, npm_alias_requires_review: 1 },
    entries: [{ entry: 'node_modules/host/node_modules/internal-bundled', reason: 'bundled_dependency' }, { entry: 'node_modules/internal-shim', reason: 'npm_alias_requires_review' }] });
  assert.deepEqual(b.findings.map(f => f.aliases), [['CVE-2026-0001', GHSA_A]]);
});

test('DFBASE-9: a cache row holds only public registry facts, a hit must equal the lock entry, and evidence cites this run\'s time', async () => {
  const rows: DepsIdentityFacts[] = [], cache: DepsIdentityCache = { get: async (name, version, integrity) => rows.find(r => r.name === name && r.version === version && r.integrity === integrity) ?? null, put: async facts => { rows.push(structuredClone(facts)); } };
  const first = world({ records: [A_FIXED] });
  await staticDeps(lockfile(minimal()), caps(first.http, { cache }));
  assert.deepEqual(rows.map(r => Object.keys(r).sort()), [['integrity', 'manifest', 'name', 'tarball', 'version']], 'no tenant, repository or installation field');
  assert.deepEqual(rows[0]!.manifest, { name: 'a', version: '1.0.0' }, 'only the manifest fields fix facts compare are kept');
  const later = NOW + 3_600_000, second = world({ records: [A_FIXED] }), state: { saved?: DepsCheckState } = {};
  const b = body(await staticDeps(lockfile(minimal()), { ...caps(second.http, { cache, checkpoint: { save: async s => { state.saved = structuredClone(s); } } }), now: () => later }));
  assert.ok(!second.calls.some(c => c.url === 'https://registry.npmjs.org/a/1.0.0'), 'the hit saves the registry lookup');
  assert.deepEqual(second.osvQueried().slice(0, 1), ['a@1.0.0']);
  assert.equal(Object.values(state.saved!.identities)[0]!.state === 'verified' && (Object.values(state.saved!.identities)[0] as { confirmed_at: string }).confirmed_at, new Date(later).toISOString());
  assert.equal(b.evidence.find(e => e.evidence_id === 'ev-lockfile')!.captured_at, new Date(later).toISOString());
  // The same name and version with another integrity is another key; a row that answers for it anyway is refused.
  const lying: DepsIdentityCache = { get: async () => rows[0]!, put: async () => {} }, third = world();
  const forged = body(await staticDeps(lockfile(minimal({ 'node_modules/a': reg('a', '1.0.0', { integrity: 'sha512-ZGlmZmVyZW50' }) })), caps(third.http, { cache: lying })));
  assert.ok(third.calls.some(c => c.url === 'https://registry.npmjs.org/a/1.0.0'), 'a hit that does not equal the lock entry is not used');
  assert.deepEqual(forged.extension.not_checked.by_reason, { public_identity_mismatch: 1 });
  assert.deepEqual(third.osvQueried(), []);
});

test('DFBASE-9: identities beyond the caller\'s limit stay local and are listed, in bytewise order', async () => {
  const packages = { '': { name: 'app', dependencies: { a: '^1.0.0', b: '^1.0.0', c: '^1.0.0' } }, 'node_modules/a': reg('a', '1.0.0'), 'node_modules/b': reg('b', '1.0.0'), 'node_modules/c': reg('c', '1.0.0') };
  const w = world(), b = body(await staticDeps(lockfile(packages), caps(w.http, { limits: { max_identities: 2 } })));
  assert.deepEqual(w.osvQueried(), ['a@1.0.0', 'b@1.0.0']);
  assert.deepEqual(b.extension.not_checked.entries, [{ entry: 'node_modules/c', reason: 'identity_limit' }]);
  assert.equal(b.coverage.state, 'partial');
});

test('DFBASE-11: an OSV or registry outage is a failed source, never a no-match report', async () => {
  for (const [down, source] of [[{ osvDown: true }, 'osv'], [{ registryDown: true }, 'npm-registry']] as const) {
    await assert.rejects(staticDeps(lockfile(minimal()), caps(world({ ...down, records: [A_FIXED] }).http)), (e: DepsCheckError) => e instanceof DepsCheckError && e.code === 'deps_check.source_failed' && e.source === source && e.message === 'client_failed');
  }
  const deferred: PublicHTTP = { json: async () => { throw Error('public_retry_after_deferred'); } };
  await assert.rejects(staticDeps(lockfile(minimal()), caps(deferred)), (e: DepsCheckError) => e.message === 'public_retry_after_deferred', 'a deferral reaches the caller by its own code (DFBASE-7)');
  const controller = new AbortController(); controller.abort();
  await assert.rejects(staticDeps(lockfile(minimal()), caps(world().http, { signal: controller.signal })), (e: DepsCheckError) => e.code === 'deps_check.cancelled');
});

test('DFBASE-11: OSV hits outside the affected range are retained as refuted, and a complete run with no finding says so honestly', async () => {
  const old = advisory(GHSA_A, 'a', fixed('0.9.0')), b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [old] }).http)));
  assert.equal(b.findings.length, 0);
  assert.equal(b.observations.length, 1, 'the hit is not dropped (DFDISC-9)');
  assert.deepEqual(b.dispositions.map(d => [d.kind, d.reason, d.observation_id === b.observations[0]!.observation_id]), [['refuted', 'outside_affected_range', true]]);
  assert.deepEqual([b.coverage.state, b.coverage.union_status], ['complete', 'proven']);
  const clean = body(await staticDeps(lockfile(minimal()), caps(world().http)));
  assert.deepEqual([clean.observations.length, clean.findings.length, clean.coverage.state], [0, 0, 'complete']);
  assert.equal(joinDepsReport(clean, envelope()).report.coverage.state, 'complete', 'no known advisory matched the checked dependencies');
});

test('DFBASE-11: Dependabot states, a capped read, an in-scope alert with no occurrence and alerts outside the scope', async () => {
  const w = () => world({ records: [A_FIXED] });
  const disabled = body(await staticDeps(lockfile(minimal()), caps(w().http), alerts([], 'not_configured', 'disabled')));
  assert.deepEqual([component(disabled, DEPS_COMPONENTS.dependabot).state, component(disabled, DEPS_COMPONENTS.dependabot).reasons, disabled.coverage.state], ['not_configured', ['disabled'], 'complete']);
  const capped = body(await staticDeps(lockfile(minimal()), caps(w().http), alerts([alert(1, 'a', GHSA_A, '< 1.0.5', '1.0.5')], 'incomplete', 'page_limit')));
  assert.deepEqual([component(capped, DEPS_COMPONENTS.dependabot).state, component(capped, DEPS_COMPONENTS.dependabot).reasons, capped.coverage.state, capped.coverage.union_status], ['incomplete', ['page_limit'], 'partial', 'incomplete']);
  assert.equal(joinDepsReport(capped, envelope()).report.coverage.state, 'partial');
  const elsewhere = alert(7, 'a', GHSA_A, '< 1.0.5', '1.0.5'); elsewhere.dependency.manifest_path = 'other/package-lock.json';
  const pip = alert(8, 'a', GHSA_A, '< 1.0.5', '1.0.5'); pip.dependency.package.ecosystem = 'pip';
  const gone = alert(9, 'zzz', GHSA_B, '< 3.0.0', '3.0.0'), odd = alert(10, 'a', GHSA_C, 'not a range', null);
  const b = body(await staticDeps(lockfile(minimal()), caps(w().http), alerts([elsewhere, pip, gone, odd, alert(11, 'a', GHSA_A, '< 1.0.5', '1.0.5')])));
  const d = component(b, DEPS_COMPONENTS.dependabot);
  assert.equal(d.observation_ids.length, 3, 'alerts for another manifest or ecosystem are outside this scope and are not observations');
  assert.deepEqual(b.dispositions.map(x => [x.kind, x.reason]).sort(), [['held', 'alert_range_unsupported'], ['held', 'alert_without_occurrence']], 'in-scope alerts with no occurrence are retained, held');
  assert.deepEqual([d.state, b.coverage.state, b.coverage.union_status], ['complete', 'complete', 'proven']);
  const { report } = joinDepsReport(b, envelope());
  assert.equal(report.observations.length, 4);
  assert.equal(report.findings.length, 1);
});

test('DFBASE-12: Dependabot and OSV merge only on the same occurrence and GHSA; two flaws in one package stay separate', async () => {
  const two = advisory(GHSA_B, 'a', fixed('1.0.7')), w = world({ records: [A_FIXED, two] });
  const b = body(await staticDeps(lockfile(minimal()), caps(w.http), alerts([alert(1, 'a', GHSA_A, '< 1.0.5', '1.0.5'), alert(2, 'a', GHSA_C, '< 1.0.9', '1.0.9')])));
  assert.equal(b.findings.length, 3, 'one finding per flaw at the occurrence');
  const merged = b.findings.find(f => f.aliases.includes(GHSA_A))!;
  assert.deepEqual(merged.observation_ids.map(id => (b.observations.find(o => o.observation_id === id) as { source_namespace: string }).source_namespace), ['osv', 'github.dependabot'], 'same occurrence and same GHSA merge');
  assert.equal(b.findings.find(f => f.aliases.includes(GHSA_C))!.observation_ids.length, 1, 'a Dependabot-only flaw is its own finding');
  assert.equal(new Set(b.findings.flatMap(f => f.occurrence_keys)).size, 1, 'all three are on the one lock occurrence');
  // DFBASE-13.3/4: the upgrade group's candidate is the highest fixed version, and it closes all three.
  assert.deepEqual([...new Set(b.extension.fix_facts.map(f => f.candidate))], ['1.0.9']);
  assert.deepEqual(b.extension.fix_facts.map(f => f.class), ['single_entry_upgrade', 'single_entry_upgrade', 'single_entry_upgrade']);
  assert.equal(b.recommendations.length, 1, 'findings on one occurrence with the same class share a recommendation (DFBASE-14)');
  assert.deepEqual([...b.recommendations[0]!.finding_ids].sort(), b.findings.map(f => f.finding_id).sort());
  // The same package at a second occurrence is a second finding, never merged by name.
  const nested = minimal({ 'node_modules/b': reg('b', '1.0.0', { dependencies: { a: '^1.0.0' } }), 'node_modules/b/node_modules/a': reg('a', '1.0.2') });
  const twice = body(await staticDeps(lockfile(nested), caps(world({ records: [A_FIXED] }).http)));
  assert.deepEqual(twice.findings.map(f => f.title), ['a 1.0.0: ' + GHSA_A, 'a 1.0.2: ' + GHSA_A]);
  assert.equal(new Set(twice.findings.map(f => f.finding_id)).size, 2);
});

test('DFBASE-12: a match on a CVE alone links two findings and holds both; it never merges them', async () => {
  const other = advisory('MAL-2026-1', 'a', fixed('1.0.5'), { aliases: ['CVE-2026-0002'] });
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [other] }).http), alerts([alert(1, 'a', GHSA_A, '< 1.0.5', '1.0.5', { security_advisory: { ghsa_id: GHSA_A, cve_id: 'CVE-2026-0002', summary: 's', severity: 'high' } })])));
  assert.equal(b.findings.length, 2);
  for (const f of b.findings) {
    assert.ok(f.assessment.holds.includes('cve_only_match'));
    assert.equal(f.assessment.dependency, 'unknown');
    assert.ok(f.summary.includes(b.findings.find(x => x !== f)!.finding_id), 'each names the other');
  }
  assert.deepEqual(b.extension.fix_facts.map(f => [f.class, f.related_finding_ids.length]), [['verify_occurrence', 1], ['verify_occurrence', 1]]);
  joinDepsReport(b, envelope());
});

test('DFBASE-12: fixed assessment values; affected only inside the canonical range; holds are kept as holds', async () => {
  const withdrawn = advisory(GHSA_B, 'a', fixed('1.0.5'), { withdrawn: '2026-10-02T00:00:00Z' }), git = advisory(GHSA_C, 'a', [], { affected: [{ package: { ecosystem: 'npm', name: 'a' }, ranges: [{ type: 'GIT', events: [{ introduced: '0' }] }] }] });
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [A_FIXED, withdrawn, git] }).http)));
  const by = (ghsa: string) => b.findings.find(f => f.aliases.includes(ghsa))!;
  assert.deepEqual(by(GHSA_A).assessment, { provenance: 'verified', validity: 'unreviewed', dependency: 'affected', currentness: 'current', exposure: 'unverified', breaker: 'not_attempted', assessor: 'static.deps',
    evidence_ids: by(GHSA_A).assessment.evidence_ids, profile_digest: null, holds: [] });
  assert.ok(by(GHSA_A).assessment.evidence_ids.length >= 2, 'the lockfile and the advisory record are cited');
  assert.deepEqual([by(GHSA_B).assessment.dependency, by(GHSA_B).assessment.holds], ['unknown', ['withdrawn_source', 'affected_range_unreadable']]);
  assert.deepEqual([by(GHSA_C).assessment.dependency, by(GHSA_C).assessment.holds], ['unknown', ['unsupported_advisory_range', 'affected_range_unreadable']]);
  for (const f of b.findings) assert.deepEqual([f.assessment.exposure, f.assessment.breaker, f.assessment.validity], ['unverified', 'not_attempted', 'unreviewed'], 'never reachability or exploitability');
  assert.deepEqual(factsOf(b), { [`a:${GHSA_A}`]: 'manual_fix_selection', [`a:${GHSA_B}`]: 'verify_occurrence', [`a:${GHSA_C}`]: 'verify_occurrence' }, 'a hold on the occurrence leaves its other finding no valid candidate (DFBASE-13.4)');
  assert.deepEqual(b.extension.fix_facts.find(f => f.class === 'manual_fix_selection')!.candidate_reasons, ['occurrence_held']);
  // Dependabot says affected where OSV's full record says outside the range: both are kept, in conflict.
  const disagree = body(await staticDeps(lockfile(minimal()), caps(world({ records: [advisory(GHSA_A, 'a', fixed('0.9.0'))] }).http), alerts([alert(1, 'a', GHSA_A, '< 1.0.5', '1.0.5')])));
  assert.deepEqual([disagree.findings[0]!.assessment.provenance, disagree.findings[0]!.assessment.dependency, disagree.findings[0]!.assessment.holds, disagree.findings[0]!.observation_ids.length], ['conflicting', 'unknown', ['source_disagreement', 'affected_range_unreadable'], 2]);
});

test('DFBASE-13: a candidate\'s OSV answer reads an advisory again when OSV names a later revision than the one the installed version\'s query read', async () => {
  // OSV moves the fix above the candidate between the installed version's record read and the candidate's query.
  const moved = advisory(GHSA_A, 'a', fixed('1.0.9'), { aliases: ['CVE-2026-0001'], modified: '2026-11-01T00:00:00Z' });
  const before = world({ records: [A_FIXED] }), after = world({ records: [moved] });
  let shifted = false;
  const http: PublicHTTP = { async json(url, sent, max) {
    const response = await (shifted ? after : before).http.json(url, sent, max);
    if (url.includes('/v1/vulns/')) shifted = true;
    return response;
  } };
  const b = body(await staticDeps(lockfile(minimal()), caps(http)));
  assert.deepEqual(b.extension.fix_facts.map(f => [f.class, f.candidate_reasons]), [['manual_fix_selection', ['candidate_affected']]]);
  assert.equal(after.calls.filter(c => c.url.endsWith(`/v1/vulns/${GHSA_A}`)).length, 1, 'the later revision is read once');
});

test('DFBASE-13: the check verifies each candidate itself: its registry identity, its own OSV answer and both manifests', async () => {
  const run = async (w: World, packages = minimal(), extra: Partial<DepsCheckLockfile> & { lockfileVersion?: number } = {}) => { const made = world(w); return { b: body(await staticDeps(lockfile(packages, extra), caps(made.http))), made }; };
  const single = await run({ records: [A_FIXED] });
  assert.equal(single.b.extension.fix_facts[0]!.class, 'single_entry_upgrade');
  assert.ok(single.made.calls.some(c => c.url === 'https://registry.npmjs.org/a/1.0.5'), 'the candidate\'s registry identity is read');
  assert.ok(single.made.osvQueried().includes('a@1.0.5'), 'OSV is asked about the candidate itself');
  assert.match(single.b.recommendations[0]!.rationale, /Change the one lock entry node_modules\/a from a 1\.0\.0 to 1\.0\.5/);
  // The candidate is itself affected by another advisory that the installed version is outside of.
  const later = advisory(GHSA_B, 'a', fixed('1.0.6', '1.0.5'));
  assert.deepEqual((await run({ records: [A_FIXED, later] })).b.extension.fix_facts.map(f => [f.class, f.candidate_reasons]), [['manual_fix_selection', ['candidate_affected']]]);
  assert.deepEqual((await run({ records: [A_FIXED], private: [] , manifests: { 'a@1.0.5': { dist: { tarball: 'http://elsewhere.example/a.tgz', integrity: INTEGRITY } } } })).b.extension.fix_facts.map(f => [f.class, f.candidate_reasons]), [['manual_fix_selection', ['identity_unverified', 'candidate_osv_unknown']]]);
  assert.equal((await run({ records: [A_FIXED], manifests: { 'a@1.0.5': { dependencies: { extra: '^1.0.0' } } } })).b.extension.fix_facts[0]!.class, 'multi_entry_upgrade', 'changed edges change other lock entries');
  assert.equal((await run({ records: [A_FIXED] }, minimal(), { lockfileVersion: 2 })).b.extension.fix_facts[0]!.class, 'multi_entry_upgrade', 'lockfileVersion 2 never yields single_entry_upgrade');
  const pinned = await run({ records: [advisory(GHSA_A, 'a', fixed('1.1.0'))] }, minimal({ '': { name: 'app', dependencies: { a: '~1.0.0' } } }));
  assert.equal(pinned.b.extension.fix_facts[0]!.class, 'range_change_needed');
  assert.match(pinned.b.recommendations[0]!.rationale, /1 declared range excludes it: \(root\) dependencies "~1\.0\.0"/);
  assert.equal((await run({ records: [A_FIXED] }, minimal(), { overrides: { state: 'present', value: { a: '1.0.0' } } })).b.extension.fix_facts[0]!.class, 'manual_fix_selection');
  assert.equal((await run({ records: [advisory(GHSA_A, 'a', [{ introduced: '0' }])] })).b.extension.fix_facts[0]!.class, 'no_fix_published');
  const dev = await run({ records: [A_FIXED] }, { '': { name: 'app', devDependencies: { a: '^1.0.0' } }, 'node_modules/a': reg('a', '1.0.0', { dev: true }) });
  assert.deepEqual([dev.b.extension.fix_facts[0]!.dev_only, dev.b.extension.fix_facts[0]!.class], [true, 'single_entry_upgrade']);
  // An unfixed advisory that also covers the candidate leaves no valid candidate at all.
  assert.deepEqual((await run({ records: [A_FIXED, advisory(GHSA_B, 'a', [{ introduced: '0' }])] })).b.extension.fix_facts.map(f => f.class).sort(), ['manual_fix_selection', 'no_fix_published']);
  // An upgrade that leaves another finding on the occurrence open says so (DFBASE-14): here a Dependabot-only alert with no patch.
  const made = world({ records: [A_FIXED] }), open = { b: body(await staticDeps(lockfile(minimal()), caps(made.http), alerts([alert(4, 'a', GHSA_B, '< 2.0.0', null)]))) };
  assert.deepEqual(open.b.extension.fix_facts.map(f => f.class).sort(), ['no_fix_published', 'single_entry_upgrade']);
  const upgrade = open.b.recommendations.find(r => r.category === 'dependency.single_entry_upgrade')!, unfixed = open.b.findings.find(f => f.aliases.includes(GHSA_B))!;
  assert.ok(upgrade.uncertainties.some(u => u.includes(`does not close ${unfixed.finding_id}`)));
  assert.ok(open.b.recommendations.every(r => r.requires_human_review && r.uncertainties.some(u => u.startsWith('Engine constraints, install scripts and behavior changes'))));
});

test('DFBASE-14: the extension is strict and versioned, counts first-party entries, and hostile source text cannot break a report', async () => {
  const hostile = advisory(GHSA_A, 'a', fixed('1.0.5'), { summary: '<script>alert(1)</script> \u0007 ' + 'x'.repeat(11000) });
  const packages = minimal({ 'packages/web': { name: 'web', version: '1.0.0', dependencies: { a: '^1.0.0' } }, 'node_modules/web': { resolved: 'packages/web', link: true } });
  const b = body(await staticDeps(lockfile(packages), caps(world({ records: [hostile] }).http)));
  assert.deepEqual([b.extension.schema, b.extension.first_party_count, b.extension.registry_count, b.extension.lockfile], ['summation.discovery/static-deps/1', 2, 1, { path: PATH, lockfile_version: 3, parser_version: 'npm-pnpm-yarn-lock/semver-7.8.6/deps-v3' }]);
  assert.throws(() => DepsDiscoveryExtension.parse({ ...b.extension, routing: 'factory' }), 'an unknown key is refused');
  assert.throws(() => DepsDiscoveryExtension.parse({ ...b.extension, schema: 'summation.discovery/static-deps/2' }));
  assert.ok(b.findings[0]!.summary.length <= 1001 && !b.findings[0]!.summary.includes('\u0007'), 'source text is bounded and has no control characters');
  const { report } = joinDepsReport(b, envelope());
  assert.deepEqual(Object.keys(report.extensions!), ['summation.discovery']);
  assert.equal(b.extension.fix_facts[0]!.dependents_total, 2, 'the root and the workspace folder both depend on the occurrence');
});

test('DFBASE-14: a lockfile over a single-report limit is held with its totals and publishes nothing; nothing is truncated', async () => {
  const count = DEPS_REPORT_LIMITS.observations + 1, root: Record<string, string> = {}, packages: Record<string, unknown> = {};
  for (let i = 0; i < count; i++) { root[`p${i}`] = '^1.0.0'; packages[`node_modules/p${i}`] = reg(`p${i}`, '1.0.0'); }
  const records = Array.from({ length: count }, (_, i) => advisory(`GHSA-${String(i).padStart(4, '0')}-aaaa-aaaa`, `p${i}`, [{ introduced: '0' }]));
  const result = await staticDeps(lockfile({ '': { name: 'app', dependencies: root }, ...packages }), caps(world({ records }).http));
  assert.equal(result.outcome, 'held');
  if (result.outcome !== 'held') return;
  assert.equal(result.reason, 'discovery.report_limit');
  assert.deepEqual([result.totals.observations, result.totals.findings, result.limits.observations], [count, count, 1000]);
  assert.ok(!('body' in result), 'no report body, so nothing truncated can be published');
});

test('DFBASE-10, DFBASE-15: a credential-shaped, unsupported or malformed lockfile is skipped with its reason: no request, no report', async () => {
  const secret = lockfile({ '': { name: 'app' }, 'node_modules/a': { ...reg('a', '1.0.0'), note: 'password=hunter2hunter2' } }), w = world({ records: [A_FIXED] });
  assert.deepEqual(await staticDeps(secret, caps(w.http)), { outcome: 'skipped', reason: 'credential_shaped_content', requests: { registry: 0, osv: 0 } });
  const v1 = lockfile(minimal(), { lockfileVersion: 1 });
  assert.deepEqual(await staticDeps(v1, caps(w.http), alerts([alert(1, 'a', GHSA_A, '< 1.0.5', '1.0.5')])), { outcome: 'skipped', reason: 'unsupported_lockfile', requests: { registry: 0, osv: 0 } });
  const bytes = Buffer.from('{not json');
  assert.deepEqual(await staticDeps({ ...v1, bytes, git_blob: gitBlob(bytes), sha256: sha256(bytes) }, caps(w.http)), { outcome: 'skipped', reason: 'malformed_json', requests: { registry: 0, osv: 0 } });
  assert.equal(w.calls.length, 0, 'nothing is disclosed for a lockfile that did not parse');
  assert.equal(body(await staticDeps(lockfile(minimal(), { lockfileVersion: 2 }), caps(w.http))).extension.lockfile.lockfile_version, 2, 'lockfileVersion 2 is read through its packages section');
  await assert.rejects(staticDeps({ ...v1, path: '../escape/package-lock.json' }, caps(world().http)), (e: DepsCheckError) => e.code === 'deps_check.input');
});

test('DFBASE-14: unsafe source members become quarantined observations, and the report cannot then read complete', async () => {
  const unsafe = { ...advisory(GHSA_B, 'a', fixed('1.0.5')), summary: 'api_key=sk_live_0123456789abcdef0123' };
  const leaking = alert(3, 'a', GHSA_C, '< 1.0.5', '1.0.5', { note: 'Bearer abcdefghijklmnopqrstuvwxyz012345' });
  const b = body(await staticDeps(lockfile(minimal()), caps(world({ records: [A_FIXED, unsafe] }).http), alerts([leaking])));
  const quarantined = b.observations.filter(o => o.kind === 'quarantined_observation');
  assert.equal(quarantined.length, 2, 'one from OSV, one from Dependabot: neither disappears');
  assert.ok(!JSON.stringify(b).includes('sk_live') && !JSON.stringify(b).includes('abcdefghijklmnopqrstuvwxyz012345'), 'the unsafe text is not in the body');
  assert.deepEqual(b.dispositions.filter(d => d.kind === 'quarantined').map(d => d.reason).sort(), ['credential_shaped_evidence', 'credential_shaped_evidence']);
  assert.deepEqual([component(b, DEPS_COMPONENTS.osv).state, component(b, DEPS_COMPONENTS.dependabot).state, b.coverage.state, b.coverage.union_status], ['incomplete', 'incomplete', 'partial', 'incomplete']);
  const { report } = joinDepsReport(b, envelope());
  assert.equal(report.findings.length, 1, 'the safe finding is still reported');
  assert.equal(b.observations.filter(o => o.kind === 'source_observation').every(o => o.scope_id === DEPS_BODY_SCOPE), true);
});
