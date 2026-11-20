import assert from 'node:assert/strict';
import { dirname } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { joinDepsReport, staticDeps, type DepsCheckLockfile, type DepsReportEnvelope } from '../src/security-deps-check.ts';
import { DEPS_REPAIR_LIMITS, DEPS_REPAIR_VERSION, DEPS_REPAIR_WRITER, DepsRepairHold, buildLockRepair, lockEntryDiff, recordNpmConsistency, renderRepairPullRequest, repairLockEntry,
  type DepsNpmConsistency, type DepsRepairPacket, type DepsRepairTarget } from '../src/security-deps-repair.ts';
import type { PublicHTTP } from '../src/security-advisories.ts';
import { gitBlob, sha256 } from '../src/security-primitives.ts';
import { reportHash } from '../src/security-report-json.ts';
import { GHSA_A, GHSA_B, INTEGRITY, NOW, PATH, advisory, caps, fixed, reg, tarball, world, type World } from './deps-world.ts';
import { importGraph, impurities } from './import-graph.ts';

const COMMIT = 'a'.repeat(40), ENTRY = 'node_modules/a', NEXT = 'sha512-Y2FuZGlkYXRl';
const text = (bytes: Uint8Array) => Buffer.from(bytes).toString('utf8');
/** A lockfile as npm writes it: two-space indentation and a final newline, unless a test asks otherwise. */
function lockfile(packages: Record<string, unknown>, format: { indent?: string | number; eol?: string; final?: boolean } = {}): DepsCheckLockfile {
  const { indent = 2, eol = '\n', final = true } = format;
  const bytes = Buffer.from(JSON.stringify({ name: 'app', lockfileVersion: 3, requires: true, packages }, null, indent).replace(/\n/g, eol) + (final ? eol : ''));
  return { path: PATH, bytes, git_blob: gitBlob(bytes), sha256: sha256(bytes), overrides: { state: 'absent' }, package_json: null };
}
// One root dependency `a@^1.0.0` installed at 1.0.0 with a fix published at 1.0.5, and a neighbour the repair must not touch.
const packages = (entry: Record<string, unknown> = {}, extra: Record<string, unknown> = {}): Record<string, unknown> => ({ '': { name: 'app', dependencies: { a: '^1.0.0', b: '^2.0.0' } },
  [ENTRY]: reg('a', '1.0.0', entry), 'node_modules/b': reg('b', '2.0.0'), ...extra });
const A_FIXED = advisory(GHSA_A, 'a', fixed('1.0.5'), { aliases: ['CVE-2026-0001'] });
/** A registry manifest override: the candidate version has its own integrity, as a real one does. */
const next = (extra: Record<string, unknown> = {}) => ({ 'a@1.0.5': { dist: { tarball: tarball('a', '1.0.5'), integrity: NEXT }, ...extra } });
const target = (extra: Partial<DepsRepairTarget> = {}): DepsRepairTarget => ({ repository: 'acme/app', commit: COMMIT, entry: ENTRY, ...extra });
const repair = (lock: DepsCheckLockfile, w: World = {}, t: Partial<DepsRepairTarget> = {}) => repairLockEntry(lock, target(t), caps(world({ records: [A_FIXED], ...w, manifests: { ...next(), ...w.manifests } }).http));
const holds = (code: string) => (e: unknown) => e instanceof DepsRepairHold && e.code === code;
const envelope = (extra: Partial<DepsReportEnvelope> = {}): DepsReportEnvelope => ({ producer: { namespace: 'summation.discovery', product: 'dependency-baseline', version: '1' }, report_id: 'repo-42-lock-1', revision: 1, previous_digest: null,
  generated_at: '2026-11-12T18:00:05Z', snapshot: { target_id: 'github', repository_id: '42', repository: 'acme/app', sha: COMMIT, scopes: [{ scope_id: 'lock-1', service: 'repository', paths: [PATH] }] },
  profile: { id: 'discovery-deps-v1', revision: 1, digest: 'b'.repeat(64) }, ...extra });
async function reportFor(lock: DepsCheckLockfile, extra: Partial<DepsReportEnvelope> = {}) {
  const result = await staticDeps(lock, caps(world({ records: [A_FIXED], manifests: next() }).http));
  assert.equal(result.outcome, 'report');
  return joinDepsReport((result as Extract<typeof result, { outcome: 'report' }>).body, envelope(extra)).report;
}
/** The registry and OSV change once the lane has read the installed manifest again: what the candidate check sees is `later`. */
function shifting(first: World, later: World) {
  const before = world(first), after = world(later);
  let reads = 0, shifted = false;
  const http: PublicHTTP = { async json(url, body, max) {
    const response = await (shifted ? after : before).http.json(url, body, max);
    if (url.endsWith('/a/1.0.5') && ++reads === 2) shifted = true;
    return response;
  } };
  return http;
}
const step = (packet: DepsRepairPacket, name: string) => packet.steps.find(s => s.name === name)!;
const npm = (outcome: DepsNpmConsistency['outcome'], extra: Partial<DepsNpmConsistency> = {}): DepsNpmConsistency => ({ outcome, npm_version: '11.0.0', detail: outcome, started_at: '2026-11-12T18:00:01.000Z', finished_at: '2026-11-12T18:00:02.000Z', ...extra });

test('DFREP-1, DFREP-5, DFREP-6: one occurrence is moved to the candidate the base check computed, and the proof passes', async () => {
  const lock = lockfile(packages()), { packet, candidate } = await repair(lock);
  assert.equal(packet.outcome, 'proved');
  assert.equal(packet.failed_step, null);
  assert.deepEqual(packet.occurrence, { entry: ENTRY, package: 'a', installed: '1.0.0', candidate: '1.0.5' });
  assert.equal(packet.targets.length, 1);
  assert.ok(packet.targets[0]!.aliases.includes(GHSA_A) && packet.targets[0]!.aliases.includes('CVE-2026-0001'));
  assert.deepEqual(packet.remaining, []);
  // DFREP-5: the base bytes with that entry's values replaced, and every other byte unchanged.
  assert.equal(text(candidate), text(lock.bytes).replace('"version": "1.0.0"', '"version": "1.0.5"').replace(tarball('a', '1.0.0'), tarball('a', '1.0.5')).replace(`"integrity": "${INTEGRITY}"`, `"integrity": "${NEXT}"`));
  assert.equal(text(candidate).split(INTEGRITY).length, 2, 'the neighbour keeps its own integrity');
  assert.deepEqual(packet.changed_fields, [{ field: 'version', before: '1.0.0', after: '1.0.5' }, { field: 'resolved', before: tarball('a', '1.0.0'), after: tarball('a', '1.0.5') }, { field: 'integrity', before: INTEGRITY, after: NEXT }]);
  assert.deepEqual(lockEntryDiff(lock.bytes, candidate), { changed: [ENTRY], added: [], removed: [], reordered: false, outside_equal: true });
  // DFREP-6: the same check, run fresh on the candidate bytes, no longer has the finding.
  const after = await staticDeps({ ...lock, bytes: candidate, git_blob: gitBlob(candidate), sha256: sha256(candidate) }, caps(world({ records: [A_FIXED], manifests: next() }).http));
  assert.equal(after.outcome, 'report');
  assert.deepEqual((after as Extract<typeof after, { outcome: 'report' }>).body.findings, []);
  assert.deepEqual(packet.coverage, { base: 'complete', candidate: 'complete', base_findings: 1, candidate_findings: 0 });
  assert.equal(step(packet, 'base_check').outcome, 'passed');
  assert.equal(step(packet, 'candidate_check').outcome, 'passed');
});

test('DFREP-1: the lane takes no version to upgrade to, and refuses an occurrence or a named finding that is not a single_entry_upgrade', async () => {
  const lock = lockfile(packages());
  // A caller that smuggles a version in is ignored: the candidate is the base check's.
  const smuggled = await repair(lock, {}, { candidate: '9.9.9', version: '9.9.9' } as Partial<DepsRepairTarget>);
  assert.equal(smuggled.packet.occurrence.candidate, '1.0.5');
  await assert.rejects(repair(lock, {}, { entry: 'node_modules/b' }), holds('repair.not_single_entry_upgrade'), 'an occurrence with no finding');
  await assert.rejects(repair(lock, {}, { entry: 'node_modules/missing' }), holds('repair.not_single_entry_upgrade'), 'no such occurrence');
  await assert.rejects(repair(lock, {}, { finding_ids: ['deps-' + '0'.repeat(32)] }), holds('repair.not_single_entry_upgrade'), 'a named finding that is not a target');
  // The fix is outside the declared range, so the report's class is range_change_needed: not this lane's to build.
  await assert.rejects(repair(lock, { records: [advisory(GHSA_A, 'a', fixed('2.0.0'))] }), holds('repair.not_single_entry_upgrade'));
  // No fix published at all.
  await assert.rejects(repair(lock, { records: [advisory(GHSA_A, 'a', [{ introduced: '0' }])] }), holds('repair.not_single_entry_upgrade'));
  const named = await repair(lock, {}, { finding_ids: [smuggled.packet.targets[0]!.finding_id] });
  assert.equal(named.packet.packet_digest, smuggled.packet.packet_digest, 'naming the target changes nothing');
  await assert.rejects(repair(lock, {}, { commit: 'main' }), holds('repair.report_mismatch'), 'the commit is a full SHA');
});

test('DFREP-2: a supplied report is only checked against the bytes and the base check, and its extension is never read', async () => {
  const lock = lockfile(packages()), report = await reportFor(lock);
  const guarded = structuredClone(report);
  Object.defineProperty(guarded, 'extensions', { get() { throw Error('the lane read the report extension'); } });
  const { packet } = await repair(lock, {}, { report: guarded });
  assert.equal(packet.outcome, 'proved');
  assert.equal(packet.occurrence.candidate, '1.0.5');
  await assert.rejects(repair(lock, {}, { report: await reportFor(lock, { snapshot: { ...envelope().snapshot, sha: 'c'.repeat(40) } }) }), holds('repair.report_mismatch'), 'another commit');
  await assert.rejects(repair({ ...lock, path: 'other/package-lock.json' }, {}, { report }), holds('repair.report_mismatch'), 'another lockfile path');
  const recategorized = structuredClone(report);
  recategorized.recommendations[0]!.category = 'dependency.range_change_needed';
  await assert.rejects(repair(lock, {}, { report: recategorized }), holds('repair.report_mismatch'), 'the report recommends something else');
  const other = structuredClone(report);
  other.findings[0]!.finding_id = 'deps-' + 'f'.repeat(32);
  await assert.rejects(repair(lock, {}, { report: other }), holds('repair.report_mismatch'), 'the report does not hold the target finding');
});

test('DFREP-3: every changed value is derived from the registry manifests, by a rule that first reproduces the base entry', () => {
  const manifest = (version: string, extra: Record<string, unknown> = {}) => ({ name: 'a', version, dist: { tarball: tarball('a', version), integrity: version === '1.0.0' ? INTEGRITY : NEXT }, description: 'not a lock field',
    license: { type: 'MIT', url: 'https://example.invalid/license' }, engines: { node: '>=14' }, bin: { a: 'cli.js' }, dependencies: { c: '^1.0.0', d: '^2.0.0' }, optionalDependencies: { d: '^2.0.0' },
    peerDependencies: { e: '>=1' }, peerDependenciesMeta: { e: { optional: true } }, scripts: { test: 'node test.js' }, funding: {}, os: [], ...extra });
  const entry = reg('a', '1.0.0', { dev: true, license: 'MIT', engines: { node: '>=14' }, bin: { a: 'cli.js' }, dependencies: { c: '^1.0.0' }, optionalDependencies: { d: '^2.0.0' }, peerDependencies: { e: '>=1' }, peerDependenciesMeta: { e: { optional: true } } });
  const lock = lockfile(packages(entry));
  const built = buildLockRepair(lock.bytes, ENTRY, manifest('1.0.0'), manifest('1.0.5', { engines: { node: '>=16' }, dependencies: { c: '^1.2.0', d: '^2.0.0' } }));
  const after = JSON.parse(text(built.candidate)).packages[ENTRY];
  // Position flags are kept, key order is kept, a license object is its type, optional dependencies are listed once, and changed engines are carried.
  assert.deepEqual(Object.keys(after), Object.keys(entry));
  assert.deepEqual(after, { ...entry, version: '1.0.5', resolved: tarball('a', '1.0.5'), integrity: NEXT, engines: { node: '>=16' }, dependencies: { c: '^1.2.0' } });
  assert.deepEqual(built.changes.map(c => c.field), ['version', 'resolved', 'integrity', 'engines', 'dependencies']);
  // An install script is a lock field whether the registry computed the flag or only lists the script.
  const scripted = lockfile(packages(reg('a', '1.0.0', { hasInstallScript: true })));
  const bare = (version: string, extra: Record<string, unknown> = {}) => ({ name: 'a', version, dist: { tarball: tarball('a', version), integrity: INTEGRITY }, ...extra });
  assert.equal(JSON.parse(text(buildLockRepair(scripted.bytes, ENTRY, bare('1.0.0', { scripts: { postinstall: 'node build.js' } }), bare('1.0.5', { hasInstallScript: true })).candidate)).packages[ENTRY].hasInstallScript, true);
});

test('DFREP-4: the builder holds instead of guessing, and a hold produces no candidate', async () => {
  const bare = (version: string, extra: Record<string, unknown> = {}) => ({ name: 'a', version, dist: { tarball: tarball('a', version), integrity: INTEGRITY }, ...extra });
  const build = (entry: Record<string, unknown>, installed: unknown, candidate: unknown, format = {}) => () => buildLockRepair(lockfile(packages(entry), format).bytes, ENTRY, installed, candidate);
  // The installed manifest does not reproduce the entry npm wrote: a value, a missing field, and a different key order.
  assert.throws(build({ license: 'MIT' }, bare('1.0.0', { license: 'ISC' }), bare('1.0.5', { license: 'ISC' })), holds('repair.entry_not_reproducible'));
  assert.throws(build({ license: 'MIT' }, bare('1.0.0'), bare('1.0.5')), holds('repair.entry_not_reproducible'));
  assert.throws(build({}, bare('1.0.0', { engines: { node: '>=14' } }), bare('1.0.5')), holds('repair.entry_not_reproducible'));
  assert.throws(build({ dependencies: { c: '1', d: '1' } }, bare('1.0.0', { dependencies: { d: '1', c: '1' } }), bare('1.0.5', { dependencies: { d: '1', c: '1' } })), holds('repair.entry_not_reproducible'));
  assert.throws(build({}, { ...bare('1.0.0'), dist: { tarball: tarball('a', '1.0.0'), integrity: NEXT } }, bare('1.0.5')), holds('repair.entry_not_reproducible'), 'another integrity');
  // The candidate would add or remove a key of the entry.
  assert.throws(build({}, bare('1.0.0'), bare('1.0.5', { engines: { node: '>=20' } })), holds('repair.entry_shape_changes'));
  assert.throws(build({ dependencies: { c: '1' } }, bare('1.0.0', { dependencies: { c: '1' } }), bare('1.0.5')), holds('repair.entry_shape_changes'));
  // A key outside the lists this lane understands.
  assert.throws(build({ extraneous: true }, bare('1.0.0'), bare('1.0.5')), holds('repair.entry_key_unknown'));
  assert.throws(build({ link: true }, bare('1.0.0'), bare('1.0.5')), holds('repair.entry_key_unknown'));
  // The unchanged lockfile does not re-serialize to its own bytes.
  assert.throws(build({}, bare('1.0.0'), bare('1.0.5'), { indent: 0 }), holds('repair.format_not_reproducible'));
  assert.throws(() => buildLockRepair(Buffer.from(text(lockfile(packages()).bytes) + '\n'), ENTRY, bare('1.0.0'), bare('1.0.5')), holds('repair.format_not_reproducible'));
  assert.throws(() => buildLockRepair(Buffer.from(text(lockfile(packages()).bytes).replace('"requires": true', '"requires":true')), ENTRY, bare('1.0.0'), bare('1.0.5')), holds('repair.format_not_reproducible'));
  // A missing manifest, and a deprecated candidate.
  assert.throws(build({}, null, bare('1.0.5')), holds('repair.identity_unverified'));
  assert.throws(build({}, bare('1.0.0'), bare('1.0.5', { deprecated: 'use 2.x' })), holds('repair.candidate_deprecated'));
  // A deprecation notice on the old version is not a manifest field the entry must reproduce, and does not carry over.
  const undeprecated = buildLockRepair(lockfile(packages({ deprecated: 'has a flaw' })).bytes, ENTRY, bare('1.0.0'), bare('1.0.5'));
  assert.equal('deprecated' in JSON.parse(text(undeprecated.candidate)).packages[ENTRY], false);
  assert.deepEqual(undeprecated.changes.at(-1), { field: 'deprecated', before: 'has a flaw', after: null });

  // Through the lane: the registry no longer confirms the candidate when the builder reads it again.
  const registry = world({ records: [A_FIXED], manifests: next() }).http;
  let reads = 0;
  const unconfirmed: PublicHTTP = { async json(url, body, max) { const r = await registry.json(url, body, max); return url.endsWith('/a/1.0.5') && ++reads === 2 ? { ...r, body: { ...r.body as object, name: 'not-a' } } : r; } };
  await assert.rejects(repairLockEntry(lockfile(packages()), target(), caps(unconfirmed)), holds('repair.identity_unverified'));
  // A lockfile the check does not report on has nothing to repair.
  await assert.rejects(repairLockEntry({ ...lockfile(packages()), bytes: Buffer.from('{') }, target(), caps(world().http)), holds('repair.base_not_reported'));
});

test('DFREP-5: the lockfile\'s own indentation, line endings and final newline are kept, and the entry diff is judged on the bytes', async () => {
  for (const format of [{ indent: 4 }, { indent: '\t' }, { eol: '\r\n' }, { final: false }, { indent: 4, eol: '\r\n', final: false }]) {
    const lock = lockfile(packages(), format), { packet, candidate } = await repair(lock);
    assert.equal(packet.outcome, 'proved', JSON.stringify(format));
    const expected = text(lock.bytes).replace('"version": "1.0.0"', '"version": "1.0.5"').replace(tarball('a', '1.0.0'), tarball('a', '1.0.5')).replace(`"integrity": "${INTEGRITY}"`, `"integrity": "${NEXT}"`);
    assert.equal(text(candidate), expected, JSON.stringify(format));
    assert.equal(packet.candidate.sha256, sha256(candidate));
    assert.equal(packet.candidate.git_blob, gitBlob(candidate));
  }
  // The diff is its own judgment, independent of how a candidate was built.
  const base = lockfile(packages()).bytes, edit = (change: (lock: { packages: Record<string, Record<string, unknown>> } & Record<string, unknown>) => unknown) => { const lock = JSON.parse(text(base)); const result = change(lock) ?? lock; return Buffer.from(JSON.stringify(result, null, 2) + '\n'); };
  assert.deepEqual(lockEntryDiff(base, base), { changed: [], added: [], removed: [], reordered: false, outside_equal: true });
  assert.deepEqual(lockEntryDiff(base, edit(l => { l.packages[ENTRY]!.version = '1.0.5'; l.packages['node_modules/b']!.version = '2.0.1'; })).changed, [ENTRY, 'node_modules/b'], 'a second changed entry');
  assert.deepEqual(lockEntryDiff(base, edit(l => { l.packages['']!.dependencies = { a: '^1.0.5', b: '^2.0.0' }; })).changed, [''], 'the root entry is a packages key like any other');
  assert.deepEqual(lockEntryDiff(base, edit(l => { l.packages['node_modules/c'] = reg('c', '1.0.0'); })).added, ['node_modules/c']);
  assert.deepEqual(lockEntryDiff(base, edit(l => { delete l.packages['node_modules/b']; })).removed, ['node_modules/b']);
  assert.equal(lockEntryDiff(base, edit(l => { l.packages = { '': l.packages['']!, 'node_modules/b': l.packages['node_modules/b']!, [ENTRY]: l.packages[ENTRY]! }; })).reordered, true);
  assert.equal(lockEntryDiff(base, edit(l => { l.lockfileVersion = 2; })).outside_equal, false);
  assert.equal(lockEntryDiff(base, edit(l => { l.dependencies = {}; })).outside_equal, false);
  assert.equal(lockEntryDiff(base, edit(l => ({ packages: l.packages, name: l.name, lockfileVersion: l.lockfileVersion, requires: l.requires }))).outside_equal, false, 'top-level key order');
});

test('DFREP-6: a target finding still present on the candidate fails the proof', async () => {
  // After the lane built the candidate, the advisory's fix moved: 1.0.5 is affected after all.
  const http = shifting({ records: [A_FIXED], manifests: next() }, { records: [advisory(GHSA_A, 'a', fixed('1.0.6'), { modified: '2026-11-12T00:00:00Z' })], manifests: next() });
  const { packet } = await repairLockEntry(lockfile(packages()), target(), caps(http));
  assert.equal(packet.outcome, 'failed');
  assert.equal(packet.failed_step, 'candidate_check');
  assert.match(step(packet, 'candidate_check').detail, /1 target finding is still present/);
  assert.equal(step(packet, 'entry_diff').outcome, 'passed', 'the change was the described change; it did not close the finding');
  assert.throws(() => renderRepairPullRequest(packet), /deps_repair_packet_not_proved/);
});

test('DFREP-7: a new finding on the candidate, or coverage worse than the base\'s, fails the proof', async () => {
  // Another advisory that begins at the candidate version: the upgrade would trade one flaw for another.
  const traded = shifting({ records: [A_FIXED], manifests: next() }, { records: [A_FIXED, advisory(GHSA_B, 'a', fixed('1.0.9', '1.0.5'))], manifests: next() });
  const one = (await repairLockEntry(lockfile(packages()), target(), caps(traded))).packet;
  assert.equal(one.failed_step, 'candidate_check');
  assert.match(step(one, 'candidate_check').detail, /1 finding the base did not/);
  assert.deepEqual(one.coverage, { base: 'complete', candidate: 'complete', base_findings: 1, candidate_findings: 1 });
  // The candidate's identity can no longer be confirmed, so it is not checked at all: the finding is absent for the wrong reason.
  const unchecked = shifting({ records: [A_FIXED], manifests: next() }, { records: [A_FIXED], private: ['a'] });
  const two = (await repairLockEntry(lockfile(packages()), target(), caps(unchecked))).packet;
  assert.equal(two.outcome, 'failed');
  assert.equal(two.failed_step, 'candidate_check');
  assert.match(step(two, 'candidate_check').detail, /coverage is worse than the base's: coverage went from complete to partial; entries not checked went from 0 to 1/);
  assert.throws(() => renderRepairPullRequest(two), /deps_repair_packet_not_proved/);
  // A source record the check quarantines on both runs is the same member, even when the source serializes it to other bytes the second time.
  const unsafe = (id: string, extra: Record<string, unknown> = {}) => ({ ...advisory(id, 'b', fixed('2.0.1')), summary: 'api_key=sk_live_0123456789abcdef0123', ...extra });
  const same = shifting({ records: [A_FIXED, unsafe(GHSA_B)], manifests: next() }, { records: [A_FIXED, unsafe(GHSA_B, { schema_version: '1.6.0' })], manifests: next() });
  const three = (await repairLockEntry(lockfile(packages()), target(), caps(same))).packet;
  assert.equal(three.outcome, 'proved', step(three, 'candidate_check').detail);
  assert.deepEqual([three.coverage.base, three.coverage.candidate], ['partial', 'partial']);
  assert.ok(renderRepairPullRequest(three).body.includes('its coverage was partial before and partial after'), 'partial coverage is stated, not hidden');
  // A record quarantined only on the candidate run is evidence the base run did not lack.
  const more = shifting({ records: [A_FIXED, unsafe(GHSA_B)], manifests: next() }, { records: [A_FIXED, unsafe(GHSA_B), unsafe('GHSA-dddd-dddd-dddd')], manifests: next() });
  const four = (await repairLockEntry(lockfile(packages()), target(), caps(more))).packet;
  assert.equal(four.failed_step, 'candidate_check');
  assert.match(step(four, 'candidate_check').detail, /1 quarantined source record the base did not have/);
  // As many entries unchecked on each run, but not the same ones: the base could not verify b, the candidate cannot verify the upgraded a.
  const swapped = shifting({ records: [A_FIXED], manifests: next(), private: ['b'] }, { records: [A_FIXED], private: ['a'] });
  const five = (await repairLockEntry(lockfile(packages()), target(), caps(swapped))).packet;
  assert.deepEqual([five.coverage.base, five.coverage.candidate], ['partial', 'partial']);
  assert.equal(five.failed_step, 'candidate_check');
  assert.match(step(five, 'candidate_check').detail, /the upgraded entry node_modules\/a was not checked; 1 entry not checked that the base checked$/);
});

test('DFREP-9: one packet records the inputs, the change, a step per action and the versions, and identical inputs give an identical packet apart from times', async () => {
  const lock = lockfile(packages()), { packet, candidate } = await repair(lock);
  assert.deepEqual(Object.keys(packet).sort(), ['base', 'candidate', 'changed_fields', 'commit', 'coverage', 'failed_step', 'limits', 'lockfile', 'occurrence', 'outcome', 'packet_digest', 'packet_version', 'remaining', 'repository', 'requests', 'steps', 'targets', 'versions']);
  assert.equal(packet.packet_version, DEPS_REPAIR_VERSION);
  assert.deepEqual([packet.repository, packet.commit, packet.lockfile], ['acme/app', COMMIT, PATH]);
  assert.deepEqual(packet.base, { sha256: lock.sha256, git_blob: lock.git_blob, bytes: lock.bytes.byteLength });
  assert.deepEqual(packet.candidate, { sha256: sha256(candidate), git_blob: gitBlob(candidate), bytes: candidate.byteLength });
  assert.deepEqual(packet.steps.map(s => [s.name, s.outcome]), [['base_check', 'passed'], ['build', 'passed'], ['entry_diff', 'passed'], ['candidate_check', 'passed'], ['npm_consistency', 'not_run']]);
  assert.ok(packet.steps.every(s => s.writer === DEPS_REPAIR_WRITER && s.writer === 'harness:lock-repair'));
  assert.ok(packet.steps.slice(0, 4).every(s => s.inputs.length && s.outputs.length && [...s.inputs, ...s.outputs].every(d => /^[0-9a-f]{64}$/.test(d))), 'each step names its input and output digests');
  assert.deepEqual(step(packet, 'build').outputs, [packet.candidate.sha256]);
  assert.deepEqual(packet.versions, { repair: 'lock-repair/v1', check: 'static-deps/v1', facts: packet.versions.facts, lock_parser: packet.versions.lock_parser, npm: null });
  assert.ok(packet.requests.registry > 0 && packet.requests.osv > 0);
  const { packet_digest, ...rest } = packet;
  assert.equal(packet_digest, reportHash(rest), 'the digest covers every other field');
  // Another run at another time: the same packet apart from times and the digest over them.
  const again = (await repairLockEntry(lock, target(), { ...caps(world({ records: [A_FIXED], manifests: next() }).http), now: () => NOW + 60_000 })).packet;
  const timeless = (p: DepsRepairPacket) => ({ ...p, packet_digest: null, steps: p.steps.map(s => ({ ...s, started_at: null, finished_at: null })) });
  assert.notEqual(again.packet_digest, packet.packet_digest);
  assert.deepEqual(timeless(again), timeless(packet));
  assert.equal(step(again, 'base_check').started_at, new Date(NOW + 60_000).toISOString());
});

test('DFREP-10, DFREP-11: the packet and the pull request body carry the same fixed limits, and the body is rendered from the packet', async () => {
  const { packet } = await repair(lockfile(packages()));
  assert.deepEqual(packet.limits, [...DEPS_REPAIR_LIMITS]);
  assert.equal(DEPS_REPAIR_LIMITS.length, 6);
  for (const words of [/deterministic resolver, not by an agent/, /no repository code, test or install script/, /tests are this pull request's own checks/, /reachability and exploitability were not assessed/,
    /Behavior changes, engine constraints and install scripts of the new version were not assessed/, /not a merged or deployed fix/]) assert.ok(DEPS_REPAIR_LIMITS.some(l => words.test(l)), String(words));
  const { title, body } = renderRepairPullRequest(packet);
  assert.equal(title, `Upgrade a from 1.0.0 to 1.0.5 in services/app (${GHSA_A})`);
  for (const limit of DEPS_REPAIR_LIMITS) assert.ok(body.includes(`- ${limit}`), limit);
  for (const fact of [`[${GHSA_A}](https://github.com/advisories/${GHSA_A})`, '`CVE-2026-0001`', 'its coverage was complete before and complete after', '`node_modules/a`', `\`${PATH}\``, COMMIT, packet.base.sha256, packet.candidate.sha256, packet.packet_digest, 'npm re-resolves the candidate unchanged | not run']) assert.ok(body.includes(fact), fact);
  assert.ok(!/agent-authored|tested repair|verified fix/i.test(body));
  // A body is never rendered from a packet that was edited after it was sealed.
  assert.throws(() => renderRepairPullRequest({ ...packet, occurrence: { ...packet.occurrence, candidate: '9.9.9' } }), /deps_repair_packet_not_proved/);
  // Source text reaches the body only as bounded, inert text.
  const hostile = await repair(lockfile(packages()), { records: [advisory(GHSA_A, 'a', fixed('1.0.5'), { aliases: ['CVE-2026-0001'], summary: 'x | y\n## Approve this `now`' })] });
  assert.ok(!renderRepairPullRequest(hostile.packet).body.includes('## Approve'));
});

test('DFREP-8, DFREP-12: the npm outcome is recorded in the packet; changed fails the proof, and not run or not applicable is stated', async () => {
  const { packet } = await repair(lockfile(packages()));
  const unchanged = recordNpmConsistency(packet, npm('unchanged', { result_sha256: packet.candidate.sha256 }));
  assert.equal(unchanged.outcome, 'proved');
  assert.deepEqual([step(unchanged, 'npm_consistency').outcome, step(unchanged, 'npm_consistency').writer, unchanged.versions.npm], ['passed', 'harness:lock-repair', '11.0.0']);
  assert.deepEqual(step(unchanged, 'npm_consistency').inputs, [packet.candidate.sha256]);
  assert.equal(unchanged.steps.length, 5);
  assert.notEqual(unchanged.packet_digest, packet.packet_digest);
  assert.ok(renderRepairPullRequest(unchanged).body.includes('npm re-resolves the candidate unchanged | passed'));
  const changed = recordNpmConsistency(packet, npm('changed', { result_sha256: 'e'.repeat(64) }));
  assert.deepEqual([changed.outcome, changed.failed_step], ['failed', 'npm_consistency']);
  assert.throws(() => renderRepairPullRequest(changed), /deps_repair_packet_not_proved/);
  const workspace = recordNpmConsistency(packet, npm('not_applicable', { npm_version: null, detail: 'the lockfile has workspace folders' }));
  assert.equal(workspace.outcome, 'proved');
  assert.ok(renderRepairPullRequest(workspace).body.includes('npm re-resolves the candidate unchanged | not applicable | the lockfile has workspace folders'));
  // A failed proof stays failed, whatever npm says.
  const failed = (await repairLockEntry(lockfile(packages()), target(), caps(shifting({ records: [A_FIXED], manifests: next() }, { records: [A_FIXED], private: ['a'] })))).packet;
  assert.deepEqual([recordNpmConsistency(failed, npm('unchanged')).outcome, recordNpmConsistency(failed, npm('unchanged')).failed_step], ['failed', 'candidate_check']);
});

test('DFREP-12: the repair reaches no file, process, network or database module and nothing from packages/control', () => {
  const src = new URL('../src/security-deps-repair.ts', import.meta.url), graph = importGraph(src);
  assert.deepEqual(impurities(graph), []);
  assert.deepEqual(graph.unresolved, []);
  assert.deepEqual(graph.packages, ['node:crypto', 'semver', 'zod']);
  assert.deepEqual(graph.modules.filter(m => dirname(m) !== dirname(fileURLToPath(src))), []);
});
