import assert from 'node:assert/strict';
import { test } from 'node:test';
import { dependentsOf, parseDepsLock, resolveDependency, type DepsLock } from '../src/security-deps-lock.ts';
import { candidateRequests, classify, DEPS_FACTS_VERSION, DEPS_FIX_CLASSES, planCandidates, type DepsAffectedInterval, type DepsFindingInput, type DepsOccurrenceEvidence, type DepsOverridesInput } from '../src/security-deps-facts.ts';

const reg = (name: string, version: string, extra: Record<string, unknown> = {}) => ({ version, resolved: `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`, integrity: 'sha512-Zml4dHVyZQ==', ...extra });
const lockOf = (packages: Record<string, unknown>, lockfileVersion = 3) => parseDepsLock(JSON.stringify({ name: 'app', lockfileVersion, requires: true, packages }));
const fixed = (upper: string, lower: string | null = null): DepsAffectedInterval => ({ lower, upper, upper_kind: 'fixed' });
const finding = (finding_id: string, entry: string, intervals: DepsAffectedInterval[], extra: Partial<DepsFindingInput> = {}): DepsFindingInput =>
  ({ finding_id, entry, held: false, current: true, affected: { intervals, versions: [] }, ...extra });
const manifest = (name: string, version: string, extra: Record<string, unknown> = {}) => ({ name, version, dist: { tarball: 'x', integrity: 'y' }, ...extra });
const clear = (name: string, installed: string, candidate: string, extra: Partial<DepsOccurrenceEvidence> = {}): DepsOccurrenceEvidence =>
  ({ identity_verified: true, candidate_osv: 'clear', installed_manifest: manifest(name, installed), candidate_manifest: manifest(name, candidate), ...extra });
const absent: DepsOverridesInput = { state: 'absent' };
function facts(lock: DepsLock, findings: DepsFindingInput[], evidence: Record<string, DepsOccurrenceEvidence> = {}, overrides: DepsOverridesInput = absent) {
  return classify(lock, overrides, findings, planCandidates(lock, findings), evidence);
}
const classes = (result: ReturnType<typeof facts>) => Object.fromEntries(result.findings.map(f => [f.finding_id, f.class]));
// One root dependency on a@^1.0.0, installed at 1.0.0: the smallest lockfile every class starts from.
const minimal = (extra: Record<string, unknown> = {}, rootRange = '^1.0.0', v = 3) => lockOf({ '': { name: 'app', dependencies: { a: rootRange } }, 'node_modules/a': reg('a', '1.0.0'), ...extra }, v);
const A = 'node_modules/a';

test('DFBASE-13: each class from a minimal lockfile, first match winning in the rule\'s order', () => {
  assert.deepEqual(DEPS_FIX_CLASSES, ['verify_occurrence', 'no_fix_published', 'manual_fix_selection', 'range_change_needed', 'multi_entry_upgrade', 'single_entry_upgrade']);
  assert.equal(DEPS_FACTS_VERSION, 'deps-facts/v1');
  const lock = minimal(), ok = { [A]: clear('a', '1.0.0', '1.0.5') };
  assert.equal(facts(lock, [finding('held', A, [fixed('1.0.5')], { held: true })], ok).findings[0]!.class, 'verify_occurrence');
  assert.equal(facts(lock, [finding('stale', A, [fixed('1.0.5')], { current: false })], ok).findings[0]!.class, 'verify_occurrence');
  assert.equal(facts(lock, [finding('open', A, [{ lower: null, upper: null, upper_kind: null }])], ok).findings[0]!.class, 'no_fix_published');
  assert.equal(facts(lock, [finding('f', A, [fixed('1.0.5')])], {}).findings[0]!.class, 'manual_fix_selection');
  assert.equal(facts(minimal({}, '~1.0.0'), [finding('f', A, [fixed('1.1.0')])], { [A]: clear('a', '1.0.0', '1.1.0') }).findings[0]!.class, 'range_change_needed');
  const grown = { [A]: clear('a', '1.0.0', '1.0.5', { candidate_manifest: manifest('a', '1.0.5', { dependencies: { b: '^1.0.0' } }) }) };
  assert.equal(facts(lock, [finding('f', A, [fixed('1.0.5')])], grown).findings[0]!.class, 'multi_entry_upgrade');
  const single = facts(lock, [finding('f', A, [fixed('1.0.5')])], ok).findings[0]!;
  assert.deepEqual(single, { finding_id: 'f', entry: A, class: 'single_entry_upgrade', dev_only: false, fixed_version: '1.0.5', candidate: '1.0.5', candidate_valid: true, candidate_reasons: [],
    range_ok: true, range_reasons: [], dependents_total: 1, blocking_dependents: [], blocking_total: 0, edges_unchanged: true });
  const onHeldEntry = lockOf({ '': { dependencies: { a: '^1.0.0' } }, [A]: { ...reg('a', '1.0.0'), name: 'b' } });
  assert.equal(facts(onHeldEntry, [finding('f', A, [fixed('1.0.5')])], ok).findings[0]!.class, 'verify_occurrence', 'a finding on a held entry is verify_occurrence even unflagged');
});

test('DFBASE-13: dev_only is the lock entry\'s dev flag, and only a fixed bound is a fixed version', () => {
  const lock = lockOf({ '': { devDependencies: { a: '^1.0.0' } }, [A]: reg('a', '1.0.0', { dev: true }) });
  const result = facts(lock, [finding('fixed', A, [fixed('1.0.5')]), finding('limit', A, [{ lower: null, upper: '2.0.0', upper_kind: 'limit' }]),
    finding('last', A, [{ lower: '0.9.0', upper: '1.0.1', upper_kind: 'last_affected' }]), finding('listed', A, [], { affected: { intervals: [], versions: ['1.0.0'] } }),
    finding('overlap', A, [fixed('1.0.5'), { lower: '0.5.0', upper: '1.0.2', upper_kind: 'limit' }]), finding('both', A, [fixed('1.0.3'), fixed('1.0.4', '0.9.0')])], { [A]: clear('a', '1.0.0', '1.0.5') });
  assert.ok(result.findings.every(f => f.dev_only));
  assert.deepEqual(Object.fromEntries(result.findings.map(f => [f.finding_id, f.fixed_version])), { fixed: '1.0.5', limit: null, last: null, listed: null, overlap: null, both: '1.0.4' });
  assert.deepEqual(classes(result), { fixed: 'single_entry_upgrade', limit: 'no_fix_published', last: 'no_fix_published', listed: 'no_fix_published', overlap: 'no_fix_published', both: 'single_entry_upgrade' });
});

test('DFBASE-13: a group with one unfixed finding keeps the unfixed one at no_fix_published and lists what the candidate closes', () => {
  const lock = minimal(), findings = [finding('fix', A, [fixed('1.2.0')]), finding('open', A, [{ lower: '0.1.0', upper: null, upper_kind: null }]), finding('below', A, [{ lower: null, upper: '1.0.9', upper_kind: 'last_affected' }])];
  const plan = planCandidates(lock, findings).occurrences[0]!;
  assert.deepEqual([plan.group, plan.candidate, plan.state, plan.closes], [['fix'], '1.2.0', 'proposed', ['below', 'fix']]);
  assert.deepEqual(candidateRequests(planCandidates(lock, findings)), [{ entry: A, name: 'a', installed: '1.0.0', candidate: '1.2.0' }]);
  // The open advisory still affects 1.2.0, so OSV's answer for the candidate itself makes it invalid for the whole group.
  const affected = facts(lock, findings, { [A]: clear('a', '1.0.0', '1.2.0', { candidate_osv: 'affected' }) });
  assert.deepEqual(classes(affected), { fix: 'manual_fix_selection', open: 'no_fix_published', below: 'no_fix_published' });
  assert.deepEqual(affected.findings[0]!.candidate_reasons, ['candidate_affected']);
  assert.deepEqual(classes(facts(lock, findings, { [A]: clear('a', '1.0.0', '1.2.0') })), { fix: 'single_entry_upgrade', open: 'no_fix_published', below: 'no_fix_published' });
});

test('DFBASE-13: the candidate is the group\'s highest fixed version, valid only outside every member\'s affected range', () => {
  const lock = minimal({}, '^1.0.0');
  const highest = planCandidates(lock, [finding('x', A, [fixed('1.2.0')]), finding('z', A, [fixed('1.5.0')])]).occurrences[0]!;
  assert.deepEqual([highest.candidate, highest.state, highest.closes], ['1.5.0', 'proposed', ['x', 'z']]);
  const inside = [finding('x', A, [fixed('1.2.0')]), finding('z', A, [fixed('1.1.0'), fixed('1.3.0', '1.2.0')])];
  assert.deepEqual([planCandidates(lock, inside).occurrences[0]!.state, planCandidates(lock, inside).occurrences[0]!.closes], ['inside_affected_range', ['x']]);
  assert.deepEqual(classes(facts(lock, inside, { [A]: clear('a', '1.0.0', '1.2.0') })), { x: 'manual_fix_selection', z: 'manual_fix_selection' }, 'evidence cannot rescue an invalid plan');
  const listed = [finding('x', A, [fixed('1.2.0')]), finding('y', A, [fixed('1.1.0')], { affected: { intervals: [fixed('1.1.0')], versions: ['1.2.0'] } })];
  assert.equal(planCandidates(lock, listed).occurrences[0]!.state, 'inside_affected_range');
  const elsewhere = [finding('x', A, [{ lower: '0.5.0', upper: '0.9.0', upper_kind: 'fixed' }, fixed('1.0.0', '1.0.0')])];
  assert.deepEqual([planCandidates(lock, elsewhere).occurrences[0]!.fixed_versions[0]!.fixed_version, planCandidates(lock, elsewhere).occurrences[0]!.state], [null, 'no_fixed_version'],
    'only an interval holding the installed version gives a fixed version, so every candidate is above the installed version');
  const held = [finding('x', A, [fixed('1.2.0')]), finding('h', A, [fixed('1.2.0')], { held: true })];
  assert.equal(planCandidates(lock, held).occurrences[0]!.state, 'occurrence_held');
  assert.deepEqual(classes(facts(lock, held, { [A]: clear('a', '1.0.0', '1.2.0') })), { x: 'manual_fix_selection', h: 'verify_occurrence' }, 'a hold on any finding blocks the occurrence\'s candidate');
  assert.deepEqual(candidateRequests(planCandidates(lock, held)), []);
});

test('DFBASE-13: a candidate that OSV finds affected or held, or whose identity or evidence is missing, is not valid', () => {
  const lock = minimal(), findings = [finding('f', A, [fixed('1.0.5')])];
  const cases: [Partial<DepsOccurrenceEvidence> | null, string[]][] = [[{ candidate_osv: 'affected' }, ['candidate_affected']], [{ candidate_osv: 'held' }, ['candidate_held']],
    [{ candidate_osv: 'unknown' }, ['candidate_osv_unknown']], [{ identity_verified: false }, ['identity_unverified']], [{ identity_verified: false, candidate_osv: 'held' }, ['identity_unverified', 'candidate_held']], [null, ['evidence_missing']]];
  for (const [change, reasons] of cases) {
    const f = facts(lock, findings, change ? { [A]: clear('a', '1.0.0', '1.0.5', change) } : {}).findings[0]!;
    assert.deepEqual([f.class, f.candidate, f.candidate_valid, f.candidate_reasons, f.range_ok, f.edges_unchanged], ['manual_fix_selection', '1.0.5', false, reasons, null, null], JSON.stringify(change));
  }
});

test('DFBASE-13: a nested occurrence has the dependents that resolve to it by npm\'s nearest-ancestor rule', () => {
  const lock = lockOf({ '': { dependencies: { a: '^1.0.0', b: '^1.0.0', d: '^1.0.0' } },
    'node_modules/a': reg('a', '1.0.0', { dependencies: { c: '^1.0.0' } }), 'node_modules/d': reg('d', '1.0.0', { dependencies: { c: '~1.0.0' } }),
    'node_modules/b': reg('b', '1.0.0', { dependencies: { c: '^2.0.0', e: '^1.0.0' } }), 'node_modules/b/node_modules/c': reg('c', '2.0.0'),
    'node_modules/b/node_modules/e': reg('e', '1.0.0', { peerDependencies: { c: '>=2.0.0 <2.1.0' } }), 'node_modules/c': reg('c', '1.0.0') });
  assert.equal(resolveDependency(lock, 'node_modules/a', 'c'), 'node_modules/c');
  assert.equal(resolveDependency(lock, 'node_modules/b', 'c'), 'node_modules/b/node_modules/c');
  assert.equal(resolveDependency(lock, 'node_modules/b/node_modules/e', 'c'), 'node_modules/b/node_modules/c', 'from the enclosing node_modules');
  assert.equal(resolveDependency(lock, '', 'missing'), null);
  assert.deepEqual(dependentsOf(lock, 'node_modules/c'), { dependents: [{ path: 'node_modules/a', kind: 'registry', field: 'dependencies', range: '^1.0.0' }, { path: 'node_modules/d', kind: 'registry', field: 'dependencies', range: '~1.0.0' }], unread: [] });
  assert.deepEqual(dependentsOf(lock, 'node_modules/b/node_modules/c').dependents.map(d => [d.path, d.field]), [['node_modules/b', 'dependencies'], ['node_modules/b/node_modules/e', 'peerDependencies']]);
  const top = 'node_modules/c', nested = 'node_modules/b/node_modules/c';
  const patch = facts(lock, [finding('top', top, [fixed('1.0.5')])], { [top]: clear('c', '1.0.0', '1.0.5') }).findings[0]!;
  assert.deepEqual([patch.class, patch.dependents_total], ['single_entry_upgrade', 2]);
  const minor = facts(lock, [finding('top', top, [fixed('1.1.0')])], { [top]: clear('c', '1.0.0', '1.1.0') }).findings[0]!;
  assert.deepEqual([minor.class, minor.range_ok, minor.blocking_dependents, minor.blocking_total], ['range_change_needed', false, [{ path: 'node_modules/d', field: 'dependencies', range: '~1.0.0' }], 1]);
  const deep = facts(lock, [finding('nested', nested, [fixed('2.1.0')])], { [nested]: clear('c', '2.0.0', '2.1.0') }).findings[0]!;
  assert.deepEqual([deep.class, deep.blocking_dependents.map(d => d.path)], ['range_change_needed', ['node_modules/b/node_modules/e']]);
});

test('DFBASE-13: a workspace folder and the root are dependents, their devDependencies included', () => {
  const lock = lockOf({ '': { name: 'app', workspaces: ['packages/*'], devDependencies: { a: '^1.0.0' } }, 'node_modules/w': { resolved: 'packages/w', link: true },
    'packages/w': { name: 'w', version: '0.1.0', dependencies: { a: '^1.0.0' }, devDependencies: { a: '~1.0.0', b: '^1.0.0' } }, [A]: reg('a', '1.0.0', { dev: true }),
    'node_modules/b': reg('b', '1.0.0', { dependencies: { a: '^1.0.0' }, devDependencies: { a: '^9.0.0' } }), 'packages/w/node_modules/b': reg('b', '2.0.0') });
  assert.deepEqual(dependentsOf(lock, A).dependents.map(d => [d.path, d.kind, d.field, d.range]),
    [['', 'root', 'devDependencies', '^1.0.0'], ['node_modules/b', 'registry', 'dependencies', '^1.0.0'], ['packages/w', 'first_party', 'dependencies', '^1.0.0'], ['packages/w', 'first_party', 'devDependencies', '~1.0.0']],
    'a package inside node_modules does not install its devDependencies');
  assert.equal(resolveDependency(lock, 'packages/w', 'b'), 'packages/w/node_modules/b', 'a workspace resolves from its own node_modules first');
  assert.equal(resolveDependency(lock, 'packages/w', 'a'), A, 'then the root\'s');
  const f = facts(lock, [finding('w', A, [fixed('1.1.0')])], { [A]: clear('a', '1.0.0', '1.1.0') }).findings[0]!;
  assert.deepEqual([f.class, f.dev_only, f.blocking_dependents], ['range_change_needed', true, [{ path: 'packages/w', field: 'devDependencies', range: '~1.0.0' }]]);
});

test('DFBASE-13: a dependent range that is not a semver range, or was not read, needs manual fix selection', () => {
  for (const range of ['git+https://example.test/a.git', 'github:org/a', 'org/a', 'https://example.test/a.tgz', 'file:../a', 'latest', 'npm:other@^1.0.0', 'workspace:*', 'link:../a']) {
    const f = facts(minimal({}, range), [finding('f', A, [fixed('1.0.5')])], { [A]: clear('a', '1.0.0', '1.0.5') }).findings[0]!;
    assert.deepEqual([f.class, f.range_ok, f.range_reasons], ['manual_fix_selection', false, ['dependent_range_not_semver']], range);
  }
  for (const range of ['', '*', 'x', '1', '~1.0.0', '>=1.0.0 <2', '1.x || 2.x', '^1.0.0-0', '=1.0.5', '1.0.0 - 1.0.9'])
    assert.equal(facts(minimal({}, range), [finding('f', A, [fixed('1.0.5')])], { [A]: clear('a', '1.0.0', '1.0.5') }).findings[0]!.class, 'single_entry_upgrade', range);
  const unread = minimal({ 'node_modules/x': reg('x', '1.0.0', { dependencies: 'a@^1' }) });
  const f = facts(unread, [finding('f', A, [fixed('1.0.5')])], { [A]: clear('a', '1.0.0', '1.0.5') }).findings[0]!;
  assert.deepEqual([f.class, f.range_reasons, dependentsOf(unread, A).unread], ['manual_fix_selection', ['dependent_range_unread'], ['node_modules/x']]);
  const nestedUnread = minimal({ 'node_modules/b': reg('b', '1.0.0'), 'node_modules/b/node_modules/y': 'not an entry' });
  assert.deepEqual(dependentsOf(nestedUnread, A).unread, ['node_modules/b/node_modules/y'], 'a held entry with no readable ranges may depend on anything it resolves');
  const rootless = lockOf({ [A]: reg('a', '1.0.0') });
  assert.deepEqual(facts(rootless, [finding('f', A, [fixed('1.0.5')])], { [A]: clear('a', '1.0.0', '1.0.5') }).findings[0]!.range_reasons, ['dependent_range_unread']);
});

test('DFBASE-13: every key in the tree is a dependent at any path length, held ones included; a key that cannot be placed leaves its range unread', () => {
  const ev = { [A]: clear('a', '1.0.0', '1.1.0') }, findings = [finding('f', A, [fixed('1.1.0')])];
  const deep = 'node_modules/p/'.repeat(34) + 'node_modules/consumer';
  assert.ok(deep.length > 500, 'past the evidence path bound');
  const deepLock = minimal({ [deep]: reg('consumer', '1.0.0', { dependencies: { a: '~1.0.0' } }) });
  const deepEntry = deepLock.entries.find(e => e.path === deep)!;
  assert.deepEqual([deepEntry.kind, deepEntry.hold_reason, deepEntry.name], ['held', 'unsupported_entry', 'consumer'], 'held, but still placed in the tree');
  const f = facts(deepLock, findings, ev).findings[0]!;
  assert.deepEqual([f.class, f.range_ok, f.dependents_total, f.blocking_dependents], ['range_change_needed', false, 2, [{ path: deep, field: 'dependencies', range: '~1.0.0' }]]);
  const ownCopy = minimal({ [deep]: reg('consumer', '1.0.0', { dependencies: { a: '~1.0.0' } }), [`${deep}/node_modules/a`]: reg('a', '1.0.9') });
  assert.equal(resolveDependency(ownCopy, deep, 'a'), `${deep}/node_modules/a`, 'a deep copy is installed too');
  assert.equal(facts(ownCopy, findings, ev).findings[0]!.class, 'single_entry_upgrade', 'so the deep consumer is not the top copy\'s dependent');
  const percent = minimal({ 'packages/100%': { name: 'w', devDependencies: { a: '~1.0.0' } } });
  assert.equal(percent.entries.find(e => e.path === 'packages/100%')!.kind, 'held');
  assert.deepEqual(facts(percent, findings, ev).findings[0]!.blocking_dependents, [{ path: 'packages/100%', field: 'devDependencies', range: '~1.0.0' }], 'a folder outside the evidence bounds is still a workspace folder in the tree');
  for (const key of ['node_modules/x//node_modules/y', 'node_modules\\b', 'node_modules/./y', 'packages/../node_modules/y', '..']) {
    const declaring = facts(minimal({ [key]: reg('y', '1.0.0', { dependencies: { a: '~1.0.0' } }) }), findings, ev).findings[0]!;
    assert.deepEqual([declaring.class, declaring.range_reasons], ['manual_fix_selection', ['dependent_range_unread']], key);
    assert.equal(facts(minimal({ [key]: reg('y', '1.0.0', { dependencies: { b: '^1.0.0' } }) }), findings, ev).findings[0]!.class, 'single_entry_upgrade', `${key} declaring only b has no effect`);
    assert.equal(facts(minimal({ [key]: 'unreadable' }), findings, ev).findings[0]!.class, 'manual_fix_selection', `${key} with no readable ranges`);
  }
  const outside = minimal({ 'node_modules/shared': { resolved: '../shared', link: true }, '../shared': { name: 'shared', dependencies: { a: '~1.0.0' } }, '../shared/node_modules/a': reg('a', '1.0.0') });
  assert.equal(resolveDependency(outside, '', 'a'), A);
  assert.deepEqual(dependentsOf(outside, A), { dependents: [{ path: '', kind: 'root', field: 'dependencies', range: '^1.0.0' }], unread: [] }, 'resolution from a file: target outside the lockfile\'s folder never comes back inside');
});

test('DFBASE-13: overrides that are absent pass; unreadable ones, or a key naming the package at any depth, need manual fix selection', () => {
  const lock = minimal(), findings = [finding('f', A, [fixed('1.0.5')])], ev = { [A]: clear('a', '1.0.0', '1.0.5') };
  const run = (overrides: DepsOverridesInput) => facts(lock, findings, ev, overrides).findings[0]!;
  assert.deepEqual([run({ state: 'absent' }).class, run({ state: 'absent' }).range_ok], ['single_entry_upgrade', true]);
  for (const value of [{}, { b: '1.0.0' }, { b: { c: '1.0.0', '.': '2.0.0' } }, { '@s/a': '1.0.0' }, { ab: '1.0.0' }, { 'b@^1': { aa: '1' } }])
    assert.equal(run({ state: 'present', value }).class, 'single_entry_upgrade', JSON.stringify(value));
  for (const value of [{ a: '1.0.5' }, { 'a@^1.0.0': '1.0.5' }, { b: { a: '1.0.5' } }, { b: { c: { 'a@1': { '.': '1.0.5' } } } }, { a: { b: '1.0.0' } }])
    assert.deepEqual([run({ state: 'present', value }).class, run({ state: 'present', value }).range_reasons], ['manual_fix_selection', ['overrides_name_package']], JSON.stringify(value));
  for (const overrides of [{ state: 'unreadable' }, { state: 'present', value: 'a@1' }, { state: 'present', value: null }, { state: 'present', value: [] }, { state: 'present', value: { b: 1 } }] as DepsOverridesInput[])
    assert.deepEqual([run(overrides).class, run(overrides).range_reasons], ['manual_fix_selection', ['overrides_unreadable']], JSON.stringify(overrides));
  const scoped = lockOf({ '': { dependencies: { '@s/a': '^1.0.0' } }, 'node_modules/@s/a': reg('@s/a', '1.0.0') });
  const scopedFacts = facts(scoped, [finding('f', 'node_modules/@s/a', [fixed('1.0.5')])], { 'node_modules/@s/a': clear('@s/a', '1.0.0', '1.0.5') }, { state: 'present', value: { x: { '@s/a@^1': '1.0.5' } } });
  assert.equal(scopedFacts.findings[0]!.class, 'manual_fix_selection');
  let deep: Record<string, unknown> = { a: '1.0.5' };
  for (let i = 0; i < 20000; i++) deep = { [`p${i}`]: deep };
  assert.equal(run({ state: 'present', value: deep }).class, 'manual_fix_selection', 'deep nesting is walked without recursion');
});

test('DFBASE-13: edges compare the two registry manifests: dependency, optional, peer and bundled', () => {
  const lock = minimal({ [A]: reg('a', '1.0.0', { dependencies: { b: '^1.0.0' }, optionalDependencies: { o: '^1.0.0' } }) }), findings = [finding('f', A, [fixed('1.0.5')])];
  // The registry folds optional dependencies into `dependencies`; the lock entry does not. Only manifests are compared.
  const base = { dependencies: { b: '^1.0.0', o: '^1.0.0' }, optionalDependencies: { o: '^1.0.0' } };
  const run = (installed: Record<string, unknown>, candidate: Record<string, unknown>) => facts(lock, findings, { [A]: clear('a', '1.0.0', '1.0.5', { installed_manifest: manifest('a', '1.0.0', installed), candidate_manifest: manifest('a', '1.0.5', candidate) }) }).findings[0]!;
  assert.deepEqual([run(base, { ...base, description: 'changed prose', scripts: { test: 'x' } }).edges_unchanged, run(base, base).class], [true, 'single_entry_upgrade']);
  assert.deepEqual([run(base, { dependencies: { o: '^1.0.0', b: '^1.0.0' }, optionalDependencies: { o: '^1.0.0' } }).edges_unchanged], [true], 'key order is not a change');
  for (const candidate of [{ ...base, dependencies: { b: '^1.1.0', o: '^1.0.0' } }, { ...base, dependencies: { ...base.dependencies, n: '^1.0.0' } }, { ...base, optionalDependencies: {} },
    { ...base, peerDependencies: { p: '^1.0.0' } }, { ...base, bundleDependencies: ['b'] }, { ...base, bundledDependencies: true }])
    assert.deepEqual([run(base, candidate).edges_unchanged, run(base, candidate).class], [false, 'multi_entry_upgrade'], JSON.stringify(candidate));
  assert.equal(run(base, { ...base, peerDependencies: {}, peerDependenciesMeta: {} }).edges_unchanged, true, 'empty peer fields are no edges');
  const peer = { ...base, peerDependencies: { p: '^1.0.0' } };
  assert.equal(run(peer, { ...peer, peerDependenciesMeta: { p: { optional: true } } }).edges_unchanged, false, 'an optional peer is a different edge');
  assert.equal(run({ ...base, bundleDependencies: ['b', 'o'] }, { ...base, bundledDependencies: ['o', 'b'] }).edges_unchanged, true);
  assert.equal(run({ ...base, bundleDependencies: true }, { ...base, bundleDependencies: ['b', 'o'] }).edges_unchanged, true);
  for (const [installed, candidate] of [[base, { ...base, dependencies: 'b' }], [base, { ...base, bundleDependencies: 'b' }], [{ ...base, peerDependenciesMeta: [] }, base]] as const)
    assert.deepEqual([run(installed, candidate).edges_unchanged, run(installed, candidate).class], [null, 'multi_entry_upgrade'], 'unread edges are not unchanged');
  for (const ev of [{ installed_manifest: null }, { candidate_manifest: manifest('a', '1.0.6') }, { installed_manifest: manifest('b', '1.0.0') }]) {
    const f = facts(lock, findings, { [A]: clear('a', '1.0.0', '1.0.5', ev) }).findings[0]!;
    assert.deepEqual([f.edges_unchanged, f.class], [null, 'multi_entry_upgrade'], `${JSON.stringify(ev)}: only the expected versions' manifests count`);
  }
});

test('DFBASE-13: lockfile v2 never yields single_entry_upgrade; the same facts give multi_entry_upgrade', () => {
  for (const v of [2, 3]) {
    const result = facts(minimal({}, '^1.0.0', v), [finding('f', A, [fixed('1.0.5')])], { [A]: clear('a', '1.0.0', '1.0.5') });
    assert.deepEqual([result.lockfile_version, result.findings[0]!.class, result.findings[0]!.range_ok, result.findings[0]!.edges_unchanged], [v, v === 2 ? 'multi_entry_upgrade' : 'single_entry_upgrade', true, true]);
  }
  assert.equal(facts(minimal({}, '~1.0.0', 2), [finding('f', A, [fixed('1.1.0')])], { [A]: clear('a', '1.0.0', '1.1.0') }).findings[0]!.class, 'range_change_needed', 'earlier classes are unchanged under v2');
});

test('DFBASE-13: prerelease versions follow semver precedence in advisories and npm\'s prerelease rule in ranges', () => {
  const pre = (rootRange: string, extra: Record<string, unknown> = {}) => lockOf({ '': { dependencies: { a: rootRange } }, [A]: reg('a', '2.0.0-beta.1'), ...extra });
  const findings = [finding('f', A, [fixed('2.0.0-beta.3')])], ev = { [A]: clear('a', '2.0.0-beta.1', '2.0.0-beta.3') };
  assert.deepEqual([facts(pre('^2.0.0-beta.1'), findings, ev).findings[0]!.fixed_version, facts(pre('^2.0.0-beta.1'), findings, ev).findings[0]!.class], ['2.0.0-beta.3', 'single_entry_upgrade']);
  assert.equal(facts(pre('*'), findings, ev).findings[0]!.class, 'single_entry_upgrade', 'npm treats * as any version');
  assert.equal(facts(pre('>=1.0.0'), findings, ev).findings[0]!.class, 'range_change_needed', 'a range without a prerelease on 2.0.0 excludes it');
  const pair = [finding('x', A, [fixed('2.0.0-rc.1')]), finding('y', A, [fixed('2.0.0-beta.2'), { lower: '2.0.0-rc.0', upper: '2.0.0', upper_kind: 'fixed' }])];
  assert.deepEqual([planCandidates(pre('^2.0.0-beta.1'), pair).occurrences[0]!.candidate, planCandidates(pre('^2.0.0-beta.1'), pair).occurrences[0]!.state], ['2.0.0-rc.1', 'inside_affected_range'], '2.0.0-rc.1 precedes 2.0.0');
  assert.equal(planCandidates(pre('^2.0.0-beta.1'), [finding('b', A, [fixed('2.0.0-beta.3+build.7')])]).occurrences[0]!.candidate, '2.0.0-beta.3+build.7');
});

test('DFBASE-13: range_change_needed names up to 10 blocking dependents and their total', () => {
  const packages: Record<string, unknown> = { '': { dependencies: { a: '^1.0.0' } }, [A]: reg('a', '1.0.0') };
  for (let i = 0; i < 12; i++) packages[`node_modules/d${String(i).padStart(2, '0')}`] = reg(`d${String(i).padStart(2, '0')}`, '1.0.0', { dependencies: { a: '~1.0.0' }, peerDependencies: i === 3 ? { a: '1.0.x' } : {} });
  const f = facts(lockOf(packages), [finding('f', A, [fixed('1.1.0')])], { [A]: clear('a', '1.0.0', '1.1.0') }).findings[0]!;
  assert.deepEqual([f.class, f.blocking_total, f.blocking_dependents.length, f.dependents_total], ['range_change_needed', 13, 10, 14]);
  assert.deepEqual(f.blocking_dependents.slice(0, 5).map(d => `${d.path}:${d.field}`), ['node_modules/d00:dependencies', 'node_modules/d01:dependencies', 'node_modules/d02:dependencies', 'node_modules/d03:dependencies', 'node_modules/d03:peerDependencies']);
});

test('DFBASE-13: facts are deterministic, the plan must be the findings\' own plan, and bad input is refused', () => {
  const lock = lockOf({ '': { dependencies: { a: '^1.0.0', b: '^1.0.0' } }, [A]: reg('a', '1.0.0'), 'node_modules/b': reg('b', '1.0.0') });
  const findings = [finding('f2', 'node_modules/b', [fixed('1.0.2')]), finding('f1', A, [fixed('1.0.5')]), finding('f3', A, [fixed('1.0.3')])];
  const ev = { [A]: clear('a', '1.0.0', '1.0.5'), 'node_modules/b': clear('b', '1.0.0', '1.0.2') };
  const once = facts(lock, findings, ev), again = facts(lock, [...findings].reverse(), ev);
  assert.deepEqual(once.findings.map(f => f.finding_id), ['f2', 'f1', 'f3'], 'facts follow the input order');
  assert.deepEqual([...again.findings].reverse(), once.findings);
  assert.deepEqual(planCandidates(lock, findings), planCandidates(lock, [...findings].reverse()));
  const plan = planCandidates(lock, findings);
  assert.throws(() => classify(lock, absent, findings, { ...plan, occurrences: plan.occurrences.map(o => ({ ...o, candidate: '9.9.9' })) }, ev), /deps_facts_plan_mismatch/);
  assert.throws(() => classify(lock, absent, findings.slice(1), plan, ev), /deps_facts_plan_mismatch/);
  assert.deepEqual(classify(lock, absent, findings, JSON.parse(JSON.stringify(plan)), JSON.parse(JSON.stringify(ev))), once, 'plan and evidence survive a worker boundary');
  assert.throws(() => planCandidates(lock, [finding('x', 'node_modules/none', [fixed('1.0.1')])]), /deps_facts_unknown_entry/);
  assert.throws(() => planCandidates(lock, [finding('x', A, [fixed('1.0.1')]), finding('x', A, [fixed('1.0.2')])]), /deps_facts_duplicate_finding/);
  assert.throws(() => planCandidates(lock, [finding('x', A, [{ lower: null, upper: '1.0.1', upper_kind: null }])]));
  assert.throws(() => planCandidates(lock, [finding('x', A, [fixed('not-a-version')])]));
  assert.throws(() => planCandidates(parseDepsLock('{'), []), /deps_lock_not_parsed/);
  assert.throws(() => dependentsOf(lock, 'node_modules/none'), /deps_lock_unknown_entry/);
});
