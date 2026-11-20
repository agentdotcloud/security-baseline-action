// DFRPT-17, 18, 19, 21, 22: a local document, built the way an outside producer builds one: from this package's entry
// point and nothing else. The shape follows `secure`'s report: a dependency finding, a code finding read from a working
// tree, a result its second pass refuted, a merged duplicate, and Dependabot not consulted.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as checks from '../src/index.ts';
import { canonicalJson, compareSourceUnion, observationKey, occurrenceKey, parseLocalSecurityReport, parseSecurityReport, reportHash, sealReport, selfSourceComponent, treeDigest,
  type LocalReportObservation, type SecurityReportLocal } from '../src/index.ts';

const TIME = '2026-11-12T18:00:00Z', COMMIT = 'a'.repeat(40), BLOB = 'b'.repeat(40), LOCK = 'package-lock.json', SERVER = 'server.mjs';
const FILES = [{ path: SERVER, sha256: reportHash('server bytes') }, { path: LOCK, sha256: reportHash('lock bytes') }];
type Snapshot = SecurityReportLocal['snapshot'];
type Unavailable = SecurityReportLocal['unavailable'];
const scopes = [{ scope_id: 'repo', service: 'repository', paths: [LOCK, SERVER] }], tree = (dirty: boolean, base_sha: string | null) => ({ digest: treeDigest(FILES), dirty, base_sha });
// The four ways DFRPT-17 gives for a producer that cannot name an importable snapshot.
const DIRTY: [Snapshot, Unavailable] = [{ target_id: null, repository_id: null, repository: null, sha: null, scopes, tree: tree(true, COMMIT) },
  [{ field: 'snapshot.target_id', reason: 'no_repository_identity' }, { field: 'snapshot.repository_id', reason: 'no_repository_identity' }, { field: 'snapshot.repository', reason: 'no_repository_identity' }, { field: 'snapshot.sha', reason: 'dirty_tree' }]];
const NO_COMMIT: [Snapshot, Unavailable] = [{ ...DIRTY[0], tree: tree(true, null) }, [...DIRTY[1].slice(0, 3), { field: 'snapshot.sha', reason: 'not_a_commit' }, { field: 'snapshot.tree.base_sha', reason: 'not_a_commit' }]];
const NO_IDENTITY: [Snapshot, Unavailable] = [{ ...DIRTY[0], sha: COMMIT, tree: tree(false, COMMIT) }, DIRTY[1].slice(0, 3)];
const NO_CHAIN: [Snapshot, Unavailable] = [{ target_id: 'github', repository_id: '42', repository: 'acme/app', sha: COMMIT, scopes, tree: tree(false, COMMIT) }, []];

const dependency = { kind: 'dependency' as const, ecosystem: 'npm' as const, package: 'a', version: '1.0.0', manifest: LOCK, entry: 'node_modules/a' };
/** A code occurrence read from the working tree: no blob, the file's content hash instead. Given a blob, it carries no content hash. */
function code(extra: Record<string, unknown> = {}) {
  const o: { kind: 'code'; rule: string; rule_version: string; path: string; git_blob: string | null; content_sha256?: string; start_line: number; end_line: number; fingerprint: string } = { kind: 'code', rule: 'secure.read.path-traversal', rule_version: '1', path: SERVER,
    git_blob: null, content_sha256: FILES[0]!.sha256, start_line: 12, end_line: 14, fingerprint: 'join(root, name)', ...extra };
  if (o.git_blob !== null) delete o.content_sha256;
  return o;
}
type Occurrence = Parameters<typeof occurrenceKey>[0];
const observation = (observation_id: string, source_id: string, occurrence: Occurrence): LocalReportObservation => ({ kind: 'source_observation', observation_id, source_namespace: 'summation.secure', source_id, source_revision_digest: reportHash(source_id),
  scope_id: 'repo', occurrence: { ...occurrence, key: occurrenceKey(occurrence) } as never, evidence_ids: ['ev-1'], observed_at: TIME, retrieved_at: TIME, lifecycle: 'open', severity: { original: '', normalized: 'unknown' }, confidence: { original: '', normalized: 'unknown' },
  provenance_claim: 'secure\'s own check' });
const neutral = (dependencyStatus: 'unknown' | 'not_applicable') => ({ provenance: 'unverified' as const, validity: 'unreviewed' as const, dependency: dependencyStatus, currentness: 'unknown' as const, exposure: 'unverified' as const,
  breaker: 'not_attempted' as const, assessor: 'secure', evidence_ids: [], profile_digest: null, holds: [] });
const CONFIG = { engines: { reader: 'codex' }, checks: ['static.deps', 'static.read'], local_exec: false, budget_usd: 5 };

/** A whole local document, sealed. `change` edits it before the digest is taken, so each test states one difference. */
function local(variant: [Snapshot, Unavailable] = DIRTY, change: (d: SecurityReportLocal) => void = () => {}): SecurityReportLocal {
  const [snapshot, unavailable] = structuredClone(variant);
  const at = snapshot.sha !== null ? { git_blob: BLOB } : {};
  const dep = observation('obs-dep', 'GHSA-aaaa-aaaa-aaaa', dependency), read = observation('obs-read', 'read-1', code(at)), merged = observation('obs-merged', 'read-2', code({ ...at, start_line: 13 })), refuted = observation('obs-refuted', 'read-3', code({ ...at, start_line: 40, end_line: 41 }));
  const component = (id: string, read_id: string, observations: LocalReportObservation[]) => selfSourceComponent({ id, version: '1', configuration_digest: reportHash(CONFIG), scope_digest: reportHash(scopes), source_revision: read_id, retrieved_at: TIME, required: true, read_id, observations, snapshot });
  const empty = reportHash([]);
  const d: SecurityReportLocal = { document_type: 'defensive-security-report-local', schema_version: '1.0', producer: { namespace: 'summation.secure', product: 'secure', version: '0.3.0' }, report_id: 'scan-1', generated_at: TIME, content_digest: '0'.repeat(64),
    snapshot, unavailable, profile: { id: 'secure-default', revision: 1, digest: reportHash(CONFIG) },
    coverage: { state: 'complete', union_status: 'proven', components: [component('static.deps', 'read-deps-1', [dep]), component('static.read', 'read-code-1', [read, merged, refuted]),
      // DFRPT-20: `secure` reads no alerts, and says so.
      { id: 'source.github-dependabot', version: '1', configuration_digest: empty, scope_digest: reportHash(scopes), source_revision: 'none', retrieved_at: TIME, state: 'not_selected', required: false, reasons: ['alerts_not_read'], pagination_complete: false, checkpoint: null,
        observed_count: 0, mapped_count: 0, missing_count: 0, observed_set_digest: empty, mapped_set_digest: empty, mapped_observation_keys: [], baseline_receipt: null }] },
    observations: [dep, read, merged, refuted],
    findings: [
      { finding_id: 'F-1', observation_ids: ['obs-dep'], scope_ids: ['repo'], occurrence_keys: [dep.kind === 'source_observation' ? dep.occurrence.key : ''], aliases: ['GHSA-aaaa-aaaa-aaaa'], title: 'a 1.0.0 has a known advisory', summary: 'From secure\'s npm parsing.', assessment: neutral('unknown'), recommendation_ids: [], reproduction_receipt_ids: [] },
      { finding_id: 'F-2', observation_ids: ['obs-read', 'obs-merged'], scope_ids: ['repo'], occurrence_keys: [read, merged].map(o => o.kind === 'source_observation' ? o.occurrence.key : ''), aliases: [], title: 'Path traversal in the download handler', summary: 'The file name is joined to the root unchecked.', assessment: neutral('not_applicable'), recommendation_ids: [], reproduction_receipt_ids: [] },
    ],
    // DFRPT-19: nothing the reads returned is dropped. The duplicate is grouped; the result the skeptic refuted stays, refuted.
    dispositions: [{ observation_id: 'obs-merged', kind: 'grouped', reason: 'same_defect_site', attribution: 'secure', evidence_ids: [], finding_id: 'F-2', quarantine_receipt_id: null },
      { observation_id: 'obs-refuted', kind: 'refuted', reason: 'skeptic_refuted', attribution: 'secure', evidence_ids: [], finding_id: null, quarantine_receipt_id: null }],
    evidence: [{ evidence_id: 'ev-1', sha256: reportHash('scan ledger'), bytes: 100, media_type: 'application/json', classification: 'restricted', kind: 'scan-ledger', origin: 'secure run ledger', captured_at: TIME, artifact_id: null, git: null }],
    recommendations: [] };
  change(d);
  return sealReport(d);
}
const parse = (d: SecurityReportLocal) => parseLocalSecurityReport(canonicalJson(d));
const refused = (d: SecurityReportLocal | Record<string, unknown>, code: RegExp) => assert.throws(() => parseLocalSecurityReport(canonicalJson(d)), code);
const sourceOf = (d: SecurityReportLocal, id: string) => { const o = d.observations.find(o => o.observation_id === id)!; if (o.kind !== 'source_observation') throw Error('fixture'); return o; };

test('DFRPT-17: a dirty tree, a tree with no commit, a repository with no numeric identity and a producer with no revision chain each validate with the matching unavailable entries', () => {
  for (const [name, variant] of Object.entries({ DIRTY, NO_COMMIT, NO_IDENTITY, NO_CHAIN })) {
    const d = parse(local(variant));
    assert.equal(d.document_type, 'defensive-security-report-local', name);
    assert.deepEqual(d.unavailable.map(u => u.field).sort(), Object.entries({ 'snapshot.target_id': d.snapshot.target_id, 'snapshot.repository_id': d.snapshot.repository_id, 'snapshot.repository': d.snapshot.repository, 'snapshot.sha': d.snapshot.sha,
      'snapshot.tree.base_sha': d.snapshot.tree.base_sha }).filter(([, v]) => v === null).map(([field]) => field).sort(), `${name}: a snapshot field is null if and only if it is listed`);
    assert.deepEqual([d.coverage.state, d.coverage.union_status], ['complete', 'proven'], name);
    assert.equal(d.content_digest, sealReport(d).content_digest, 'the digest is computed the same way as a report\'s');
  }
  // A commit this contract's 40-hex SHA cannot hold: neither it nor the base is named, clean or not.
  const sha256Repository: [Snapshot, Unavailable] = [{ ...DIRTY[0], tree: tree(false, null) }, [...DIRTY[1].slice(0, 3), { field: 'snapshot.sha', reason: 'unsupported_object_format' }, { field: 'snapshot.tree.base_sha', reason: 'unsupported_object_format' }]];
  assert.equal(parse(local(sha256Repository)).snapshot.tree.dirty, false);
});

test('DFRPT-17: a null field with no entry, an entry for a field with a value, a reason the field cannot have and a tree that disagrees are refused', () => {
  refused(local(DIRTY, d => { d.unavailable = d.unavailable.slice(1); }), /report_local_unavailable/);
  refused(local(NO_CHAIN, d => { d.unavailable = [{ field: 'snapshot.sha', reason: 'dirty_tree' }]; }), /report_local_unavailable/);
  refused(local(DIRTY, d => { d.unavailable[3] = { field: 'snapshot.sha', reason: 'no_repository_identity' }; }), /report_local_unavailable/);
  refused(local(NO_COMMIT, d => { d.unavailable[4] = { field: 'snapshot.tree.base_sha', reason: 'dirty_tree' as never }; }), /report_local_unavailable|invalid/i);
  refused(local(DIRTY, d => { d.unavailable.push(d.unavailable[0]!); }), /report_duplicate_id/);
  refused(local(DIRTY, d => { d.unavailable[0] = { field: 'snapshot.scopes' as never, reason: 'no_repository_identity' }; }), /invalid/i);
  // The tree must agree with what is and is not named.
  refused(local(NO_IDENTITY, d => { d.snapshot.tree.dirty = true; }), /report_local_tree/);
  refused(local(NO_IDENTITY, d => { d.snapshot.tree.base_sha = 'c'.repeat(40); }), /report_local_tree/);
  refused(local(DIRTY, d => { d.snapshot.tree.dirty = false; }), /report_local_tree/);
  refused(local(NO_COMMIT, d => { d.snapshot.tree.dirty = false; }), /report_local_tree/);
  refused(local(DIRTY, d => { d.unavailable[3] = { field: 'snapshot.sha', reason: 'not_a_commit' }; }), /report_local_tree/);
  const { tree: _tree, ...treeless } = local().snapshot;
  refused({ ...local(), snapshot: treeless }, /invalid/i);
});

test('DFRPT-17: a local document has no revision, no previous digest and no part, and no other field is relaxed', () => {
  const d = local();
  for (const extra of [{ revision: 1 }, { previous_digest: null }, { part_of: { report_id: 'root', revision: 1, part_id: 'a' } }]) refused(sealReport({ ...d, ...extra } as never), /unrecognized/i);
  const { unavailable: _unavailable, ...unlisted } = d;
  refused(sealReport(unlisted as never), /invalid/i);
  const { profile: _profile, ...profileless } = d;
  refused(sealReport(profileless as never), /invalid/i);
  refused(local(DIRTY, d => { d.evidence[0]!.git = { sha: null as never, blob: BLOB, path: SERVER }; }), /invalid/i);
  refused({ ...d, content_digest: '1'.repeat(64) }, /report_content_digest/);
  // DFRPT-8 and DFRPT-15 apply as they do to a report.
  refused(local(DIRTY, d => { d.findings[1]!.summary = 'api_key=sk_live_0123456789abcdef0123'; }), /credential-shaped/);
  refused(local(DIRTY, d => { d.evidence = Array.from({ length: 1001 }, (_, i) => ({ ...d.evidence[0]!, evidence_id: `ev-${i}` })); }), /too_big|invalid/i);
});

test('DFRPT-17, DFRPT-21: a code occurrence has no Git blob only where no commit is named, and then derives its key from the cited file\'s content hash', () => {
  const d = parse(local()), read = sourceOf(d, 'obs-read');
  assert.ok(read.occurrence.kind === 'code' && read.occurrence.git_blob === null);
  assert.equal(read.occurrence.key, reportHash(['code', 'secure.read.path-traversal', '1', SERVER, FILES[0]!.sha256, 12, 14, 'join(root, name)']), 'the content hash stands where the blob would');
  assert.notEqual(read.occurrence.key, occurrenceKey(code({ git_blob: BLOB })));
  const edit = (change: (o: Record<string, unknown>) => void, rekey = true) => (d: SecurityReportLocal) => {
    const o = sourceOf(d, 'obs-refuted'), before = o.occurrence.key;
    change(o.occurrence as never);
    if (rekey) { o.occurrence.key = occurrenceKey(o.occurrence); const c = d.coverage.components[1]!, keys = ['obs-read', 'obs-merged', 'obs-refuted'].map(id => observationKey(sourceOf(d, id), d.snapshot)).sort(); Object.assign(c, { mapped_observation_keys: keys, observed_set_digest: reportHash(keys), mapped_set_digest: reportHash(keys) }); }
    assert.ok(before);
  };
  // No blob and no content hash; both; and no blob although a commit is named.
  assert.throws(() => local(DIRTY, edit(o => { delete o.content_sha256; })), /report_local_occurrence/);
  refused(local(DIRTY, edit(o => { delete o.content_sha256; }, false)), /report_local_occurrence/);
  refused(local(DIRTY, edit(o => { o.git_blob = BLOB; })), /report_local_occurrence/);
  refused(local(NO_IDENTITY, edit(o => { o.git_blob = null; o.content_sha256 = FILES[0]!.sha256; })), /report_local_occurrence/);
  // A dirty tree may still cite a blob for a file it can name one for.
  assert.ok(parse(local(DIRTY, edit(o => { o.git_blob = BLOB; delete o.content_sha256; }))));
  // DFRPT-21: a key that is not the derived one is refused, whichever coordinate moved.
  refused(local(DIRTY, edit(o => { o.content_sha256 = reportHash('other bytes'); }, false)), /report_occurrence_key/);
  refused(local(DIRTY, d => { sourceOf(d, 'obs-dep').occurrence.key = reportHash('chosen'); }), /report_occurrence_key/);
});

test('DFRPT-17: a local observation key never equals the importable key for the same observation, and every importer refuses the type before reading it', () => {
  const d = local(NO_CHAIN), o = sourceOf(d, 'obs-dep'), { tree: _tree, ...importable } = d.snapshot;
  assert.notEqual(observationKey(o, d.snapshot), observationKey(o, importable as never), 'the same repository, commit and observation');
  assert.equal(observationKey(o, d.snapshot), reportHash([o.source_namespace, o.source_id, o.source_revision_digest, 'local', d.snapshot.tree.digest, o.occurrence.key]));
  assert.throws(() => parseSecurityReport(canonicalJson(d), ['summation.secure']), /report_local_not_importable/);
  // Refused by type, before the schema, the producer list or the digest is looked at.
  assert.throws(() => parseSecurityReport(JSON.stringify({ document_type: 'defensive-security-report-local', anything: 'at all' }), []), /report_local_not_importable/);
  // It is never upgraded: relabelled as a report, the same bytes do not parse as one.
  assert.throws(() => parseSecurityReport(canonicalJson(sealReport({ ...d, document_type: 'defensive-security-report' } as never)), ['summation.secure']));
  assert.throws(() => parseLocalSecurityReport(canonicalJson({ ...d, document_type: 'defensive-security-report' })), /report_not_local/);
});

test('DFRPT-18: neutral values need no evidence and no profile digest; not_applicable is neutral only off a dependency occurrence; every other value is a claim', () => {
  const d = parse(local());
  assert.deepEqual(d.findings.map(f => [f.assessment.dependency, f.assessment.evidence_ids.length, f.assessment.profile_digest]), [['unknown', 0, null], ['not_applicable', 0, null]]);
  assert.ok(parse(local(DIRTY, d => { d.findings[1]!.assessment.dependency = 'unknown'; })), 'unknown stays neutral on every finding');
  refused(local(DIRTY, d => { d.findings[0]!.assessment.dependency = 'not_applicable'; }), /report_assessment_dependency/);
  // A claim names evidence and carries the document's own profile digest.
  for (const claim of [{ currentness: 'current' }, { exposure: 'possible' }, { validity: 'supported' }, { dependency: 'affected' }, { breaker: 'not_reproduced' }] as const) {
    refused(local(DIRTY, d => { Object.assign(d.findings[0]!.assessment, claim); }), /report_assessment_evidence/);
    refused(local(DIRTY, d => { Object.assign(d.findings[0]!.assessment, claim, { evidence_ids: ['ev-1'] }); }), /report_assessment_evidence/);
    refused(local(DIRTY, d => { Object.assign(d.findings[0]!.assessment, claim, { evidence_ids: ['ev-1'], profile_digest: reportHash('another profile') }); }), /report_assessment_profile/);
    assert.ok(parse(local(DIRTY, d => { Object.assign(d.findings[0]!.assessment, claim, { evidence_ids: ['ev-1'], profile_digest: d.profile.digest }); })));
  }
  // The producer's profile is its own declared configuration; nothing has to admit it for a local document.
  assert.equal(d.profile.digest, reportHash(CONFIG));
});

test('DFRPT-19: a producer that is its own only source states proven with its own reads as baseline receipts, and a dropped result leaves it unproven', () => {
  const d = parse(local());
  assert.deepEqual(d.coverage.components.map(c => [c.id, c.state, c.baseline_receipt, c.observed_count, c.missing_count]), [['static.deps', 'complete', 'read-deps-1', 1, 0], ['static.read', 'complete', 'read-code-1', 3, 0], ['source.github-dependabot', 'not_selected', null, 0, 0]]);
  assert.deepEqual(d.dispositions.map(x => x.kind), ['grouped', 'refuted'], 'the merged duplicate and the refuted result are still observations');
  // The refuted result left out of the document while its read still counts it.
  const drop = (d: SecurityReportLocal) => { d.observations = d.observations.filter(o => o.observation_id !== 'obs-refuted'); d.dispositions = d.dispositions.slice(0, 1); };
  refused(local(DIRTY, drop), /report_coverage_members/);
  // Left out and not counted either: the document cannot show it, so the read's receipt does. A host comparing the read finds the member missing.
  const hidden = local(DIRTY, d => { drop(d); d.coverage.components[1] = selfSourceComponent({ ...d.coverage.components[1]!, read_id: 'read-code-1', observations: d.observations.slice(1), snapshot: d.snapshot }); });
  assert.ok(parse(hidden), 'as under DFRPT-6, the producer\'s proven is a claim until a host validates the receipts');
  const expected = hidden.coverage.components.slice(0, 2).map(c => ({ component_id: c.id, scope_digest: c.scope_digest, configuration_digest: c.configuration_digest }));
  const baselines = (code: LocalReportObservation[]) => [{ component_id: 'static.deps', receipt_id: 'read-deps-1', observations: d.observations.slice(0, 1) }, { component_id: 'static.read', receipt_id: 'read-code-1', observations: code }].map((b, i) => ({ ...b, snapshot_digest: reportHash(d.snapshot),
    scope_digest: expected[i]!.scope_digest, configuration_digest: expected[i]!.configuration_digest, state: 'complete' as const, pagination_complete: true }));
  const read = d.observations.slice(1);
  assert.equal(compareSourceUnion(hidden.snapshot, expected, baselines(read), hidden.observations).status, 'failed');
  assert.equal(compareSourceUnion(hidden.snapshot, expected, baselines(read), hidden.observations).missing.length, 1);
  // The same result kept, as a refuted disposition: proven.
  assert.equal(compareSourceUnion(d.snapshot, expected, baselines(read), d.observations).status, 'proven');
  // An observation in the document that nothing maps is refused whatever the coverage says.
  refused(local(DIRTY, d => { d.dispositions = d.dispositions.slice(0, 1); }), /report_unmapped_observation/);
});

test('DFRPT-17: the tree digest is over the sorted paths and content hashes of the files read', () => {
  assert.equal(treeDigest(FILES), reportHash([[LOCK, FILES[1]!.sha256], [SERVER, FILES[0]!.sha256]]));
  assert.equal(treeDigest([...FILES].reverse()), treeDigest(FILES), 'the order files were read in does not matter');
  assert.notEqual(treeDigest([{ ...FILES[0]!, sha256: reportHash('edited') }, FILES[1]!]), treeDigest(FILES));
  assert.equal(treeDigest([]), reportHash([]));
  assert.throws(() => treeDigest([FILES[0]!, FILES[0]!]), /report_duplicate_id/);
  assert.throws(() => treeDigest([{ path: '../outside', sha256: FILES[0]!.sha256 }]));
});

// A file name Git allows and a URL would read as an encoded space.
const EVIDENCE = 'docs/4k%20monitor.evidence.json', EVIDENCE_HASH = reportHash('evidence bytes');
/**
 * The document for a tree that also holds `path`: named in the scope and cited by the refuted code observation, by blob
 * where a commit is named and by content hash where none is. Coverage is restated, since every local key moves with the tree digest.
 */
const withFile = (path: string) => (d: SecurityReportLocal) => {
  d.snapshot.scopes[0]!.paths.push(path);
  d.snapshot.tree.digest = treeDigest([...FILES, { path, sha256: EVIDENCE_HASH }]);
  const cited = sourceOf(d, 'obs-refuted');
  Object.assign(cited.occurrence, { path, ...d.snapshot.sha === null ? { content_sha256: EVIDENCE_HASH } : {} });
  cited.occurrence.key = occurrenceKey(cited.occurrence);
  const component = (i: number, read_id: string, ids: string[]) => { d.coverage.components[i] = selfSourceComponent({ ...d.coverage.components[i]!, read_id, observations: ids.map(id => sourceOf(d, id)), snapshot: d.snapshot }); };
  component(0, 'read-deps-1', ['obs-dep']); component(1, 'read-code-1', ['obs-read', 'obs-merged', 'obs-refuted']);
};

test('DFRPT-1, DFRPT-17: a tree with a `%` in a file name gets a digest, and `a%2fb` and `a/b` are different paths with different digests', () => {
  assert.equal(treeDigest([...FILES, { path: EVIDENCE, sha256: EVIDENCE_HASH }]), reportHash([[EVIDENCE, EVIDENCE_HASH], [LOCK, FILES[1]!.sha256], [SERVER, FILES[0]!.sha256]]), 'the path is digested as written');
  assert.notEqual(treeDigest([{ path: EVIDENCE, sha256: EVIDENCE_HASH }]), treeDigest([{ path: 'docs/4k monitor.evidence.json', sha256: EVIDENCE_HASH }]), 'never percent-decoded');
  const digests = ['a%2fb', 'a%2Fb', 'a/b'].map(path => treeDigest([{ path, sha256: EVIDENCE_HASH }]));
  assert.equal(new Set(digests).size, 3);
  // Two files in one tree, not one file named twice.
  assert.equal(treeDigest([{ path: 'a/b', sha256: EVIDENCE_HASH }, { path: 'a%2fb', sha256: EVIDENCE_HASH }]), reportHash([['a%2fb', EVIDENCE_HASH], ['a/b', EVIDENCE_HASH]]));
});

test('DFRPT-1, DFRPT-17, DFRPT-21: a local document validates with a scope path and a code occurrence path that have `%` in them, and the scope match is on the literal path', () => {
  const d = parse(local(DIRTY, withFile(EVIDENCE))), cited = sourceOf(d, 'obs-refuted');
  assert.deepEqual(d.snapshot.scopes[0]!.paths, [LOCK, SERVER, EVIDENCE]);
  assert.ok(cited.occurrence.kind === 'code' && cited.occurrence.path === EVIDENCE);
  assert.equal(cited.occurrence.key, reportHash(['code', 'secure.read.path-traversal', '1', EVIDENCE, EVIDENCE_HASH, 40, 41, 'join(root, name)']), 'the key is derived from the path as written');
  assert.deepEqual([d.coverage.state, d.coverage.union_status], ['complete', 'proven']);
  const committed = sourceOf(parse(local(NO_IDENTITY, withFile(EVIDENCE))), 'obs-refuted').occurrence;
  assert.ok(committed.kind === 'code' && committed.path === EVIDENCE && committed.git_blob === BLOB, 'and at a named commit, citing a blob');
  // The scope names the encoded-looking file; an occurrence at the decoded path, or at another spelling, is outside it.
  for (const other of ['docs/4k monitor.evidence.json', 'docs/4k%2520monitor.evidence.json', 'docs/4K%20monitor.evidence.json'])
    refused(local(DIRTY, d => { withFile(EVIDENCE)(d); const o = sourceOf(d, 'obs-refuted'); Object.assign(o.occurrence, { path: other }); o.occurrence.key = occurrenceKey(o.occurrence); }), /report_scope/);
});

test('DFRPT-1, DFRPT-17: a backslash, a control character and a 501-character path still refuse the tree digest and the document', () => {
  const long = `${'d/'.repeat(250)}a`, fits = `${'d/'.repeat(249)}ab`;
  assert.deepEqual([long.length, fits.length], [501, 500]);
  for (const [path, why] of [['docs\\notes.md', /literal repository-relative path required/], ['docs/a\u0007b.md', /literal repository-relative path required/], ['docs/a\nb.md', /literal repository-relative path required/],
    ['docs/a\u007fb.md', /literal repository-relative path required/], [long, /too_big/]] as const) {
    assert.throws(() => treeDigest([...FILES, { path, sha256: EVIDENCE_HASH }]), why, JSON.stringify(path.slice(0, 20)));
    // One such file among the files read leaves the producer with no digest, so with no document; a document that names one is refused.
    refused(local(DIRTY, d => { d.snapshot.scopes[0]!.paths.push(path); }), why);
    refused(local(DIRTY, d => { const o = sourceOf(d, 'obs-refuted'); Object.assign(o.occurrence, { path }); }), why);
  }
  assert.ok(parse(local(DIRTY, withFile(fits))), 'a 500-character path is inside the limit');
});

test('DFRPT-22: the entry point exports every derivation and check a local producer needs, and this file used nothing else', () => {
  for (const name of ['SecurityReportLocal', 'parseLocalSecurityReport', 'treeDigest', 'selfSourceComponent', 'occurrenceKey', 'observationKey', 'observationSetDigest', 'canonicalJson', 'reportHash', 'documentDigest', 'sealReport', 'compareSourceUnion', 'reportJsonSchemas'] as const)
    assert.ok(name in checks, `the entry point exports ${name}`);
  assert.ok('local' in checks.reportJsonSchemas(), 'the local document has a published machine schema');
});
