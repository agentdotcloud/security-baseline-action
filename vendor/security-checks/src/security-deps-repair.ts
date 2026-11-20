// DFREP-1 to 12: the one-entry lock repair. From one lock occurrence whose findings the shared check classes
// `single_entry_upgrade`, it builds the candidate lockfile, proves on the bytes that it is exactly that one-entry change
// and that the check no longer finds the advisory, and emits one proof packet. Deterministic: no model, no repository
// code, no test execution. It is DFSEC-5's deterministic resolver, never an agent-authored or tested repair.
//
// Pure (DFBASE-3, DFREP-12): the caller supplies the bytes and the HTTP client. Publication and the optional npm
// consistency step belong to the operator command, which records the npm outcome with recordNpmConsistency.
import { DEPS_CHECK_VERSION, staticDeps, type DepsCheckCapabilities, type DepsCheckLockfile, type DepsCheckResult } from './security-deps-check.ts';
import { DEPS_FACTS_VERSION } from './security-deps-facts.ts';
import { DEPS_LOCK_VERSION } from './security-deps-lock.ts';
import { gitBlob, gitSha, repositoryName, sha256 } from './security-primitives.ts';
import { reportHash } from './security-report-json.ts';
import type { SecurityReport } from './security-report.ts';

export const DEPS_REPAIR_VERSION = 'lock-repair/v1';
export const DEPS_REPAIR_WRITER = 'harness:lock-repair';
/** DFREP-10: the same limits, in fixed words, on every packet and every pull request body. */
export const DEPS_REPAIR_LIMITS = [
  'This change was produced by a deterministic resolver, not by an agent.',
  'The lane ran no repository code, test or install script.',
  'The repository\'s tests are this pull request\'s own checks.',
  'Runtime reachability and exploitability were not assessed.',
  'Behavior changes, engine constraints and install scripts of the new version were not assessed.',
  'An open pull request is not a merged or deployed fix.',
] as const;
export type DepsRepairHoldCode = 'repair.not_single_entry_upgrade' | 'repair.report_mismatch' | 'repair.base_not_reported' | 'repair.identity_unverified' | 'repair.entry_not_reproducible'
  | 'repair.entry_shape_changes' | 'repair.entry_key_unknown' | 'repair.format_not_reproducible' | 'repair.candidate_deprecated';
/** DFREP-4: the builder holds instead of guessing. A hold produces no candidate. */
export class DepsRepairHold extends Error {
  readonly code: DepsRepairHoldCode;
  constructor(code: DepsRepairHoldCode, detail: string) { super(detail); this.code = code; }
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
// Order matters: the builder writes a value in the manifest's own key order, so that order must be the one npm wrote.
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const REGISTRY = 'https://registry.npmjs.org';
// DFREP-3: what npm copies from a manifest into a lock entry, and the flags that come from the entry's place in the tree.
const IDENTITY_KEYS = ['version', 'resolved', 'integrity'] as const;
const COPIED_KEYS = ['license', 'engines', 'os', 'cpu', 'libc', 'bin', 'funding', 'hasInstallScript', 'dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'acceptDependencies', 'bundleDependencies'] as const;
const POSITION_KEYS = ['dev', 'optional', 'devOptional', 'peer', 'inBundle'];
const DERIVED_KEYS: readonly string[] = [...IDENTITY_KEYS, ...COPIED_KEYS];

/** The lock entry fields a registry manifest determines, as npm writes them: empty values are absent, a license object is its type. */
function derivedEntry(manifest: Json): Json {
  const dist = isObject(manifest.dist) ? manifest.dist : {}, out: Json = { version: manifest.version, resolved: dist.tarball, integrity: dist.integrity };
  for (const key of COPIED_KEYS) {
    let value = key === 'bundleDependencies' ? manifest.bundleDependencies ?? manifest.bundledDependencies : manifest[key];
    // The registry folds optional dependencies into `dependencies`; a lock entry lists them only as optional.
    if (key === 'dependencies' && isObject(value) && isObject(manifest.optionalDependencies)) value = Object.fromEntries(Object.entries(value).filter(([name]) => !Object.hasOwn(manifest.optionalDependencies as Json, name)));
    if (key === 'license' && isObject(value) && typeof value.type === 'string') value = value.type;
    // npm marks an entry when the package declares an install-time script, whether or not the registry computed the flag.
    if (key === 'hasInstallScript') value = value === true || (isObject(manifest.scripts) && ['preinstall', 'install', 'postinstall'].some(name => (manifest.scripts as Json)[name]));
    if (!value || (typeof value === 'object' && !Object.keys(value).length)) continue;
    out[key] = value;
  }
  return out;
}

interface LockFormat { indent: string; eol: '\n' | '\r\n'; final: boolean }
/** DFREP-4/5: the lockfile's own formatting, accepted only if it reproduces the file's exact bytes from its parsed value. */
function lockFormat(text: string, parsed: unknown): LockFormat {
  const eol = text.includes('\r\n') ? '\r\n' as const : '\n' as const, indent = /^\{\r?\n([ \t]+)"/.exec(text)?.[1] ?? '', final = text.endsWith(eol);
  const format = { indent, eol, final };
  if (!indent || serialize(parsed, format) !== text) throw new DepsRepairHold('repair.format_not_reproducible', 'the lockfile does not re-serialize to its own bytes');
  return format;
}
const serialize = (value: unknown, f: LockFormat) => { const text = JSON.stringify(value, null, f.indent); return (f.eol === '\n' ? text : text.replace(/\n/g, '\r\n')) + (f.final ? f.eol : ''); };

export interface DepsRepairChange { field: string; before: unknown; after: unknown }
export interface DepsRepairBuild { candidate: Uint8Array; changes: DepsRepairChange[] }
/**
 * DFREP-3 to 5: the candidate lockfile bytes: the base bytes with the one entry moved to the candidate version. The
 * installed manifest must first reproduce the base entry; only then is the candidate entry derived the same way.
 */
export function buildLockRepair(base: Uint8Array, entry: string, installedManifest: unknown, candidateManifest: unknown): DepsRepairBuild {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(base);
  let lock: unknown;
  try { lock = JSON.parse(text); } catch { throw new DepsRepairHold('repair.format_not_reproducible', 'the lockfile is not JSON'); }
  const format = lockFormat(text, lock), packages = isObject(lock) && isObject(lock.packages) ? lock.packages : null, before = packages && Object.hasOwn(packages, entry) ? packages[entry] : null;
  if (!isObject(lock) || lock.lockfileVersion !== 3 || !packages || !isObject(before)) throw new DepsRepairHold('repair.not_single_entry_upgrade', 'no such entry in a lockfileVersion 3 lockfile');
  if (!isObject(installedManifest) || !isObject(candidateManifest)) throw new DepsRepairHold('repair.identity_unverified', 'a registry manifest is missing');
  const unknown = Object.keys(before).filter(k => !DERIVED_KEYS.includes(k) && !POSITION_KEYS.includes(k) && k !== 'deprecated');
  if (unknown.length) throw new DepsRepairHold('repair.entry_key_unknown', `the entry has ${unknown.join(', ')}`);
  const installed = derivedEntry(installedManifest), candidate = derivedEntry(candidateManifest);
  // A version can be deprecated after the lockfile was written, so `deprecated` need not reproduce. The lane does not
  // move an entry to a deprecated version, and a deprecation notice for the old version does not carry over.
  const stale = DERIVED_KEYS.filter(k => !same(installed[k], before[k]));
  if (stale.length) throw new DepsRepairHold('repair.entry_not_reproducible', `the installed manifest does not reproduce ${stale.join(', ')}`);
  if (candidateManifest.deprecated) throw new DepsRepairHold('repair.candidate_deprecated', 'the candidate version is deprecated');
  const reshaped = DERIVED_KEYS.filter(k => (candidate[k] === undefined) !== (before[k] === undefined));
  if (reshaped.length) throw new DepsRepairHold('repair.entry_shape_changes', `the candidate would add or remove ${reshaped.join(', ')}`);
  const after: Json = {}, changes: DepsRepairChange[] = [];
  for (const [key, value] of Object.entries(before)) {
    if (key === 'deprecated') { changes.push({ field: key, before: value, after: null }); continue; }
    const next = DERIVED_KEYS.includes(key) && !same(candidate[key], value) ? candidate[key] : value;
    if (next !== value) changes.push({ field: key, before: value, after: next });
    after[key] = next;
  }
  // Own data properties in the original order: a `packages` key is never reordered, and no other key is touched.
  const repaired = { ...lock, packages: Object.fromEntries(Object.entries(packages).map(([path, value]) => [path, path === entry ? after : value])) };
  return { candidate: new TextEncoder().encode(serialize(repaired, format)), changes };
}

export interface DepsEntryDiff { changed: string[]; added: string[]; removed: string[]; reordered: boolean; outside_equal: boolean }
/** DFREP-5: what differs between two lockfiles, judged on their bytes alone and independently of how one was built. */
export function lockEntryDiff(base: Uint8Array, candidate: Uint8Array): DepsEntryDiff {
  const read = (bytes: Uint8Array) => { const v: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)); if (!isObject(v) || !isObject(v.packages)) throw Error('deps_repair_not_a_lockfile'); return v as Json & { packages: Json }; };
  const a = read(base), b = read(candidate), keysA = Object.keys(a.packages), keysB = Object.keys(b.packages);
  const outside = (v: Json) => JSON.stringify(Object.entries(v).filter(([k]) => k !== 'packages'));
  return { changed: keysA.filter(k => Object.hasOwn(b.packages, k) && JSON.stringify(a.packages[k]) !== JSON.stringify(b.packages[k])), added: keysB.filter(k => !Object.hasOwn(a.packages, k)),
    removed: keysA.filter(k => !Object.hasOwn(b.packages, k)), reordered: JSON.stringify(keysA.filter(k => Object.hasOwn(b.packages, k))) !== JSON.stringify(keysB.filter(k => Object.hasOwn(a.packages, k))),
    outside_equal: outside(a) === outside(b) && JSON.stringify(Object.keys(a)) === JSON.stringify(Object.keys(b)) };
}

export type DepsRepairStepName = 'base_check' | 'build' | 'entry_diff' | 'candidate_check' | 'npm_consistency';
export interface DepsRepairStep {
  name: DepsRepairStepName; writer: typeof DEPS_REPAIR_WRITER; outcome: 'passed' | 'failed' | 'not_run' | 'not_applicable';
  detail: string; inputs: string[]; outputs: string[]; started_at: string; finished_at: string;
}
interface FindingRef { finding_id: string; title: string; aliases: string[] }
export interface DepsRepairPacket {
  packet_version: typeof DEPS_REPAIR_VERSION; outcome: 'proved' | 'failed'; failed_step: DepsRepairStepName | null;
  repository: string; commit: string; lockfile: string;
  base: { sha256: string; git_blob: string; bytes: number }; candidate: { sha256: string; git_blob: string; bytes: number };
  occurrence: { entry: string; package: string; installed: string; candidate: string };
  /** DFREP-6: the findings this change closes. */
  targets: FindingRef[];
  /** DFREP-7: findings on the same occurrence that the upgrade does not close. */
  remaining: (FindingRef & { class: string })[];
  changed_fields: DepsRepairChange[];
  coverage: { base: string; candidate: string; base_findings: number; candidate_findings: number };
  steps: DepsRepairStep[];
  versions: { repair: typeof DEPS_REPAIR_VERSION; check: typeof DEPS_CHECK_VERSION; facts: typeof DEPS_FACTS_VERSION; lock_parser: typeof DEPS_LOCK_VERSION; npm: string | null };
  requests: { registry: number; osv: number };
  limits: readonly string[];
  /** SHA-256 of the canonical JSON of every other field. */
  packet_digest: string;
}
export interface DepsRepairTarget {
  repository: string; commit: string; entry: string;
  /** Optional: findings that must be among the occurrence's `single_entry_upgrade` findings. */
  finding_ids?: readonly string[];
  /** Optional: the report the finding came from. It is only checked, never used as input (DFREP-2). */
  report?: SecurityReport;
}
export interface DepsRepairResult { packet: DepsRepairPacket; candidate: Uint8Array }

const sealed = (packet: Omit<DepsRepairPacket, 'packet_digest'>): DepsRepairPacket => ({ ...packet, packet_digest: reportHash(packet) });
const reported = (r: DepsCheckResult) => r.outcome === 'report' ? r : null;
const RANK = { complete: 2, partial: 1 } as const;
type Reported = Extract<DepsCheckResult, { outcome: 'report' }>;
// By advisory ID, not by response digest: OSV does not serialize one record to the same bytes twice.
const quarantined = (r: Reported) => r.quarantined_osv;
/** What a check run concluded, without its times: the digest a step records, equal for equal inputs and source responses (DFREP-9). */
const conclusion = (r: Reported) => reportHash({ check: DEPS_CHECK_VERSION, lockfile: r.body.lockfile.sha256, findings: r.body.findings.map(f => [f.finding_id, f.assessment.dependency]).sort(),
  classes: r.facts.map(f => [f.finding_id, f.class, f.candidate]).sort(), coverage: [r.body.coverage.state, r.body.coverage.union_status], not_checked: r.body.extension.not_checked.total, quarantined: [...quarantined(r)].sort() });

/**
 * DFREP-1 to 9: repair one occurrence. Throws DepsRepairHold when there is nothing this lane may build, and
 * DepsCheckError as the check does. Otherwise it returns the candidate bytes and the packet, whose outcome is `proved`
 * only if every step passed (DFREP-12).
 */
export async function repairLockEntry(lockfile: DepsCheckLockfile, target: DepsRepairTarget, capabilities: DepsCheckCapabilities): Promise<DepsRepairResult> {
  if (!gitSha.safeParse(target.commit).success || !repositoryName.safeParse(target.repository).success) throw new DepsRepairHold('repair.report_mismatch', 'a repository name and a full commit SHA are required');
  const clock = () => new Date(capabilities.now()).toISOString(), steps: DepsRepairStep[] = [];
  const step = (name: DepsRepairStepName, started: string, passed: boolean, detail: string, inputs: string[], outputs: string[]) => { steps.push({ name, writer: DEPS_REPAIR_WRITER, outcome: passed ? 'passed' : 'failed', detail, inputs, outputs, started_at: started, finished_at: clock() }); return passed; };

  // DFREP-1/2/6: the base check. The candidate is the one it computes; nothing comes from the caller or a report's text.
  let started = clock();
  const base = reported(await staticDeps(lockfile, capabilities));
  if (!base) throw new DepsRepairHold('repair.base_not_reported', 'the base lockfile gives no report');
  const onEntry = base.facts.filter(f => f.entry === target.entry), targets = onEntry.filter(f => f.class === 'single_entry_upgrade');
  const named = target.finding_ids ?? [];
  if (!targets.length || named.some(id => !targets.some(f => f.finding_id === id))) throw new DepsRepairHold('repair.not_single_entry_upgrade', 'the occurrence has no such single_entry_upgrade finding');
  const candidateVersion = targets[0]!.candidate!, finding = (id: string) => base.body.findings.find(f => f.finding_id === id)!;
  const occurrence = base.body.observations.flatMap(o => o.kind === 'source_observation' && o.occurrence.kind === 'dependency' && o.occurrence.entry === target.entry ? [o.occurrence] : [])[0]!;
  if (target.report) {
    const r = target.report, categories = new Map(r.recommendations.flatMap(a => a.finding_ids.map(id => [typeof id === 'string' ? id : id.local_id, a.category] as const)));
    if (r.snapshot.sha !== target.commit || r.snapshot.scopes.length !== 1 || r.snapshot.scopes[0]!.paths.join('\n') !== lockfile.path
      || targets.some(f => !r.findings.some(x => x.finding_id === f.finding_id) || categories.get(f.finding_id) !== 'dependency.single_entry_upgrade')) throw new DepsRepairHold('repair.report_mismatch', 'the report does not describe these bytes and findings');
  }
  const affected = targets.every(f => finding(f.finding_id).assessment.dependency === 'affected');
  step('base_check', started, affected, affected ? `${targets.length} single_entry_upgrade finding${targets.length === 1 ? '' : 's'} on the occurrence, affected on the base` : 'a target finding is not affected on the base',
    [lockfile.sha256], [conclusion(base)]);

  // DFREP-3/4: both registry manifests, read again in full. The check kept only their dependency edges.
  started = clock();
  const manifest = async (version: string) => {
    try { return (await capabilities.http.json(`${REGISTRY}/${encodeURIComponent(occurrence.package)}/${encodeURIComponent(version)}`)).body; }
    catch { throw new DepsRepairHold('repair.identity_unverified', `the registry did not return ${occurrence.package}@${version}`); }
  };
  const installedManifest = await manifest(occurrence.version), candidateManifest = await manifest(candidateVersion);
  const dist = isObject(candidateManifest) && isObject(candidateManifest.dist) ? candidateManifest.dist : {};
  if (!isObject(candidateManifest) || candidateManifest.name !== occurrence.package || candidateManifest.version !== candidateVersion || typeof dist.tarball !== 'string' || !dist.tarball.startsWith(`${REGISTRY}/`)
    || typeof dist.integrity !== 'string' || !/^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(dist.integrity)) throw new DepsRepairHold('repair.identity_unverified', 'the candidate\'s registry identity does not verify');
  const built = buildLockRepair(lockfile.bytes, target.entry, installedManifest, candidateManifest), candidate = built.candidate;
  const candidateFile: DepsCheckLockfile = { ...lockfile, bytes: candidate, git_blob: gitBlob(candidate), sha256: sha256(candidate) };
  step('build', started, true, `${occurrence.package} ${occurrence.version} to ${candidateVersion}: ${built.changes.map(c => c.field).join(', ')}`, [lockfile.sha256, reportHash(installedManifest), reportHash(candidateManifest)], [candidateFile.sha256]);

  // DFREP-5: proven on the bytes, not on the builder's intent.
  started = clock();
  const diff = lockEntryDiff(lockfile.bytes, candidate);
  const oneEntry = diff.changed.length === 1 && diff.changed[0] === target.entry && !diff.added.length && !diff.removed.length && !diff.reordered && diff.outside_equal;
  step('entry_diff', started, oneEntry, oneEntry ? 'exactly one packages key differs and nothing else in the file' : `changed ${diff.changed.length}, added ${diff.added.length}, removed ${diff.removed.length}`, [lockfile.sha256, candidateFile.sha256], [reportHash(diff)]);

  // DFREP-6/7: a fresh run of the same check on the candidate. No checkpoint: it is another input.
  started = clock();
  const after = reported(await staticDeps(candidateFile, { ...capabilities, checkpoint: undefined }));
  const baseIds = new Set(base.body.findings.map(f => f.finding_id)), afterIds = new Set(after?.body.findings.map(f => f.finding_id) ?? []);
  const stillThere = targets.filter(f => afterIds.has(f.finding_id)).length, fresh = [...afterIds].filter(id => !baseIds.has(id));
  // DFREP-7: coverage no worse than the base's, each way it can be worse named in the step's detail. Which entries went unchecked counts, not
  // only how many: the upgraded entry, or one the base checked, left unchecked on the candidate is a finding absent for the wrong reason.
  const unchecked = (r: Reported) => new Set(r.body.extension.not_checked.entries.map(e => e.entry));
  const newlyUnchecked = after ? [...unchecked(after)].filter(e => !unchecked(base).has(e)) : [];
  const worse = !after ? ['the candidate lockfile gives no report'] : [
    ...RANK[after.body.coverage.state] < RANK[base.body.coverage.state] ? [`coverage went from ${base.body.coverage.state} to ${after.body.coverage.state}`] : [],
    ...after.body.extension.not_checked.total > base.body.extension.not_checked.total ? [`entries not checked went from ${base.body.extension.not_checked.total} to ${after.body.extension.not_checked.total}`] : [],
    ...quarantined(after).some(d => !quarantined(base).includes(d)) ? [`${quarantined(after).filter(d => !quarantined(base).includes(d)).length} quarantined source record the base did not have`] : [],
    ...unchecked(after).has(target.entry) ? [`the upgraded entry ${target.entry} was not checked`] : [],
    ...newlyUnchecked.length ? [`${newlyUnchecked.length} entr${newlyUnchecked.length === 1 ? 'y' : 'ies'} not checked that the base checked`] : []];
  const closed = Boolean(after) && !stillThere && !fresh.length && !worse.length;
  step('candidate_check', started, closed, !after ? 'the candidate lockfile gives no report' : stillThere ? `${stillThere} target finding${stillThere === 1 ? ' is' : 's are'} still present on the candidate`
    : fresh.length ? `the candidate has ${fresh.length} finding${fresh.length === 1 ? '' : 's'} the base did not` : worse.length ? `the candidate's coverage is worse than the base's: ${worse.join('; ')}`
    : `${targets.length} target finding${targets.length === 1 ? '' : 's'} absent on the candidate; no new finding; coverage not worse`, [candidateFile.sha256], after ? [conclusion(after)] : []);

  const ref = (id: string): FindingRef => ({ finding_id: id, title: finding(id).title, aliases: finding(id).aliases });
  const failed = steps.find(s => s.outcome === 'failed')?.name ?? null;
  const packet = sealed({ packet_version: DEPS_REPAIR_VERSION, outcome: failed ? 'failed' : 'proved', failed_step: failed, repository: target.repository, commit: target.commit, lockfile: lockfile.path,
    base: { sha256: lockfile.sha256, git_blob: lockfile.git_blob, bytes: lockfile.bytes.byteLength }, candidate: { sha256: candidateFile.sha256, git_blob: candidateFile.git_blob, bytes: candidate.byteLength },
    occurrence: { entry: target.entry, package: occurrence.package, installed: occurrence.version, candidate: candidateVersion },
    targets: targets.map(f => ref(f.finding_id)), remaining: onEntry.filter(f => f.class !== 'single_entry_upgrade' && afterIds.has(f.finding_id)).map(f => ({ ...ref(f.finding_id), class: f.class })),
    changed_fields: built.changes, coverage: { base: base.body.coverage.state, candidate: after?.body.coverage.state ?? 'none', base_findings: baseIds.size, candidate_findings: afterIds.size },
    steps: [...steps, { name: 'npm_consistency', writer: DEPS_REPAIR_WRITER, outcome: 'not_run', detail: 'the npm consistency step was not run', inputs: [], outputs: [], started_at: clock(), finished_at: clock() }],
    versions: { repair: DEPS_REPAIR_VERSION, check: DEPS_CHECK_VERSION, facts: DEPS_FACTS_VERSION, lock_parser: DEPS_LOCK_VERSION, npm: null },
    requests: { registry: base.requests.registry + (after?.requests.registry ?? 0) + 2, osv: base.requests.osv + (after?.requests.osv ?? 0) }, limits: DEPS_REPAIR_LIMITS });
  return { packet, candidate };
}

export interface DepsNpmConsistency { outcome: 'unchanged' | 'changed' | 'not_applicable' | 'not_run'; npm_version: string | null; detail: string; started_at: string; finished_at: string; result_sha256?: string }
/** DFREP-8/12: record the operator command's npm step. `changed` fails the proof; `not_run` and `not_applicable` are stated, never hidden. */
export function recordNpmConsistency(packet: DepsRepairPacket, npm: DepsNpmConsistency): DepsRepairPacket {
  const { packet_digest: _digest, ...rest } = packet;
  const step: DepsRepairStep = { name: 'npm_consistency', writer: DEPS_REPAIR_WRITER, outcome: npm.outcome === 'unchanged' ? 'passed' : npm.outcome === 'changed' ? 'failed' : npm.outcome, detail: npm.detail,
    inputs: [packet.candidate.sha256], outputs: npm.result_sha256 ? [npm.result_sha256] : [], started_at: npm.started_at, finished_at: npm.finished_at };
  const steps = [...rest.steps.filter(s => s.name !== 'npm_consistency'), step], failed = steps.find(s => s.outcome === 'failed')?.name ?? null;
  return sealed({ ...rest, steps, outcome: failed ? 'failed' : 'proved', failed_step: failed, versions: { ...rest.versions, npm: npm.npm_version } });
}

// An advisory ID is linked only when it has the GitHub advisory shape; anything else is inert text.
const advisory = (id: string) => /^GHSA(-[0-9a-z]{4}){3}$/.test(id) ? `[${id}](https://github.com/advisories/${id})` : code(id);
const code = (text: unknown) => '`' + String(text).replace(/[`\r\n|]/g, ' ').slice(0, 200) + '`';
/** DFREP-10/11: the pull request title and body, rendered from a proved packet only. */
export function renderRepairPullRequest(packet: DepsRepairPacket): { title: string; body: string } {
  if (packet.outcome !== 'proved' || packet.packet_digest !== reportHash(Object.fromEntries(Object.entries(packet).filter(([k]) => k !== 'packet_digest')))) throw Error('deps_repair_packet_not_proved');
  const o = packet.occurrence, advisories = [...new Set(packet.targets.flatMap(t => t.aliases.filter(a => a.startsWith('GHSA-'))))];
  const outcome = { passed: 'passed', failed: 'failed', not_run: 'not run', not_applicable: 'not applicable' };
  const label: Record<DepsRepairStepName, string> = { base_check: 'Advisory check on the base lockfile', build: 'Build the candidate entry from registry manifests', entry_diff: 'Entry diff',
    candidate_check: 'Advisory check on the candidate lockfile', npm_consistency: 'npm re-resolves the candidate unchanged' };
  const body = [
    `Upgrades the lock entry ${code(o.entry)} in ${code(packet.lockfile)} from ${o.package} ${o.installed} to ${o.candidate}. One lock entry changes; \`package.json\` does not.`,
    '', '## Advisories this closes', '',
    ...packet.targets.map(t => `- ${t.aliases.map(advisory).join(', ')}`),
    ...packet.remaining.length ? ['', '## Still open on this entry', '', ...packet.remaining.map(t => `- ${t.aliases.map(advisory).join(', ')} (${t.class})`)] : [],
    '', '## What changed in the entry', '', '| Field | Before | After |', '| --- | --- | --- |',
    ...packet.changed_fields.map(c => `| ${code(c.field)} | ${code(typeof c.before === 'string' ? c.before : JSON.stringify(c.before))} | ${code(c.after === null ? 'removed' : typeof c.after === 'string' ? c.after : JSON.stringify(c.after))} |`),
    '', '## Proof', '', '| Step | Outcome | Detail |', '| --- | --- | --- |',
    ...packet.steps.map(s => `| ${label[s.name]} | ${outcome[s.outcome]} | ${s.detail.replace(/[|\r\n]/g, ' ')} |`),
    '', `Base commit ${code(packet.commit)}. Lockfile SHA-256 ${code(packet.base.sha256)} before and ${code(packet.candidate.sha256)} after. The advisory check found ${packet.coverage.base_findings} finding${packet.coverage.base_findings === 1 ? '' : 's'} in this lockfile before and ${packet.coverage.candidate_findings} after; its coverage was ${packet.coverage.base} before and ${packet.coverage.candidate} after.`,
    '', '## Limits', '', ...packet.limits.map(l => `- ${l}`),
    '', `Proof packet ${code(packet.packet_digest)} (${packet.packet_version}; check ${packet.versions.check}${packet.versions.npm ? `; npm ${packet.versions.npm}` : ''}).`, '',
  ].join('\n');
  return { title: `Upgrade ${o.package} from ${o.installed} to ${o.candidate} in ${packet.lockfile.replace(/\/?package-lock\.json$/, '') || 'the root lockfile'} (${advisories.slice(0, 2).join(', ')}${advisories.length > 2 ? ` and ${advisories.length - 2} more` : ''})`.slice(0, 200), body };
}
