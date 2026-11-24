// DFBASE-13, DFBASE-23: fix facts and one class per finding, in two pure phases (DFBASE-3). planCandidates proposes a candidate per
// occurrence from the lockfile and advisories alone. The caller verifies each proposed candidate over the network (its
// registry identity, an OSV query for the candidate itself, and the registry manifests of both versions) and hands that
// evidence to classify. Nothing here reads a file, the network or a clock.
import semver from 'semver';
import { z } from 'zod';
import { dependentsOf, lockFormatOf, type DepsLock, type DepsRangeField } from './security-deps-lock.ts';
import { digest, screenedJson, utf8 } from './security-primitives.ts';

export const DEPS_FACTS_VERSION = 'deps-facts/v1';
/** In DFBASE-13's order: each finding gets the first that applies. */
export const DEPS_FIX_CLASSES = ['verify_occurrence', 'no_fix_published', 'manual_fix_selection', 'range_change_needed', 'multi_entry_upgrade', 'single_entry_upgrade'] as const;
export type DepsFixClass = typeof DEPS_FIX_CLASSES[number];
export const DEPS_BLOCKING_SHOWN = 10;

const version = z.string().min(1).max(256).refine(v => semver.valid(v) !== null, 'semver version required');
/**
 * One affected interval of an advisory for this package: `lower` inclusive (null is "introduced 0"); `upper` exclusive
 * for `fixed` and `limit`, inclusive for `last_affected`, and null when the interval is open. Only `fixed` is a fix.
 */
export const DepsAffectedInterval = z.strictObject({ lower: version.nullable(), upper: version.nullable(), upper_kind: z.enum(['fixed', 'last_affected', 'limit']).nullable() })
  .refine(i => (i.upper === null) === (i.upper_kind === null), 'upper and upper_kind are both set or both null');
export const DepsFindingInput = z.strictObject({
  finding_id: z.string().min(1).max(200), entry: z.string().min(1).max(500), held: z.boolean(), current: z.boolean(),
  affected: z.strictObject({ intervals: z.array(DepsAffectedInterval).max(10000), versions: z.array(version).max(100000) }),
});
export type DepsAffectedInterval = z.infer<typeof DepsAffectedInterval>;
export type DepsFindingInput = z.infer<typeof DepsFindingInput>;
/** Produced from the sibling package.json by acquisition: no `overrides`/`resolutions` key, an unusable file, or the raw value. */
export type DepsOverridesInput = { state: 'absent' } | { state: 'unreadable' } | { state: 'present'; value: unknown };
export type DepsCandidateOsv = 'clear' | 'affected' | 'held' | 'unknown';
/** The caller's verification of one proposed candidate, keyed by the occurrence's entry path. */
export interface DepsOccurrenceEvidence {
  identity_verified: boolean; candidate_osv: DepsCandidateOsv;
  installed_manifest: unknown; candidate_manifest: unknown;
}
export type DepsCandidateState = 'proposed' | 'occurrence_held' | 'no_fixed_version' | 'inside_affected_range';
export interface DepsOccurrencePlan {
  entry: string; name: string | null; installed: string | null;
  finding_ids: string[]; fixed_versions: { finding_id: string; fixed_version: string | null }[];
  /** The upgrade group: findings on this occurrence that have a fixed version. */
  group: string[]; candidate: string | null; state: DepsCandidateState;
  /** Findings on this occurrence whose affected range the candidate lies outside of. */
  closes: string[];
}
export interface DepsCandidatePlan { facts_version: typeof DEPS_FACTS_VERSION; occurrences: DepsOccurrencePlan[] }
/** One declared edge that the candidate does not satisfy. */
export interface DepsBlockingDependent { path: string; field: DepsRangeField; range: string }
export interface DepsFindingFacts {
  finding_id: string; entry: string; class: DepsFixClass;
  dev_only: boolean; fixed_version: string | null;
  candidate: string | null; candidate_valid: boolean; candidate_reasons: string[];
  /** Null when there is no valid candidate to assess. */
  range_ok: boolean | null; range_reasons: string[];
  dependents_total: number | null; blocking_dependents: DepsBlockingDependent[]; blocking_total: number;
  edges_unchanged: boolean | null;
}
export interface DepsFacts { facts_version: typeof DEPS_FACTS_VERSION; lockfile_version: number; findings: DepsFindingFacts[] }

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
const bytewise = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const highest = (a: string, b: string) => semver.rcompare(a, b) || bytewise(a, b);
const contains = (i: DepsAffectedInterval, v: string) => (i.lower === null || semver.gte(v, i.lower)) &&
  (i.upper === null || (i.upper_kind === 'last_affected' ? semver.lte(v, i.upper) : semver.lt(v, i.upper)));
const affects = (f: DepsFindingInput, v: string) => f.affected.intervals.some(i => contains(i, v)) || f.affected.versions.some(x => semver.eq(x, v));

/**
 * DFBASE-8, DFBASE-13, DFBASE-23: extract the sibling package.json's override/resolution map for the lockfile's tool
 * (`overrides` for package-lock.json, `pnpm.overrides` and `overrides` for pnpm-lock.yaml, `resolutions` and `overrides`
 * for yarn.lock). An unreadable or credential-shaped manifest leaves overrides `unreadable`, never assumed absent.
 */
export function parseManifestOverrides(
  siblingBytes: Uint8Array | null,
  siblingUnreadable: boolean,
  lockPath = 'package-lock.json',
): { overrides: DepsOverridesInput; siblingSafe: boolean } {
  if (!siblingBytes) return { overrides: { state: siblingUnreadable ? 'unreadable' : 'absent' }, siblingSafe: false };
  let overrides: DepsOverridesInput = { state: 'unreadable' };
  let siblingSafe = false;
  try {
    const buf = Buffer.from(siblingBytes.buffer, siblingBytes.byteOffset, siblingBytes.byteLength);
    const manifest: unknown = JSON.parse(utf8(buf));
    screenedJson(manifest, 512 * 1024);
    siblingSafe = true;
    if (isObject(manifest)) {
      const base = lockPath.split('/').at(-1);
      if (base === 'pnpm-lock.yaml') {
        const pnpmVal = Object.hasOwn(manifest, 'pnpm') ? manifest.pnpm : undefined;
        if (pnpmVal !== undefined && !isObject(pnpmVal)) return { overrides: { state: 'unreadable' }, siblingSafe };
        const hasNpm = Object.hasOwn(manifest, 'overrides');
        const hasPnpm = isObject(pnpmVal) && Object.hasOwn(pnpmVal, 'overrides');
        if (!hasNpm && !hasPnpm) overrides = { state: 'absent' };
        else if (hasNpm && hasPnpm) {
          overrides = isObject(manifest.overrides) && isObject((pnpmVal as Json).overrides)
            ? { state: 'present', value: { '.npm': manifest.overrides, '.pnpm': (pnpmVal as Json).overrides } }
            : { state: 'unreadable' };
        } else {
          overrides = { state: 'present', value: hasPnpm ? (pnpmVal as Json).overrides : manifest.overrides };
        }
      } else if (base === 'yarn.lock') {
        const hasRes = Object.hasOwn(manifest, 'resolutions');
        const hasOvr = Object.hasOwn(manifest, 'overrides');
        if (!hasRes && !hasOvr) overrides = { state: 'absent' };
        else if (hasRes && hasOvr) {
          overrides = isObject(manifest.resolutions) && isObject(manifest.overrides)
            ? { state: 'present', value: { '.yarn': manifest.resolutions, '.npm': manifest.overrides } }
            : { state: 'unreadable' };
        } else {
          overrides = { state: 'present', value: hasRes ? manifest.resolutions : manifest.overrides };
        }
      } else {
        overrides = Object.hasOwn(manifest, 'overrides') ? { state: 'present', value: manifest.overrides } : { state: 'absent' };
      }
    }
  } catch {
    // An unreadable or unsafe manifest makes overrides unestablished, never assumed absent (DFBASE-8, DFBASE-13).
  }
  return { overrides, siblingSafe };
}

/** DFBASE-13.2: the fixed bound of the interval holding the installed version. Overlapping intervals must all be fixed. */
function fixedVersion(f: DepsFindingInput, installed: string): string | null {
  const holding = f.affected.intervals.filter(i => contains(i, installed));
  if (!holding.length || holding.some(i => i.upper_kind !== 'fixed')) return null;
  return holding.map(i => i.upper!).sort(highest)[0]!;
}

function parsedFindings(lock: DepsLock, input: readonly DepsFindingInput[]) {
  if (lock.state !== 'parsed' || lock.lockfile_version === null) throw Error('deps_lock_not_parsed');
  const findings = input.map(f => DepsFindingInput.parse(f));
  if (new Set(findings.map(f => f.finding_id)).size !== findings.length) throw Error('deps_facts_duplicate_finding');
  const entries = new Map(lock.entries.map(e => [e.path, e]));
  for (const f of findings) if (!entries.has(f.entry)) throw Error('deps_facts_unknown_entry');
  return { findings, entries };
}

/** Phase 1 (DFBASE-13.2–4, without the network): one candidate per occurrence that has findings. */
export function planCandidates(lock: DepsLock, input: readonly DepsFindingInput[]): DepsCandidatePlan {
  const { findings, entries } = parsedFindings(lock, input);
  const byEntry = new Map<string, DepsFindingInput[]>();
  for (const f of findings) byEntry.set(f.entry, [...byEntry.get(f.entry) ?? [], f]);
  const occurrences = [...byEntry.keys()].sort(bytewise).map((path): DepsOccurrencePlan => {
    const entry = entries.get(path)!, on = byEntry.get(path)!.sort((a, b) => bytewise(a.finding_id, b.finding_id));
    const installed = entry.kind === 'registry' ? entry.version : null;
    const fixed = on.map(f => ({ finding_id: f.finding_id, fixed_version: installed ? fixedVersion(f, installed) : null }));
    const group = fixed.filter(f => f.fixed_version).map(f => f.finding_id);
    const candidate = fixed.map(f => f.fixed_version).filter((v): v is string => v !== null).sort(highest)[0] ?? null;
    const members = on.filter(f => group.includes(f.finding_id));
    // A fixed bound is exclusive and its interval holds the installed version, so a candidate is always above it (DFSEC-5).
    const state: DepsCandidateState = !installed || on.some(f => f.held) ? 'occurrence_held'
      : !candidate ? 'no_fixed_version'
      : members.some(f => affects(f, candidate)) ? 'inside_affected_range' : 'proposed';
    return { entry: path, name: entry.name, installed, finding_ids: on.map(f => f.finding_id), fixed_versions: fixed, group, candidate, state,
      closes: candidate ? on.filter(f => !affects(f, candidate)).map(f => f.finding_id) : [] };
  });
  return { facts_version: DEPS_FACTS_VERSION, occurrences };
}

/** What the caller must verify before classify: each proposed candidate, by occurrence. */
export function candidateRequests(plan: DepsCandidatePlan) {
  return plan.occurrences.filter(o => o.state === 'proposed').map(o => ({ entry: o.entry, name: o.name!, installed: o.installed!, candidate: o.candidate! }));
}

// npm-package-arg's split: a dependency spec is a semver range only when it parses as one. Git, URL, file, tag, `npm:`
// alias and `workspace:` specs never do. npm treats "" and "*" as matching any version, prereleases included.
const semverRange = (range: string) => !/[:/\\]/.test(range) && semver.validRange(range, { loose: true }) !== null;
const satisfies = (v: string, range: string) => ['', '*'].includes(range.trim()) || semver.satisfies(v, range, { loose: true });

/**
 * The package name an `overrides`, `pnpm.overrides` or Yarn `resolutions` key selects: `name`, `name@spec`, `@scope/name`,
 * `@scope/name@spec`, pnpm's `parent>name@spec`, or Yarn's `**\/name` / `parent/@scope/name@spec`.
 */
function overrideKeyName(key: string) {
  const afterArrow = key.includes('>') ? key.slice(key.lastIndexOf('>') + 1).trim() : key;
  const segs = afterArrow.split('/');
  const spec = segs.length >= 2
    ? (segs.at(-2)!.startsWith('@') ? `${segs.at(-2)}/${segs.at(-1)}` : segs.at(-1)!)
    : afterArrow;
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  return at < 0 ? spec : spec.slice(0, at);
}
/** Whether any `overrides` key at any depth names the package, or null when the value cannot be read as overrides. */
function overridesName(value: unknown, name: string): boolean | null {
  if (!isObject(value)) return null;
  for (const stack: Json[] = [value]; stack.length;) {
    for (const [key, v] of Object.entries(stack.pop()!)) {
      if (overrideKeyName(key) === name) return true;
      if (isObject(v)) stack.push(v); else if (typeof v !== 'string') return null;
    }
  }
  return false;
}

function pairs(raw: unknown): [string, string][] | null {
  if (raw === undefined) return [];
  if (!isObject(raw)) return null;
  const out = Object.entries(raw);
  return out.every((p): p is [string, string] => typeof p[1] === 'string') ? out.sort(([a], [b]) => bytewise(a, b)) : null;
}
/**
 * DFBASE-13.6: the dependency, optional, peer and bundled edges of one registry manifest, or null when it is not the
 * expected version's manifest. Only registry manifests are compared with each other: the registry folds optional
 * dependencies into `dependencies`, so a lock entry is never comparable with a manifest.
 */
function manifestEdges(manifest: unknown, name: string, expected: string): string | null {
  if (!isObject(manifest) || manifest.name !== name || manifest.version !== expected) return null;
  const dependencies = pairs(manifest.dependencies), optional = pairs(manifest.optionalDependencies), peer = pairs(manifest.peerDependencies);
  const meta = manifest.peerDependenciesMeta === undefined ? {} : manifest.peerDependenciesMeta;
  const bundle = Object.hasOwn(manifest, 'bundleDependencies') ? manifest.bundleDependencies : manifest.bundledDependencies;
  if (!dependencies || !optional || !peer || !isObject(meta)) return null;
  const bundled = bundle === true ? dependencies.map(([n]) => n) : bundle === undefined || bundle === false ? []
    : Array.isArray(bundle) && bundle.every(n => typeof n === 'string') ? bundle as string[] : null;
  if (!bundled) return null;
  const optionalPeer = (n: string) => Object.hasOwn(meta, n) && isObject(meta[n]) && (meta[n] as Json).optional === true;
  return digest({ dependencies, optional, peer: peer.map(([n, r]) => [n, r, optionalPeer(n)]), bundled: [...new Set(bundled)].sort(bytewise) });
}

interface OccurrenceFacts extends Omit<DepsFindingFacts, 'finding_id' | 'entry' | 'class' | 'dev_only' | 'fixed_version'> { manual: boolean }
function occurrenceFacts(lock: DepsLock, overrides: DepsOverridesInput, plan: DepsOccurrencePlan, evidence: Readonly<Record<string, DepsOccurrenceEvidence>>): OccurrenceFacts {
  const ev = Object.hasOwn(evidence, plan.entry) ? evidence[plan.entry] : undefined;
  const candidate_reasons = plan.state !== 'proposed' ? [plan.state] : !ev ? ['evidence_missing'] : [
    ...ev.identity_verified === true ? [] : ['identity_unverified'],
    ...ev.candidate_osv === 'clear' ? [] : [ev.candidate_osv === 'affected' ? 'candidate_affected' : ev.candidate_osv === 'held' ? 'candidate_held' : 'candidate_osv_unknown'],
  ];
  const none = { candidate: plan.candidate, candidate_valid: false, candidate_reasons, range_ok: null, range_reasons: [], dependents_total: null, blocking_dependents: [], blocking_total: 0, edges_unchanged: null, manual: true };
  if (candidate_reasons.length || !ev) return none;
  const candidate = plan.candidate!, name = plan.name!, { dependents, unread } = dependentsOf(lock, plan.entry);
  const named = overrides.state === 'absent' ? false : overrides.state === 'present' ? overridesName(overrides.value, name) : null;
  const manualReasons = [
    ...unread.length ? ['dependent_range_unread'] : [],
    ...dependents.some(d => !semverRange(d.range)) ? ['dependent_range_not_semver'] : [],
    ...named === null ? ['overrides_unreadable'] : named ? ['overrides_name_package'] : [],
  ];
  const blocking = dependents.filter(d => semverRange(d.range) && !satisfies(candidate, d.range)).map(({ path, field, range }) => ({ path, field, range }));
  const range_reasons = [...manualReasons, ...blocking.length ? ['dependent_range_unsatisfied'] : []];
  const before = manifestEdges(ev.installed_manifest, name, plan.installed!), after = manifestEdges(ev.candidate_manifest, name, candidate);
  return { candidate, candidate_valid: true, candidate_reasons, range_ok: range_reasons.length === 0, range_reasons,
    dependents_total: dependents.length + unread.length, blocking_dependents: blocking.slice(0, DEPS_BLOCKING_SHOWN), blocking_total: blocking.length,
    edges_unchanged: before && after ? before === after : null, manual: manualReasons.length > 0 };
}

/**
 * Phase 2 (DFBASE-13): each finding's facts and its one class, the first that applies. `plan` must be
 * planCandidates(lock, findings); `evidence` is the caller's verification of each proposed candidate. A missing or
 * unverified candidate is not valid, and edges that could not be read are not unchanged.
 */
export function classify(lock: DepsLock, overrides: DepsOverridesInput, input: readonly DepsFindingInput[], plan: DepsCandidatePlan,
  evidence: Readonly<Record<string, DepsOccurrenceEvidence>>): DepsFacts {
  const { findings, entries } = parsedFindings(lock, input);
  if (digest(plan) !== digest(planCandidates(lock, findings))) throw Error('deps_facts_plan_mismatch');
  const format = lockFormatOf(lock);
  const plans = new Map(plan.occurrences.map(o => [o.entry, o]));
  const facts = new Map([...plans].map(([path, o]) => [path, occurrenceFacts(lock, overrides, o, evidence)]));
  return { facts_version: DEPS_FACTS_VERSION, lockfile_version: lock.lockfile_version!, findings: findings.map((f): DepsFindingFacts => {
    const entry = entries.get(f.entry)!, o = plans.get(f.entry)!, { manual, ...shared } = facts.get(f.entry)!;
    const fixed_version = o.fixed_versions.find(v => v.finding_id === f.finding_id)!.fixed_version;
    const cls: DepsFixClass = f.held || !f.current || entry.kind !== 'registry' ? 'verify_occurrence'
      : !fixed_version ? 'no_fix_published'
      : manual ? 'manual_fix_selection'
      : shared.blocking_total ? 'range_change_needed'
      // DFBASE-13, DFBASE-23: only npm package-lock.json v3 matches DFSEC-5's single-entry JSON repair shape.
      : format !== 'npm' || lock.lockfile_version !== 3 || shared.edges_unchanged !== true ? 'multi_entry_upgrade' : 'single_entry_upgrade';
    return { finding_id: f.finding_id, entry: f.entry, class: cls, dev_only: entry.dev, fixed_version, ...shared };
  }) };
}
