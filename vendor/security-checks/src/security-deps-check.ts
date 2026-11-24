// DFBASE-3, 9, 11, 12, 14, 15: the shared `static.deps` check. Per lockfile it takes the bytes the caller already read
// and injected capabilities, and returns a report body: observations, findings, dispositions, evidence descriptors,
// recommendations, coverage states and the `summation.discovery` extension. It builds no envelope: joinDepsReport does
// that, because only the caller knows the producer, report ID, revision chain, snapshot and profile.
//
// Pure (DFBASE-3): no file, process, database or network connection of its own. Every request goes through the injected
// client, to the two fixed public origins only, and only a `name@version` whose public registry metadata matches the lock
// entry is ever sent to OSV (DFBASE-9). Any caller gets the same findings, IDs and classes from the same inputs.
import semver from 'semver';
import { z } from 'zod';
import { osvMatch, queryOsv, type Advisory, type InventoryOccurrence, type OsvCheckpoint, type PublicHTTP } from './security-advisories.ts';
import { candidateRequests, classify, planCandidates, DEPS_FACTS_VERSION, DEPS_FIX_CLASSES, type DepsAffectedInterval, type DepsFindingFacts,
  type DepsFindingInput, type DepsFixClass, type DepsOccurrenceEvidence, type DepsOccurrencePlan, type DepsOverridesInput } from './security-deps-facts.ts';
import { DEPS_LOCK_VERSION, lockFormatOf, parseDepsLock, type DepsLockEntry, type DepsLockFormat } from './security-deps-lock.ts';
import { npmExactVersion, npmPackageName } from './security-npm.ts';
import { evidenceHash, exactPath, gitSha, safeSourceText, sha256 } from './security-primitives.ts';
import { canonicalJson, reportHash } from './security-report-json.ts';
import { occurrenceKey, parseSecurityReport, observationKey, ReportProfile, ReportSnapshot, sealReport, type ReportFinding, type ReportObservation,
  type SecurityReport } from './security-report.ts';

export const DEPS_CHECK_ID = 'static.deps';
export const DEPS_CHECK_VERSION = 'static-deps/v1';
export const DEPS_IDENTITY_VERSION = 'npm-registry-identity/v1';
export const DEPS_OSV_VERSION = 'osv-querybatch/v1';
export const DEPS_DEPENDABOT_VERSION = 'github-dependabot-alerts/2022-11-28';
export const DEPS_EXTENSION = 'summation.discovery';
export const DEPS_EXTENSION_SCHEMA = 'summation.discovery/static-deps/1';
export const DEPS_COMPONENTS = { inventory: 'inventory.npm-lock', osv: 'source.osv', dependabot: 'source.github-dependabot' } as const;
/** DFRPT-15's single-report limits. A lockfile whose results exceed one is held, never truncated (DFBASE-14). */
export const DEPS_REPORT_LIMITS = { observations: 1000, findings: 1000, dispositions: 1000, recommendations: 1000, evidence: 1000, bytes: 10 * 1024 * 1024 } as const;
export const DEPS_NOT_CHECKED_SHOWN = 1000;
/** The scope ID every body object uses; joinDepsReport replaces it with the envelope's one scope. */
export const DEPS_BODY_SCOPE = 'lockfile';
const REGISTRY = 'https://registry.npmjs.org';
const ASSESSOR = DEPS_CHECK_ID;

export class DepsCheckError extends Error {
  readonly code: 'deps_check.cancelled' | 'deps_check.source_failed' | 'deps_check.input' | 'deps_check.checkpoint_scope';
  /** For `source_failed`: which source, and the client's own short code (`client_failed`, `public_retry_after_deferred`, ...). */
  readonly source: 'npm-registry' | 'osv' | null;
  constructor(code: DepsCheckError['code'], message: string, source: DepsCheckError['source'] = null) { super(message); this.code = code; this.source = source; }
}

/** One lockfile as the caller acquired it. Digests are the caller's; the check recomputes nothing it cannot see. */
export interface DepsCheckLockfile {
  /** Repository-relative path of the lockfile. */
  path: string; bytes: Uint8Array; git_blob: string; sha256: string;
  /** The sibling package.json: only its `overrides` key is an input (DFBASE-8, DFBASE-13). */
  overrides: DepsOverridesInput;
  package_json: { path: string; git_blob: string; sha256: string | null; size: number } | null;
}
/**
 * Dependabot alerts the caller has already read (DFBASE-3, DFBASE-11): every open alert of the repository, raw. The check
 * keeps the ones whose manifest path is this lockfile and counts nothing else. Omit it and the source is `not_selected`.
 */
export interface DepsDependabotInput {
  state: 'complete' | 'incomplete' | 'not_configured';
  /** `page_limit` for incomplete; `disabled` or `archived` for not_configured. */
  reason: string | null; retrieved_at: string; alerts: readonly unknown[];
  /** An acquisition checkpoint may replace unsafe alert text with its location and original artifact digest. */
  screened_alert_digests?: Readonly<Record<number, string>>;
}
export interface DepsIdentityFacts { name: string; version: string; tarball: string; integrity: string; manifest: DepsManifestFacts }
/** DFBASE-9: public registry facts only, keyed by name, version and integrity. No tenant, repository or installation. */
export interface DepsIdentityCache {
  get(name: string, version: string, integrity: string): Promise<DepsIdentityFacts | null>;
  put(facts: DepsIdentityFacts): Promise<void>;
}
/** DFBASE-7: `state` is what an earlier call saved for the same input; `save` is called after every completed request. */
export interface DepsCheckpointSink { state?: DepsCheckState; save(state: DepsCheckState): Promise<void> }
export interface DepsCheckCapabilities {
  http: PublicHTTP; now: () => number;
  limits: { max_identities: number; admitted_identities?: ReadonlySet<string> };
  /** A durable host can batch registry state; source-page checkpoints are never batched. */
  registry_checkpoint_every?: number;
  signal?: AbortSignal; cache?: DepsIdentityCache; checkpoint?: DepsCheckpointSink;
}

/** The registry manifest fields DFBASE-13.6 compares. Nothing else of a manifest is kept, cached or checkpointed. */
export type DepsManifestFacts = Record<string, unknown>;
type IdentityState = { state: 'verified'; tarball: string; integrity: string; manifest: DepsManifestFacts; confirmed_at: string }
  | { state: 'unverified'; reason: 'public_identity_unverified' | 'public_identity_mismatch' };
type CandidateState = { identity_verified: boolean; manifest: DepsManifestFacts | null; confirmed_at: string };
export interface DepsCheckState {
  version: typeof DEPS_CHECK_VERSION; input_digest: string;
  /** Keyed by JSON `[name, version, resolved, integrity]`. */
  identities: Record<string, IdentityState>;
  osv?: OsvCheckpoint;
  /** Keyed by JSON `[name, candidate]`. */
  candidates: Record<string, CandidateState>;
  candidate_osv?: OsvCheckpoint;
  requests: { registry: number; osv: number };
}

type Observation = ReportObservation;
type SourceObservation = Extract<ReportObservation, { kind: 'source_observation' }>;
type BodyEvidence = Omit<SecurityReport['evidence'][number], 'git'> & { git: { blob: string; path: string } | null };
export interface DepsBodyComponent {
  id: string; version: string; state: SecurityReport['coverage']['components'][number]['state']; required: boolean; reasons: string[];
  pagination_complete: boolean; source_revision: string; retrieved_at: string;
  /** DFRPT-19: the identifier of this component's own read. Null unless the component completed. */
  baseline_receipt: string | null;
  /** The observations this component returned, by body observation ID. The join derives their keys and digests. */
  observation_ids: string[];
}
const FactsShape = z.strictObject({
  finding_id: z.string(), entry: z.string(), package: z.string().nullable(), installed: z.string().nullable(), class: z.enum(DEPS_FIX_CLASSES), dev_only: z.boolean(),
  fixed_version: z.string().nullable(), candidate: z.string().nullable(), candidate_valid: z.boolean(), candidate_reasons: z.array(z.string()),
  range_ok: z.boolean().nullable(), range_reasons: z.array(z.string()), dependents_total: z.number().int().nullable(),
  blocking_dependents: z.array(z.strictObject({ path: z.string(), field: z.string(), range: z.string() })).max(10), blocking_total: z.number().int(),
  edges_unchanged: z.boolean().nullable(), related_finding_ids: z.array(z.string()),
});
/** DFBASE-14: the strict, versioned, display-only extension. No consumer may use it for correlation, routing or eligibility. */
export const DepsDiscoveryExtension = z.strictObject({
  schema: z.literal(DEPS_EXTENSION_SCHEMA), check: z.strictObject({ id: z.literal(DEPS_CHECK_ID), version: z.literal(DEPS_CHECK_VERSION), facts_version: z.literal(DEPS_FACTS_VERSION) }),
  lockfile: z.strictObject({ path: z.string(), lockfile_version: z.number().int().nullable(), parser_version: z.literal(DEPS_LOCK_VERSION) }),
  registry_count: z.number().int().nonnegative(), first_party_count: z.number().int().nonnegative(),
  fix_facts: z.array(FactsShape).max(DEPS_REPORT_LIMITS.findings),
  not_checked: z.strictObject({ total: z.number().int().nonnegative(), by_reason: z.record(z.string(), z.number().int().positive()),
    entries: z.array(z.strictObject({ entry: z.string(), reason: z.string() })).max(DEPS_NOT_CHECKED_SHOWN) }),
});
export type DepsDiscoveryExtension = z.infer<typeof DepsDiscoveryExtension>;
/**
 * What the check returns for one lockfile (DFBASE-3). It names no producer, report ID, revision, snapshot or profile:
 * findings carry a null `profile_digest` and evidence carries no commit SHA until joinDepsReport supplies them.
 */
export interface DepsReportBody {
  check: { id: typeof DEPS_CHECK_ID; version: typeof DEPS_CHECK_VERSION };
  lockfile: { path: string; git_blob: string; sha256: string };
  observations: Observation[]; findings: ReportFinding[]; dispositions: SecurityReport['dispositions'];
  evidence: BodyEvidence[]; recommendations: SecurityReport['recommendations'];
  coverage: { state: 'complete' | 'partial'; union_status: 'proven' | 'incomplete'; components: DepsBodyComponent[] };
  extension: DepsDiscoveryExtension;
}
export type DepsCheckResult =
  /** `facts` are the exact fix facts behind the body's display-only extension, for a caller that acts on them (DFREP-1). */
  | { outcome: 'report'; body: DepsReportBody; facts: DepsFindingFacts[];
    /** The OSV record IDs the body quarantined. The body carries only their response digests, which differ between two reads of one record (DFREP-7). */
    quarantined_osv: string[]; requests: DepsCheckState['requests'] }
  /** DFBASE-14: over a DFRPT-15 single-report limit. No report; the totals go to the run summary. */
  | { outcome: 'held'; reason: 'discovery.report_limit'; totals: Record<keyof typeof DEPS_REPORT_LIMITS, number>; limits: typeof DEPS_REPORT_LIMITS; requests: DepsCheckState['requests'] }
  /** DFBASE-10, DFBASE-15, DFBASE-23: a lockfile that is credential-shaped, unsupported or malformed publishes no report, and nothing derived from it is kept. */
  | { outcome: 'skipped'; reason: 'credential_shaped_content' | 'unsupported_lockfile' | 'malformed_json' | 'malformed_lockfile'; requests: DepsCheckState['requests'] };

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
const bytewise = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const iso = (value: string) => new Date(value).toISOString();
const short = (...parts: unknown[]) => reportHash(parts).slice(0, 32);
// Lockfile and advisory text shown in a rationale or the extension: no control characters, no lone surrogates, and
// bounded well inside the report's 4 KiB field limit. It is display text, never an identifier.
const shown = (text: string, max = 300) => {
  const clean = text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/gu, '�').replace(/[\u0000-\u001f\u007f]/g, ' ');
  const points = Array.from(clean);
  return points.length > max ? points.slice(0, max).join('') + '…' : clean;
};
const MANIFEST_KEYS = ['name', 'version', 'dependencies', 'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta', 'bundleDependencies', 'bundledDependencies'] as const;
const manifestFacts = (manifest: Json): DepsManifestFacts => Object.fromEntries(MANIFEST_KEYS.filter(k => Object.hasOwn(manifest, k)).map(k => [k, manifest[k]]));
const RegistryManifest = z.object({ name: z.string(), version: z.string(), dist: z.object({ tarball: z.string(), integrity: z.string() }) }).passthrough();
const clientCode = (e: unknown) => e instanceof Error && /^[a-z0-9_.]+$/.test(e.message) ? e.message : 'client_failed';

const Alert = z.object({
  number: z.number().int().positive().safe(), updated_at: z.iso.datetime({ offset: true }).optional(), created_at: z.iso.datetime({ offset: true }).optional(),
  dependency: z.object({ package: z.object({ ecosystem: z.string().max(100), name: z.string().max(1000) }), manifest_path: z.string().max(4096) }),
  security_advisory: z.object({ ghsa_id: z.string().regex(/^GHSA(?:-[0-9a-z]{4}){3}$/), cve_id: z.string().max(200).nullable().optional(), summary: z.string().max(12000).optional(), severity: z.string().max(200).optional() }),
  security_vulnerability: z.object({ vulnerable_version_range: z.string().max(500), first_patched_version: z.object({ identifier: z.string().max(256) }).nullable().optional() }).optional(),
});
type Alert = z.infer<typeof Alert>;
const CVE = /^CVE-[0-9]{4}-[0-9]{4,19}$/, GHSA = /^GHSA-[a-z0-9-]+$/;
const normalSeverity = (raw: string | undefined) => {
  const s = (raw ?? '').toLowerCase();
  return s === 'moderate' ? 'medium' as const : (['low', 'medium', 'high', 'critical'] as const).find(x => x === s) ?? 'unknown' as const;
};

/** GitHub's `>= 1.0.0, < 1.2.3` as a semver range, or null when it is not one. */
const alertRange = (range: string | undefined) => { const r = range?.replace(/,\s*/g, ' ') ?? null; return r !== null && semver.validRange(r) !== null ? r : null; };
/** A Dependabot-only finding's affected interval, from the alert's range and first patched version. Null when unreadable. */
function alertAffected(a: Alert): DepsFindingInput['affected'] | null {
  const comparators = a.security_vulnerability?.vulnerable_version_range.split(',').map(s => s.trim()).filter(Boolean) ?? [];
  let lower: string | null = null, upper: string | null = null, kind: DepsAffectedInterval['upper_kind'] = null; const versions: string[] = [];
  for (const c of comparators) {
    const m = /^(>=|<=|<|=)\s*(\S+)$/.exec(c), v = m && semver.valid(m[2]!);
    if (!m || !v) return null;
    if (m[1] === '>=') lower = v; else if (m[1] === '<') { upper = v; kind = 'limit'; } else if (m[1] === '<=') { upper = v; kind = 'last_affected'; } else versions.push(v);
  }
  if (versions.length) return comparators.length === 1 ? { intervals: [], versions } : null;
  const patched = a.security_vulnerability?.first_patched_version?.identifier, fixed = patched ? semver.valid(patched) : null;
  // The first patched version is the fix when it closes the stated range: at its exclusive bound, or above its inclusive one.
  if (fixed && (upper === null || (kind === 'limit' ? semver.eq(fixed, upper) : semver.gt(fixed, upper)))) { upper = fixed; kind = 'fixed'; }
  return { intervals: [{ lower, upper, upper_kind: kind }], versions: [] };
}

/** An OSV record's affected intervals for one npm package, with each bound's kind kept (DFBASE-13.2). Null when unreadable. */
function osvAffected(record: Advisory, name: string): DepsFindingInput['affected'] | null {
  const intervals: DepsAffectedInterval[] = [], versions: string[] = [];
  for (const a of record.affected.filter(a => a.package.ecosystem === 'npm' && a.package.name === name)) {
    for (const v of a.versions ?? []) { if (!semver.valid(v)) return null; versions.push(v); }
    for (const range of a.ranges ?? []) {
      if (range.type !== 'SEMVER') return null;
      let lower: string | null = null, open = false;
      for (const event of range.events) {
        const [key, value] = Object.entries(event)[0] ?? [];
        if (Object.keys(event).length !== 1 || !key || !value) return null;
        if (key === 'introduced') { if (open || (value !== '0' && !semver.valid(value))) return null; lower = value === '0' ? null : value; open = true; }
        else { if (!open || !semver.valid(value) || !['fixed', 'limit', 'last_affected'].includes(key)) return null; intervals.push({ lower, upper: value, upper_kind: key as 'fixed' | 'limit' | 'last_affected' }); open = false; }
      }
      if (open) intervals.push({ lower, upper: null, upper_kind: null });
    }
  }
  return intervals.length || versions.length ? { intervals, versions } : null;
}

const dependencyOccurrence = (path: string, e: { path: string; name: string; version: string }) => {
  const coordinates = { kind: 'dependency' as const, ecosystem: 'npm' as const, package: e.name, version: e.version, manifest: path, entry: e.path };
  return { ...coordinates, key: occurrenceKey(coordinates) };
};
/** An entry a dependency occurrence can name: the report's coordinates are stricter than a `packages` key. */
const reportable = (e: DepsLockEntry): e is DepsLockEntry & { name: string; version: string } => e.kind !== 'first_party' && e.name !== null && e.version !== null
  && npmPackageName.safeParse(e.name).success && npmExactVersion.safeParse(e.version).success && exactPath.safeParse(e.path).success;

interface Group { entry: DepsLockEntry & { name: string; version: string }; flaw: string; osv: { observation: SourceObservation; record: Advisory; match: ReturnType<typeof osvMatch> }[]; alerts: { observation: SourceObservation; alert: Alert }[] }

const RATIONALE: Record<DepsFixClass, (f: DepsFindingFacts, o: DepsOccurrencePlan, lockVersion: number, format: DepsLockFormat) => string> = {
  verify_occurrence: () => 'This finding is held, so no fix is proposed. Verify the occurrence and the advisory before acting on it.',
  no_fix_published: (_f, o) => `No fixed version is published for the affected range that contains ${o.name ?? 'this package'} ${o.installed ?? ''}.`.replace(' .', '.'),
  manual_fix_selection: f => `A fixed version exists but no upgrade could be selected automatically (${[...f.candidate_reasons, ...f.range_reasons].join(', ') || 'no valid candidate'}). Choose the fix by hand.`,
  range_change_needed: (f, o) => `${o.name} ${f.candidate} fixes this, but ${f.blocking_total} declared range${f.blocking_total === 1 ? '' : 's'} exclude${f.blocking_total === 1 ? 's' : ''} it: `
    + f.blocking_dependents.map(d => `${shown(d.path || '(root)', 120)} ${d.field} "${shown(d.range, 60)}"`).join('; ') + (f.blocking_total > f.blocking_dependents.length ? `; and ${f.blocking_total - f.blocking_dependents.length} more` : '') + '. A dependent\'s range must change first.',
  multi_entry_upgrade: (f, o, v, fmt) => `Upgrade ${o.name} at ${shown(o.entry, 200)} from ${o.installed} to ${f.candidate}. Every dependent's declared range accepts it, but `
    + (fmt !== 'npm' ? `this ${fmt === 'pnpm' ? 'pnpm-lock.yaml' : 'yarn.lock'} lockfile updates with ${fmt}` : v !== 3 ? 'this lockfileVersion 2 file also carries the legacy dependency tree' : 'its dependency edges differ from the installed version\'s, or could not be read') + ', so more than one lock entry changes.',
  single_entry_upgrade: (f, o) => `Change the one lock entry ${shown(o.entry, 200)} from ${o.name} ${o.installed} to ${f.candidate}. Every dependent's declared range accepts ${f.candidate}, and its registry manifest declares the same dependency edges as ${o.installed}.`,
};
const UNCERTAINTIES = ['Engine constraints, install scripts and behavior changes of another version are not assessed.', 'Runtime reachability and exploitability are not assessed.'];
const preconditionsFor = (cls: DepsFixClass, format: DepsLockFormat): string[] => {
  const tool = format === 'pnpm' ? 'pnpm' : format === 'yarn' ? 'yarn' : 'npm';
  switch (cls) {
    case 'verify_occurrence': return ['Resolve the listed holds.'];
    case 'no_fix_published': return ['Watch the advisory for a fixed version, or replace or remove the dependency.'];
    case 'manual_fix_selection': return ['Select a fixed version that every dependent accepts.'];
    case 'range_change_needed': return ['Change the listed dependents\' declared ranges, or upgrade those dependents.'];
    case 'multi_entry_upgrade': return [`Regenerate the lockfile with ${tool} and review every changed entry.`, 'Run the project\'s tests.'];
    case 'single_entry_upgrade': return ['Regenerate the lockfile with npm and confirm that one entry changed.', 'Run the project\'s tests.'];
  }
};

/**
 * Run `static.deps` on one lockfile. Throws DepsCheckError for cancellation, a checkpoint from another input, and a source
 * that failed: an outage is never a no-match (DFBASE-11), so the caller retries, defers or fails the run (DFBASE-7).
 */
export async function staticDeps(lockfile: DepsCheckLockfile, capabilities: DepsCheckCapabilities, dependabot?: DepsDependabotInput): Promise<DepsCheckResult> {
  const { http, now, limits, signal, cache } = capabilities, path = lockfile.path;
  if (!exactPath.safeParse(path).success || !gitSha.safeParse(lockfile.git_blob).success || !evidenceHash.safeParse(lockfile.sha256).success
    || !Number.isSafeInteger(limits.max_identities) || limits.max_identities < 0) throw new DepsCheckError('deps_check.input', 'lockfile path, digests or limits are not valid');
  const inputDigest = reportHash([DEPS_CHECK_VERSION, path, lockfile.sha256, lockfile.overrides.state === 'present' ? sha256(JSON.stringify(lockfile.overrides.value) ?? 'null') : lockfile.overrides.state,
    dependabot ? [dependabot.state, dependabot.reason, sha256(JSON.stringify(dependabot.alerts)), ...(dependabot.screened_alert_digests ? [dependabot.screened_alert_digests] : [])] : null]);
  const state: DepsCheckState = capabilities.checkpoint?.state ? structuredClone(capabilities.checkpoint.state)
    : { version: DEPS_CHECK_VERSION, input_digest: inputDigest, identities: {}, candidates: {}, requests: { registry: 0, osv: 0 } };
  if (state.version !== DEPS_CHECK_VERSION || state.input_digest !== inputDigest) throw new DepsCheckError('deps_check.checkpoint_scope', 'the checkpoint belongs to another input');
  const save = async () => { await capabilities.checkpoint?.save(state); };
  let registrySinceSave = 0;
  const saveRegistry = async (flush = false) => {
    if (!flush) registrySinceSave++;
    if (registrySinceSave && (flush || registrySinceSave >= (capabilities.registry_checkpoint_every ?? 1))) {
      await save(); registrySinceSave = 0;
    }
  };
  const live = () => { if (signal?.aborted) throw new DepsCheckError('deps_check.cancelled', 'cancelled'); };
  // One client for the whole check: it counts requests and refuses to start one after cancellation.
  const client = (source: 'npm-registry' | 'osv'): PublicHTTP => ({ async json(url, body, max) {
    live(); state.requests[source === 'osv' ? 'osv' : 'registry']++;
    try { return await http.json(url, body, max); }
    catch (e) { if (/^source_http_404$/.test(clientCode(e))) throw e; throw new DepsCheckError('deps_check.source_failed', clientCode(e), source); }
  } });
  const registry = client('npm-registry'), osv = client('osv');
  const startedAt = new Date(now()).toISOString();

  const lock = parseDepsLock(lockfile.bytes, path);
  // DFBASE-10, DFBASE-15, DFBASE-23: only a parsed lockfile reports. Nothing is disclosed or derived for any other.
  if (lock.state !== 'parsed') {
    const skipReason = lock.state === 'credential_shaped' ? 'credential_shaped_content'
      : lock.state === 'unsupported' ? 'unsupported_lockfile'
      : lock.reason === 'malformed_lockfile' ? 'malformed_lockfile' : 'malformed_json';
    return { outcome: 'skipped', reason: skipReason, requests: state.requests };
  }
  const format = lockFormatOf(lock);
  const entries = lock.entries;
  const registryEntries = entries.filter((e): e is DepsLockEntry & { name: string; version: string; resolved: string; integrity: string } => e.kind === 'registry');
  const notChecked = new Map<string, string>();
  for (const e of entries) if (e.kind === 'held') notChecked.set(e.path, e.hold_reason ?? 'unsupported_entry');

  // DFBASE-9: the public-identity gate. Unique name@version identities, in bytewise order, up to the caller's limit.
  const identityKey = (e: { name: string; version: string; resolved: string; integrity: string }) => JSON.stringify([e.name, e.version, e.resolved, e.integrity]);
  const pairs = [...new Set(registryEntries.map(e => JSON.stringify([e.name, e.version])))].sort(bytewise);
  const admitted = new Set(pairs.filter(p => !limits.admitted_identities || limits.admitted_identities.has(p)).slice(0, limits.max_identities));
  const verified = new Map<string, Extract<IdentityState, { state: 'verified' }>>();
  for (const e of [...registryEntries].sort((a, b) => bytewise(a.path, b.path))) {
    if (!admitted.has(JSON.stringify([e.name, e.version]))) { notChecked.set(e.path, 'identity_limit'); continue; }
    const key = identityKey(e);
    const isYarnBerryChecksum = e.integrity.startsWith('yarn-berry-sha512:');
    if (!Object.hasOwn(state.identities, key)) {
      const hit = !isYarnBerryChecksum ? (await cache?.get(e.name, e.version, e.integrity) ?? null) : null;
      // A cache hit must still equal the lock entry, and evidence cites this run's time, never the row's.
      if (hit && hit.name === e.name && hit.version === e.version && hit.tarball === e.resolved && hit.integrity === e.integrity) {
        state.identities[key] = { state: 'verified', tarball: hit.tarball, integrity: hit.integrity, manifest: hit.manifest, confirmed_at: new Date(now()).toISOString() };
      } else {
        try {
          const response = await registry.json(`${REGISTRY}/${encodeURIComponent(e.name)}/${encodeURIComponent(e.version)}`);
          const m = RegistryManifest.safeParse(response.body);
          const sriOk = m.success && /^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(m.data.dist.integrity);
          if (!m.success || m.data.name !== e.name || m.data.version !== e.version) state.identities[key] = { state: 'unverified', reason: 'public_identity_unverified' };
          else if (m.data.dist.tarball !== e.resolved || (isYarnBerryChecksum ? !sriOk : m.data.dist.integrity !== e.integrity)) state.identities[key] = { state: 'unverified', reason: 'public_identity_mismatch' };
          else {
            const facts = manifestFacts(m.data);
            state.identities[key] = { state: 'verified', tarball: e.resolved, integrity: m.data.dist.integrity, manifest: facts, confirmed_at: iso(response.retrieved_at) };
            if (!isYarnBerryChecksum) await cache?.put({ name: e.name, version: e.version, tarball: e.resolved, integrity: e.integrity, manifest: facts });
          }
        } catch (error) {
          if (error instanceof DepsCheckError) throw error;
          state.identities[key] = { state: 'unverified', reason: 'public_identity_unverified' }; // the registry does not know it: not public
        }
      }
      await saveRegistry();
    }
    const identity = state.identities[key]!;
    if (identity.state === 'verified') verified.set(e.path, identity); else notChecked.set(e.path, identity.reason);
  }
  const checked = registryEntries.filter(e => verified.has(e.path));

  // DFBASE-11: OSV, a required source. Only verified identities are queried; its failure is the caller's to retry.
  const occurrences: InventoryOccurrence[] = checked.map(e => ({ entry: e.path, name: e.name, version: e.version, resolved: e.resolved, integrity: verified.get(e.path)!.integrity, dev: e.dev, optional: e.optional }));
  const queried = async (occ: InventoryOccurrence[], slot: 'osv' | 'candidate_osv') => {
    try { return state[slot] = await queryOsv(osv, occ, state[slot], async cp => { state[slot] = cp; await save(); }); }
    catch (e) { if (e instanceof DepsCheckError) throw e; throw new DepsCheckError('deps_check.source_failed', clientCode(e), 'osv'); }
  };
  await saveRegistry(true);
  const osvState = await queried(occurrences, 'osv');
  const records = new Map((osvState.records ?? []).map(r => [r.record.id, r]));

  const evidence = new Map<string, BodyEvidence>(), observations: Observation[] = [], dispositions: SecurityReport['dispositions'] = [];
  const cite = (e: BodyEvidence) => { evidence.set(e.evidence_id, e); return e.evidence_id; };
  const lockMediaType = format === 'pnpm' ? 'application/yaml' : format === 'yarn' ? 'text/plain' : 'application/json';
  const lockEvidence = cite({ evidence_id: 'ev-lockfile', sha256: lockfile.sha256, bytes: lockfile.bytes.byteLength, media_type: lockMediaType, classification: 'restricted', kind: 'npm-lockfile',
    origin: 'repository blob at the pinned commit', captured_at: startedAt, artifact_id: null, git: { blob: lockfile.git_blob, path } });
  if (lockfile.package_json?.sha256 && exactPath.safeParse(lockfile.package_json.path).success) cite({ evidence_id: 'ev-package-json', sha256: lockfile.package_json.sha256, bytes: lockfile.package_json.size, media_type: 'application/json',
    classification: 'restricted', kind: 'npm-manifest-overrides', origin: 'repository blob at the pinned commit; only its overrides key was read', captured_at: startedAt, artifact_id: null, git: { blob: lockfile.package_json.git_blob, path: lockfile.package_json.path } });
  const components = { osv: [] as string[], dependabot: [] as string[] };
  const quarantine = (component: 'osv' | 'dependabot', artifact: string, ordinal: number, reason: string, capturedAt: string) => {
    const opaque = reportHash([artifact, ordinal]);
    observations.push({ kind: 'quarantined_observation', observation_id: `qobs-${opaque}`, quarantine_receipt_id: `quarantine-${opaque}`, source_artifact_digest: artifact, ordinal, reason, captured_by: ASSESSOR, captured_at: capturedAt });
    dispositions.push({ observation_id: `qobs-${opaque}`, kind: 'quarantined', reason, attribution: ASSESSOR, evidence_ids: [], finding_id: null, quarantine_receipt_id: `quarantine-${opaque}` });
    components[component].push(`qobs-${opaque}`);
  };

  const groups = new Map<string, Group>();
  const groupOf = (entry: Group['entry'], flaw: string) => {
    const key = JSON.stringify([entry.path, flaw]);
    if (!groups.has(key)) groups.set(key, { entry, flaw, osv: [], alerts: [] });
    return groups.get(key)!;
  };
  const hits = new Map<string, string[]>();
  for (const h of osvState.hits ?? []) { const k = JSON.stringify([h.name, h.version]); if (!hits.get(k)?.includes(h.id)) hits.set(k, [...hits.get(k) ?? [], h.id]); }
  for (const [ordinal, q] of (osvState.quarantined ?? []).entries()) quarantine('osv', q.sha256, ordinal, q.reason, iso(q.retrieved_at));
  for (const e of checked) {
    for (const id of [...hits.get(JSON.stringify([e.name, e.version])) ?? []].sort(bytewise)) {
      const r = records.get(id);
      if (!r) continue; // quarantined: kept above as a quarantined observation, never dropped
      const record = r.record, canonical = canonicalJson(record), recordDigest = sha256(canonical), match = osvMatch(record, e.name, e.version);
      const source = cite({ evidence_id: `ev-osv-${recordDigest.slice(0, 32)}`, sha256: recordDigest, bytes: Buffer.byteLength(canonical), media_type: 'application/json', classification: 'public', kind: 'osv-record',
        origin: `canonical JSON of https://api.osv.dev/v1/vulns/${encodeURIComponent(record.id)}`, captured_at: iso(r.retrieved_at), artifact_id: null, git: null });
      const occurrence = dependencyOccurrence(path, e), severity = isObject(record.database_specific) && typeof record.database_specific.severity === 'string' ? record.database_specific.severity : '';
      const observation: SourceObservation = { kind: 'source_observation', observation_id: `obs-${short('osv', record.id, occurrence.key)}`, source_namespace: 'osv', source_id: record.id, source_revision_digest: recordDigest,
        scope_id: DEPS_BODY_SCOPE, occurrence, evidence_ids: [lockEvidence, source], observed_at: iso(record.modified), retrieved_at: iso(r.retrieved_at), lifecycle: record.withdrawn ? 'withdrawn' : 'open',
        severity: { original: shown(severity, 100), normalized: normalSeverity(severity) }, confidence: { original: match.reason, normalized: match.state === 'held' ? 'unknown' : 'high' },
        provenance_claim: 'OSV record returned for this exact npm name and version, whose public registry identity matched the lock entry' };
      observations.push(observation); components.osv.push(observation.observation_id);
      groupOf(e, match.flaw_ref?.slice('github-advisory:'.length) ?? record.id).osv.push({ observation, record, match });
    }
  }

  // DFBASE-11: Dependabot, an optional source the caller already read. This lockfile's scope is the alerts that name it.
  const mappable = entries.filter(reportable);
  let alertOrdinal = 0;
  for (const [index, raw] of (dependabot?.state === 'not_configured' ? [] : dependabot?.alerts ?? []).entries()) {
    const located = z.object({ dependency: z.object({ manifest_path: z.string(), package: z.object({ ecosystem: z.string() }) }) }).safeParse(raw);
    if (!located.success || located.data.dependency.manifest_path !== path || located.data.dependency.package.ecosystem.toLowerCase() !== 'npm') continue; // outside this scope: the run summary counts it
    const screenedDigest = dependabot?.screened_alert_digests?.[index];
    if (screenedDigest && evidenceHash.safeParse(screenedDigest).success) {
      quarantine('dependabot', screenedDigest, alertOrdinal++, 'credential_shaped_evidence', iso(dependabot!.retrieved_at));
      continue;
    }
    const text = JSON.stringify(raw), artifact = sha256(text), ordinal = alertOrdinal++, alert = Alert.safeParse(raw);
    let screened = alert.success;
    try { safeSourceText(text, 0); } catch { screened = false; }
    if (!alert.success || !screened) { quarantine('dependabot', artifact, ordinal, alert.success ? 'credential_shaped_evidence' : 'unsupported_alert_schema', iso(dependabot!.retrieved_at)); continue; }
    const a = alert.data, range = alertRange(a.security_vulnerability?.vulnerable_version_range);
    const source = cite({ evidence_id: `ev-alert-${a.number}`, sha256: artifact, bytes: Buffer.byteLength(text), media_type: 'application/json', classification: 'restricted', kind: 'dependabot-alert',
      origin: `GitHub Dependabot alert ${a.number}`, captured_at: iso(dependabot!.retrieved_at), artifact_id: null, git: null });
    const base = { kind: 'source_observation' as const, source_namespace: 'github.dependabot', source_id: String(a.number), source_revision_digest: artifact, scope_id: DEPS_BODY_SCOPE, evidence_ids: [lockEvidence, source],
      observed_at: iso(a.updated_at ?? a.created_at ?? dependabot!.retrieved_at), retrieved_at: iso(dependabot!.retrieved_at), lifecycle: 'open',
      severity: { original: shown(a.security_advisory.severity ?? '', 100), normalized: normalSeverity(a.security_advisory.severity) }, confidence: { original: 'github-dependabot-alert', normalized: 'unknown' as const } };
    const matches = range === null ? [] : mappable.filter(e => e.name === a.dependency.package.name && semver.satisfies(e.version, range, { includePrerelease: true }));
    if (!matches.length) {
      const coordinates = { kind: 'unsupported' as const, reason: range === null ? 'alert_range_unsupported' : 'no_matching_occurrence', locations: [path] };
      const observation: SourceObservation = { ...base, observation_id: `obs-${short('dependabot', a.number, 'none')}`, occurrence: { ...coordinates, key: occurrenceKey(coordinates) },
        provenance_claim: 'Open Dependabot alert for this lockfile with no lock entry of its package inside its vulnerable range' };
      observations.push(observation); components.dependabot.push(observation.observation_id);
      dispositions.push({ observation_id: observation.observation_id, kind: 'held', reason: coordinates.reason === 'no_matching_occurrence' ? 'alert_without_occurrence' : coordinates.reason, attribution: ASSESSOR, evidence_ids: [source], finding_id: null, quarantine_receipt_id: null });
    }
    for (const e of matches) {
      const occurrence = dependencyOccurrence(path, e);
      const observation: SourceObservation = { ...base, observation_id: `obs-${short('dependabot', a.number, occurrence.key)}`, occurrence, provenance_claim: 'Open Dependabot alert for this lockfile; the lock entry\'s version is inside its vulnerable range' };
      observations.push(observation); components.dependabot.push(observation.observation_id);
      groupOf(e, a.security_advisory.ghsa_id).alerts.push({ observation, alert: a });
    }
  }

  // DFBASE-12: a finding is one flaw at one lock occurrence. Observations merge only on the same occurrence and GHSA.
  const findings: ReportFinding[] = [], inputs: DepsFindingInput[] = [], cves = new Map<string, string[]>();
  for (const g of [...groups.values()].sort((a, b) => bytewise(a.entry.path, b.entry.path) || bytewise(a.flaw, b.flaw))) {
    const affected = g.osv.filter(o => o.match.state === 'affected'), held = g.osv.filter(o => o.match.state === 'held'), outside = g.osv.filter(o => o.match.state === 'not-affected');
    if (!affected.length && !held.length && !g.alerts.length) {
      // Every source that named this flaw here says the installed version is outside its range: retained, refuted.
      for (const o of outside) dispositions.push({ observation_id: o.observation.observation_id, kind: 'refuted', reason: 'outside_affected_range', attribution: ASSESSOR, evidence_ids: o.observation.evidence_ids, finding_id: null, quarantine_receipt_id: null });
      continue;
    }
    const range = affected.length && !held.length && !outside.length ? osvAffected(affected[0]!.record, g.entry.name) : !g.osv.length ? alertAffected(g.alerts[0]!.alert) : null;
    const holds = [...new Set([...held.map(o => o.match.reason), ...outside.length ? ['source_disagreement'] : [], ...g.entry.kind === 'registry' && !verified.has(g.entry.path) ? ['identity_not_checked'] : [],
      ...g.entry.kind === 'held' ? [g.entry.hold_reason ?? 'unsupported_entry'] : [], ...range ? [] : ['affected_range_unreadable']])].filter(h => /^[a-z][a-z0-9_]*$/.test(h));
    const id = `deps-${short(path, g.entry.path, g.flaw)}`, members = [...g.osv.map(o => o.observation), ...g.alerts.map(a => a.observation)];
    const aliases = [...new Set([g.flaw, ...g.osv.flatMap(o => [o.record.id, ...o.record.aliases ?? []]), ...g.alerts.flatMap(a => [a.alert.security_advisory.ghsa_id, ...a.alert.security_advisory.cve_id ? [a.alert.security_advisory.cve_id] : []])])]
      .filter(s => CVE.test(s) || GHSA.test(s) || s === g.flaw).sort(bytewise);
    for (const cve of aliases.filter(s => CVE.test(s))) cves.set(JSON.stringify([g.entry.path, cve]), [...cves.get(JSON.stringify([g.entry.path, cve])) ?? [], id]);
    const summary = g.osv.find(o => o.record.summary)?.record.summary ?? g.alerts.find(a => a.alert.security_advisory.summary)?.alert.security_advisory.summary ?? '';
    findings.push({ finding_id: id, observation_ids: members.map(o => o.observation_id), scope_ids: [DEPS_BODY_SCOPE], occurrence_keys: [members[0]!.occurrence.key], aliases,
      title: shown(`${g.entry.name} ${g.entry.version}: ${g.flaw}`, 190), summary: shown(summary, 1000),
      assessment: { provenance: outside.length ? 'conflicting' : 'verified', validity: 'unreviewed', dependency: holds.length ? 'unknown' : 'affected', currentness: 'current', exposure: 'unverified', breaker: 'not_attempted',
        assessor: ASSESSOR, evidence_ids: [...new Set(members.flatMap(o => o.evidence_ids as string[]))], profile_digest: null, holds },
      recommendation_ids: [], reproduction_receipt_ids: [] });
    inputs.push({ finding_id: id, entry: g.entry.path, held: holds.length > 0, current: true, affected: range ?? { intervals: [], versions: [] } });
  }
  // A CVE shared by two different flaws on one occurrence links them and holds both; it never merges them (DFINT-5).
  const related = new Map<string, Set<string>>();
  for (const ids of cves.values()) if (ids.length > 1) for (const id of ids) related.set(id, new Set([...related.get(id) ?? [], ...ids.filter(x => x !== id)]));
  for (const [id, others] of related) {
    const f = findings.find(x => x.finding_id === id)!, input = inputs.find(x => x.finding_id === id)!;
    if (!f.assessment.holds.includes('cve_only_match')) f.assessment.holds.push('cve_only_match');
    f.assessment.dependency = 'unknown'; input.held = true;
    f.summary = shown(`${f.summary} Shares a CVE with ${[...others].sort(bytewise).join(', ')}; not merged.`.trim(), 1200);
  }

  // DFBASE-13: fix facts. Each proposed candidate's identity, its own OSV answer and both registry manifests are verified here.
  const plan = planCandidates(lock, inputs);
  const requests = candidateRequests(plan), candidateKey = (r: { name: string; candidate: string }) => JSON.stringify([r.name, r.candidate]);
  for (const r of requests) {
    if (Object.hasOwn(state.candidates, candidateKey(r))) continue;
    try {
      const response = await registry.json(`${REGISTRY}/${encodeURIComponent(r.name)}/${encodeURIComponent(r.candidate)}`), m = RegistryManifest.safeParse(response.body);
      const ok = m.success && m.data.name === r.name && m.data.version === r.candidate && /^https:\/\/registry\.npmjs\.org\//.test(m.data.dist.tarball) && /^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(m.data.dist.integrity);
      state.candidates[candidateKey(r)] = { identity_verified: ok, manifest: ok ? manifestFacts(m.data) : null, confirmed_at: iso(response.retrieved_at) };
    } catch (error) {
      if (error instanceof DepsCheckError) throw error;
      state.candidates[candidateKey(r)] = { identity_verified: false, manifest: null, confirmed_at: new Date(now()).toISOString() };
    }
    await saveRegistry();
  }
  await saveRegistry(true);
  const publicCandidates = requests.filter(r => state.candidates[candidateKey(r)]!.identity_verified);
  const candidateOccurrences = publicCandidates.map(r => ({ entry: r.entry, name: r.name, version: r.candidate, resolved: '', integrity: '', dev: false, optional: false }));
  // The candidate's query starts from the records this run already read, so no advisory is fetched twice.
  if (candidateOccurrences.length && !state.candidate_osv) state.candidate_osv = { quarantined: [], hits: [], seen_tokens: [], records: structuredClone(osvState.records ?? []), pending_ids: [], pages: [], phase: 'queries',
    remaining: [...new Map(candidateOccurrences.map(o => [JSON.stringify([o.name, o.version]), { package: { name: o.name, ecosystem: 'npm' as const }, version: o.version }])).values()] };
  const candidateOsv = candidateOccurrences.length ? await queried(candidateOccurrences, 'candidate_osv') : null;
  const occurrenceEvidence: Record<string, DepsOccurrenceEvidence> = {};
  for (const r of requests) {
    const c = state.candidates[candidateKey(r)]!, installed = registryEntries.find(e => e.path === r.entry);
    const answers = (candidateOsv?.hits ?? []).filter(h => h.name === r.name && h.version === r.candidate).map(h => {
      const record = candidateOsv!.records.find(x => x.record.id === h.id);
      return record ? osvMatch(record.record, r.name, r.candidate).state : 'held' as const; // a quarantined record cannot clear a candidate
    });
    occurrenceEvidence[r.entry] = { identity_verified: c.identity_verified,
      candidate_osv: !c.identity_verified ? 'unknown' : answers.includes('affected') ? 'affected' : answers.includes('held') ? 'held' : 'clear',
      installed_manifest: installed && verified.get(installed.path)?.manifest, candidate_manifest: c.manifest };
  }
  const facts = classify(lock, lockfile.overrides, inputs, plan, occurrenceEvidence);

  // DFBASE-14: findings on one occurrence with the same class share one recommendation, whose category is the class.
  const recommendations: SecurityReport['recommendations'] = [], plans = new Map(plan.occurrences.map(o => [o.entry, o]));
  const byRecommendation = new Map<string, DepsFindingFacts[]>();
  for (const f of facts.findings) byRecommendation.set(JSON.stringify([f.entry, f.class]), [...byRecommendation.get(JSON.stringify([f.entry, f.class])) ?? [], f]);
  for (const [, members] of [...byRecommendation].sort(([a], [b]) => bytewise(a, b))) {
    const first = members[0]!, o = plans.get(first.entry)!, id = `rec-${short(path, first.entry, first.class)}`, upgrade = (['range_change_needed', 'multi_entry_upgrade', 'single_entry_upgrade'] as DepsFixClass[]).includes(first.class);
    const open = upgrade ? o.finding_ids.filter(x => !o.closes.includes(x)) : [];
    recommendations.push({ recommendation_id: id, finding_ids: members.map(f => f.finding_id), category: `dependency.${first.class}`, rationale: shown(RATIONALE[first.class](first, o, facts.lockfile_version, format), 2000),
      scope_ids: [DEPS_BODY_SCOPE], evidence_ids: [lockEvidence], preconditions: preconditionsFor(first.class, format),
      uncertainties: [...UNCERTAINTIES, ...open.length ? [`This upgrade does not close ${open.slice(0, 10).join(', ')}${open.length > 10 ? ` and ${open.length - 10} more` : ''} on the same occurrence.`] : []], requires_human_review: true });
    for (const f of members) findings.find(x => x.finding_id === f.finding_id)!.recommendation_ids = [id];
  }

  // DFBASE-15: coverage. Any entry not checked leaves OSV incomplete; a quarantined member leaves the union unproven.
  const quarantinedOsv = (osvState.quarantined ?? []).length > 0, quarantinedAlerts = components.dependabot.some(id => id.startsWith('qobs-'));
  const osvComplete = !quarantinedOsv && notChecked.size === 0;
  const inventory: DepsBodyComponent = { id: DEPS_COMPONENTS.inventory, version: DEPS_LOCK_VERSION, state: 'complete', required: true, reasons: [],
    pagination_complete: true, source_revision: `blob:${lockfile.git_blob}`, retrieved_at: startedAt, baseline_receipt: `blob-${lockfile.git_blob}`, observation_ids: [] };
  const osvRead = reportHash([(osvState.hits ?? []).map(h => [h.name, h.version, h.id, h.modified]), [...records.keys()].sort(bytewise)]);
  const osvComponent: DepsBodyComponent = { id: DEPS_COMPONENTS.osv, version: `${DEPS_OSV_VERSION}/${DEPS_IDENTITY_VERSION}`, state: osvComplete ? 'complete' : 'incomplete', required: true,
    reasons: [...notChecked.size ? ['identities_not_checked'] : [], ...quarantinedOsv ? ['quarantined_advisory_evidence'] : []], pagination_complete: true,
    source_revision: `read:${osvRead}`, retrieved_at: osvState.pages.length ? iso(osvState.pages.at(-1)!.retrieved_at) : startedAt, baseline_receipt: `osv-read-${osvRead.slice(0, 32)}`, observation_ids: components.osv };
  const alertRead = dependabot ? reportHash([dependabot.state, dependabot.reason, components.dependabot]) : null;
  const dependabotComponent: DepsBodyComponent = { id: DEPS_COMPONENTS.dependabot, version: DEPS_DEPENDABOT_VERSION, required: false, observation_ids: components.dependabot,
    state: !dependabot ? 'not_selected' : dependabot.state === 'complete' && quarantinedAlerts ? 'incomplete' : dependabot.state,
    reasons: !dependabot ? ['not_supplied'] : [...dependabot.state !== 'complete' ? [/^[a-z][a-z0-9_]*$/.test(dependabot.reason ?? '') ? dependabot.reason! : 'unspecified'] : [], ...quarantinedAlerts ? ['quarantined_alert_evidence'] : []],
    pagination_complete: dependabot?.state === 'complete', source_revision: alertRead ? `read:${alertRead}` : 'not selected', retrieved_at: dependabot ? iso(dependabot.retrieved_at) : startedAt,
    baseline_receipt: dependabot?.state === 'complete' && !quarantinedAlerts ? `dependabot-read-${alertRead!.slice(0, 32)}` : null };
  const dependabotDone = !dependabot || dependabot.state === 'not_configured' || (dependabot.state === 'complete' && !quarantinedAlerts);
  const coverage: DepsReportBody['coverage'] = { state: osvComplete && dependabotDone ? 'complete' : 'partial',
    union_status: !quarantinedOsv && !quarantinedAlerts && (!dependabot || dependabot.state !== 'incomplete') ? 'proven' : 'incomplete', components: [inventory, osvComponent, dependabotComponent] };

  // DFBASE-14: over a single-report limit the lockfile is held with its totals. Nothing is truncated and no body is built.
  const counts = { observations: observations.length, findings: findings.length, dispositions: dispositions.length, recommendations: recommendations.length, evidence: evidence.size };
  const over = (totals: Record<keyof typeof DEPS_REPORT_LIMITS, number>): DepsCheckResult | null => (Object.keys(DEPS_REPORT_LIMITS) as (keyof typeof DEPS_REPORT_LIMITS)[]).some(k => totals[k] > DEPS_REPORT_LIMITS[k])
    ? { outcome: 'held', reason: 'discovery.report_limit', totals, limits: DEPS_REPORT_LIMITS, requests: state.requests } : null;
  const overCount = over({ ...counts, bytes: 0 });
  if (overCount) return overCount;
  const byReason: Record<string, number> = {};
  for (const reason of notChecked.values()) byReason[reason] = (byReason[reason] ?? 0) + 1;
  const names = new Map(entries.map(e => [e.path, e]));
  const extension = DepsDiscoveryExtension.parse({ schema: DEPS_EXTENSION_SCHEMA, check: { id: DEPS_CHECK_ID, version: DEPS_CHECK_VERSION, facts_version: DEPS_FACTS_VERSION },
    lockfile: { path, lockfile_version: lock.lockfile_version, parser_version: lock.parser_version }, registry_count: registryEntries.length, first_party_count: entries.filter(e => e.kind === 'first_party').length,
    fix_facts: facts.findings.map(f => ({ ...f, entry: shown(f.entry, 500), package: names.get(f.entry)?.name ?? null, installed: names.get(f.entry)?.version ?? null,
      blocking_dependents: f.blocking_dependents.map(d => ({ path: shown(d.path, 300), field: d.field, range: shown(d.range, 100) })), related_finding_ids: [...related.get(f.finding_id) ?? []].sort(bytewise) })),
    not_checked: { total: notChecked.size, by_reason: byReason, entries: [...notChecked].sort(([a], [b]) => bytewise(a, b)).slice(0, DEPS_NOT_CHECKED_SHOWN).map(([entry, reason]) => ({ entry: shown(entry, 300), reason })) } });
  const body: DepsReportBody = { check: { id: DEPS_CHECK_ID, version: DEPS_CHECK_VERSION }, lockfile: { path, git_blob: lockfile.git_blob, sha256: lockfile.sha256 }, observations,
    findings, dispositions, evidence: [...evidence.values()], recommendations, coverage, extension };
  // The envelope and the keys the join adds are bounded; leave room for them under the 10 MiB document limit.
  const overBytes = over({ ...counts, bytes: Buffer.byteLength(JSON.stringify(body)) + 512 * observations.length + 65536 });
  if (overBytes) return overBytes;
  live();
  return { outcome: 'report', body, facts: facts.findings, quarantined_osv: (osvState.quarantined ?? []).map(q => q.id), requests: state.requests };
}

/** What only the caller knows (DFBASE-14): the hosted run supplies it; so does any other entry point. */
export interface DepsReportEnvelope {
  producer: SecurityReport['producer']; report_id: string; revision: number; previous_digest: string | null; generated_at: string;
  /** Exactly one scope, whose only path is the lockfile. */
  snapshot: SecurityReport['snapshot']; profile: SecurityReport['profile'];
}
/**
 * Join one body with one envelope into a validated DFRPT report (DFBASE-3, DFBASE-14). It computes what depends on the
 * snapshot (observation keys, coverage digests, the content digest), refuses a body that does not fit the envelope, and
 * returns the canonical bytes only after the report library's parse, graph and source-union checks pass.
 */
export function joinDepsReport(body: DepsReportBody, envelope: DepsReportEnvelope): { report: SecurityReport; bytes: string } {
  const snapshot = ReportSnapshot.parse(envelope.snapshot), profile = ReportProfile.parse(envelope.profile), scope = snapshot.scopes[0]!;
  if (snapshot.scopes.length !== 1 || scope.paths.length !== 1 || scope.paths[0] !== body.lockfile.path) throw Error('deps_report_scope');
  for (const o of body.observations) {
    if (o.kind !== 'source_observation') continue;
    const { key, ...coordinates } = o.occurrence;
    if (o.scope_id !== DEPS_BODY_SCOPE || key !== occurrenceKey(coordinates) || (o.occurrence.kind === 'dependency' ? o.occurrence.manifest !== body.lockfile.path : o.occurrence.kind !== 'unsupported' || o.occurrence.locations.some(l => l !== body.lockfile.path))) throw Error('deps_report_body_mismatch');
  }
  const observations = body.observations.map(o => o.kind === 'source_observation' ? { ...o, scope_id: scope.scope_id } : o);
  const keys = new Map(observations.map(o => [o.observation_id, observationKey(o, snapshot)]));
  const scopeDigest = reportHash(scope);
  const components = body.coverage.components.map(c => {
    const mapped = c.observation_ids.map(id => { const k = keys.get(id); if (!k) throw Error('deps_report_body_mismatch'); return k; }), setDigest = reportHash([...mapped].sort());
    return { id: c.id, version: c.version, configuration_digest: reportHash([body.check, c.id, c.version, profile.digest]), scope_digest: scopeDigest, source_revision: c.source_revision, retrieved_at: c.retrieved_at,
      state: c.state, required: c.required, reasons: c.reasons, pagination_complete: c.pagination_complete, checkpoint: null, observed_count: mapped.length, mapped_count: mapped.length, missing_count: 0,
      observed_set_digest: setDigest, mapped_set_digest: setDigest, mapped_observation_keys: mapped, baseline_receipt: c.baseline_receipt };
  });
  const report = sealReport({ document_type: 'defensive-security-report' as const, schema_version: '1.0' as const, producer: envelope.producer, report_id: envelope.report_id, revision: envelope.revision,
    previous_digest: envelope.previous_digest, generated_at: envelope.generated_at, snapshot, profile, coverage: { state: body.coverage.state, union_status: body.coverage.union_status, components },
    extensions: { [DEPS_EXTENSION]: DepsDiscoveryExtension.parse(body.extension) as z.core.util.JSONType },
    observations, findings: body.findings.map(f => ({ ...f, scope_ids: [scope.scope_id], assessment: { ...f.assessment, profile_digest: profile.digest } })), dispositions: body.dispositions,
    evidence: body.evidence.map(e => ({ ...e, git: e.git ? { sha: snapshot.sha, blob: e.git.blob, path: e.git.path } : null })),
    recommendations: body.recommendations.map(r => ({ ...r, scope_ids: [scope.scope_id] })) });
  const bytes = canonicalJson(report), checked = parseSecurityReport(bytes, [envelope.producer.namespace]);
  if (checked.document_type !== 'defensive-security-report' || checked.content_digest !== report.content_digest) throw Error('deps_report_invalid');
  return { report: checked, bytes };
}
