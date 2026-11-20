// DFRPT-1–8/14/15, DFRPT-17–21: portable report data; no acquisition, database, Work or execution authority.
import { z } from 'zod';
import { evidenceHash, gitSha, reportPath, repositoryName, screenedJson } from './security-primitives.ts';
import { canonicalJson, documentDigest, parseReportJson, reportHash } from './security-report-json.ts';
import { npmExactVersion, npmPackageName } from './security-npm.ts';
const text = z.string().max(4096);
const id = z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9_.:@/-]*$/);
const artifactId = z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/);
const namespace = z.string().min(1).max(100).regex(/^[a-z][a-z0-9_.:-]*$/);
const count = z.number().int().nonnegative().safe();
const date = z.iso.datetime();
const list = <T extends z.ZodType>(schema: T) => z.array(schema).max(1000);
export const ReportReference = z.union([id, z.strictObject({ part_id: id, local_id: id })]);
const refs = list(ReportReference);
export const ReportScope = z.strictObject({ scope_id: id, service: id, paths: list(reportPath).min(1) });
export const ReportSnapshot = z.strictObject({ target_id: id, repository_id: z.string().regex(/^[1-9][0-9]{0,18}$/), repository: repositoryName, sha: gitSha, scopes: list(ReportScope).min(1) });
// DFRPT-17: a local document's snapshot. Each identity field and the commit may be null, and each null is named in the
// root `unavailable` list with one of that field's reasons. `tree` says what was read instead of a commit.
export const LocalReportSnapshot = z.strictObject({ target_id: id.nullable(), repository_id: ReportSnapshot.shape.repository_id.nullable(), repository: repositoryName.nullable(), sha: gitSha.nullable(), scopes: list(ReportScope).min(1),
  tree: z.strictObject({ digest: evidenceHash, dirty: z.boolean(), base_sha: gitSha.nullable() }) });
const UNAVAILABLE = { 'snapshot.target_id': ['no_repository_identity'], 'snapshot.repository_id': ['no_repository_identity'], 'snapshot.repository': ['no_repository_identity'],
  'snapshot.sha': ['not_a_commit', 'dirty_tree', 'unsupported_object_format'], 'snapshot.tree.base_sha': ['not_a_commit', 'unsupported_object_format'] } as const;
type UnavailableField = keyof typeof UNAVAILABLE;
export const ReportUnavailable = z.strictObject({ field: z.enum(Object.keys(UNAVAILABLE) as [UnavailableField, ...UnavailableField[]]), reason: z.enum(['no_repository_identity', 'not_a_commit', 'dirty_tree', 'unsupported_object_format']) });
export const ReportProfile = z.strictObject({ id, revision: z.number().int().positive().safe(), digest: evidenceHash });
// DFRPT-20: `not_selected` is a source the caller chose not to consult; `not_configured` is one the target does not offer.
const componentState = z.enum(['complete', 'incomplete', 'failed', 'not_authorized', 'unsupported', 'not_configured', 'not_selected']);
export const ReportCoverageComponent = z.strictObject({
  id, version: id, configuration_digest: evidenceHash, scope_digest: evidenceHash,
  source_revision: text, retrieved_at: date, state: componentState, required: z.boolean(), reasons: list(id),
  pagination_complete: z.boolean(), checkpoint: text.nullable(), observed_count: count, mapped_count: count, missing_count: count,
  observed_set_digest: evidenceHash, mapped_set_digest: evidenceHash, mapped_observation_keys: list(evidenceHash), baseline_receipt: id.nullable(),
});
export const ReportCoverage = z.strictObject({ state: z.enum(['complete', 'partial', 'failed', 'cancelled']), union_status: z.enum(['proven', 'incomplete', 'failed', 'not_comparable']), components: list(ReportCoverageComponent) });
export const ReportOccurrence = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('dependency'), key: evidenceHash, ecosystem: z.literal('npm'), package: npmPackageName, version: z.union([npmExactVersion, z.literal('unknown')]), manifest: reportPath, entry: reportPath }),
  z.strictObject({ kind: z.literal('code'), key: evidenceHash, rule: id, rule_version: id, path: reportPath, git_blob: gitSha, start_line: z.number().int().positive().safe(), end_line: z.number().int().positive().safe(), fingerprint: text }),
  z.strictObject({ kind: z.literal('unsupported'), key: evidenceHash, reason: id, locations: list(reportPath) }),
]);
// DFRPT-17: in a local document only, a code occurrence may have no Git blob; it then carries the cited file's content hash.
export const LocalReportOccurrence = z.discriminatedUnion('kind', [
  ReportOccurrence.options[0],
  z.strictObject({ kind: z.literal('code'), key: evidenceHash, rule: id, rule_version: id, path: reportPath, git_blob: gitSha.nullable(), content_sha256: evidenceHash.optional(), start_line: z.number().int().positive().safe(), end_line: z.number().int().positive().safe(), fingerprint: text }),
  ReportOccurrence.options[2],
]);
const severity = z.enum(['unknown', 'info', 'low', 'medium', 'high', 'critical']);
export const SourceObservation = z.strictObject({
  kind: z.literal('source_observation'), observation_id: id, source_namespace: namespace, source_id: z.string().min(1).max(300), source_revision_digest: evidenceHash,
  scope_id: id, occurrence: ReportOccurrence, evidence_ids: refs, observed_at: date, retrieved_at: date, lifecycle: z.string().min(1).max(100),
  severity: z.strictObject({ original: z.string().max(200), normalized: severity }), confidence: z.strictObject({ original: z.string().max(200), normalized: z.enum(['unknown', 'low', 'medium', 'high']) }), provenance_claim: text,
});
export const QuarantinedObservation = z.strictObject({ kind: z.literal('quarantined_observation'), observation_id: id, quarantine_receipt_id: id, source_artifact_digest: evidenceHash, ordinal: count, reason: id, captured_by: id, captured_at: date });
export const ReportObservation = z.discriminatedUnion('kind', [SourceObservation, QuarantinedObservation]);
export const LocalSourceObservation = z.strictObject({ ...SourceObservation.shape, occurrence: LocalReportOccurrence });
export const LocalReportObservation = z.discriminatedUnion('kind', [LocalSourceObservation, QuarantinedObservation]);
export const ReportAssessment = z.strictObject({
  provenance: z.enum(['verified', 'unverified', 'conflicting']), validity: z.enum(['unreviewed', 'supported', 'refuted', 'disputed']), dependency: z.enum(['affected', 'not_affected', 'unknown', 'not_applicable']),
  currentness: z.enum(['current', 'historical', 'drifted', 'unknown']), exposure: z.enum(['unverified', 'possible', 'observed_in_isolation', 'ruled_out_for_profile']),
  breaker: z.enum(['reproduced_in_isolation', 'not_reproduced', 'inconclusive', 'not_attempted', 'out_of_scope']), assessor: id, evidence_ids: refs, profile_digest: evidenceHash.nullable(), holds: list(id),
});
export const ReportFinding = z.strictObject({ finding_id: id, observation_ids: refs.min(1), scope_ids: list(id).min(1), occurrence_keys: list(evidenceHash).min(1), aliases: list(z.string().max(200)), title: z.string().min(1).max(200), summary: text, assessment: ReportAssessment, recommendation_ids: refs, reproduction_receipt_ids: refs });
export const ReportDisposition = z.strictObject({ observation_id: ReportReference, kind: z.enum(['grouped', 'held', 'refuted', 'out_of_scope', 'quarantined']), reason: id, attribution: id, evidence_ids: refs, finding_id: ReportReference.nullable(), quarantine_receipt_id: id.nullable() });
export const ReportEvidence = z.strictObject({ evidence_id: id, sha256: evidenceHash, bytes: count, media_type: z.string().min(1).max(100), classification: z.enum(['public', 'restricted']), kind: id, origin: text, captured_at: date, artifact_id: artifactId.nullable(), git: z.strictObject({ sha: gitSha, blob: gitSha, path: reportPath }).nullable() });
export const ReportRecommendation = z.strictObject({ recommendation_id: id, finding_ids: refs.min(1), category: id, rationale: text, scope_ids: list(id).min(1), evidence_ids: refs, preconditions: list(text), uncertainties: list(text), requires_human_review: z.literal(true) });
const envelope = {
  schema_version: z.literal('1.0'), producer: z.strictObject({ namespace, product: id, version: id }), report_id: id, revision: z.number().int().positive().safe(), previous_digest: evidenceHash.nullable(), generated_at: date,
  content_digest: evidenceHash, snapshot: ReportSnapshot, profile: ReportProfile, coverage: ReportCoverage, extensions: z.record(namespace, z.json()).optional(),
};
export const SecurityReport = z.strictObject({
  document_type: z.literal('defensive-security-report'), ...envelope,
  observations: list(ReportObservation), findings: list(ReportFinding), dispositions: list(ReportDisposition), evidence: list(ReportEvidence), recommendations: list(ReportRecommendation),
  part_of: z.strictObject({ report_id: id, revision: z.number().int().positive().safe(), part_id: id }).optional(),
});
// DFRPT-17: the fourth type. The report's body unchanged, no revision chain, a nullable snapshot and the `unavailable` list. Never importable.
const { revision: _revision, previous_digest: _previous, snapshot: _snapshot, ...localEnvelope } = envelope;
export const SecurityReportLocal = z.strictObject({
  document_type: z.literal('defensive-security-report-local'), ...localEnvelope, snapshot: LocalReportSnapshot, unavailable: list(ReportUnavailable),
  observations: list(LocalReportObservation), findings: list(ReportFinding), dispositions: list(ReportDisposition), evidence: list(ReportEvidence), recommendations: list(ReportRecommendation),
});
export const SecurityReportSet = z.strictObject({ document_type: z.literal('defensive-security-report-set'), ...envelope,
  parts: z.array(z.strictObject({ part_id: id, report_id: id, revision: z.number().int().positive().safe(), content_digest: evidenceHash, bytes: count.max(10 * 1024 * 1024), artifact_id: artifactId, observation_count: count.max(1000), finding_count: count.max(1000), disposition_count: count.max(1000) })).min(1),
  totals: z.strictObject({ observations: count, findings: count, dispositions: count }), union_observation_set_digest: evidenceHash,
});
export const SecurityReportView = z.strictObject({ document_type: z.literal('defensive-security-report-view'), schema_version: z.literal('1.0'),
  source_report: z.strictObject({ producer_namespace: namespace, report_id: id, revision: z.number().int().positive().safe(), content_digest: evidenceHash }), generated_at: date, view_digest: evidenceHash,
  redactions: list(z.strictObject({ field: id, reason: id })), summary: z.strictObject({ source_sha: gitSha, coverage_state: ReportCoverage.shape.state, observation_count: count, finding_count: count, held_count: count, quarantined_count: count,
    findings: list(z.strictObject({ public_id: id, title: z.string().max(200), severity, exposure_status: ReportAssessment.shape.exposure, limitations: list(text), recommended_actions: list(text) })),
  }),
});
export type SecurityReport = z.infer<typeof SecurityReport>;
export type SecurityReportSet = z.infer<typeof SecurityReportSet>;
export type SecurityReportLocal = z.infer<typeof SecurityReportLocal>;
/** A report or a local document: what one reference graph is checked over. */
export type GraphReport = SecurityReport | SecurityReportLocal;
export type AnyReportSnapshot = GraphReport['snapshot'];
export type SecurityReportView = z.infer<typeof SecurityReportView>;
export type ReportObservation = z.infer<typeof ReportObservation>;
export type LocalReportObservation = z.infer<typeof LocalReportObservation>;
export type AnyReportObservation = ReportObservation | LocalReportObservation;
export type ReportFinding = z.infer<typeof ReportFinding>;
export type ReportReference = z.infer<typeof ReportReference>;
export type ReportDocument = SecurityReport | SecurityReportSet;
/**
 * DFRPT-21: an occurrence key is derived from the occurrence's coordinates in a fixed order, never chosen. Producers call
 * this, and the graph check refuses a document whose key differs. A local code occurrence with no Git blob derives from
 * its `content_sha256` (DFRPT-17).
 */
type Unkeyed<T> = T extends unknown ? Omit<T, 'key'> : never;
export type ReportOccurrenceCoordinates = Unkeyed<z.infer<typeof LocalReportOccurrence>>;
export function occurrenceKey(o: ReportOccurrenceCoordinates): string {
  return o.kind === 'dependency' ? reportHash(['dependency', o.ecosystem, o.package, o.version, o.manifest, o.entry])
    : o.kind === 'code' ? reportHash(['code', o.rule, o.rule_version, o.path, o.git_blob ?? o.content_sha256 ?? fail('report_local_occurrence'), o.start_line, o.end_line, o.fingerprint])
    : reportHash(['unsupported', o.reason, [...o.locations].sort((a, b) => a < b ? -1 : a > b ? 1 : 0)]);
}
function fail(code: string): never { throw Error(code); }
/**
 * DFRPT-17: `tree.digest`, over the files a producer read: the SHA-256 of the canonical JSON of `[path, sha256]` pairs,
 * sorted bytewise by repository-relative path. Each path is taken as written (DFRPT-1): `%` is an ordinary character,
 * and one path the rule refuses (a backslash, a control character, over 500 characters) refuses the whole tree.
 */
export function treeDigest(files: readonly { path: string; sha256: string }[]): string {
  const pairs = files.map(f => [reportPath.parse(f.path), evidenceHash.parse(f.sha256)] as const).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  unique(pairs.map(([path]) => path));
  return reportHash(pairs);
}
export function referenceKey(ref: ReportReference, localPart = '') { return typeof ref === 'string' ? `${localPart}\0${ref}` : `${ref.part_id}\0${ref.local_id}`; }
/** DFRPT-17: a local snapshot keys on the literal `local` and its tree digest, so a local key never equals an importable one. */
export function observationKey(o: AnyReportObservation, snapshot: AnyReportSnapshot): string {
  const [repository, revision] = 'tree' in snapshot ? ['local', snapshot.tree.digest] : [snapshot.repository_id, snapshot.sha];
  return o.kind === 'quarantined_observation' ? reportHash(['quarantine', o.source_artifact_digest, o.ordinal]) : reportHash([o.source_namespace, o.source_id, o.source_revision_digest, repository, revision, o.occurrence.key]);
}
export function observationSetDigest(observations: AnyReportObservation[], snapshot: AnyReportSnapshot) { return reportHash(observations.map(o => observationKey(o, snapshot)).sort()); }
function unique(values: string[]) { if (new Set(values).size !== values.length) throw Error('report_duplicate_id'); }
function verifyCoverage(c: SecurityReport['coverage'], observations: AnyReportObservation[], snapshot: AnyReportSnapshot) {
  const keys = new Set(observations.map(o => observationKey(o, snapshot))), mapped = new Set<string>();
  const quarantined = observations.some(o => o.kind === 'quarantined_observation');
  unique(c.components.map(x => x.id));
  for (const s of c.components) {
    unique(s.mapped_observation_keys);
    if (s.state === 'not_selected' && (s.observed_count || s.mapped_count || s.missing_count || s.mapped_observation_keys.length || !s.reasons.length)) throw Error('report_coverage_not_selected');
    if (s.mapped_observation_keys.some(k => !keys.has(k)) || s.mapped_count !== s.mapped_observation_keys.length || reportHash([...s.mapped_observation_keys].sort()) !== s.mapped_set_digest) throw Error('report_coverage_members');
    s.mapped_observation_keys.forEach(k => mapped.add(k));
    if (s.mapped_count + s.missing_count !== s.observed_count || s.state === 'complete' && !s.pagination_complete) throw Error('report_coverage_counts');
    if (c.union_status === 'proven' && (s.state === 'complete' && (!s.baseline_receipt || s.missing_count || s.observed_set_digest !== s.mapped_set_digest))) throw Error('report_union_unproven');
  }
  if (c.union_status === 'proven' && (mapped.size !== keys.size || !c.components.length)) throw Error('report_union_unproven');
  if (c.state === 'complete' && (quarantined || !c.components.some(s => s.state === 'complete') || c.union_status !== 'proven' || c.components.some(s => s.required && s.state !== 'complete'))) throw Error('report_incomplete_coverage');
}
function verifyEnvelope(d: ReportDocument | SecurityReportLocal) {
  const strings = (v: unknown): void => {
    if (typeof v === 'string' && Buffer.byteLength(v) > 4096) throw Error('report_field_bytes');
    if (Array.isArray(v)) v.forEach(strings);
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { strings(k); strings(x); }
  };
  strings(d);
  if ('revision' in d && (d.revision === 1) !== (d.previous_digest === null)) throw Error('report_revision_chain');
  unique(d.snapshot.scopes.map(s => s.scope_id));
  for (const s of d.snapshot.scopes) unique(s.paths);
  if (documentDigest(d) !== d.content_digest) throw Error('report_content_digest');
}
// DFRPT-17: a snapshot field is null if and only if it is listed, with a reason that field can have, and the tree agrees with them.
function verifyLocalSnapshot(d: SecurityReportLocal) {
  const s = d.snapshot, values: Record<UnavailableField, unknown> = { 'snapshot.target_id': s.target_id, 'snapshot.repository_id': s.repository_id, 'snapshot.repository': s.repository, 'snapshot.sha': s.sha, 'snapshot.tree.base_sha': s.tree.base_sha };
  unique(d.unavailable.map(u => u.field));
  const reasons = new Map<UnavailableField, string>(d.unavailable.map(u => [u.field, u.reason]));
  for (const [field, value] of Object.entries(values) as [UnavailableField, unknown][]) {
    const reason = reasons.get(field);
    if ((value === null) !== (reason !== undefined) || reason !== undefined && !(UNAVAILABLE[field] as readonly string[]).includes(reason)) throw Error('report_local_unavailable');
  }
  // A named commit is a clean tree at that commit. Otherwise the reason says which: changed content on a commit, no
  // commit at all (content that is no commit's differs from every commit, so `dirty` is true), or a commit this
  // contract's 40-hex SHA cannot hold.
  const why = reasons.get('snapshot.sha'), base = reasons.get('snapshot.tree.base_sha');
  if (s.sha !== null ? s.tree.dirty || s.tree.base_sha !== s.sha
    : why === 'dirty_tree' ? !s.tree.dirty || s.tree.base_sha === null
    : why === 'not_a_commit' ? !s.tree.dirty || base !== 'not_a_commit'
    : base !== 'unsupported_object_format') throw Error('report_local_tree');
}
const partOf = (r: GraphReport) => 'part_of' in r ? r.part_of?.part_id ?? '' : '';
// Multipart validation shares one global reference graph; parts alone are never factory inputs.
export function validateReportGraph(reports: GraphReport[], parent?: SecurityReportSet) {
  const tables = { observations: new Map<string, AnyReportObservation>(), findings: new Map<string, ReportFinding>(), evidence: new Map<string, z.infer<typeof ReportEvidence>>(), recommendations: new Map<string, z.infer<typeof ReportRecommendation>>() };
  for (const r of reports) {
    const part = partOf(r);
    for (const name of ['observations', 'findings', 'evidence', 'recommendations'] as const) {
      const field = { observations: 'observation_id', findings: 'finding_id', evidence: 'evidence_id', recommendations: 'recommendation_id' }[name];
      const values = r[name] as Record<string, unknown>[]; unique(values.map(x => String(x[field])));
      for (const x of values) (tables[name] as Map<string, unknown>).set(referenceKey(String(x[field]), part), x);
    }
  }
  const requireRef = (name: keyof typeof tables, ref: ReportReference, part: string) => {
    if (!parent && typeof ref !== 'string') throw Error('report_foreign_part');
    const v = tables[name].get(referenceKey(ref, part)); if (!v) throw Error('report_dangling_reference'); return v;
  };
  const covered = new Set<string>(), observedKeys = new Set<string>(), dispositionKeys = new Set<string>();
  for (const r of reports) {
    const part = partOf(r), scopes = new Map(r.snapshot.scopes.map(s => [s.scope_id, s]));
    for (const o of r.observations) {
      const key = observationKey(o, r.snapshot); if (observedKeys.has(key)) throw Error('report_duplicate_observation'); observedKeys.add(key);
      if (o.kind === 'quarantined_observation') continue;
      const scope = scopes.get(o.scope_id); if (!scope) throw Error('report_scope');
      const paths = o.occurrence.kind === 'dependency' ? [o.occurrence.manifest] : o.occurrence.kind === 'code' ? [o.occurrence.path] : o.occurrence.locations;
      if (paths.some(p => !scope.paths.includes(p))) throw Error('report_scope');
      if (o.occurrence.kind === 'code' && o.occurrence.end_line < o.occurrence.start_line) throw Error('report_location');
      // DFRPT-17: no Git blob only where there is no commit, and then the cited file's content hash stands in for it.
      if (o.occurrence.kind === 'code') { const blob = o.occurrence.git_blob, content = 'content_sha256' in o.occurrence ? o.occurrence.content_sha256 : undefined; if ((blob === null) !== (content !== undefined) || blob === null && r.snapshot.sha !== null) throw Error('report_local_occurrence'); }
      // DFRPT-21: a key that differs from the derived value is refused.
      if (occurrenceKey(o.occurrence) !== o.occurrence.key) throw Error('report_occurrence_key');
      for (const ref of o.evidence_ids) requireRef('evidence', ref, part);
    }
    for (const f of r.findings) {
      if (f.scope_ids.some(s => !scopes.has(s))) throw Error('report_scope');
      const obs = f.observation_ids.map(ref => {
        const o = requireRef('observations', ref, part) as AnyReportObservation;
        if (o.kind !== 'source_observation' || !f.scope_ids.includes(o.scope_id) || !f.occurrence_keys.includes(o.occurrence.key)) throw Error('report_finding_members');
        covered.add(referenceKey(ref, part)); return o;
      });
      if (new Set(f.observation_ids.map(ref => referenceKey(ref, part))).size !== obs.length) throw Error('report_duplicate_reference');
      if (f.occurrence_keys.some(k => !obs.some(o => o.kind === 'source_observation' && o.occurrence.key === k))) throw Error('report_occurrence');
      for (const ref of [...f.assessment.evidence_ids, ...f.reproduction_receipt_ids]) requireRef('evidence', ref, part);
      for (const ref of f.recommendation_ids) requireRef('recommendations', ref, part);
      // DFRPT-18: each dimension's neutral value states no claim. `not_applicable` is neutral only where there is no dependency occurrence, and is never stated where there is one.
      const a = f.assessment, onDependency = obs.some(o => o.kind === 'source_observation' && o.occurrence.kind === 'dependency');
      if (a.dependency === 'not_applicable' && onDependency) throw Error('report_assessment_dependency');
      const neutral = a.validity === 'unreviewed' && a.provenance === 'unverified' && (a.dependency === 'unknown' || a.dependency === 'not_applicable') && a.currentness === 'unknown' && a.exposure === 'unverified' && a.breaker === 'not_attempted';
      if (!neutral && (!a.evidence_ids.length || !a.profile_digest)) throw Error('report_assessment_evidence');
      if (f.assessment.profile_digest && f.assessment.profile_digest !== r.profile.digest) throw Error('report_assessment_profile');
      if (f.assessment.exposure === 'observed_in_isolation' && (f.assessment.breaker !== 'reproduced_in_isolation' || !f.reproduction_receipt_ids.length)) throw Error('report_reproduction_evidence');
    }
    for (const d of r.dispositions) {
      const o = requireRef('observations', d.observation_id, part) as AnyReportObservation, key = referenceKey(d.observation_id, part); if (dispositionKeys.has(key)) throw Error('report_duplicate_id'); dispositionKeys.add(key); covered.add(key);
      if (o.kind === 'quarantined_observation' ? d.kind !== 'quarantined' || d.quarantine_receipt_id !== o.quarantine_receipt_id || d.finding_id !== null : d.kind === 'quarantined' || d.quarantine_receipt_id !== null) throw Error('report_quarantine_reference');
      if (d.kind === 'grouped' && !d.finding_id) throw Error('report_grouped_finding');
      if (d.finding_id) { const f = requireRef('findings', d.finding_id, part) as ReportFinding; const findingPart = typeof d.finding_id === 'string' ? part : d.finding_id.part_id; if (!f.observation_ids.some(ref => referenceKey(ref, findingPart) === key)) throw Error('report_grouped_finding'); }
      for (const ref of d.evidence_ids) requireRef('evidence', ref, part);
    }
    for (const a of r.recommendations) {
      if (a.scope_ids.some(s => !scopes.has(s))) throw Error('report_scope');
      for (const ref of a.finding_ids) requireRef('findings', ref, part);
      for (const ref of a.evidence_ids) requireRef('evidence', ref, part);
    }
    verifyCoverage(r.coverage, r.observations, r.snapshot);
  }
  for (const r of reports) for (const o of r.observations) if (!covered.has(referenceKey(o.observation_id, partOf(r)))) throw Error('report_unmapped_observation');
  return tables;
}
export function parseSecurityReport(input: Uint8Array | string, allowedProducers: readonly string[]): ReportDocument | { document_type: 'staged-security-report-part'; part: SecurityReport } {
  const raw = parseReportJson(input);
  const type = (raw as Record<string, unknown> | null)?.document_type;
  if (type === 'defensive-security-report-view') throw Error('report_view_not_importable');
  // DFRPT-17: refused before anything is read from it. A local document is validated by parseLocalSecurityReport, and never becomes a report.
  if (type === 'defensive-security-report-local') throw Error('report_local_not_importable');
  const d = type === 'defensive-security-report-set' ? SecurityReportSet.parse(raw) : SecurityReport.parse(raw);
  if (!allowedProducers.includes(d.producer.namespace)) throw Error('report_producer_unapproved');
  if (canonicalJson(raw) !== canonicalJson(d)) throw Error('report_schema_transform');
  screenedJson(d, 10 * 1024 * 1024); verifyEnvelope(d);
  if (d.document_type === 'defensive-security-report') {
    if (d.part_of) {
      if (d.part_of.report_id === d.report_id || d.coverage.state !== 'partial') throw Error('report_part_identity');
      // Cross-part edges require the parent graph. A parsed part is explicitly staged, never validated intake.
      return { document_type: 'staged-security-report-part' as const, part: d };
    }
    validateReportGraph([d]);
  }
  if (d.document_type === 'defensive-security-report-set') { unique(d.parts.map(p => p.part_id)); unique(d.parts.map(p => p.report_id)); }
  return d;
}
/**
 * DFRPT-17: validate a local document: the same strict body, limits, screening, digest and reference graph as a report.
 * The result is not importable and no producer allow-list applies, since nothing here grants intake authority.
 */
export function parseLocalSecurityReport(input: Uint8Array | string): SecurityReportLocal {
  const raw = parseReportJson(input);
  if ((raw as Record<string, unknown> | null)?.document_type !== 'defensive-security-report-local') throw Error('report_not_local');
  const d = SecurityReportLocal.parse(raw);
  if (canonicalJson(raw) !== canonicalJson(d)) throw Error('report_schema_transform');
  screenedJson(d, 10 * 1024 * 1024); verifyEnvelope(d); verifyLocalSnapshot(d);
  validateReportGraph([d]);
  return d;
}
export function validateReportSet(parent: SecurityReportSet, parts: SecurityReport[]) {
  SecurityReportSet.parse(parent); verifyEnvelope(parent);
  unique(parent.parts.map(p => p.part_id)); unique(parent.parts.map(p => p.report_id));
  if (parts.length !== parent.parts.length) throw Error('report_missing_part');
  const parentScopes = new Map(parent.snapshot.scopes.map(s => [s.scope_id, s]));
  const byPart = new Map<string, SecurityReport>();
  for (const r of parts) { if (!r.part_of || byPart.has(r.part_of.part_id)) throw Error('report_part_identity'); byPart.set(r.part_of.part_id, r); }
  const ordered = parent.parts.map(p => {
    const member = byPart.get(p.part_id); if (!member) throw Error('report_part_identity');
    const r = SecurityReport.parse(member); verifyEnvelope(r); screenedJson(r, 10 * 1024 * 1024);
    const { scopes, ...snapshot } = r.snapshot, { scopes: _, ...expected } = parent.snapshot;
    if (r.report_id === parent.report_id || r.report_id !== p.report_id || r.revision !== p.revision || r.content_digest !== p.content_digest || Buffer.byteLength(canonicalJson(r)) !== p.bytes || r.part_of?.report_id !== parent.report_id || r.part_of.revision !== parent.revision || reportHash(r.producer) !== reportHash(parent.producer) || reportHash(snapshot) !== reportHash(expected) || reportHash(r.profile) !== reportHash(parent.profile) || r.coverage.state !== 'partial') throw Error('report_part_identity');
    if (scopes.some(s => { const scope = parentScopes.get(s.scope_id); return !scope || s.service !== scope.service || s.paths.some(p => !scope.paths.includes(p)); })) throw Error('report_part_scope');
    if (p.observation_count !== r.observations.length || p.finding_count !== r.findings.length || p.disposition_count !== r.dispositions.length) throw Error('report_part_counts');
    return r;
  });
  for (const [key, field] of [['observations', 'observation_count'], ['findings', 'finding_count'], ['dispositions', 'disposition_count']] as const) if (parent.totals[key] !== parent.parts.reduce((n, p) => n + p[field], 0)) throw Error('report_set_counts');
  validateReportGraph(ordered, parent);
  const keys = ordered.flatMap(r => r.observations.map(o => observationKey(o, r.snapshot))).sort();
  if (reportHash(keys) !== parent.union_observation_set_digest) throw Error('report_set_union');
  verifyCoverage(parent.coverage, ordered.flatMap(r => r.observations), parent.snapshot);
  return ordered;
}
export function sealReport<T extends Omit<SecurityReport, 'content_digest'> | Omit<SecurityReportSet, 'content_digest'> | Omit<SecurityReportLocal, 'content_digest'>>(body: T): T & { content_digest: string } {
  return { ...body, content_digest: documentDigest(body as Record<string, unknown>) };
}
export function quarantineReportObservation(artifactDigest: string, ordinal: number, actor: string, capturedAt: string) {
  evidenceHash.parse(artifactDigest); count.parse(ordinal); id.parse(actor); date.parse(capturedAt);
  const opaque = reportHash([artifactDigest, ordinal]);
  return QuarantinedObservation.parse({ kind: 'quarantined_observation', observation_id: `qobs-${opaque}`, quarantine_receipt_id: `quarantine-${opaque}`, source_artifact_digest: artifactDigest, ordinal, reason: 'secret_screening', captured_by: actor, captured_at: capturedAt });
}
export function reportJsonSchemas() { return { report: z.toJSONSchema(SecurityReport), report_set: z.toJSONSchema(SecurityReportSet), public_view: z.toJSONSchema(SecurityReportView), local: z.toJSONSchema(SecurityReportLocal) }; }
