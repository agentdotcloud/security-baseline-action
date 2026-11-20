// DFDISC-8–12, DFRPT-6: compare actual retained source members, never just aggregate counts.
import { reportHash } from './security-report-json.ts';
import { observationKey, type AnyReportObservation as ReportObservation, type AnyReportSnapshot } from './security-report.ts';
export interface CoverageBaseline {
  component_id: string; receipt_id: string; snapshot_digest: string; scope_digest: string; configuration_digest: string;
  state: 'complete' | 'incomplete' | 'failed' | 'not_authorized' | 'unsupported' | 'not_configured' | 'not_selected';
  pagination_complete: boolean; observations: ReportObservation[];
}
export interface SourceUnionResult {
  status: 'proven' | 'incomplete' | 'failed' | 'not_comparable';
  observed_count: number; mapped_count: number; missing: string[]; conflicting: string[];
  observed_set_digest: string; mapped_set_digest: string;
  sources: { component_id: string; receipt_id: string; observed: number; mapped: number; missing: string[]; state: CoverageBaseline['state'] }[];
}
export function compareSourceUnion(
  snapshot: AnyReportSnapshot,
  expected: { component_id: string; scope_digest: string; configuration_digest: string }[],
  baselines: CoverageBaseline[], observations: ReportObservation[],
  // Trusted host mapping only; no report-provided key can authorize a quarantine substitution.
  quarantined: ReadonlyMap<string, string> = new Map(),
): SourceUnionResult {
  const snapshotDigest = reportHash(snapshot), byKey = new Map<string, string>(), conflicting = new Set<string>();
  for (const o of observations) {
    const key = observationKey(o, snapshot), body = reportHash(o);
    if (byKey.has(key) && byKey.get(key) !== body) conflicting.add(key);
    byKey.set(key, body);
  }
  const stubKeys = new Set(observations.filter(o => o.kind === 'quarantined_observation').map(o => observationKey(o, snapshot)));
  if (new Set(quarantined.values()).size !== quarantined.size || [...quarantined.values()].some(k => !stubKeys.has(k))) throw Error('coverage_quarantine_mapping');
  const isMapped = (key: string, body: string) => byKey.get(key) === body || quarantined.has(key);
  let incomplete = !expected.length || quarantined.size > 0, incomparable = false;
  if (new Set(expected.map(e => e.component_id)).size !== expected.length || baselines.some(b => !expected.some(e => e.component_id === b.component_id))) throw Error('coverage_component_identity');
  const observed = new Set<string>(), mapped = new Set<string>(), missing = new Set<string>();
  const sources = expected.map(e => {
    const matches = baselines.filter(b => b.component_id === e.component_id);
    if (matches.length > 1) throw Error('coverage_component_identity');
    const b = matches[0];
    if (!b) { incomplete = true; return { component_id: e.component_id, receipt_id: '', observed: 0, mapped: 0, missing: [], state: 'incomplete' as const }; }
    if (b.snapshot_digest !== snapshotDigest || b.scope_digest !== e.scope_digest || b.configuration_digest !== e.configuration_digest) incomparable = true;
    if (b.state !== 'complete' || !b.pagination_complete || !b.receipt_id) incomplete = true;
    const keys = new Map<string, string>();
    for (const o of b.observations) {
      const key = observationKey(o, snapshot), body = reportHash(o);
      if (keys.has(key) && keys.get(key) !== body) conflicting.add(key);
      keys.set(key, body); observed.add(key);
      if (isMapped(key, body)) mapped.add(key);
      else if (!byKey.has(key)) missing.add(key);
      else conflicting.add(key);
      if (o.kind === 'quarantined_observation') incomplete = true;
    }
    const absent = [...keys.keys()].filter(k => !byKey.has(k) && !quarantined.has(k)).sort();
    return { component_id: b.component_id, receipt_id: b.receipt_id, observed: keys.size, mapped: [...keys.keys()].filter(k => isMapped(k, keys.get(k)!)).length, missing: absent, state: b.state };
  });
  if ([...quarantined.keys()].some(k => !observed.has(k))) throw Error('coverage_quarantine_mapping');
  return {
    status: missing.size || conflicting.size ? 'failed' : incomparable ? 'not_comparable' : incomplete ? 'incomplete' : 'proven',
    observed_count: observed.size, mapped_count: mapped.size, missing: [...missing].sort(), conflicting: [...conflicting].sort(),
    observed_set_digest: reportHash([...observed].sort()), mapped_set_digest: reportHash([...mapped].sort()), sources,
  };
}
/**
 * DFRPT-19: the coverage component of a producer that is its own only source. Its baseline receipt is the identifier of
 * its own source read, which the producer retains, and `observations` is every result that read returned. Each must also
 * be in the document, mapped to a finding or a disposition: a merged duplicate as `grouped`, a result a second pass
 * refuted as `refuted`, a suppressed one as `out_of_scope`. A result left out makes the union unproven.
 */
export function selfSourceComponent(input: { id: string; version: string; configuration_digest: string; scope_digest: string; source_revision: string; retrieved_at: string; required: boolean; read_id: string;
  observations: readonly ReportObservation[]; snapshot: AnyReportSnapshot }) {
  const keys = input.observations.map(o => observationKey(o, input.snapshot)).sort(), set = reportHash(keys);
  return { id: input.id, version: input.version, configuration_digest: input.configuration_digest, scope_digest: input.scope_digest, source_revision: input.source_revision, retrieved_at: input.retrieved_at,
    state: 'complete' as const, required: input.required, reasons: [] as string[], pagination_complete: true, checkpoint: null, observed_count: keys.length, mapped_count: keys.length, missing_count: 0,
    observed_set_digest: set, mapped_set_digest: set, mapped_observation_keys: keys, baseline_receipt: input.read_id };
}
