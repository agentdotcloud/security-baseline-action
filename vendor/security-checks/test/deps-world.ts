// A deterministic public npm registry and OSV for the dependency check's and the lock repair's tests.
import type { DepsCheckCapabilities } from '../src/security-deps-check.ts';
import type { PublicHTTP } from '../src/security-advisories.ts';
import { sha256 } from '../src/security-primitives.ts';

export const PATH = 'services/app/package-lock.json', NOW = Date.parse('2026-11-12T18:00:00Z'), INTEGRITY = 'sha512-Zml4dHVyZQ==';
export const tarball = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name.split('/').at(-1)}-${version}.tgz`;
export const reg = (name: string, version: string, extra: Record<string, unknown> = {}) => ({ version, resolved: tarball(name, version), integrity: INTEGRITY, ...extra });
export const fixed = (version: string, introduced = '0'): Record<string, string>[] => [{ introduced }, { fixed: version }];
export const advisory = (id: string, name: string, events: Record<string, string>[], extra: Record<string, unknown> = {}) => ({ id, modified: '2026-10-01T00:00:00Z', summary: `${id} in ${name}`,
  affected: [{ package: { ecosystem: 'npm', name }, ranges: [{ type: 'SEMVER', events }] }], database_specific: { severity: 'HIGH' }, ...extra });
export const GHSA_A = 'GHSA-aaaa-aaaa-aaaa', GHSA_B = 'GHSA-bbbb-bbbb-bbbb', GHSA_C = 'GHSA-cccc-cccc-cccc';
export interface World { private?: string[]; manifests?: Record<string, Record<string, unknown>>; records?: Record<string, unknown>[]; osvDown?: boolean; registryDown?: boolean }
/** Deterministic npm registry and OSV. Every request is recorded; a private package answers 404 like the real registry. */
export function world(w: World = {}) {
  const calls: { url: string; body?: unknown }[] = [], records = w.records ?? [];
  const http: PublicHTTP = { async json(url, body) {
    calls.push({ url, body });
    const respond = (value: unknown) => ({ body: structuredClone(value), sha256: sha256(JSON.stringify(value)), retrieved_at: new Date(NOW).toISOString() });
    const u = new URL(url);
    if (u.hostname === 'registry.npmjs.org') {
      if (w.registryDown) throw Error('client_failed');
      const [name, version] = u.pathname.slice(1).split('/').map(decodeURIComponent) as [string, string];
      if (w.private?.includes(name)) throw Error('source_http_404');
      return respond({ name, version, dist: { tarball: tarball(name, version), integrity: INTEGRITY }, description: 'never kept', ...w.manifests?.[`${name}@${version}`] });
    }
    if (u.hostname !== 'api.osv.dev') throw Error('public_endpoint_refused');
    if (w.osvDown) throw Error('client_failed');
    if (u.pathname === '/v1/querybatch') {
      const queries = (body as { queries: { package: { name: string }; version: string }[] }).queries;
      // The real querybatch over-reports: it returns every record for the package, whatever the version.
      return respond({ results: queries.map(q => ({ vulns: records.filter(r => (r.affected as { package: { name: string } }[]).some(a => a.package.name === q.package.name)).map(r => ({ id: r.id, modified: r.modified })) })) });
    }
    const record = records.find(r => r.id === decodeURIComponent(u.pathname.split('/').at(-1)!));
    if (!record) throw Error('source_http_404');
    return respond(record);
  } };
  const osvQueried = () => calls.filter(c => c.url.endsWith('/querybatch')).flatMap(c => (c.body as { queries: { package: { name: string }; version: string }[] }).queries.map(q => `${q.package.name}@${q.version}`));
  return { http, calls, osvQueried };
}
export const caps = (http: PublicHTTP, extra: Partial<DepsCheckCapabilities> = {}): DepsCheckCapabilities => ({ http, now: () => NOW, limits: { max_identities: 5000 }, ...extra });
