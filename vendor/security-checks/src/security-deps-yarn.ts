// DFBASE-23: pure zero-dependency Yarn Classic (v1) and Yarn Berry (v2/v3/v4 __metadata) lockfile parser.
// Imports only node/package primitives and security-deps-pnpm's strict YAML subset (DFBASE-3, DFDIST-8).
import { npmExactVersion, npmPackageName, npmResolvedUnder } from './security-npm.ts';
import { exactPath, sha256 } from './security-primitives.ts';
import { parseLockYaml, YamlSyntaxError, type DirectLockGraph } from './security-deps-pnpm.ts';
import type { DepsDeclared, DepsDependent, DepsLock, DepsLockEntry, DepsLockRoot, DepsLockState, DepsRangeField, DepsRanges, DepsResolution } from './security-deps-lock.ts';

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
const bytewise = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const safeSeg = (s: string) => /^[A-Za-z0-9._+-]{1,120}$/.test(s) && s !== '.' && s !== '..';

function setOwn(target: Json, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function unquoteYarn(token: string): string {
  const s = token.trim();
  if (!s.startsWith('"')) return s;
  if (!s.endsWith('"') || s.length < 2) throw new YamlSyntaxError('unterminated Yarn string');
  let out = '';
  for (let i = 1; i < s.length - 1; i++) {
    const ch = s[i]!;
    if (ch !== '\\') { out += ch; continue; }
    const next = s[++i];
    if (next === undefined) throw new YamlSyntaxError('trailing backslash');
    if (next === 'n') out += '\n';
    else if (next === 'r') out += '\r';
    else if (next === 't') out += '\t';
    else out += next;
  }
  return out;
}

function splitDescriptors(header: string): string[] {
  const out: string[] = [];
  let inQuote = false, start = 0;
  for (let i = 0; i < header.length; i++) {
    const ch = header[i]!;
    if (inQuote) {
      if (ch === '\\') i++;
      else if (ch === '"') inQuote = false;
    } else if (ch === '"') inQuote = true;
    else if (ch === ',') {
      const part = unquoteYarn(header.slice(start, i));
      if (part) out.push(part);
      start = i + 1;
    }
  }
  if (inQuote) throw new YamlSyntaxError('unterminated quote in descriptor header');
  const tail = unquoteYarn(header.slice(start));
  if (tail) out.push(tail);
  return out;
}

function splitDescriptorAt(desc: string): { name: string; spec: string } | null {
  const at = desc.indexOf('@', desc.startsWith('@') ? 1 : 0);
  if (at <= 0) return null;
  return { name: desc.slice(0, at), spec: desc.slice(at + 1) };
}

function stripNpmProtocol(spec: string): string {
  if (!spec.startsWith('npm:')) return spec;
  const rest = spec.slice(4);
  // Keep `npm:other-pkg@1.0.0` intact as a non-semver alias; strip `npm:^1.0.0` to `^1.0.0`.
  const at = rest.indexOf('@', rest.startsWith('@') ? 1 : 0);
  return at > 0 ? spec : rest;
}

interface ClassicStanza {
  rawHeader: string;
  descriptors: string[];
  version: string | null;
  resolved: string | null;
  integrity: string | null;
  dependencies: Record<string, string> | null;
  optionalDependencies: Record<string, string> | null;
}

function parseClassicKeyVal(line: string): { key: string; value: string } | null {
  const trimmed = line.trim();
  let i = 0;
  if (trimmed.startsWith('"')) {
    i = 1;
    while (i < trimmed.length) {
      if (trimmed[i] === '\\') { i += 2; continue; }
      if (trimmed[i] === '"') { i++; break; }
      i++;
    }
    if (i > trimmed.length) return null;
  } else {
    while (i < trimmed.length && trimmed[i] !== ' ' && trimmed[i] !== '\t') i++;
  }
  const key = unquoteYarn(trimmed.slice(0, i));
  let rest = trimmed.slice(i).trim();
  if (rest.startsWith(':')) rest = rest.slice(1).trim();
  if (!key || !rest) return null;
  return { key, value: unquoteYarn(rest) };
}

function parseYarnClassic(
  source: string,
  parserVersion: DepsLock['parser_version'],
): { lock: DepsLock; graph: DirectLockGraph | null } {
  const refused = (state: DepsLockState, reason: string, lockfileVersion: number | null = null) => ({
    lock: { parser_version: parserVersion, state, reason, lockfile_version: lockfileVersion, root: null, entries: [] } as DepsLock,
    graph: null,
  });

  const lines = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  let sawV1Banner = false;
  for (const raw of lines.slice(0, 10)) {
    const t = raw.trim();
    if (/^#\s*yarn lockfile v1$/i.test(t)) { sawV1Banner = true; break; }
    if (/^#\s*yarn lockfile v([0-9]+)$/i.test(t)) {
      const m = /^#\s*yarn lockfile v([0-9]+)$/i.exec(t)!;
      return refused('unsupported', 'unsupported_lockfile', Number(m[1]));
    }
  }
  if (!sawV1Banner) return refused('malformed', 'malformed_lockfile');

  const stanzas: ClassicStanza[] = [];
  let i = 0;
  try {
    while (i < lines.length) {
      const raw = lines[i]!;
      if (/^[ ]*\t/.test(raw)) return refused('malformed', 'malformed_lockfile');
      const indent = raw.length - raw.trimStart().length;
      const trimmed = raw.trim();
      if (!trimmed || trimmed.startsWith('#')) { i++; continue; }
      if (indent !== 0 || !trimmed.endsWith(':')) return refused('malformed', 'malformed_lockfile');
      const rawHeader = trimmed.slice(0, -1);
      const descriptors = splitDescriptors(rawHeader);
      if (!descriptors.length) return refused('malformed', 'malformed_lockfile');
      i++;
      const stanza: ClassicStanza = {
        rawHeader, descriptors, version: null, resolved: null, integrity: null,
        dependencies: {}, optionalDependencies: {},
      };
      while (i < lines.length) {
        const subRaw = lines[i]!;
        if (/^[ ]*\t/.test(subRaw)) return refused('malformed', 'malformed_lockfile');
        const subTrim = subRaw.trim();
        if (!subTrim || subTrim.startsWith('#')) { i++; continue; }
        const subIndent = subRaw.length - subRaw.trimStart().length;
        if (subIndent === 0) break;
        if (subIndent !== 2) return refused('malformed', 'malformed_lockfile');
        if (subTrim.endsWith(':')) {
          const section = unquoteYarn(subTrim.slice(0, -1));
          i++;
          const map: Json = {};
          let validMap = true;
          while (i < lines.length) {
            const depRaw = lines[i]!;
            if (/^[ ]*\t/.test(depRaw)) return refused('malformed', 'malformed_lockfile');
            const depTrim = depRaw.trim();
            if (!depTrim || depTrim.startsWith('#')) { i++; continue; }
            const depIndent = depRaw.length - depRaw.trimStart().length;
            if (depIndent <= 2) break;
            if (depIndent !== 4) { validMap = false; i++; continue; }
            const kv = parseClassicKeyVal(depTrim);
            if (!kv) validMap = false;
            else setOwn(map, kv.key, kv.value);
            i++;
          }
          if (section === 'dependencies') stanza.dependencies = validMap ? (map as Record<string, string>) : null;
          else if (section === 'optionalDependencies') stanza.optionalDependencies = validMap ? (map as Record<string, string>) : null;
        } else {
          const kv = parseClassicKeyVal(subTrim);
          if (!kv) return refused('malformed', 'malformed_lockfile');
          if (kv.key === 'version') stanza.version = kv.value;
          else if (kv.key === 'resolved') stanza.resolved = kv.value;
          else if (kv.key === 'integrity') stanza.integrity = kv.value;
          i++;
        }
      }
      stanzas.push(stanza);
    }
  } catch {
    return refused('malformed', 'malformed_lockfile');
  }

  const parsedStanzas = stanzas.map(s => {
    const parsedDesc = s.descriptors.map(splitDescriptorAt);
    const firstName = parsedDesc[0]?.name ?? null;
    return { stanza: s, parsedDesc, firstName };
  });

  const pairCounts = new Map<string, number>();
  for (const p of parsedStanzas) {
    const k = `${p.firstName ?? ''}\0${p.stanza.version ?? ''}`;
    pairCounts.set(k, (pairCounts.get(k) ?? 0) + 1);
  }

  const entries: DepsLockEntry[] = [];
  const descriptorToPath = new Map<string, string>();
  const entryDescriptors = new Map<string, { name: string; spec: string }[]>();

  for (const { stanza: s, parsedDesc, firstName } of parsedStanzas) {
    const validFirst = firstName !== null && npmPackageName.safeParse(firstName).success ? firstName : null;
    const count = pairCounts.get(`${firstName ?? ''}\0${s.version ?? ''}`) ?? 0;
    const verSeg = s.version && safeSeg(s.version) ? (count === 1 ? s.version : `${s.version}_${sha256(s.rawHeader).slice(0, 8)}`) : sha256(s.rawHeader).slice(0, 12);
    const path = validFirst ? `yarn/${verSeg}/node_modules/${validFirst}` : `yarn/${sha256(s.rawHeader).slice(0, 12)}/node_modules/invalid`;

    const decl: DepsDeclared = {
      dependencies: s.dependencies,
      optionalDependencies: s.optionalDependencies,
      peerDependencies: {},
      devDependencies: {},
    };
    const base = { path, version: s.version, resolved: s.resolved, integrity: s.integrity, dev: false, optional: false, ...decl };
    const held = (reason: string): DepsLockEntry => ({ ...base, name: validFirst, kind: 'held', hold_reason: reason });

    const goodDescs: { name: string; spec: string }[] = [];
    for (const d of parsedDesc) {
      if (d) {
        descriptorToPath.set(`${d.name}@${d.spec}`, path);
        goodDescs.push(d);
      }
    }
    entryDescriptors.set(path, goodDescs);

    if (!exactPath.safeParse(path).success || parsedDesc.some(d => d === null) || !validFirst) {
      entries.push(held('unsupported_entry'));
      continue;
    }
    if (goodDescs.some(d => d.name !== validFirst || (d.spec.startsWith('npm:') && splitDescriptorAt(d.spec.slice(4)) !== null))) {
      entries.push(held('npm_alias_requires_review'));
      continue;
    }
    if (s.resolved && /^link:/i.test(s.resolved)) {
      entries.push({ ...base, name: validFirst, kind: 'first_party', hold_reason: null });
      continue;
    }
    if (!s.version || !npmExactVersion.safeParse(s.version).success) {
      entries.push(held('unsupported_exact_version'));
      continue;
    }
    if (!s.resolved) { entries.push(held('unsupported_entry')); continue; }
    if (/^file:/i.test(s.resolved)) { entries.push(held('unsupported_entry')); continue; }
    let url: URL;
    try { url = new URL(s.resolved); } catch { entries.push(held('unsupported_entry')); continue; }
    const validHash = url.hash === '' || /^#[0-9a-fA-F]{40}$/.test(url.hash);
    if (url.protocol !== 'https:' || (url.hostname !== 'registry.npmjs.org' && url.hostname !== 'registry.yarnpkg.com')
      || url.username || url.password || url.port || url.search || !validHash) {
      entries.push(held('not_approved_public_registry'));
      continue;
    }
    const normalizedUrl = `https://registry.npmjs.org${url.pathname}`;
    if (!s.integrity || !/^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(s.integrity)) {
      entries.push({ ...base, resolved: normalizedUrl, name: validFirst, kind: 'held', hold_reason: 'unsupported_integrity' });
      continue;
    }
    if (!npmResolvedUnder(new URL(normalizedUrl), validFirst)) {
      entries.push({ ...base, resolved: normalizedUrl, name: validFirst, kind: 'held', hold_reason: 'npm_alias_requires_review' });
      continue;
    }
    entries.push({ ...base, resolved: normalizedUrl, name: validFirst, kind: 'registry', hold_reason: null });
  }

  // Build dependents graph: every stanza's dependencies/optionalDependencies resolve through descriptorToPath, and any
  // descriptor on a stanza not claimed by a transitive stanza came from a root/workspace manifest.
  const byEntry = new Map<string, { dependents: DepsDependent[]; unread: Set<string>; claimedSpecs: Set<string> }>();
  for (const e of entries) byEntry.set(e.path, { dependents: [], unread: new Set(), claimedSpecs: new Set() });

  const unreadEntries: string[] = [];
  for (const e of entries) {
    if (e.dependencies === null || e.optionalDependencies === null) unreadEntries.push(e.path);
    for (const field of ['dependencies', 'optionalDependencies'] as const) {
      const map = e[field];
      if (!map) continue;
      for (const [depName, depRange] of Object.entries(map)) {
        const target = descriptorToPath.get(`${depName}@${depRange}`);
        if (target && byEntry.has(target)) {
          const bucket = byEntry.get(target)!;
          bucket.dependents.push({ path: e.path, kind: e.kind, field, range: depRange });
          bucket.claimedSpecs.add(depRange);
        }
      }
    }
  }

  const rootDeps: Json = {};
  for (const e of entries) {
    const bucket = byEntry.get(e.path)!;
    for (const u of unreadEntries) if (u !== e.path) bucket.unread.add(u);
    for (const d of entryDescriptors.get(e.path) ?? []) {
      if (!bucket.claimedSpecs.has(d.spec)) {
        bucket.dependents.push({ path: '', kind: 'root', field: 'dependencies', range: d.spec });
        if (!Object.hasOwn(rootDeps, d.name)) setOwn(rootDeps, d.name, d.spec);
      }
    }
  }

  const root: DepsLockRoot = { present: true, name: null, version: null, dependencies: rootDeps as DepsRanges, optionalDependencies: {}, peerDependencies: {}, devDependencies: {} };
  const finalGraph = new Map<string, DepsResolution>();
  for (const [entryPath, bucket] of byEntry) {
    finalGraph.set(entryPath, {
      dependents: bucket.dependents.sort((a, b) => bytewise(a.path, b.path) || bytewise(a.field, b.field) || bytewise(a.range, b.range)),
      unread: [...bucket.unread].sort(bytewise),
    });
  }
  return {
    lock: { parser_version: parserVersion, state: 'parsed', reason: null, lockfile_version: 1, root, entries },
    graph: { format: 'yarn', byEntry: finalGraph },
  };
}

function readBerryRanges(stanza: Json, field: DepsRangeField): { clean: DepsRanges | null; raw: Record<string, string> | null } {
  const val = stanza[field];
  if (val === undefined || val === null) return { clean: {}, raw: {} };
  if (!isObject(val)) return { clean: null, raw: null };
  const clean: Json = {}, raw: Json = {};
  for (const [k, v] of Object.entries(val)) {
    if (typeof v !== 'string' && typeof v !== 'number') return { clean: null, raw: null };
    const str = String(v);
    setOwn(raw, k, str);
    setOwn(clean, k, stripNpmProtocol(str));
  }
  return { clean: clean as DepsRanges, raw: raw as Record<string, string> };
}

function parseYarnBerry(
  raw: Json,
  parserVersion: DepsLock['parser_version'],
): { lock: DepsLock; graph: DirectLockGraph | null } {
  const refused = (state: DepsLockState, reason: string, lockfileVersion: number | null = null) => ({
    lock: { parser_version: parserVersion, state, reason, lockfile_version: lockfileVersion, root: null, entries: [] } as DepsLock,
    graph: null,
  });

  const meta = raw.__metadata;
  const ver = isObject(meta) && typeof meta.version === 'number' && Number.isInteger(meta.version) ? meta.version
    : isObject(meta) && typeof meta.version === 'string' && /^[0-9]+$/.test(meta.version) ? Number(meta.version) : null;
  if (!isObject(meta) || ver === null || ver < 4 || ver > 20) return refused('unsupported', 'unsupported_lockfile', ver);

  interface BerryItem {
    key: string;
    obj: Json | null;
    descriptors: ({ name: string; spec: string } | null)[];
    resolution: string | null;
    resParts: { name: string; spec: string } | null;
    version: string | null;
  }

  const items: BerryItem[] = [];
  for (const [key, val] of Object.entries(raw)) {
    if (key === '__metadata') continue;
    const obj = isObject(val) ? val : null;
    let descs: string[] = [];
    try { descs = splitDescriptors(key); } catch { return refused('malformed', 'malformed_lockfile'); }
    if (!descs.length) return refused('malformed', 'malformed_lockfile');
    const resolution = typeof obj?.resolution === 'string' ? obj.resolution : null;
    items.push({
      key,
      obj,
      descriptors: descs.map(splitDescriptorAt),
      resolution,
      resParts: resolution ? splitDescriptorAt(resolution) : null,
      version: typeof obj?.version === 'string' ? obj.version : null,
    });
  }

  let root: DepsLockRoot = { present: false, name: null, version: null, dependencies: null, optionalDependencies: null, peerDependencies: null, devDependencies: null };
  const entries: DepsLockEntry[] = [];
  const rawEdges: { from: string; kind: 'root' | DepsLockEntry['kind']; field: DepsRangeField; depName: string; rawSpec: string; cleanRange: string }[] = [];
  const unreadSources = new Set<string>();
  const descriptorToPath = new Map<string, string>();
  const entryDescriptors = new Map<string, { name: string; spec: string }[]>();

  const pairCounts = new Map<string, number>();
  for (const it of items) {
    if (it.resParts?.spec.startsWith('workspace:')) continue;
    const name = it.resParts?.name ?? it.descriptors[0]?.name ?? '';
    const k = `${name}\0${it.version ?? ''}`;
    pairCounts.set(k, (pairCounts.get(k) ?? 0) + 1);
  }

  for (const it of items) {
    const obj = it.obj;
    if (!obj) {
      const p = `yarn/${sha256(it.key).slice(0, 12)}/node_modules/invalid`;
      entries.push({ path: p, name: null, version: null, kind: 'held', hold_reason: 'unsupported_entry', resolved: null, integrity: null, dev: false, optional: false,
        dependencies: null, optionalDependencies: null, peerDependencies: null, devDependencies: null });
      unreadSources.add(p);
      continue;
    }

    const depR = readBerryRanges(obj, 'dependencies');
    const optR = readBerryRanges(obj, 'optionalDependencies');
    const peerR = readBerryRanges(obj, 'peerDependencies');
    const devR = readBerryRanges(obj, 'devDependencies');
    const decl: DepsDeclared = { dependencies: depR.clean, optionalDependencies: optR.clean, peerDependencies: peerR.clean, devDependencies: devR.clean };

    if (it.resParts?.spec.startsWith('workspace:')) {
      const wsRel = it.resParts.spec.slice('workspace:'.length);
      const fromPath = wsRel === '.' ? '' : wsRel;
      const nodeKind: 'root' | 'first_party' = wsRel === '.' ? 'root' : 'first_party';
      if (wsRel === '.') {
        root = { present: true, name: it.resParts.name, version: it.version, ...decl };
      } else {
        const validWs = exactPath.safeParse(wsRel).success && !wsRel.split('/').includes('node_modules');
        entries.push({ path: wsRel, name: it.resParts.name, version: it.version, kind: validWs ? 'first_party' : 'held',
          hold_reason: validWs ? null : 'unsupported_entry', resolved: null, integrity: null, dev: false, optional: false, ...decl });
      }
      if ([depR.clean, optR.clean, peerR.clean, devR.clean].some(v => v === null)) unreadSources.add(fromPath);
      for (const [field, r] of [['dependencies', depR], ['optionalDependencies', optR], ['peerDependencies', peerR], ['devDependencies', devR]] as const) {
        if (!r.raw || !r.clean) continue;
        for (const [depName, rawSpec] of Object.entries(r.raw)) {
          rawEdges.push({ from: fromPath, kind: nodeKind, field, depName, rawSpec, cleanRange: r.clean[depName]! });
        }
      }
      continue;
    }

    const candidateName = it.resParts?.name ?? it.descriptors[0]?.name ?? null;
    const validName = candidateName !== null && npmPackageName.safeParse(candidateName).success ? candidateName : null;
    const count = pairCounts.get(`${candidateName ?? ''}\0${it.version ?? ''}`) ?? 0;
    const verSeg = it.version && safeSeg(it.version) ? (count === 1 ? it.version : `${it.version}_${sha256(it.key).slice(0, 8)}`) : sha256(it.key).slice(0, 12);
    const path = validName ? `yarn/${verSeg}/node_modules/${validName}` : `yarn/${sha256(it.key).slice(0, 12)}/node_modules/invalid`;

    const goodDescs: { name: string; spec: string }[] = [];
    for (const d of it.descriptors) {
      if (d) {
        descriptorToPath.set(`${d.name}@${d.spec}`, path);
        descriptorToPath.set(`${d.name}@${stripNpmProtocol(d.spec)}`, path);
        goodDescs.push(d);
      }
    }
    entryDescriptors.set(path, goodDescs);

    const base = { path, version: it.version, resolved: it.resolution, integrity: null as string | null, dev: false, optional: false, ...decl };
    const pushEntry = (e: DepsLockEntry) => {
      entries.push(e);
      if ([depR.clean, optR.clean, peerR.clean].some(v => v === null)) unreadSources.add(path);
      for (const [field, r] of [['dependencies', depR], ['optionalDependencies', optR], ['peerDependencies', peerR]] as const) {
        if (!r.raw || !r.clean) continue;
        for (const [depName, rawSpec] of Object.entries(r.raw)) {
          rawEdges.push({ from: path, kind: e.kind, field, depName, rawSpec, cleanRange: r.clean[depName]! });
        }
      }
    };
    const held = (reason: string): DepsLockEntry => ({ ...base, name: validName, kind: 'held', hold_reason: reason });

    if (!exactPath.safeParse(path).success || it.descriptors.some(d => d === null) || !it.resParts || !validName) {
      pushEntry(held('unsupported_entry'));
      continue;
    }
    const resSpec = it.resParts.spec;
    if (resSpec.startsWith('portal:') || resSpec.startsWith('link:')) {
      const targetRel = resSpec.slice(resSpec.indexOf(':') + 1);
      if (exactPath.safeParse(targetRel).success) pushEntry({ ...base, name: validName, kind: 'first_party', hold_reason: null });
      else pushEntry(held('unsupported_entry'));
      continue;
    }
    if (/^(?:https?|git(?:\+[a-z]+)?|ssh):/i.test(resSpec)) {
      pushEntry(held('not_approved_public_registry'));
      continue;
    }
    if (!resSpec.startsWith('npm:')) {
      pushEntry(held('unsupported_entry'));
      continue;
    }
    if (goodDescs.some(d => d.name !== validName)) {
      pushEntry(held('npm_alias_requires_review'));
      continue;
    }
    const resVer = resSpec.slice(4);
    if (!it.version || resVer !== it.version || !npmExactVersion.safeParse(it.version).success) {
      pushEntry(held('unsupported_exact_version'));
      continue;
    }
    const resolvedUrl = `https://registry.npmjs.org/${validName}/-/${validName.split('/').at(-1)}-${it.version}.tgz`;
    const checksum = typeof obj.checksum === 'string' ? obj.checksum.trim() : '';
    const m = /^[0-9A-Za-z._-]+\/([0-9a-f]{128})$/.exec(checksum);
    if (!m) {
      pushEntry({ ...base, resolved: resolvedUrl, name: validName, kind: 'held', hold_reason: 'unsupported_integrity' });
      continue;
    }
    if (!npmResolvedUnder(new URL(resolvedUrl), validName)) {
      pushEntry({ ...base, resolved: resolvedUrl, integrity: `yarn-berry-sha512:${m[1]}`, name: validName, kind: 'held', hold_reason: 'npm_alias_requires_review' });
      continue;
    }
    pushEntry({ ...base, resolved: resolvedUrl, integrity: `yarn-berry-sha512:${m[1]}`, name: validName, kind: 'registry', hold_reason: null });
  }

  // Compute dev-only reachability when root workspace is present, and populate dependents.
  const byEntry = new Map<string, { dependents: DepsDependent[]; unread: Set<string>; claimedSpecs: Set<string> }>();
  for (const e of entries) byEntry.set(e.path, { dependents: [], unread: new Set(), claimedSpecs: new Set() });

  const outGraph = new Map<string, Set<string>>();
  const prodSeeds: string[] = [], devSeeds: string[] = [];
  for (const edge of rawEdges) {
    const target = descriptorToPath.get(`${edge.depName}@${edge.rawSpec}`) ?? descriptorToPath.get(`${edge.depName}@${edge.cleanRange}`);
    if (!target || !byEntry.has(target)) continue;
    const bucket = byEntry.get(target)!;
    bucket.dependents.push({ path: edge.from, kind: edge.kind, field: edge.field, range: edge.cleanRange });
    bucket.claimedSpecs.add(edge.rawSpec);
    bucket.claimedSpecs.add(edge.cleanRange);
    if (edge.from === '' || !edge.from.includes('/node_modules/')) {
      if (edge.field === 'devDependencies') devSeeds.push(target);
      else if (edge.field === 'dependencies' || edge.field === 'optionalDependencies') prodSeeds.push(target);
    } else if (edge.field !== 'peerDependencies') {
      if (!outGraph.has(edge.from)) outGraph.set(edge.from, new Set());
      outGraph.get(edge.from)!.add(target);
    }
  }

  if (root.present) {
    const bfs = (seeds: string[]): Set<string> => {
      const seen = new Set<string>(seeds);
      const stack = [...seeds];
      while (stack.length) {
        const cur = stack.pop()!;
        for (const next of outGraph.get(cur) ?? []) if (!seen.has(next)) { seen.add(next); stack.push(next); }
      }
      return seen;
    };
    const prod = bfs(prodSeeds), dev = bfs(devSeeds);
    for (const e of entries) if (e.kind !== 'first_party' && dev.has(e.path) && !prod.has(e.path)) e.dev = true;
  } else {
    const rootDeps: Json = {};
    for (const e of entries) {
      if (e.kind === 'first_party') continue;
      const bucket = byEntry.get(e.path)!;
      for (const d of entryDescriptors.get(e.path) ?? []) {
        const clean = stripNpmProtocol(d.spec);
        if (!bucket.claimedSpecs.has(d.spec) && !bucket.claimedSpecs.has(clean)) {
          bucket.dependents.push({ path: '', kind: 'root', field: 'dependencies', range: clean });
          if (!Object.hasOwn(rootDeps, d.name)) setOwn(rootDeps, d.name, clean);
        }
      }
    }
    root = { present: true, name: null, version: null, dependencies: rootDeps as DepsRanges, optionalDependencies: {}, peerDependencies: {}, devDependencies: {} };
  }

  for (const [entryPath, bucket] of byEntry) {
    for (const u of unreadSources) if (u !== entryPath) bucket.unread.add(u);
  }

  const finalGraph = new Map<string, DepsResolution>();
  for (const [entryPath, bucket] of byEntry) {
    finalGraph.set(entryPath, {
      dependents: bucket.dependents.sort((a, b) => bytewise(a.path, b.path) || bytewise(a.field, b.field) || bytewise(a.range, b.range)),
      unread: [...bucket.unread].sort(bytewise),
    });
  }
  return {
    lock: { parser_version: parserVersion, state: 'parsed', reason: null, lockfile_version: ver, root, entries },
    graph: { format: 'yarn', byEntry: finalGraph },
  };
}

export function parseYarnLock(
  source: string,
  parserVersion: DepsLock['parser_version'],
): { lock: DepsLock; graph: DirectLockGraph | null } {
  if (/^(?:\s*#[^\n]*\n|\s*\n)*__metadata\s*:/m.test(source)) {
    let raw: Json;
    try { raw = parseLockYaml(source); }
    catch {
      return { lock: { parser_version: parserVersion, state: 'malformed', reason: 'malformed_lockfile', lockfile_version: null, root: null, entries: [] }, graph: null };
    }
    return parseYarnBerry(raw, parserVersion);
  }
  return parseYarnClassic(source, parserVersion);
}
