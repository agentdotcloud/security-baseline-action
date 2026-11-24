// DFBASE-23: pure zero-dependency YAML lockfile subset and pnpm-lock.yaml (v6 and v9) parser.
// Imports only node/package primitives (DFBASE-3, DFDIST-8): never reads files, runs code or expands YAML aliases/tags.
import { npmBundled, npmExactVersion, npmPackageName, npmResolvedUnder } from './security-npm.ts';
import { exactPath, sha256 } from './security-primitives.ts';
import type { DepsDeclared, DepsDependent, DepsLock, DepsLockEntry, DepsLockRoot, DepsLockState, DepsRangeField, DepsRanges, DepsResolution } from './security-deps-lock.ts';

export class YamlSyntaxError extends Error {
  constructor(message: string) { super(message); }
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
const bytewise = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
const RANGE_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies'] as const;
const MAX_DEPTH = 32;

function setOwn(target: Json, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

function stripLineComment(line: string): string {
  let single = false, double = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (single) {
      if (ch === "'" && line[i + 1] === "'") i++;
      else if (ch === "'") single = false;
    } else if (double) {
      if (ch === '\\') i++;
      else if (ch === '"') double = false;
    } else if (ch === "'") single = true;
    else if (ch === '"') double = true;
    else if (ch === '#' && (i === 0 || line[i - 1] === ' ' || line[i - 1] === '\t')) return line.slice(0, i).trimEnd();
  }
  if (single || double) return line; // caller handles multiline quotes or throws
  return line.trimEnd();
}

function flowBalance(text: string): { delta: number; unclosedQuote: "'" | '"' | null } {
  let single = false, double = false, delta = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (single) {
      if (ch === "'" && text[i + 1] === "'") i++;
      else if (ch === "'") single = false;
    } else if (double) {
      if (ch === '\\') i++;
      else if (ch === '"') double = false;
    } else if (ch === "'") single = true;
    else if (ch === '"') double = true;
    else if (ch === '{' || ch === '[') delta++;
    else if (ch === '}' || ch === ']') { delta--; if (delta < 0) throw new YamlSyntaxError('unmatched closing bracket'); }
  }
  return { delta, unclosedQuote: single ? "'" : double ? '"' : null };
}

function parseDoubleQuoted(raw: string): string {
  if (!raw.startsWith('"') || !raw.endsWith('"') || raw.length < 2) throw new YamlSyntaxError('unterminated double-quoted string');
  let out = '';
  for (let i = 1; i < raw.length - 1; i++) {
    const ch = raw[i]!;
    if (ch !== '\\') { out += ch; continue; }
    const next = raw[++i];
    if (next === undefined) throw new YamlSyntaxError('trailing backslash');
    switch (next) {
      case '"': case '\\': case '/': out += next; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case '0': out += '\0'; break;
      case 'x': {
        const hex = raw.slice(i + 1, i + 3);
        if (!/^[0-9a-fA-F]{2}$/.test(hex)) throw new YamlSyntaxError('invalid \\x escape');
        out += String.fromCharCode(parseInt(hex, 16));
        i += 2;
        break;
      }
      case 'u': {
        const hex = raw.slice(i + 1, i + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new YamlSyntaxError('invalid \\u escape');
        out += String.fromCharCode(parseInt(hex, 16));
        i += 4;
        break;
      }
      case 'U': {
        const hex = raw.slice(i + 1, i + 9);
        if (!/^[0-9a-fA-F]{8}$/.test(hex)) throw new YamlSyntaxError('invalid \\U escape');
        out += String.fromCodePoint(parseInt(hex, 16));
        i += 8;
        break;
      }
      default: out += next; break;
    }
  }
  return out;
}

function parseSingleQuoted(raw: string): string {
  if (!raw.startsWith("'") || !raw.endsWith("'") || raw.length < 2) throw new YamlSyntaxError('unterminated single-quoted string');
  return raw.slice(1, -1).replace(/''/g, "'");
}

function splitTopLevel(inner: string, sep: ',' | ':'): string[] {
  const parts: string[] = [];
  let single = false, double = false, depth = 0, start = 0;
  for (let i = 0; i < inner.length; i++) {
    const ch = inner[i]!;
    if (single) {
      if (ch === "'" && inner[i + 1] === "'") i++;
      else if (ch === "'") single = false;
    } else if (double) {
      if (ch === '\\') i++;
      else if (ch === '"') double = false;
    } else if (ch === "'") single = true;
    else if (ch === '"') double = true;
    else if (ch === '{' || ch === '[') depth++;
    else if (ch === '}' || ch === ']') depth--;
    else if (depth === 0 && ch === sep && (sep === ',' || i + 1 === inner.length || inner[i + 1] === ' ' || inner[i + 1] === '\t')) {
      parts.push(inner.slice(start, i));
      start = i + 1;
      if (sep === ':') { parts.push(inner.slice(start)); return parts; }
    }
  }
  if (single || double || depth !== 0) throw new YamlSyntaxError('unbalanced flow collection');
  parts.push(inner.slice(start));
  return parts;
}

function parseFlowValue(raw: string, depth: number): unknown {
  if (depth > MAX_DEPTH) throw new YamlSyntaxError('max YAML depth exceeded');
  const s = raw.trim();
  if (!s) return null;
  // Refuse YAML anchors, aliases and tags outside quotes.
  if (s[0] === '&' || s[0] === '*' || s[0] === '!') throw new YamlSyntaxError('YAML anchors, aliases and tags are refused');
  if (s.startsWith("'")) return parseSingleQuoted(s);
  if (s.startsWith('"')) return parseDoubleQuoted(s);
  if (s.startsWith('{')) {
    if (!s.endsWith('}')) throw new YamlSyntaxError('unclosed flow mapping');
    const body = s.slice(1, -1).trim();
    const obj: Json = {};
    if (!body) return obj;
    for (const item of splitTopLevel(body, ',')) {
      const trimmed = item.trim();
      if (!trimmed) continue;
      const kv = splitKeyValue(trimmed);
      if (!kv) throw new YamlSyntaxError('invalid flow mapping entry');
      if (kv.key === '<<') throw new YamlSyntaxError('YAML merge keys are refused');
      setOwn(obj, kv.key, parseFlowValue(kv.rest, depth + 1));
    }
    return obj;
  }
  if (s.startsWith('[')) {
    if (!s.endsWith(']')) throw new YamlSyntaxError('unclosed flow sequence');
    const body = s.slice(1, -1).trim();
    if (!body) return [];
    return splitTopLevel(body, ',').map(x => x.trim()).filter(Boolean).map(x => parseFlowValue(x, depth + 1));
  }
  if (s === 'true') return true;
  if (s === 'false') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?(?:0|[1-9][0-9]*)$/.test(s)) {
    const n = Number(s);
    if (Number.isSafeInteger(n)) return n;
  }
  if (/^-?(?:0|[1-9][0-9]*)\.[0-9]+$/.test(s)) return Number(s);
  return s;
}

function splitKeyValue(content: string): { key: string; rest: string } | null {
  if (content.startsWith("'")) {
    for (let i = 1; i < content.length; i++) {
      if (content[i] === "'" && content[i + 1] === "'") { i++; continue; }
      if (content[i] === "'") {
        const after = content.slice(i + 1);
        if (after === ':' || after.startsWith(': ') || after.startsWith(':\t')) {
          return { key: parseSingleQuoted(content.slice(0, i + 1)), rest: after.slice(1).trim() };
        }
        return null;
      }
    }
    throw new YamlSyntaxError('unterminated single-quoted key');
  }
  if (content.startsWith('"')) {
    for (let i = 1; i < content.length; i++) {
      if (content[i] === '\\') { i++; continue; }
      if (content[i] === '"') {
        const after = content.slice(i + 1);
        if (after === ':' || after.startsWith(': ') || after.startsWith(':\t')) {
          return { key: parseDoubleQuoted(content.slice(0, i + 1)), rest: after.slice(1).trim() };
        }
        return null;
      }
    }
    throw new YamlSyntaxError('unterminated double-quoted key');
  }
  const parts = splitTopLevel(content, ':');
  if (parts.length !== 2) return null;
  const key = parts[0]!.trim();
  if (!key || key[0] === '&' || key[0] === '*' || key[0] === '!') throw new YamlSyntaxError('invalid YAML key');
  return { key, rest: parts[1]!.trim() };
}

interface Line { indent: number; text: string }

/** Parse the strict YAML subset used by pnpm-lock.yaml and Yarn Berry yarn.lock into prototype-safe objects. */
export function parseLockYaml(source: string): Json {
  const rawLines = source.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const lines: Line[] = [];
  let sawContent = false;
  for (let i = 0; i < rawLines.length; i++) {
    const raw = rawLines[i]!;
    if (/^[ ]*\t/.test(raw)) throw new YamlSyntaxError('tab indentation is not valid YAML');
    const indent = raw.length - raw.trimStart().length;
    const stripped = stripLineComment(raw.slice(indent));
    if (!stripped) continue;
    if (indent === 0 && stripped === '---') {
      if (sawContent) throw new YamlSyntaxError('multiple YAML documents are refused');
      continue;
    }
    if (indent === 0 && stripped === '...') break;
    sawContent = true;
    let combined = stripped;
    for (;;) {
      const state = flowBalance(combined);
      if (state.delta === 0 && state.unclosedQuote === null) break;
      if (++i >= rawLines.length) throw new YamlSyntaxError('unterminated multiline flow or string');
      const nextRaw = rawLines[i]!;
      if (/^[ ]*\t/.test(nextRaw)) throw new YamlSyntaxError('tab indentation is not valid YAML');
      const nextIndent = nextRaw.length - nextRaw.trimStart().length;
      if (nextIndent <= indent && state.unclosedQuote === null && state.delta === 0) break;
      const nextPart = state.unclosedQuote ? nextRaw.trim() : stripLineComment(nextRaw.trim());
      combined = state.unclosedQuote ? `${combined} ${nextPart}` : `${combined} ${nextPart}`;
    }
    lines.push({ indent, text: combined });
  }
  if (!lines.length) return {};

  let idx = 0;
  function parseBlockScalar(parentIndent: number, style: string): string {
    const folded = style.startsWith('>');
    const chomp = style.endsWith('-') ? 'strip' : style.endsWith('+') ? 'keep' : 'clip';
    const chunks: string[] = [];
    let blockIndent: number | null = null;
    while (idx < lines.length && lines[idx]!.indent > parentIndent) {
      const l = lines[idx++]!;
      blockIndent ??= l.indent;
      if (l.indent < blockIndent) throw new YamlSyntaxError('inconsistent block scalar indentation');
      chunks.push(' '.repeat(l.indent - blockIndent) + l.text);
    }
    const joined = folded ? chunks.join(' ') : chunks.join('\n');
    return chomp === 'strip' ? joined : chomp === 'keep' ? `${joined}\n` : chunks.length ? `${joined}\n` : '';
  }

  function parseNode(expectedIndent: number, depth: number): unknown {
    if (depth > MAX_DEPTH) throw new YamlSyntaxError('max YAML depth exceeded');
    if (idx >= lines.length || lines[idx]!.indent < expectedIndent) return {};
    const startIndent = lines[idx]!.indent;
    if (lines[idx]!.text === '-' || lines[idx]!.text.startsWith('- ')) {
      const arr: unknown[] = [];
      while (idx < lines.length && lines[idx]!.indent === startIndent) {
        const cur = lines[idx]!.text;
        if (cur !== '-' && !cur.startsWith('- ')) break;
        idx++;
        const rest = cur.slice(1).trim();
        if (rest) {
          const kv = splitKeyValue(rest);
          if (kv) {
            const obj: Json = {};
            if (kv.rest) setOwn(obj, kv.key, parseFlowValue(kv.rest, depth + 1));
            else if (idx < lines.length && lines[idx]!.indent > startIndent) setOwn(obj, kv.key, parseNode(lines[idx]!.indent, depth + 1));
            else setOwn(obj, kv.key, null);
            if (idx < lines.length && lines[idx]!.indent > startIndent) {
              const more = parseNode(lines[idx]!.indent, depth + 1);
              if (isObject(more)) for (const [k, v] of Object.entries(more)) setOwn(obj, k, v);
            }
            arr.push(obj);
          } else {
            arr.push(parseFlowValue(rest, depth + 1));
          }
        } else if (idx < lines.length && lines[idx]!.indent > startIndent) {
          arr.push(parseNode(lines[idx]!.indent, depth + 1));
        } else {
          arr.push(null);
        }
      }
      return arr;
    }

    const firstKv = splitKeyValue(lines[idx]!.text);
    if (!firstKv) {
      // Plain indented scalar continuation under a `key:` line.
      if (depth > 0) return parseFlowValue(lines[idx++]!.text, depth + 1);
      throw new YamlSyntaxError('top-level YAML document must be a mapping');
    }

    const obj: Json = {};
    while (idx < lines.length && lines[idx]!.indent === startIndent) {
      const line = lines[idx]!;
      if (line.text === '-' || line.text.startsWith('- ')) throw new YamlSyntaxError('mixed sequence and mapping at same indentation');
      const kv = splitKeyValue(line.text);
      if (!kv) throw new YamlSyntaxError('expected mapping entry');
      if (kv.key === '<<') throw new YamlSyntaxError('YAML merge keys are refused');
      idx++;
      if (kv.rest === '|' || kv.rest === '|-' || kv.rest === '|+' || kv.rest === '>' || kv.rest === '>-' || kv.rest === '>+') {
        setOwn(obj, kv.key, parseBlockScalar(startIndent, kv.rest));
      } else if (kv.rest) {
        setOwn(obj, kv.key, parseFlowValue(kv.rest, depth + 1));
      } else if (idx < lines.length && lines[idx]!.indent > startIndent) {
        setOwn(obj, kv.key, parseNode(lines[idx]!.indent, depth + 1));
      } else {
        setOwn(obj, kv.key, null);
      }
    }
    return obj;
  }

  const root = parseNode(lines[0]!.indent, 0);
  if (idx < lines.length || !isObject(root)) throw new YamlSyntaxError('unexpected trailing YAML content');
  return root;
}

export interface DirectLockGraph {
  format: 'pnpm' | 'yarn';
  byEntry: Map<string, DepsResolution>;
}

const EMPTY_DECLARED: DepsDeclared = { dependencies: {}, optionalDependencies: {}, peerDependencies: {}, devDependencies: {} };
const safeSeg = (s: string) => /^[A-Za-z0-9._+-]{1,120}$/.test(s) && s !== '.' && s !== '..';

function stripPeers(ref: string): string {
  const paren = ref.indexOf('(');
  return paren < 0 ? ref : ref.slice(0, paren);
}

function splitNameAt(spec: string): { name: string | null; ref: string } {
  const s = spec.startsWith('/') ? spec.slice(1) : spec;
  const at = s.indexOf('@', s.startsWith('@') ? 1 : 0);
  if (at <= 0) return { name: null, ref: s };
  return { name: s.slice(0, at), ref: s.slice(at + 1) };
}

interface ImporterEdge { from: string; kind: 'root' | 'first_party'; field: DepsRangeField; depName: string; range: string; ref: string }

function readImporterField(imp: Json, field: DepsRangeField, specifiers: Json | null, from: string, kind: 'root' | 'first_party', edges: ImporterEdge[]): DepsRanges | null {
  const raw = imp[field];
  if (raw === undefined || raw === null) return {};
  if (!isObject(raw)) return null;
  const out: Json = {};
  for (const [depName, val] of Object.entries(raw)) {
    if (isObject(val) && typeof val.specifier === 'string' && typeof val.version === 'string') {
      setOwn(out, depName, val.specifier);
      edges.push({ from, kind, field, depName, range: val.specifier, ref: val.version });
    } else if (typeof val === 'string' && specifiers && typeof specifiers[depName] === 'string') {
      const spec = specifiers[depName] as string;
      setOwn(out, depName, spec);
      edges.push({ from, kind, field, depName, range: spec, ref: val });
    } else {
      return null;
    }
  }
  return out as DepsRanges;
}

function resolvePnpmTarget(depName: string, ref: string, byKey: Map<string, string>): string | null {
  if (ref.startsWith('link:')) return null;
  const clean = ref.startsWith('/') ? ref.slice(1) : ref;
  const base = stripPeers(clean);
  for (const candidate of [`${depName}@${clean}`, `/${depName}@${clean}`, `${depName}@${base}`, `/${depName}@${base}`, clean, `/${clean}`, base, `/${base}`]) {
    const hit = byKey.get(candidate);
    if (hit) return hit;
  }
  return null;
}

export function parsePnpmLock(
  raw: Json,
  parserVersion: DepsLock['parser_version'],
): { lock: DepsLock; graph: DirectLockGraph | null } {
  const refused = (state: DepsLockState, reason: string, lockfileVersion: number | null = null) => ({
    lock: { parser_version: parserVersion, state, reason, lockfile_version: lockfileVersion, root: null, entries: [] } as DepsLock,
    graph: null,
  });

  const lv = raw.lockfileVersion;
  const major = lv === 9 || (typeof lv === 'string' && /^9(?:\.[0-9]+)?$/.test(lv)) ? 9
    : lv === 6 || (typeof lv === 'string' && /^6(?:\.[0-9]+)?$/.test(lv)) ? 6 : null;
  if (major === null) {
    const num = typeof lv === 'number' && Number.isInteger(lv) ? lv
      : typeof lv === 'string' && /^[0-9]+(?:\.[0-9]+)?$/.test(lv) ? Math.trunc(Number(lv)) : null;
    return refused('unsupported', 'unsupported_lockfile', num);
  }
  if (raw.packages !== undefined && raw.packages !== null && !isObject(raw.packages)) return refused('unsupported', 'unsupported_lockfile', major);
  if (major === 9 && raw.snapshots !== undefined && raw.snapshots !== null && !isObject(raw.snapshots)) return refused('unsupported', 'unsupported_lockfile', major);

  const hasRootImporterFields = RANGE_FIELDS.some(f => raw[f] !== undefined) || raw.specifiers !== undefined;
  const importersObj: Json | null = isObject(raw.importers) ? raw.importers
    : raw.importers === undefined && hasRootImporterFields ? { '.': raw }
    : raw.importers === undefined && isObject(raw.packages) ? {} : null;
  if (!importersObj) return refused('unsupported', 'unsupported_lockfile', major);

  const importerEdges: ImporterEdge[] = [];
  const unreadImporters = new Set<string>();
  const entries: DepsLockEntry[] = [];
  let root: DepsLockRoot = { present: false, name: null, version: null, dependencies: null, optionalDependencies: null, peerDependencies: null, devDependencies: null };

  for (const [impPath, impVal] of Object.entries(importersObj)) {
    if (!isObject(impVal)) {
      if (impPath === '.') root = { present: true, name: null, version: null, dependencies: null, optionalDependencies: null, peerDependencies: null, devDependencies: null };
      else entries.push({ path: impPath, name: null, version: null, kind: exactPath.safeParse(impPath).success ? 'first_party' : 'held',
        hold_reason: exactPath.safeParse(impPath).success ? null : 'unsupported_entry', resolved: null, integrity: null, dev: false, optional: false,
        dependencies: null, optionalDependencies: null, peerDependencies: null, devDependencies: null });
      unreadImporters.add(impPath === '.' ? '' : impPath);
      continue;
    }
    const specs = isObject(impVal.specifiers) ? impVal.specifiers : null;
    const targetPath = impPath === '.' ? '' : impPath;
    const kind: 'root' | 'first_party' = impPath === '.' ? 'root' : 'first_party';
    const decl: DepsDeclared = {
      dependencies: readImporterField(impVal, 'dependencies', specs, targetPath, kind, importerEdges),
      optionalDependencies: readImporterField(impVal, 'optionalDependencies', specs, targetPath, kind, importerEdges),
      peerDependencies: impVal.peerDependencies === undefined ? {} : readImporterField(impVal, 'peerDependencies', specs, targetPath, kind, importerEdges),
      devDependencies: readImporterField(impVal, 'devDependencies', specs, targetPath, kind, importerEdges),
    };
    if (Object.values(decl).some(v => v === null)) unreadImporters.add(targetPath);
    if (impPath === '.') {
      root = { present: true, name: typeof impVal.name === 'string' ? impVal.name : null, version: typeof impVal.version === 'string' ? impVal.version : null, ...decl };
    } else {
      const valid = exactPath.safeParse(impPath).success && !impPath.split('/').includes('node_modules');
      entries.push({ path: impPath, name: typeof impVal.name === 'string' ? impVal.name : null, version: typeof impVal.version === 'string' ? impVal.version : null,
        kind: valid ? 'first_party' : 'held', hold_reason: valid ? null : 'unsupported_entry', resolved: null, integrity: null, dev: false, optional: false, ...decl });
    }
  }
  if (!root.present && Object.keys(importersObj).length === 0) {
    root = { present: true, name: null, version: null, ...EMPTY_DECLARED };
  }

  const packagesObj: Json = isObject(raw.packages) ? raw.packages : {};
  const snapshotsObj: Json = major === 9 && isObject(raw.snapshots) ? raw.snapshots : {};

  // Pre-count (name, version) occurrences to choose clean, collision-free paths.
  interface RawPkg { pkgKey: string; val: unknown; obj: Json | null; name: string | null; version: string | null; keyName: string | null; keyRef: string }
  const rawPkgs: RawPkg[] = Object.entries(packagesObj).map(([pkgKey, val]) => {
    const obj = isObject(val) ? val : null;
    const baseKey = stripPeers(pkgKey.startsWith('/') ? pkgKey.slice(1) : pkgKey);
    const { name: keyName, ref: keyRef } = splitNameAt(baseKey);
    const explicitName = typeof obj?.name === 'string' ? obj.name : null;
    const explicitVer = typeof obj?.version === 'string' ? obj.version : null;
    return { pkgKey, val, obj, name: explicitName ?? keyName, version: explicitVer ?? keyRef, keyName, keyRef };
  });

  const pairCounts = new Map<string, number>();
  for (const p of rawPkgs) {
    const k = `${p.name ?? ''}\0${p.version ?? ''}`;
    pairCounts.set(k, (pairCounts.get(k) ?? 0) + 1);
  }

  const keyToPath = new Map<string, string>();
  const pkgByPath = new Map<string, RawPkg>();
  const snapsByBase = new Map<string, Json[]>();
  if (major === 9) {
    for (const [snapKey, snapVal] of Object.entries(snapshotsObj)) {
      if (!isObject(snapVal)) continue;
      const base = stripPeers(snapKey);
      snapsByBase.set(base, [...snapsByBase.get(base) ?? [], snapVal]);
    }
  }

  for (const p of rawPkgs) {
    const validName = p.name !== null && npmPackageName.safeParse(p.name).success;
    const count = pairCounts.get(`${p.name ?? ''}\0${p.version ?? ''}`) ?? 0;
    const verSeg = p.version && safeSeg(p.version) ? (count === 1 ? p.version : `${p.version}_${sha256(p.pkgKey).slice(0, 8)}`) : sha256(p.pkgKey).slice(0, 12);
    const path = validName ? `pnpm/${verSeg}/node_modules/${p.name}` : `pnpm/${sha256(p.pkgKey).slice(0, 12)}/node_modules/invalid`;
    keyToPath.set(p.pkgKey, path);
    if (p.pkgKey.startsWith('/')) keyToPath.set(p.pkgKey.slice(1), path);
    pkgByPath.set(path, p);
  }

  // Compute dev-only reachability across snapshots (v9) or packages (v6) from importers.
  const prodQueue: string[] = [], devQueue: string[] = [];
  for (const edge of importerEdges) {
    const target = resolvePnpmTarget(edge.depName, edge.ref, keyToPath);
    if (!target) continue;
    if (edge.field === 'devDependencies') devQueue.push(target);
    else if (edge.field === 'dependencies' || edge.field === 'optionalDependencies') prodQueue.push(target);
  }

  const transitiveOut = new Map<string, Set<string>>();
  for (const p of rawPkgs) {
    const fromPath = keyToPath.get(p.pkgKey)!;
    const sources: Json[] = major === 9 ? (snapsByBase.get(p.pkgKey) ?? (p.obj ? [p.obj] : [])) : (p.obj ? [p.obj] : []);
    for (const src of sources) {
      for (const field of ['dependencies', 'optionalDependencies'] as const) {
        const deps = src[field];
        if (!isObject(deps)) continue;
        for (const [depName, depRef] of Object.entries(deps)) {
          if (typeof depRef !== 'string') continue;
          const target = resolvePnpmTarget(depName, depRef, keyToPath);
          if (target && target !== fromPath) {
            if (!transitiveOut.has(fromPath)) transitiveOut.set(fromPath, new Set());
            transitiveOut.get(fromPath)!.add(target);
          }
        }
      }
    }
  }

  const bfs = (seeds: string[]): Set<string> => {
    const seen = new Set<string>(seeds);
    const stack = [...seeds];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const next of transitiveOut.get(cur) ?? []) if (!seen.has(next)) { seen.add(next); stack.push(next); }
    }
    return seen;
  };
  const prodReachable = bfs(prodQueue), devReachable = bfs(devQueue);

  for (const p of rawPkgs) {
    const path = keyToPath.get(p.pkgKey)!;
    const obj = p.obj;
    const resolution = isObject(obj?.resolution) ? obj.resolution : null;
    const snaps = major === 9 ? (snapsByBase.get(p.pkgKey) ?? []) : [];
    const optional = obj?.optional === true || (snaps.length > 0 && snaps.every(s => s.optional === true));
    const dev = obj?.dev === true || (devReachable.has(path) && !prodReachable.has(path));
    const validName = p.name !== null && npmPackageName.safeParse(p.name).success ? p.name : null;
    const integrity = typeof resolution?.integrity === 'string' ? resolution.integrity : null;
    const rawTarball = typeof resolution?.tarball === 'string' ? resolution.tarball : null;

    const baseEntry = {
      path,
      version: p.version,
      resolved: rawTarball,
      integrity,
      dev,
      optional,
      ...EMPTY_DECLARED,
    };
    const held = (reason: string): DepsLockEntry => ({ ...baseEntry, name: validName, kind: 'held', hold_reason: reason });

    if (!obj || !exactPath.safeParse(path).success) { entries.push(held('unsupported_entry')); continue; }
    if (resolution && typeof resolution.directory === 'string') {
      entries.push({ ...baseEntry, name: validName, kind: 'first_party', hold_reason: null });
      continue;
    }
    if (npmBundled(obj) || obj.inBundle === true) { entries.push(held('bundled_dependency')); continue; }
    if (!validName) { entries.push(held('unsupported_entry')); continue; }
    if (typeof obj.name === 'string' && p.keyName && obj.name !== p.keyName) { entries.push(held('npm_alias_requires_review')); continue; }
    if (!resolution) { entries.push(held('unsupported_entry')); continue; }
    if (resolution.type === 'git' || (rawTarball && /^(?:git(?:\+[a-z]+)?|ssh):/i.test(rawTarball))) {
      entries.push(held('not_approved_public_registry'));
      continue;
    }
    if (rawTarball && /^(?:file|link):/i.test(rawTarball)) {
      entries.push(held('unsupported_entry'));
      continue;
    }
    if (!p.version || !npmExactVersion.safeParse(p.version).success) {
      if (rawTarball && /^https?:/i.test(rawTarball)) {
        try {
          const u = new URL(rawTarball);
          if (u.protocol !== 'https:' || u.hostname !== 'registry.npmjs.org' || u.username || u.password || u.port || u.search || u.hash) {
            entries.push(held('not_approved_public_registry'));
            continue;
          }
        } catch { /* fall through */ }
      }
      entries.push(held('unsupported_exact_version'));
      continue;
    }
    if (resolution.type !== undefined) { entries.push(held('unsupported_entry')); continue; }

    const resolvedUrl = rawTarball ?? `https://registry.npmjs.org/${validName}/-/${validName.split('/').at(-1)}-${p.version}.tgz`;
    let url: URL;
    try { url = new URL(resolvedUrl); } catch { entries.push(held('unsupported_entry')); continue; }
    if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port || url.search || url.hash) {
      entries.push(held('not_approved_public_registry'));
      continue;
    }
    if (!integrity || !/^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(integrity)) {
      entries.push({ ...baseEntry, resolved: resolvedUrl, name: validName, kind: 'held', hold_reason: 'unsupported_integrity' });
      continue;
    }
    if (!npmResolvedUnder(url, validName)) {
      entries.push({ ...baseEntry, resolved: resolvedUrl, name: validName, kind: 'held', hold_reason: 'npm_alias_requires_review' });
      continue;
    }
    entries.push({ ...baseEntry, resolved: resolvedUrl, name: validName, kind: 'registry', hold_reason: null });
  }

  // Build per-entry resolution graph: importer specifiers are exact declared ranges; transitive snapshot deps mark unread
  // because pnpm-lock.yaml records resolved versions rather than transitive manifests' declared semver ranges (DFBASE-13.5).
  const byEntry = new Map<string, { dependents: DepsDependent[]; unread: Set<string> }>();
  for (const e of entries) byEntry.set(e.path, { dependents: [], unread: new Set() });
  for (const edge of importerEdges) {
    const target = resolvePnpmTarget(edge.depName, edge.ref, keyToPath);
    if (!target || !byEntry.has(target)) continue;
    byEntry.get(target)!.dependents.push({ path: edge.from, kind: edge.kind, field: edge.field, range: edge.range });
  }
  for (const [fromPath, targets] of transitiveOut) {
    for (const target of targets) byEntry.get(target)?.unread.add(fromPath);
  }
  for (const imp of unreadImporters) {
    for (const bucket of byEntry.values()) bucket.unread.add(imp);
  }

  const finalGraph = new Map<string, DepsResolution>();
  for (const [entryPath, bucket] of byEntry) {
    finalGraph.set(entryPath, {
      dependents: bucket.dependents.sort((a, b) => bytewise(a.path, b.path) || bytewise(a.field, b.field)),
      unread: [...bucket.unread].sort(bytewise),
    });
  }

  return {
    lock: { parser_version: parserVersion, state: 'parsed', reason: null, lockfile_version: major, root, entries },
    graph: { format: 'pnpm', byEntry: finalGraph },
  };
}
