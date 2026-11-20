// DFBASE-10, DFINT-17: the static.deps lock model. Pure (DFBASE-3): it parses lockfile bytes it is given and never reads
// a file, installs a package or runs repository code. npmInventory stays the pilot's parser; this one adds lockfile v2,
// first-party entries and every entry's declared ranges, which fix facts need for npm's nearest-ancestor resolution.
import { z } from 'zod';
import { npmBundled, npmExactVersion, npmPackageName, npmResolvedUnder } from './security-npm.ts';
import { exactPath, screenedJson, utf8 } from './security-primitives.ts';

export const DEPS_LOCK_VERSION = 'npm-lock-v2v3/semver-7.8.6/deps-v2';
export const DEPS_LOCK_BYTES = 2 * 1024 * 1024;
export const DEPS_RANGE_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies', 'devDependencies'] as const;
export type DepsRangeField = typeof DEPS_RANGE_FIELDS[number];
/** Declared ranges by package name. `null` means the field is present but unreadable, so it was not read. */
export type DepsRanges = Readonly<Record<string, string>>;
export type DepsLockState = 'parsed' | 'unsupported' | 'malformed' | 'credential_shaped';
export type DepsEntryKind = 'registry' | 'first_party' | 'held';
export interface DepsDeclared {
  dependencies: DepsRanges | null; optionalDependencies: DepsRanges | null;
  peerDependencies: DepsRanges | null; devDependencies: DepsRanges | null;
}
/** The root package (`packages[""]`). It is never a dependency. `present: false` leaves every range unread. */
export interface DepsLockRoot extends DepsDeclared { present: boolean; name: string | null; version: string | null }
/**
 * One `packages` key other than the root. `name` is the name it is installed under (the path after its last
 * `node_modules`), or the declared name of a workspace folder. `registry` entries passed DFINT-17's entry rules and are
 * the only dependencies; `first_party` is a link or a workspace folder; `held` carries `hold_reason`.
 */
export interface DepsLockEntry extends DepsDeclared {
  path: string; name: string | null; version: string | null;
  kind: DepsEntryKind; hold_reason: string | null;
  resolved: string | null; integrity: string | null; dev: boolean; optional: boolean;
}
export interface DepsLock {
  parser_version: typeof DEPS_LOCK_VERSION; state: DepsLockState; reason: string | null;
  lockfile_version: number | null; root: DepsLockRoot | null; entries: DepsLockEntry[];
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown) => typeof v === 'string' ? v : null;
const RegistryEntry = z.object({ name: z.string().optional(), version: z.string(), resolved: z.string(), integrity: z.string(),
  link: z.boolean().optional(), inBundle: z.boolean().optional(), dev: z.boolean().optional(), optional: z.boolean().optional() }).passthrough();

function ranges(value: Json | null, field: DepsRangeField): DepsRanges | null {
  if (!value) return null;
  const raw = value[field];
  if (raw === undefined) return {};
  if (!isObject(raw)) return null;
  const out: [string, string][] = [];
  for (const [name, range] of Object.entries(raw)) { if (typeof range !== 'string') return null; out.push([name, range]); }
  return Object.fromEntries(out); // own data properties only, so a "__proto__" key stays a key
}
const declared = (value: Json | null): DepsDeclared => ({ dependencies: ranges(value, 'dependencies'),
  optionalDependencies: ranges(value, 'optionalDependencies'), peerDependencies: ranges(value, 'peerDependencies'), devDependencies: ranges(value, 'devDependencies') });

/** The path after the last `node_modules` segment, or null for a path with no `node_modules` segment (a workspace folder). */
function installedName(path: string): string | null {
  const segments = path.split('/'), at = segments.lastIndexOf('node_modules');
  return at < 0 ? null : segments.slice(at + 1).join('/');
}

function lockEntry(path: string, value: unknown): DepsLockEntry {
  const object = isObject(value) ? value : null;
  const base = { path, version: text(object?.version), resolved: text(object?.resolved), integrity: text(object?.integrity),
    dev: object?.dev === true, optional: object?.optional === true, ...declared(object) };
  // exactPath bounds what may enter evidence (500 characters, no `%`, backslash or control characters); a key outside it is
  // held, but it keeps the name it is installed under and still sits in the tree for resolution (placeOf).
  const tail = installedName(path);
  const named = tail && npmPackageName.safeParse(tail).success ? tail : null;
  const held = (reason: string): DepsLockEntry => ({ ...base, name: named, kind: 'held', hold_reason: reason });
  if (!exactPath.safeParse(path).success || tail === '') return held('unsupported_entry');
  // A workspace folder or a link is the repository's own code: first-party, neither a dependency nor a hold.
  if (tail === null) return { ...base, name: text(object?.name), kind: 'first_party', hold_reason: null };
  if (object?.link === true) return { ...base, name: named, kind: 'first_party', hold_reason: null };
  // DFINT-17: a bundled entry's bytes came from inside its parent's tarball, never from the registry under its own name.
  // npm writes it with no resolved or integrity; one that carries both is still not a registry entry, so it is not looked up.
  if (npmBundled(value)) return held('bundled_dependency');
  // DFINT-17's entry rules, in the order npmInventory applies them, so both parsers hold an entry for the same reason.
  const shape = RegistryEntry.safeParse(value);
  if (!shape.success) return held('unsupported_entry');
  const e = shape.data, name = e.name ?? tail;
  if (!npmPackageName.safeParse(name).success) return held('unsupported_entry');
  if (e.name && name !== tail) return held('npm_alias_requires_review');
  if (!npmExactVersion.safeParse(e.version).success) return held('unsupported_exact_version');
  let url: URL;
  try { url = new URL(e.resolved); } catch { return held('unsupported_entry'); }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port || url.search || url.hash) return held('not_approved_public_registry');
  if (!/^sha(?:256|384|512)-[A-Za-z0-9+/]+=*$/.test(e.integrity)) return held('unsupported_integrity');
  // DFINT-17, last, so an entry another rule holds keeps that rule's reason: the lock must itself attribute this name to the
  // public registry. Any other path is another package installed under this name, an alias npm wrote no `name` for, and the
  // name stays local.
  if (!npmResolvedUnder(url, name)) return held('npm_alias_requires_review');
  return { ...base, name, kind: 'registry', hold_reason: null, dev: Boolean(e.dev), optional: Boolean(e.optional) };
}

const refused = (state: DepsLockState, reason: string, lockfileVersion: number | null = null): DepsLock =>
  ({ parser_version: DEPS_LOCK_VERSION, state, reason, lockfile_version: lockfileVersion, root: null, entries: [] });

/**
 * Parse one `package-lock.json` (DFBASE-10). lockfileVersion 2 and 3 are read from `packages` only; anything else is
 * `unsupported`. Content the evidence screen rejects as credential-shaped returns `credential_shaped` and nothing
 * derived from it. Bytes over 2 MiB are refused: acquisition skips them before they get here (DFBASE-8).
 */
export function parseDepsLock(content: Uint8Array | string): DepsLock {
  const size = typeof content === 'string' ? Buffer.byteLength(content) : content.byteLength;
  if (size > DEPS_LOCK_BYTES) throw Error('deps_lock_oversize');
  let raw: unknown;
  try { raw = JSON.parse(typeof content === 'string' ? content : utf8(Buffer.from(content.buffer, content.byteOffset, content.byteLength))); }
  catch { return refused('malformed', 'malformed_json'); }
  try { screenedJson(raw, DEPS_LOCK_BYTES); }
  catch (e) {
    if ((e as { code?: unknown }).code === 'security.secret') return refused('credential_shaped', 'credential_shaped_content');
    throw e;
  }
  const lockfileVersion = isObject(raw) && typeof raw.lockfileVersion === 'number' ? raw.lockfileVersion : null;
  const packages = isObject(raw) ? raw.packages : undefined;
  if ((lockfileVersion !== 2 && lockfileVersion !== 3) || !isObject(packages)) return refused('unsupported', 'unsupported_lockfile', lockfileVersion);
  const rootValue = Object.hasOwn(packages, '') ? packages[''] : undefined, rootObject = isObject(rootValue) ? rootValue : null;
  const root: DepsLockRoot = { present: rootValue !== undefined, name: text(rootObject?.name), version: text(rootObject?.version), ...declared(rootObject) };
  const entries = Object.entries(packages).filter(([path]) => path !== '').map(([path, value]) => lockEntry(path, value));
  return { parser_version: DEPS_LOCK_VERSION, state: 'parsed', reason: null, lockfile_version: lockfileVersion, root, entries };
}

// Resolution follows npm and Node: from a folder, look in its own node_modules, then each enclosing one, up to the root.
export interface DepsDependent { path: string; kind: 'root' | DepsEntryKind; field: DepsRangeField; range: string }
/**
 * `unread` lists the keys that may depend on the entry but whose range for it could not be established: folders that
 * resolve the name here with ranges that were not read, and keys that cannot be placed in the tree yet declare the name
 * or have ranges that were not read.
 */
export interface DepsResolution { dependents: DepsDependent[]; unread: string[] }
interface Node { path: string; kind: 'root' | DepsEntryKind; declared: DepsDeclared }
interface Index { installed: Set<string>; declarers: Map<string, DepsDependent[]>; unread: Node[]; unplaced: Node[] }
const indexes = new WeakMap<DepsLock, Index>();
const bytewise = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;

/**
 * Where a `packages` key sits, for resolution only and at any length. `inside` is a folder under the lockfile's own;
 * `outside` is one reached through leading `..` (a `file:` target), from which resolution never comes back inside;
 * anything else (an empty, `.` or inner `..` segment, or a backslash) cannot be placed.
 */
function placeOf(path: string): 'inside' | 'outside' | 'unplaced' {
  const segments = path.split('/'), up = segments.findIndex(s => s !== '..'), rest = up < 0 ? [] : segments.slice(up);
  if (path.includes('\\') || !rest.length || rest.some(s => s === '' || s === '.' || s === '..')) return 'unplaced';
  return up > 0 ? 'outside' : 'inside';
}
// The root and workspace folders install their devDependencies; a package inside node_modules does not.
const fieldsOf = (node: Node) => node.path === '' || installedName(node.path) === null ? DEPS_RANGE_FIELDS : DEPS_RANGE_FIELDS.slice(0, 3);
function lockIndex(lock: DepsLock): Index {
  const known = indexes.get(lock);
  if (known) return known;
  if (lock.state !== 'parsed' || !lock.root) throw Error('deps_lock_not_parsed');
  const node = (e: DepsLockEntry): Node => ({ path: e.path, kind: e.kind, declared: e });
  const nodes: Node[] = [{ path: '', kind: 'root', declared: lock.root }, ...lock.entries.filter(e => placeOf(e.path) === 'inside').map(node)];
  const index: Index = { installed: new Set(nodes.filter(n => n.path && installedName(n.path)).map(n => n.path)), declarers: new Map(), unread: [],
    unplaced: lock.entries.filter(e => placeOf(e.path) === 'unplaced').map(node) };
  for (const node of nodes) {
    let unread = false;
    for (const field of fieldsOf(node)) {
      const declared = node.declared[field];
      if (!declared) { unread = true; continue; }
      for (const [name, range] of Object.entries(declared)) index.declarers.set(name, [...index.declarers.get(name) ?? [], { path: node.path, kind: node.kind, field, range }]);
    }
    if (unread) index.unread.push(node);
  }
  indexes.set(lock, index);
  return index;
}

/** The `packages` path npm resolves `name` to from the folder at `from` ("" is the root), or null when nothing is installed. */
export function resolveDependency(lock: DepsLock, from: string, name: string): string | null {
  const { installed } = lockIndex(lock);
  for (let segments = from ? from.split('/') : []; ; segments = segments.slice(0, -1)) {
    if (segments.at(-1) !== 'node_modules') {
      const candidate = [...segments, 'node_modules', name].join('/');
      if (installed.has(candidate)) return candidate;
    }
    if (!segments.length) return null;
  }
}

/** Every declared edge that resolves to the entry at `path`, the root and first-party folders included (DFBASE-13.5). */
export function dependentsOf(lock: DepsLock, path: string): DepsResolution {
  const index = lockIndex(lock), entry = lock.entries.find(e => e.path === path);
  if (!entry) throw Error('deps_lock_unknown_entry');
  if (!entry.name || !index.installed.has(path)) return { dependents: [], unread: [] };
  const name = entry.name;
  const dependents = (index.declarers.get(name) ?? []).filter(d => resolveDependency(lock, d.path, name) === path)
    .sort((a, b) => bytewise(a.path, b.path) || bytewise(a.field, b.field));
  // A key that cannot be placed may resolve the name anywhere, so if it may declare it, its range is not established.
  const unplaced = index.unplaced.filter(n => DEPS_RANGE_FIELDS.some(f => n.declared[f] === null || Object.hasOwn(n.declared[f]!, name)));
  const unread = [...index.unread.filter(n => resolveDependency(lock, n.path, name) === path), ...unplaced].map(n => n.path).sort(bytewise);
  return { dependents, unread };
}
