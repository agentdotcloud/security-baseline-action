// DFBASE-8, DFBASE-10, DFGHR-9, DFGHR-18: read only regular package-lock.json files and their sibling package.json
// files strictly inside the checkout, in DFBASE-8's exact order and bounds, without following symlinks.
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readdirSync, readSync, realpathSync } from 'node:fs';
import { join, sep } from 'node:path';
import {
  exactPath,
  parseDepsLock,
  safeSourceText,
  screenedJson,
  sha256,
  utf8,
  type DepsCheckLockfile,
  type DepsOverridesInput,
} from '@summationai/security-checks';
import { BASELINE as P } from '../vendor/security-checks/src/baseline-profile.ts';

export interface CheckoutLock extends DepsCheckLockfile {
  pairs: string[];
}

export interface CheckoutSkip {
  path: string;
  reason: string;
}

export interface CheckoutAcquisition {
  locks: CheckoutLock[];
  selectedPaths: string[];
  skipped: CheckoutSkip[];
  other: Record<string, number>;
}

interface TreeEntry {
  path: string;
  absPath: string;
  kind: 'file' | 'symlink' | 'other';
  size: number;
}

const filename = (p: string) => p.split('/').at(-1)!;
const directory = (p: string) => p.slice(0, Math.max(0, p.lastIndexOf('/')));
const keyAt = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);
const byPath = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const safeName = (s: string) => {
  try {
    safeSourceText(s, 0);
    return true;
  } catch {
    return false;
  }
};
const gitBlobSha = (bytes: Uint8Array) =>
  createHash('sha1').update(`blob ${bytes.byteLength}\0`).update(bytes).digest('hex');

function isInsideRoot(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

function readCheckoutFileBounded(root: string, absPath: string, maxBytes: number): Buffer | null {
  // DFGHR-18: verify the resolved file stays under the checkout and is a regular file within maxBytes before reading.
  const real = realpathSync(absPath);
  if (!isInsideRoot(root, real)) throw new Error('baseline.path_outside_checkout');
  const fd = openSync(real, 'r');
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) return null;
    const chunks: Buffer[] = [];
    let total = 0;
    const buf = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1));
    for (;;) {
      const n = readSync(fd, buf, 0, Math.min(buf.length, maxBytes + 1 - total), null);
      if (n === 0) break;
      total += n;
      if (total > maxBytes) return null;
      chunks.push(Buffer.from(buf.subarray(0, n)));
    }
    return Buffer.concat(chunks, total);
  } finally {
    closeSync(fd);
  }
}

function walkCheckout(root: string): Map<string, TreeEntry> {
  const visible = new Map<string, TreeEntry>();
  const walk = (absDir: string, relDir: string) => {
    const entries = readdirSync(absDir, { withFileTypes: true }).sort((a, b) => byPath(a.name, b.name));
    for (const entry of entries) {
      if (entry.name === 'node_modules' || (!relDir && entry.name === '.git')) continue;
      const relPath = keyAt(relDir, entry.name);
      const absPath = join(absDir, entry.name);
      const stat = lstatSync(absPath);
      if (stat.isDirectory()) {
        walk(absPath, relPath);
        continue;
      }
      if (!exactPath.safeParse(relPath).success) continue;
      const kind: TreeEntry['kind'] = stat.isSymbolicLink() ? 'symlink' : stat.isFile() ? 'file' : 'other';
      visible.set(relPath, { path: relPath, absPath, kind, size: kind === 'file' ? stat.size : 0 });
    }
  };
  walk(root, '');
  return visible;
}

function parseOverrides(siblingBytes: Buffer | null, siblingUnreadable: boolean): { overrides: DepsOverridesInput; siblingSafe: boolean } {
  if (!siblingBytes) return { overrides: { state: siblingUnreadable ? 'unreadable' : 'absent' }, siblingSafe: false };
  let overrides: DepsOverridesInput = { state: 'unreadable' };
  let siblingSafe = false;
  try {
    const manifest = JSON.parse(utf8(siblingBytes));
    screenedJson(manifest, 512 * 1024);
    siblingSafe = true;
    if (manifest && typeof manifest === 'object' && !Array.isArray(manifest)) {
      overrides = Object.hasOwn(manifest, 'overrides') ? { state: 'present', value: manifest.overrides } : { state: 'absent' };
    }
  } catch {
    // An unreadable or unsafe manifest makes overrides unestablished, never assumed absent (DFBASE-8, DFBASE-13).
  }
  return { overrides, siblingSafe };
}

/**
 * DFBASE-8, DFBASE-10: discover, filter, bound and prepare package-lock.json files from a local checkout,
 * matching DFBASE's worker acquisition rules.
 */
export function acquireCheckout(checkoutDir: string): CheckoutAcquisition {
  const root = realpathSync(checkoutDir);
  const visible = walkCheckout(root);
  const candidates = [...visible.values()]
    .filter((e) => filename(e.path) === P.lock.filename)
    .sort((a, b) => a.path.split('/').length - b.path.split('/').length || byPath(a.path, b.path));

  const locks: CheckoutLock[] = [];
  const skipped: CheckoutSkip[] = [];
  const selectedPaths: string[] = [];
  const workspaces = new Set<string>();
  let totalSize = 0;

  for (const candidate of candidates) {
    const path = candidate.path;
    const dir = directory(path);
    if (!safeName(path)) {
      skipped.push({ path: `redacted-${sha256(path)}`, reason: 'credential_shaped_content' });
      continue;
    }
    const skip = (reason: string) => skipped.push({ path, reason });
    if (candidate.kind !== 'file') {
      skip(candidate.kind === 'symlink' ? 'symlink' : 'not_regular');
      continue;
    }
    if (visible.has(keyAt(dir, 'npm-shrinkwrap.json'))) {
      skip('npm_shrinkwrap_precedence');
      continue;
    }
    if (candidate.size > P.lock.bytes) {
      skip('lockfile_oversize');
      continue;
    }
    if (selectedPaths.length >= P.lock.count) {
      skip('lockfile_count_limit');
      continue;
    }
    if (totalSize + candidate.size > P.lock.run_bytes) {
      skip('lockfile_run_bytes');
      continue;
    }

    // Re-check actual file size before charging selectedPaths and totalSize so an oversize file never consumes a slot.
    const bytes = readCheckoutFileBounded(root, candidate.absPath, P.lock.bytes);
    if (bytes === null) {
      skip('lockfile_oversize');
      continue;
    }
    if (totalSize + bytes.byteLength > P.lock.run_bytes) {
      skip('lockfile_run_bytes');
      continue;
    }
    // DFBASE-8, DFBASE-15: selected lockfiles that fail DFBASE-10 parsing remain listed in selectedPaths and skipped
    // with their reason, matching DFBASE's worker acquisition behavior.
    selectedPaths.push(path);
    totalSize += bytes.byteLength;

    const parsed = parseDepsLock(bytes);
    if (parsed.state !== 'parsed') {
      skip(parsed.reason ?? 'unsupported_lockfile');
      continue;
    }

    const siblingPath = keyAt(dir, 'package.json');
    const peer = visible.get(siblingPath);
    const readablePeer = peer && peer.kind === 'file' && peer.size <= P.lock.package_bytes ? peer : null;
    const siblingBytes = readablePeer ? readCheckoutFileBounded(root, readablePeer.absPath, P.lock.package_bytes) : null;
    const { overrides, siblingSafe } = parseOverrides(siblingBytes, Boolean(peer && !siblingBytes));
    const pairs = [...new Set(parsed.entries.filter((e) => e.kind === 'registry').map((e) => JSON.stringify([e.name, e.version])))];
    for (const e of parsed.entries) {
      if (e.kind === 'first_party' && !e.path.split('/').includes('node_modules') && exactPath.safeParse(e.path).success) {
        workspaces.add(keyAt(dir, e.path));
      }
    }

    locks.push({
      path,
      bytes,
      git_blob: gitBlobSha(bytes),
      sha256: sha256(bytes),
      overrides,
      package_json:
        readablePeer && siblingBytes
          ? {
              path: siblingPath,
              size: siblingBytes.byteLength,
              git_blob: gitBlobSha(siblingBytes),
              sha256: siblingSafe ? sha256(siblingBytes) : null,
            }
          : null,
      pairs,
    });
  }

  const other: Record<string, number> = {};
  for (const e of visible.values()) {
    if (e.kind !== 'file') continue;
    const name = filename(e.path);
    const dir = directory(e.path);
    if (
      (P.other_inputs as readonly string[]).includes(name) ||
      (name === P.unlocked_manifest.filename &&
        !workspaces.has(dir) &&
        !P.unlocked_manifest.siblings.some((n) => visible.has(keyAt(dir, n))))
    ) {
      other[name] = (other[name] ?? 0) + 1;
    }
  }

  return { locks, selectedPaths, skipped, other };
}
