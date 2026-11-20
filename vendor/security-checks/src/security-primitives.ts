// DFBASE-3, DFRPT-1: pure hashing, identity and screening primitives. No file, network, process or database access:
// this module may import only zod, node:crypto and secret-in.ts, so the report library and the static.deps check can
// load it anywhere. Control's security-evidence.ts and security-source.ts re-export these names for existing callers.
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { secretIn } from './secret-in.ts';

export class SecurityWorkError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.code = code; }
}
export const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
export const gitBlob = (bytes: Uint8Array) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
// DFSEC-7, DFAPP-19: profile approval and observed census identities use the same JSONB-safe range.
export const securityTestIdentity = z.string().min(1).max(500).refine((s) => !/[\u0000\uD800-\uDFFF]/u.test(s));
export const SNAPSHOT_MAX_FILES = 50_000; // DFSEC-4, DFSEC-7: the snapshot and its install census share a path ceiling
export const snapshotFileMode = z.enum(['100644', '100755']); // DFINT-30: regular Git files only

// DFINT-30: decode standard escapes across the text, without trusting quotes or needing a valid JSON document.
const ESCAPE = /\\(?:u([\da-fA-F]{4})|x([\da-fA-F]{2})|(["\\/nrtbf]))/g;
const SIMPLE = { '"': '"', '\\': '\\', '/': '/', n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' };
const unescapeText = (text: string) => text.replace(ESCAPE, (_match, unicode: string | undefined, hex: string | undefined, simple: keyof typeof SIMPLE) =>
  // Adjacent UTF-16 surrogate code units form a pair before the decoded text is converted back to bytes.
  unicode || hex ? String.fromCharCode(parseInt((unicode ?? hex)!, 16)) : SIMPLE[simple]);
const proofSecret = (bytes: Buffer) => secretIn(bytes, true);

// Screen raw and decoded strings, including JSON embedded inside other strings or object keys.
export function secretInJson(value: unknown, scan = proofSecret): boolean {
  const pending = [value];
  while (pending.length) {
    const item = pending.pop();
    if (typeof item === 'string') {
      if (secretInFile(Buffer.from(item), scan)) return true;
    } else if (Array.isArray(item)) {
      for (const child of item) pending.push(child);
    } else if (item && typeof item === 'object') {
      for (const [key, child] of Object.entries(item)) pending.push(key, child);
    }
  }
  return false;
}
// Keep the raw-byte scan. Decode once for stored escapes and once more for escaped text inside a serialized field.
export function secretInFile(bytes: Buffer, scan = proofSecret): boolean {
  if (scan(bytes)) return true;
  if (!bytes.includes(0x5c)) return false;
  let text = bytes.toString('utf8');
  for (let pass = 0; pass < 2; pass++) {
    const decoded = unescapeText(text);
    if (decoded === text) break;
    if (scan(Buffer.from(decoded))) return true;
    text = decoded;
  }
  return false;
}
export const gitSha = z.string().regex(/^[a-f0-9]{40}$/);
export const evidenceHash = z.string().regex(/^[a-f0-9]{64}$/);
// DFRPT-1: a path a report names. It is the literal repository-relative Git path, compared as written and never
// percent-decoded, so `%` is an ordinary character in it. It selects nothing to read: a caller that acquires a file by
// path checks `exactPath` at that point.
export const reportPath = z.string().min(1).max(500).refine(s => !/[\\\u0000-\u001f\u007f]/.test(s) && !s.split('/').some(x => ['', '.', '..'].includes(x)), 'literal repository-relative path required');
// DFINT-12/29: a path that selects a file to acquire. `reportPath`, and no `%`, so no encoded separator reaches a reader.
export const exactPath = z.string().min(1).max(500).refine(s => !/[\\%\u0000-\u001f\u007f]/.test(s) && !s.split('/').some(x => ['', '.', '..'].includes(x)), 'exact repository-relative path required');
export const repositoryName = z.string().max(200).regex(/^[A-Za-z0-9_-][A-Za-z0-9_.-]*\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/);
export function utf8(bytes: Buffer,preserveBOM=false) { return new TextDecoder('utf-8', { fatal: true,ignoreBOM:preserveBOM }).decode(bytes); }
export const digest = (v: unknown) => createHash('sha256').update(canonical(v)).digest('hex');
// Object key order is not a new upstream revision. Arrays retain their source order.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(',')}}`;
  return JSON.stringify(v) ?? 'null';
}
export function safeSourceText(text: string, max: number): string {
  if (secretIn(Buffer.from(text)) || /\b(?:Bearer\s+\S+|(?:password|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+)/i.test(text)) {
    throw new SecurityWorkError('security.secret', 'Source text contains credential-shaped content; intake refused.');
  }
  return text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').slice(0, max);
}
export function screenedJson(value: unknown,max=4*1024*1024) { const text=JSON.stringify(value);if(Buffer.byteLength(text)>max)throw Error('evidence_oversize');safeSourceText(text,0);return value; }
