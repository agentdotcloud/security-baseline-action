// DFRPT-1/2: bounded I-JSON input and RFC 8785 canonical bytes. No reviver can detect duplicate keys.
import { createHash } from 'node:crypto';
export const REPORT_BYTES = 10 * 1024 * 1024;
const validString = (s: string) => !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(s);
export function parseReportJson(input: Uint8Array | string): unknown {
  const bytes = typeof input === 'string' ? Buffer.from(input) : input;
  if (bytes.length > REPORT_BYTES) throw Error('report_size');
  const text = typeof input === 'string' ? input : new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0, nodes = 0;
  const ws = () => { while (/[\x20\t\r\n]/.test(text[at] ?? '') && at < text.length) at++; };
  const string = (): string => {
    const start = at++;
    while (at < text.length) {
      const c = text[at++];
      if (c === '\\') { at++; continue; }
      if (c === '"') {
        const value = JSON.parse(text.slice(start, at)) as string;
        if (!validString(value)) throw Error('report_unicode');
        if (Buffer.byteLength(value) > 4096) throw Error('report_field_bytes');
        return value;
      }
    }
    throw Error('report_json');
  };
  const value = (depth: number): unknown => {
    if (depth > 48 || ++nodes > 300000) throw Error('report_complexity');
    ws(); const c = text[at];
    if (c === '"') return string();
    if (c === '{') {
      at++; ws(); const object: Record<string, unknown> = Object.create(null), keys = new Set<string>();
      if (text[at] === '}') { at++; return object; }
      for (;;) {
        ws(); if (text[at] !== '"') throw Error('report_json');
        const key = string(); if (['__proto__', 'constructor', 'prototype'].includes(key)) throw Error('report_unsafe_key'); if (keys.has(key)) throw Error('report_duplicate_key'); keys.add(key);
        ws(); if (text[at++] !== ':') throw Error('report_json'); object[key] = value(depth + 1);
        ws(); const end = text[at++]; if (end === '}') return object; if (end !== ',') throw Error('report_json');
      }
    }
    if (c === '[') {
      at++; ws(); const array: unknown[] = [];
      if (text[at] === ']') { at++; return array; }
      for (;;) { array.push(value(depth + 1)); ws(); const end = text[at++]; if (end === ']') return array; if (end !== ',') throw Error('report_json'); }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at))?.[0];
    if (!token) throw Error('report_json'); at += token.length;
    const result: unknown = JSON.parse(token);
    if (typeof result === 'number' && (!Number.isFinite(result) || Number.isInteger(result) && !Number.isSafeInteger(result))) throw Error('report_number');
    return result;
  };
  const result = value(0); ws(); if (at !== text.length) throw Error('report_json'); return result;
}

export function canonicalJson(input: unknown): string {
  let nodes = 0;
  const encode = (v: unknown, depth: number): string => {
    if (depth > 48 || ++nodes > 300000) throw Error('report_complexity');
    if (v === null || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'number') {
      if (!Number.isFinite(v) || Number.isInteger(v) && !Number.isSafeInteger(v)) throw Error('report_number');
      return JSON.stringify(v);
    }
    if (typeof v === 'string') { if (!validString(v)) throw Error('report_unicode'); return JSON.stringify(v); }
    if (Array.isArray(v)) {
      const items: string[] = [];
      for (let i = 0; i < v.length; i++) { if (!Object.hasOwn(v, i)) throw Error('report_sparse_array'); items.push(encode(v[i], depth + 1)); }
      return '[' + items.join(',') + ']';
    }
    if (!v || typeof v !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(v))) throw Error('report_json_type');
    return '{' + Object.keys(v).sort().map(k => { if (!validString(k)) throw Error('report_unicode'); return JSON.stringify(k) + ':' + encode((v as Record<string, unknown>)[k], depth + 1); }).join(',') + '}';
  };
  const result = encode(input, 0); if (Buffer.byteLength(result) > REPORT_BYTES) throw Error('report_size'); return result;
}
export function reportHash(input: unknown): string { return createHash('sha256').update(canonicalJson(input)).digest('hex'); }
export function documentDigest(input: Record<string, unknown>, field: 'content_digest' | 'view_digest' = 'content_digest') {
  const body = { ...input }; delete body[field]; return reportHash(body);
}
