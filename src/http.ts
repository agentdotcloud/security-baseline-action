// DFGHR-8, DFGHR-18: bounded public HTTP client for the runner action.
// Contacts only https://registry.npmjs.org and https://api.osv.dev with validated paths, no redirects, and bounded bytes.
import { npmExactVersion, npmPackageName, OsvId, sha256, type PublicHTTP } from '@summationai/security-checks';
import { BASELINE as P } from '../vendor/security-checks/src/baseline-profile.ts';

export const ALLOWED_PUBLIC_HOSTS = ['registry.npmjs.org', 'api.osv.dev'] as const;
const MAX_PUBLIC_BYTES = 8 * 1024 ** 2;

export type PublicOrigin = 'npm' | 'osv';

function safeDecode(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

export function validatePublicRequest(raw: string, body: unknown): { url: URL; origin: PublicOrigin } {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('runner.public_origin_refused');
  }
  if (url.username || url.password || url.search || url.hash) throw new Error('runner.public_origin_refused');
  if (url.origin === 'https://registry.npmjs.org' && body === undefined) {
    const parts = url.pathname.split('/');
    let name: string | null = null;
    let version: string | null = null;
    if (parts.length === 3 && parts[1] && parts[2]) {
      name = safeDecode(parts[1]);
      version = safeDecode(parts[2]);
    } else if (parts.length === 4 && parts[1] && parts[2] && parts[3]) {
      const scope = safeDecode(parts[1]);
      const pkg = safeDecode(parts[2]);
      version = safeDecode(parts[3]);
      if (scope?.startsWith('@') && !scope.includes('/') && pkg && !pkg.includes('/')) {
        name = `${scope}/${pkg}`;
      }
    }
    if (name && version && npmPackageName.safeParse(name).success && npmExactVersion.safeParse(version).success) {
      return { url, origin: 'npm' };
    }
  }
  if (
    url.origin === 'https://api.osv.dev' &&
    ((url.pathname === '/v1/querybatch' && body !== undefined) ||
      (body === undefined && /^\/v1\/vulns\/[^/]+$/.test(url.pathname)))
  ) {
    if (url.pathname === '/v1/querybatch') return { url, origin: 'osv' };
    const id = safeDecode(url.pathname.slice(10));
    if (id && !id.includes('/') && OsvId.safeParse(id).success) return { url, origin: 'osv' };
  }
  throw new Error('runner.public_origin_refused');
}

function parseRetryAfter(header: string | null, nowMs: number): number | null {
  if (!header) return null;
  const seconds = /^\d+$/.test(header) ? Number(header) : Math.ceil((Date.parse(header) - nowMs) / 1000);
  return Number.isFinite(seconds) ? Math.min(60, Math.max(1, seconds)) : null;
}

async function readBoundedBytes(res: Response, max: number): Promise<Buffer> {
  if (Number(res.headers.get('content-length')) > max) {
    await res.body?.cancel();
    throw new Error('runner.public_response_limit');
  }
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (reader) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.byteLength;
    if (size > max) {
      await reader.cancel();
      throw new Error('runner.public_response_limit');
    }
    chunks.push(next.value);
  }
  return Buffer.concat(chunks, size);
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error('aborted'));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason ?? new Error('aborted'));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export interface RunnerHttpOptions {
  fetch?: typeof fetch;
  now?: () => number;
  signal?: AbortSignal;
  retries?: number;
  baseBackoffMs?: number;
  timeoutMs?: number;
}

export function createRunnerHttp(options: RunnerHttpOptions = {}): PublicHTTP {
  const fetcher = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const retries = options.retries ?? P.request.retries;
  const baseBackoffMs = options.baseBackoffMs ?? 250;
  const timeoutMs = options.timeoutMs ?? P.request.timeout_ms;

  return {
    async json(raw, body, max = 4 * 1024 ** 2) {
      const { url } = validatePublicRequest(raw, body);
      for (let attempt = 0; ; attempt++) {
        options.signal?.throwIfAborted();
        const timeout = AbortSignal.timeout(timeoutMs);
        const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout;
        let res: Response;
        try {
          res = await fetcher(url, {
            method: body === undefined ? 'GET' : 'POST',
            redirect: 'manual',
            signal,
            ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }),
          });
        } catch {
          options.signal?.throwIfAborted();
          if (attempt >= retries) throw new Error('source_unavailable');
          await sleep(baseBackoffMs * 2 ** attempt, options.signal);
          continue;
        }

        if (res.status === 404) {
          await res.body?.cancel();
          throw new Error('source_http_404');
        }
        if (res.status === 429 || res.status >= 500) {
          const retryAfter = parseRetryAfter(res.headers.get('retry-after'), now());
          await res.body?.cancel();
          if (attempt >= retries) throw new Error('source_unavailable');
          const waitMs = retryAfter !== null ? (baseBackoffMs > 0 ? retryAfter * 1000 : 0) : baseBackoffMs * 2 ** attempt;
          await sleep(waitMs, options.signal);
          continue;
        }
        if (res.status !== 200) {
          await res.body?.cancel();
          throw new Error('source_unavailable');
        }

        let payload: Buffer;
        try {
          payload = await readBoundedBytes(res, Math.min(max, MAX_PUBLIC_BYTES));
        } catch (err) {
          options.signal?.throwIfAborted();
          if (err instanceof Error && err.message === 'runner.public_response_limit') throw err;
          if (attempt >= retries) throw new Error('source_unavailable');
          await sleep(baseBackoffMs * 2 ** attempt, options.signal);
          continue;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(payload.toString('utf8'));
        } catch {
          throw new Error('source_unavailable');
        }
        return {
          body: parsed,
          sha256: sha256(payload),
          retrieved_at: new Date(now()).toISOString(),
        };
      }
    },
  };
}
