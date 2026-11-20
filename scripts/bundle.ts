// DFGHR-17, DFGHR-18: bundle packages/security-baseline-action (including @summationai/security-checks) into one file.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { build, type Metafile } from 'esbuild';

const PACKAGE_DIR = join(import.meta.dirname, '..');
const DEFAULT_OUT = join(PACKAGE_DIR, 'dist/index.mjs');

export interface BundleResult {
  file: string;
  bytes: number;
  sha256: string;
  metafile: Metafile;
}

export async function bundleAction(options: { outFile?: string } = {}): Promise<BundleResult> {
  const outFile = resolve(options.outFile ?? DEFAULT_OUT);
  mkdirSync(dirname(outFile), { recursive: true });
  const built = await build({
    entryPoints: [join(PACKAGE_DIR, 'src/main.ts')],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    target: 'node24',
    format: 'esm',
    metafile: true,
    legalComments: 'none',
    // Allow CommonJS transitive deps inside @actions/artifact and semver to load Node built-ins only;
    // refuse any third-party or filesystem module outside this single bundle (DFGHR-18).
    banner: {
      js: [
        "import { builtinModules as __acBuiltins, createRequire as __acCreateRequire } from 'node:module';",
        "const __acNodeBuiltins = new Set([...__acBuiltins, ...__acBuiltins.map((m) => `node:${m}`)]);",
        'const __acReq = __acCreateRequire(import.meta.url);',
        "const require = (id) => { if (!__acNodeBuiltins.has(id)) { const e = new Error(`Cannot find module '${id}'`); e.code = 'MODULE_NOT_FOUND'; throw e; } return __acReq(id); };",
      ].join(' '),
    },
  });
  const data = readFileSync(outFile);
  return {
    file: outFile,
    bytes: data.byteLength,
    sha256: createHash('sha256').update(data).digest('hex'),
    metafile: built.metafile,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { values } = parseArgs({ options: { out: { type: 'string' } } });
  const result = await bundleAction({ outFile: values.out });
  console.log(JSON.stringify({ file: result.file, bytes: result.bytes, sha256: result.sha256 }));
}
