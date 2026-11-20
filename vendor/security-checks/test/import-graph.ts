// DFBASE-3: a static walker for purity tests. From one module it follows every runtime import (static, re-export,
// side-effect, dynamic and require) through the repository's own files and records the packages it reaches. Node erases
// `import type` and `export type`, so those are skipped; `import { type X }` still loads its module, so it counts.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseSync } from 'oxc-parser';

export interface ImportGraph {
  /** Absolute paths of the repository files reached, the entry included, sorted. */
  modules: string[];
  /** Package and builtin specifiers reached, as written (`node:fs/promises`, `zod`), sorted. Not followed further. */
  packages: string[];
  /** Imports the walker could not follow: a non-literal dynamic import or a relative file that does not exist. */
  unresolved: string[];
}

type Node = { type: string; [key: string]: unknown };
const isNode = (value: unknown): value is Node => typeof value === 'object' && value !== null && typeof (value as Node).type === 'string';
const literal = (value: unknown): string | null => isNode(value) && value.type === 'Literal' && typeof value.value === 'string' ? value.value : null;

function runtimeSpecifiers(file: string): (string | null)[] {
  const parsed = parseSync(file, readFileSync(file, 'utf8'));
  if (parsed.errors.length) throw Error(`${file}: ${parsed.errors[0]!.message}`);
  const out: (string | null)[] = [];
  const visit = (value: unknown): void => {
    if (Array.isArray(value)) { for (const item of value) visit(item); return; }
    if (!isNode(value)) return;
    const node = value;
    if (node.type === 'ImportDeclaration') { if (node.importKind !== 'type') out.push(literal(node.source)); }
    else if (node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') { if (node.source && node.exportKind !== 'type') out.push(literal(node.source)); }
    else if (node.type === 'TSImportEqualsDeclaration') {
      const reference = node.moduleReference;
      if (node.importKind !== 'type' && isNode(reference) && reference.type === 'TSExternalModuleReference') out.push(literal(reference.expression));
    }
    else if (node.type === 'ImportExpression') out.push(literal(node.source));
    else if (node.type === 'CallExpression' && isNode(node.callee) && node.callee.type === 'Identifier' && node.callee.name === 'require') out.push(literal((node.arguments as unknown[])[0]));
    // `import('x').T` in a type position is a TSImportType, not an ImportExpression: erased, and not counted as an import.
    for (const child of Object.values(node)) visit(child);
  };
  visit(parsed.program);
  return out;
}

export function importGraph(entry: string | URL): ImportGraph {
  const start = entry instanceof URL ? fileURLToPath(entry) : resolve(entry);
  const modules = new Set<string>(), packages = new Set<string>(), unresolved = new Set<string>();
  for (const queue = [start]; queue.length;) {
    const file = queue.pop()!;
    if (modules.has(file)) continue;
    modules.add(file);
    for (const specifier of runtimeSpecifiers(file)) {
      if (specifier === null) { unresolved.add(`${file}: non-literal import`); continue; }
      if (!specifier.startsWith('.')) { packages.add(specifier); continue; }
      const target = resolve(dirname(file), specifier);
      if (existsSync(target)) queue.push(target); else unresolved.add(`${file}: ${specifier}`);
    }
  }
  return { modules: [...modules].sort(), packages: [...packages].sort(), unresolved: [...unresolved].sort() };
}

// DFBASE-3: the check opens no file, process or network connection and imports nothing from control's runtime.
const IMPURE_PACKAGE = /^(?:node:)?(?:fs|net|http|https|http2|child_process|tls|dgram|cluster)(?:\/|$)|^(?:pg|hono|@hono\/[^/]+)(?:\/|$)/;
const IMPURE_MODULE = /[\\/]store\.ts$/;
/** What a pure module must not reach: file, network and process builtins, `pg`, `hono` and control's `store.ts`. */
export function impurities(graph: ImportGraph): string[] {
  return [...graph.packages.filter(p => IMPURE_PACKAGE.test(p)), ...graph.modules.filter(m => IMPURE_MODULE.test(m))];
}
