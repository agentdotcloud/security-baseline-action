// DFINT-17/20: one bounded npm identity contract for inventory and scoped assessments.
import { z } from 'zod';
import semver from 'semver';
export const npmPackageName = z.string().min(1).max(214).regex(/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/);
export const npmExactVersion = z.string().min(1).max(256).refine(value => {
  const parsed = semver.parse(value);
  return parsed !== null && parsed.version + (parsed.build.length ? '+' + parsed.build.join('.') : '') === value;
}, 'canonical exact npm version required');

// DFINT-17, DFBASE-10: the two rules that keep a lock entry's name on this machine. Both lock parsers call them (static.deps's
// lockEntry and the pilot's npmInventory), so a name one parser holds is never looked up on the public registry by the other.
/** npm marks a package that shipped inside its parent's tarball. Its bytes never came from the registry under its own name. */
export const npmBundled = (entry: unknown): boolean =>
  typeof entry === 'object' && entry !== null && (entry as { inBundle?: unknown }).inBundle === true;
/** The public registry serves a package's tarballs at `/<name>/-/<file>`. Any other path is another package installed under this name. */
export const npmResolvedUnder = (resolved: URL, name: string): boolean => resolved.pathname.startsWith(`/${name}/-/`);
