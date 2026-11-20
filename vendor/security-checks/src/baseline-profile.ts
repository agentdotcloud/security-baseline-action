// DFBASE-1: the release pins every revision-2 table value, including limits owned by later slices.
import { DEPS_CHECK_ID, DEPS_CHECK_VERSION, DEPS_DEPENDABOT_VERSION, DEPS_IDENTITY_VERSION, DEPS_OSV_VERSION, DEPS_REPORT_LIMITS } from './security-deps-check.ts';
import { DEPS_FACTS_VERSION } from './security-deps-facts.ts';
import { DEPS_LOCK_BYTES, DEPS_LOCK_VERSION } from './security-deps-lock.ts';

export const BASELINE = {
  id: 'discovery-deps-v1', revision: 2,
  components: { check: DEPS_CHECK_ID, check_version: DEPS_CHECK_VERSION, parser: DEPS_LOCK_VERSION, identity: DEPS_IDENTITY_VERSION,
    osv: DEPS_OSV_VERSION, dependabot: DEPS_DEPENDABOT_VERSION, correlation: DEPS_CHECK_VERSION, fix_facts: DEPS_FACTS_VERSION, renderer: 'security-report-html/1' },
  lock: { filename: 'package-lock.json', versions: [2, 3], section: 'packages', count: 25, order: 'shallowest_then_bytewise', bytes: DEPS_LOCK_BYTES, run_bytes: 20 * 1024 ** 2, package_bytes: 256 * 1024 },
  responses: { commit: 8 * 1024 ** 2, tree: 8 * 1024 ** 2, blob: DEPS_LOCK_BYTES, alerts: 4 * 1024 ** 2 },
  other_inputs: ['npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'deno.lock', 'deno.json', 'deno.jsonc',
    'requirements.txt', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'setup.py', 'setup.cfg', 'Gemfile', 'Gemfile.lock',
    'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile', 'composer.json', 'composer.lock',
    'packages.config', 'packages.lock.json', 'Package.swift', 'Package.resolved', 'pubspec.yaml', 'pubspec.lock', 'mix.exs', 'mix.lock', 'rebar.config', 'rebar.lock'],
  unlocked_manifest: { filename: 'package.json', siblings: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'], exclude_selected_workspaces: true },
  report: { per_lockfile: 1, limits: DEPS_REPORT_LIMITS }, identities: 5000,
  alerts: { state: 'open', pages: 50, per_page: 100 },
  request: { timeout_ms: 30_000, retries: 3, defer_after_s: 60 },
  rate: { npm: 20, osv: 5 }, deadline_ms: 20 * 60_000, lease_ms: 2 * 60_000,
  compute_ms: 60_000, memory_mib: 512, attempts: 3,
  active: { tenant: 1, deployment: 4, unclaimed: 1 }, spacing_s: 15 * 60,
  daily: { tenant: 200, deployment: 2000, unclaimed: 500, window_s: 24 * 3600 },
  trial: { repositories: 5, days: 14 }, stale_minutes: 60,
  proof: { hours: 1, minimum_permission: 'write', per_person_hour: 10, pages: 10, per_page: 100 },
  stale_banner_hours: 24, model_and_provider_spend: 0, retention: 'DFBASE-16',
} as const;
export const BASELINE_DIGEST = 'b0e65639847efc7fc9140dcfbdec38e817024541d01c8e14ab9a957d0de9f714';
export const BASELINE_SETTING = `${BASELINE.id}:${BASELINE.revision}:${BASELINE_DIGEST}`;
