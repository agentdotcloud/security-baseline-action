// setup.sh: adds the baseline workflow to many repositories with the caller's own gh login. Each test runs the real
// script against test/fake-gh.ts on PATH, so nothing reaches GitHub, and asserts on what the script prints and on
// what it changed in the fake repositories.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { FakeCall, FakeError, FakeRepo, FakeState } from './fake-gh.ts';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SETUP = join(ROOT, 'setup.sh');
const FAKE_GH = join(ROOT, 'test', 'fake-gh.ts');
const WORKFLOW = readFileSync(join(ROOT, 'workflow', 'agentcloud-baseline.yml'), 'utf8');
const FILE = '.github/workflows/agentcloud-baseline.yml';
const TITLE = 'Add agent.cloud dependency baseline';
// What GitHub answers when a ruleset requires pull requests on the default branch.
const RULESET: FakeError = {
  status: 409,
  message: 'Repository rule violations found\n\nChanges must be made through a pull request.\n\n',
};

const repo = (extra: Partial<FakeRepo> = {}): FakeRepo => ({
  default_branch: 'main',
  branches: { main: { 'package-lock.json': '{}' } },
  ...extra,
});

function runSetup(args: string[], state: FakeState) {
  const dir = mkdtempSync(join(tmpdir(), 'setup-sh-'));
  try {
    const bin = join(dir, 'bin');
    mkdirSync(bin);
    writeFileSync(join(bin, 'gh'), `#!/bin/sh\nexec '${process.execPath}' '${FAKE_GH}' "$@"\n`, { mode: 0o755 });
    const statePath = join(dir, 'state.json');
    const logPath = join(dir, 'calls.jsonl');
    writeFileSync(statePath, JSON.stringify(state));
    writeFileSync(logPath, '');
    const run = spawnSync(SETUP, args, {
      encoding: 'utf8',
      // Only the fake gh and system tools on PATH, and no GitHub token in the environment.
      env: { PATH: `${bin}:/usr/bin:/bin`, HOME: dir, FAKE_GH_STATE: statePath, FAKE_GH_LOG: logPath },
    });
    const calls: FakeCall[] = readFileSync(logPath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    const after: FakeState = JSON.parse(readFileSync(statePath, 'utf8'));
    return { status: run.status, stdout: run.stdout, stderr: run.stderr, state: after, calls };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const writes = (calls: FakeCall[]) => calls.filter((c) => c.method !== 'GET');

test('commits the workflow straight to the default branch when GitHub allows it', () => {
  const run = runSetup(['acme/web'], { repos: { 'acme/web': repo() } });
  assert.equal(run.stderr, '');
  assert.equal(run.stdout, 'acme/web: committed\n');
  assert.equal(run.status, 0);
  const web = run.state.repos['acme/web'];
  assert.equal(web.branches.main[FILE], WORKFLOW, 'the file is workflow/agentcloud-baseline.yml, byte for byte');
  assert.deepEqual(web.commits, [{ branch: 'main', path: FILE, message: TITLE }]);
  assert.deepEqual(Object.keys(web.branches), ['main'], 'no other branch');
  assert.equal(web.pulls, undefined, 'no pull request');
  assert.deepEqual(
    writes(run.calls).map((c) => `${c.method} ${c.endpoint}`),
    [`PUT repos/acme/web/contents/${FILE}`],
    'the one write is the file',
  );
});

test('a protected default branch gets the file on branch agentcloud-baseline with a pull request', () => {
  const run = runSetup(['acme/api'], { repos: { 'acme/api': repo({ protect: RULESET }) } });
  assert.equal(run.stdout, 'acme/api: PR https://github.com/acme/api/pull/1\n');
  assert.equal(run.status, 0);
  const api = run.state.repos['acme/api'];
  assert.equal(api.branches.main[FILE], undefined, 'the default branch is unchanged');
  assert.equal(api.branches['agentcloud-baseline'][FILE], WORKFLOW);
  assert.deepEqual(api.commits, [{ branch: 'agentcloud-baseline', path: FILE, message: TITLE }]);
  const [pull] = api.pulls ?? [];
  assert.equal(pull.title, TITLE);
  assert.equal(pull.head, 'agentcloud-baseline');
  assert.equal(pull.base, 'main');
  assert.match(pull.body, /security-baseline-action/);
});

test('a pull request already open from agentcloud-baseline is reported, not opened again', () => {
  const open = {
    number: 7,
    title: TITLE,
    head: 'agentcloud-baseline',
    base: 'main',
    body: '',
    state: 'open' as const,
    html_url: 'https://github.com/acme/api/pull/7',
  };
  const api = repo({ protect: RULESET, pulls: [open] });
  api.branches['agentcloud-baseline'] = { ...api.branches.main, [FILE]: WORKFLOW };
  const run = runSetup(['acme/api'], { repos: { 'acme/api': api } });
  assert.equal(run.stdout, 'acme/api: PR https://github.com/acme/api/pull/7 (already open)\n');
  assert.equal(run.status, 0);
  assert.equal(run.state.repos['acme/api'].pulls?.length, 1);
  assert.deepEqual(
    writes(run.calls).map((c) => `${c.method} ${c.endpoint}`),
    [`PUT repos/acme/api/contents/${FILE}`],
    'only the refused direct commit',
  );
});

test('a repository that already has the file is skipped and the file is never overwritten', () => {
  const own = repo();
  own.branches.main[FILE] = 'name: our own baseline\n';
  const run = runSetup(['acme/web'], { repos: { 'acme/web': own } });
  assert.equal(run.stdout, 'acme/web: skipped (exists)\n');
  assert.equal(run.status, 0);
  assert.equal(run.state.repos['acme/web'].branches.main[FILE], 'name: our own baseline\n');
  assert.deepEqual(writes(run.calls), []);
});

test('--dry-run only reads and changes nothing', () => {
  const own = repo();
  own.branches.main[FILE] = 'name: our own baseline\n';
  const state: FakeState = {
    repos: { 'acme/web': repo(), 'acme/api': repo({ protect: RULESET }), 'acme/own': own },
  };
  const run = runSetup(['--dry-run', 'acme/web', 'acme/api', 'acme/own'], state);
  assert.equal(
    run.stdout,
    [
      `acme/web: would commit ${FILE} to main, or open a pull request if main is protected`,
      `acme/api: would commit ${FILE} to main, or open a pull request if main is protected`,
      'acme/own: skipped (exists)',
      '',
    ].join('\n'),
  );
  assert.equal(run.status, 0);
  assert.deepEqual(writes(run.calls), [], 'every call is a GET');
  assert.deepEqual(run.state, state, 'no repository changed');
});

test('--org sets up only the non-archived repositories in the org the caller can push to', () => {
  const run = runSetup(['--org', 'acme'], {
    repos: {
      'acme/web': repo(),
      'acme/old': repo({ archived: true }),
      'acme/theirs': repo({ push: false }),
      'other/web': repo(),
    },
  });
  assert.equal(run.stdout, 'acme/web: committed\n');
  assert.equal(run.status, 0);
  assert.equal(run.calls[1].endpoint, 'orgs/acme/repos?per_page=100');
  const touched = new Set(run.calls.map((c) => c.endpoint.match(/^repos\/([^/]+\/[^/]+)/)?.[1]).filter(Boolean));
  assert.deepEqual([...touched], ['acme/web'], 'archived, read-only and other orgs\' repositories are not touched');
});

test('a failure prints GitHub\'s reason, the other repositories still run, and the exit is non-zero', () => {
  const run = runSetup(['acme/locked', 'acme/missing', 'acme/web'], {
    repos: {
      'acme/locked': repo({ putError: { status: 403, message: 'Resource not accessible by personal access token' } }),
      'acme/web': repo(),
    },
  });
  assert.equal(
    run.stdout,
    [
      'acme/locked: failed: Resource not accessible by personal access token (HTTP 403)',
      'acme/missing: failed: Not Found (HTTP 404)',
      'acme/web: committed',
      '',
    ].join('\n'),
  );
  assert.equal(run.status, 1);
  assert.ok(
    !run.calls.some((c) => c.method === 'POST'),
    'a refusal that is not about branch protection opens no pull request',
  );
});

test('a pull request that cannot be opened is a failure with GitHub\'s reason', () => {
  const api = repo({ protect: RULESET });
  api.branches['agentcloud-baseline'] = { ...api.branches.main }; // left over, with no open pull request
  const run = runSetup(['acme/api'], { repos: { 'acme/api': api } });
  assert.equal(
    run.stdout,
    'acme/api: failed: main refused a direct commit, and opening a pull request from agentcloud-baseline failed: ' +
      'Reference already exists (HTTP 422)\n',
  );
  assert.equal(run.status, 1);
});

test('a default branch other than main is the one the push trigger names', () => {
  const run = runSetup(['acme/old'], {
    repos: { 'acme/old': repo({ default_branch: 'master', branches: { master: {} } }) },
  });
  assert.equal(run.stdout, 'acme/old: committed\n');
  assert.equal(
    run.state.repos['acme/old'].branches.master[FILE],
    WORKFLOW.replace('branches: [main]', 'branches: [master]'),
  );
});

test('it needs a gh login, and the workflow scope unless --dry-run', () => {
  const state: FakeState = { repos: { 'acme/web': repo() } };
  const signedOut = runSetup(['acme/web'], { ...state, signedIn: false });
  assert.equal(signedOut.status, 1);
  assert.match(signedOut.stderr, /gh auth login/);
  assert.deepEqual(signedOut.calls.map((c) => c.endpoint), ['user']);

  const noScope = runSetup(['acme/web'], { ...state, scopes: 'gist, read:org, repo' });
  assert.equal(noScope.status, 1);
  assert.match(noScope.stderr, /gh auth refresh -s workflow/);
  assert.deepEqual(noScope.calls.map((c) => c.endpoint), ['user']);

  const preview = runSetup(['--dry-run', 'acme/web'], { ...state, scopes: 'gist, read:org, repo' });
  assert.equal(preview.status, 0);
  assert.match(preview.stdout, /^note: .*gh auth refresh -s workflow\nacme\/web: would commit /);

  const fineGrained = runSetup(['acme/web'], { ...state, scopes: null });
  assert.equal(fineGrained.stdout, 'acme/web: committed\n', 'a token with no classic scopes is left to GitHub');
});

test('arguments other than owner/repo, --org <owner> and --dry-run are refused before any call', () => {
  for (const args of [[], ['web'], ['acme/web/extra'], ['--org'], ['--force', 'acme/web']]) {
    const run = runSetup(args, { repos: {} });
    assert.equal(run.status, 2, `${JSON.stringify(args)} exits 2`);
    assert.match(run.stderr, /^usage: /);
    assert.deepEqual(run.calls, []);
  }
});
