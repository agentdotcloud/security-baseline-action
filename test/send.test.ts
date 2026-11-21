// DFGHR-11, DFGHR-12, DFGHR-13, DFGHR-15, DFGHR-20, DFGHR-22: what the action sends to agent.cloud, tested against a
// fake control that applies control's own request checks (test/fake-control.ts) and a fake GitHub OIDC endpoint.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, symlinkSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  ACTION_VERSION,
  ARTIFACT_FILE,
  controlOrigin,
  createControlClient,
  createGitHubRuntime,
  REPORT_FILE,
  REPORT_MAX_BYTES,
  runAction,
  SETUP_PAGE_URL,
  type BaselineArtifact,
} from '../src/index.ts';
import { fakeControl, fakeIdToken, fakeOidc } from './fake-control.ts';
import { githubEnv, makeCheckout, makeFakeFetch, makeRuntime, NOW, osvAdvisory, RUN, regEntry } from './helpers.ts';

const ORIGIN = 'https://agent.cloud';
const MODE = 'GET /security/github/runner/mode';
const REPORTS = 'POST /security/github/runner/reports';
const LOCKFILES = 'POST /security/github/runner/lockfiles';
const PRIVATE_NAMES = ['priv-pkg', 'internal-mirror', 'bundled-pkg'];
const RECORDS = [osvAdvisory('GHSA-1111-2222-3333', 'pub-pkg', 'HIGH', '1.2.0')];

// One public package with an advisory, and three dependencies DFBASE-9 leaves unchecked: one the public registry
// doesn't know, one from a private registry and one bundled.
const lockfile = (name: string) => ({
  lockfileVersion: 3,
  packages: {
    '': { name, dependencies: { 'pub-pkg': '^1.0.0', 'priv-pkg': '^1.0.0', '@acme/internal-mirror': '^2.0.0' } },
    'node_modules/pub-pkg': regEntry('pub-pkg', '1.0.0'),
    'node_modules/priv-pkg': regEntry('priv-pkg', '1.0.0'),
    'node_modules/@acme/internal-mirror': {
      version: '2.0.0',
      resolved: 'https://npm.internal.example/@acme/internal-mirror/-/internal-mirror-2.0.0.tgz',
      integrity: 'sha512-Zml4dHVyZQ==',
    },
    'node_modules/bundled-pkg': regEntry('bundled-pkg', '1.0.0', { inBundle: true }),
  },
});

function setup(options: { mode?: 'runner' | 'agent.cloud'; refuse?: Parameters<typeof fakeControl>[0]['refuse']; reportsPerHour?: number } = {}) {
  const control = fakeControl({ repositoryId: RUN.repositoryId, ownerId: RUN.ownerId, mode: options.mode, refuse: options.refuse, reportsPerHour: options.reportsPerHour });
  const oidc = fakeOidc(RUN);
  const net = makeFakeFetch({ privatePackages: ['priv-pkg'], records: RECORDS, others: { 'agent.cloud': control.handle } });
  return { control, oidc, net };
}

const routes = (control: ReturnType<typeof fakeControl>) => control.requests.map((r) => `${r.method} ${r.path}`);

test('DFGHR-20: with sending off the action asks GitHub for no token, reads no earlier run and contacts no agent.cloud host', async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  try {
    for (const env of [githubEnv({ GITHUB_EVENT_NAME: 'workflow_dispatch' }), githubEnv({ GITHUB_EVENT_NAME: 'workflow_dispatch', AGENTCLOUD_SEND_REPORT: 'false' })]) {
      const { control, oidc, net } = setup();
      const rt = makeRuntime(checkout.dir, net.fetcher, {
        // Everything else that could send is set: only the switch is off.
        inputs: { 'send-report': 'false', 'send-history': 'true', 'github-token': 'ghs_fake', 'agentcloud-url': ORIGIN },
        env,
        getIdToken: oidc.getIdToken,
      });
      const exec = await runAction(rt.runtime);
      assert.equal(exec.sendingEnabled, false);
      assert.equal(rt.outputs['send-report'], 'false');
      assert.deepEqual(control.requests, [], 'control was never contacted');
      assert.deepEqual(rt.github, { oidc: [], lists: [], reads: [] }, 'no OIDC token asked for, no earlier run read');
      assert.ok(net.calls.length > 0);
      for (const c of net.calls) assert.ok(c.host === 'registry.npmjs.org' || c.host === 'api.osv.dev', `contacted ${c.host}`);
      assert.deepEqual(exec.delivery, { mode: null, report: 'not_sent', lockfiles: 'not_sent', history: null });
      // The report is still kept in the artifact, for a later upload or send-history (DFGHR-22).
      assert.equal(rt.artifacts[0]!.contents[REPORT_FILE], exec.reportBytes);
      assert.deepEqual(rt.failures, []);
    }
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-11, DFGHR-12, DFGHR-15, DFGHR-20: in runner mode the action asks the mode first, then sends the report bodies with unchecked dependencies only as counts', async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo'), 'package.json': { name: 'demo' } });
  try {
    for (const turnOn of [{ inputs: { 'send-report': 'true' } }, { env: { AGENTCLOUD_SEND_REPORT: 'true' } }]) {
      const { control, oidc, net } = setup();
      const rt = makeRuntime(checkout.dir, net.fetcher, {
        inputs: turnOn.inputs,
        env: githubEnv(turnOn.env),
        getIdToken: oidc.getIdToken,
      });
      const exec = await runAction(rt.runtime);

      assert.deepEqual(rt.failures, []);
      assert.deepEqual(rt.warnings, []);
      assert.equal(rt.outputs['send-report'], 'true');
      assert.deepEqual(exec.delivery, { mode: 'runner', report: 'sent', lockfiles: 'not_sent', history: null });

      // DFGHR-15: the mode is asked before anything else, and the report goes after the scan.
      assert.deepEqual(routes(control), [MODE, REPORTS]);
      assert.equal(net.calls[0]!.host, 'agent.cloud');
      assert.equal(net.calls.at(-1)!.host, 'agent.cloud');
      assert.ok(net.calls.slice(1, -1).every((c) => c.host === 'registry.npmjs.org' || c.host === 'api.osv.dev'));

      // DFGHR-12: every request carries a fresh OIDC token whose audience is the control origin, and follows no redirect.
      assert.deepEqual(oidc.audiences, [ORIGIN, ORIGIN]);
      for (const r of control.requests) {
        assert.match(r.authorization, /^Bearer \S+\.\S+\.\S+$/);
        assert.equal(r.redirect, 'manual');
      }
      assert.equal(control.requests[1]!.contentType, 'application/json');

      // DFGHR-11: control accepted it under its own checks, and the envelope binds it to this run.
      assert.equal(control.reports.length, 1);
      const { raw, payload } = control.reports[0]!;
      assert.deepEqual(payload.envelope, {
        repository_id: RUN.repositoryId,
        repository_owner_id: RUN.ownerId,
        head_sha: RUN.sha,
        workflow_run_id: RUN.runId,
        action_version: ACTION_VERSION,
        run_started_at: new Date(NOW).toISOString(),
      });
      assert.equal(payload.reports.length, 1);
      const body = payload.reports[0]!;
      assert.equal(body.findings.length, 1);
      assert.deepEqual(body.extension.not_checked.entries, [], 'unchecked dependencies are never named');
      assert.equal(body.extension.not_checked.total, 3);
      assert.equal(Object.values(body.extension.not_checked.by_reason).reduce((a, b) => a + b, 0), 3);
      for (const name of PRIVATE_NAMES) assert.ok(!raw.includes(name), `the sent report names ${name}`);
      assert.ok(!raw.includes('content_base64') && !raw.includes('lockfileVersion'), 'no file bytes are sent');

      // The customer's own summary and artifact still name them; the artifact keeps the exact bytes sent.
      assert.match(rt.summaries[0]!, /node_modules\/priv-pkg/);
      assert.ok(rt.artifacts[0]!.contents[ARTIFACT_FILE]!.includes('node_modules/priv-pkg'));
      assert.equal(rt.artifacts[0]!.contents[REPORT_FILE], raw);
      assert.equal(exec.reportBytes, raw);
    }
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-15: in agent.cloud mode the action sends the selected lockfiles and their package.json files instead of a report, never a credential', async () => {
  const secret = `ghp_${'Q'.repeat(36)}`;
  const checkout = makeCheckout({
    'package-lock.json': lockfile('root'),
    'package.json': { name: 'root', overrides: { 'pub-pkg': '1.0.0' } },
    'apps/web/package-lock.json': lockfile('web'),
    'apps/api/package-lock.json': lockfile('api'),
    'apps/api/package.json': { name: 'api', description: secret },
    'leaky/package-lock.json': { ...lockfile('leaky'), description: secret },
    'yarn.lock': '# yarn lockfile v1\n',
  });
  mkdirSync(join(checkout.dir, 'linked'));
  symlinkSync('../package-lock.json', join(checkout.dir, 'linked/package-lock.json'));
  try {
    const { control, oidc, net } = setup({ mode: 'agent.cloud' });
    const rt = makeRuntime(checkout.dir, net.fetcher, { inputs: { 'send-report': 'true' }, env: githubEnv(), getIdToken: oidc.getIdToken });
    const exec = await runAction(rt.runtime);

    assert.deepEqual(rt.failures, []);
    assert.deepEqual(routes(control), [MODE, LOCKFILES], 'lockfiles instead of a report');
    assert.deepEqual(exec.delivery, { mode: 'agent.cloud', report: 'not_sent', lockfiles: 'sent', history: null });
    assert.deepEqual(rt.warnings, ["leaky/package-lock.json wasn't sent to agent.cloud: it looks like it holds a credential."]);

    // Control accepted it under its own strict checks; its envelope has no run_started_at.
    assert.equal(control.lockfiles.length, 1);
    const { raw, payload } = control.lockfiles[0]!;
    assert.deepEqual(payload.envelope, {
      repository_id: RUN.repositoryId,
      repository_owner_id: RUN.ownerId,
      head_sha: RUN.sha,
      workflow_run_id: RUN.runId,
      action_version: ACTION_VERSION,
    });
    const file = (rel: string) => readFileSync(join(checkout.dir, rel));
    const decode = (b64: string) => Buffer.from(b64, 'base64');
    assert.deepEqual(payload.lockfiles.map((l) => l.path), ['package-lock.json', 'apps/api/package-lock.json', 'apps/web/package-lock.json']);
    const [root, api, web] = payload.lockfiles;
    assert.deepEqual(decode(root!.content_base64), file('package-lock.json'), 'the lockfile, byte for byte');
    assert.equal(root!.package_json!.path, 'package.json');
    assert.deepEqual(decode(root!.package_json!.content_base64), file('package.json'), 'its package.json, byte for byte');
    assert.equal(root!.package_json_unreadable, undefined);
    assert.deepEqual(decode(api!.content_base64), file('apps/api/package-lock.json'));
    assert.equal(api!.package_json, null, 'a credential-shaped package.json is not sent');
    assert.equal(api!.package_json_unreadable, true);
    assert.deepEqual(decode(web!.content_base64), file('apps/web/package-lock.json'));
    assert.equal(web!.package_json, null);
    assert.equal(web!.package_json_unreadable, undefined);
    assert.deepEqual(payload.skipped, [
      { path: 'linked/package-lock.json', reason: 'symlink' },
      { path: 'leaky/package-lock.json', reason: 'credential_shaped_content' },
    ]);
    assert.deepEqual(payload.inputs_not_analyzed, { 'yarn.lock': 1 });
    assert.ok(!raw.includes(secret), 'no credential leaves the runner');

    // The job summary and artifact are written as in runner mode.
    assert.equal(rt.summaries.length, 1);
    assert.equal(rt.artifacts.length, 1);
  } finally {
    checkout.cleanup();
  }
});

test("DFGHR-12, DFGHR-13, DFGHR-15: control's refusals are logged with their code and a fix, and never fail the job or its summary", async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  const cases = [
    { refuse: { mode: { status: 401, code: 'runner.unauthenticated', message: 'The OIDC token audience must be https://agent.cloud.' } }, sent: [MODE] },
    { refuse: { mode: { status: 403, code: 'runner.not_installed', message: 'This repository does not belong to a ready, unfenced installation of the customer App (DFGHR-12).' } }, sent: [MODE] },
    { refuse: { reports: { status: 429, code: 'runner.rate_limited', message: 'At most 10 reports per repository an hour are accepted (DFGHR-13).' } }, sent: [MODE, REPORTS] },
    { refuse: { reports: { status: 400, code: 'runner.report_invalid', message: 'The report body is invalid or contains a disallowed field (DFGHR-11): x.' } }, sent: [MODE, REPORTS] },
    { mode: 'agent.cloud' as const, refuse: { lockfiles: { status: 403, code: 'runner.mode_runner', message: 'This repository is in runner mode; lockfiles are accepted only in agent.cloud mode (DFGHR-15).' } }, sent: [MODE, LOCKFILES] },
  ] as const;
  try {
    for (const c of cases) {
      const { control, oidc, net } = setup({ mode: 'mode' in c ? c.mode : undefined, refuse: c.refuse as never });
      const rt = makeRuntime(checkout.dir, net.fetcher, { inputs: { 'send-report': 'true', 'fail-on': 'critical' }, env: githubEnv(), getIdToken: oidc.getIdToken });
      const exec = await runAction(rt.runtime);
      const refusal = Object.values(c.refuse)[0]!;
      assert.deepEqual(routes(control), c.sent, refusal.code);
      assert.equal(exec.failed, false, `${refusal.code} must not fail the job`);
      assert.deepEqual(rt.failures, [], refusal.code);
      assert.equal(rt.summaries.length, 1, 'the summary is still written');
      assert.ok(rt.summaries[0]!.trim().endsWith(`(${SETUP_PAGE_URL}).`));
      assert.equal(rt.artifacts.length, 1, 'the artifact is still uploaded');
      assert.equal(rt.warnings.length, 1, refusal.code);
      const warning = rt.warnings[0]!;
      assert.ok(warning.includes(`${refusal.code} (HTTP ${refusal.status})`), warning);
      assert.ok(warning.includes(refusal.message), warning);
      assert.match(warning, / Fix: \S/);
    }

    // No OIDC token (the job lacks id-token: write): nothing is sent, and the job passes.
    {
      const { control, net } = setup();
      const rt = makeRuntime(checkout.dir, net.fetcher, { inputs: { 'send-report': 'true' }, env: githubEnv() });
      const exec = await runAction(rt.runtime);
      assert.deepEqual(control.requests, []);
      assert.equal(exec.failed, false);
      assert.match(rt.warnings[0]!, /runner\.oidc_unavailable \(no answer\).*Fix: Give the job `permissions: id-token: write`/);
    }

    // Control unreachable: one retry, then a warning, and the job passes.
    {
      const oidc = fakeOidc(RUN);
      let tries = 0;
      const net = makeFakeFetch({
        records: RECORDS,
        others: {
          'agent.cloud': async () => {
            tries++;
            throw new TypeError('connect ECONNREFUSED agent.cloud');
          },
        },
      });
      const rt = makeRuntime(checkout.dir, net.fetcher, { inputs: { 'send-report': 'true' }, env: githubEnv(), getIdToken: oidc.getIdToken });
      const exec = await runAction(rt.runtime);
      assert.equal(tries, 2);
      assert.equal(exec.failed, false);
      assert.match(rt.warnings[0]!, /runner\.unreachable \(no answer\)/);
    }
  } finally {
    checkout.cleanup();
  }
});

test('DFGHR-22: send-history sends only the reports earlier runs still keep for this commit, oldest first, before this run\'s own', async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  const OTHER_SHA = 'b'.repeat(40);
  // An earlier run's agentcloud-report.json, made by running the action as that run with sending off.
  const earlierReport = async (runId: string, sha = RUN.sha, startedAt = NOW) => {
    const rt = makeRuntime(checkout.dir, makeFakeFetch({ privatePackages: ['priv-pkg'], records: RECORDS }).fetcher, {
      env: githubEnv({ GITHUB_RUN_ID: runId, GITHUB_SHA: sha }),
    });
    rt.runtime.now = () => startedAt;
    await runAction(rt.runtime);
    return rt.artifacts[0]!.contents[REPORT_FILE]!;
  };
  try {
    const run8001 = await earlierReport('8001');
    const run8002first = await earlierReport('8002', RUN.sha, NOW - 7_200_000);
    const run8002rerun = await earlierReport('8002', RUN.sha, NOW - 3_600_000);
    const tampered = JSON.parse(await earlierReport('8003'));
    tampered.reports[0].extension.not_checked.entries = [{ entry: 'node_modules/priv-pkg', reason: 'public_identity_unverified' }];
    const artifacts: BaselineArtifact[] = [
      { id: 1, runId: '7001', headSha: OTHER_SHA, createdAt: '2026-11-10T00:00:00Z', expired: false },
      { id: 2, runId: '7500', headSha: RUN.sha, createdAt: '2026-11-11T00:00:00Z', expired: false },
      { id: 3, runId: '7600', headSha: RUN.sha, createdAt: '2026-10-01T00:00:00Z', expired: true },
      { id: 4, runId: '8001', headSha: RUN.sha, createdAt: '2026-11-12T00:00:00Z', expired: false },
      { id: 5, runId: '8002', headSha: RUN.sha, createdAt: '2026-11-13T00:00:00Z', expired: false },
      { id: 6, runId: '8002', headSha: RUN.sha, createdAt: '2026-11-13T01:00:00Z', expired: false },
      { id: 8, runId: '8003', headSha: RUN.sha, createdAt: '2026-11-14T00:00:00Z', expired: false },
      { id: 9, runId: RUN.runId, headSha: RUN.sha, createdAt: '2026-11-20T12:00:00Z', expired: false },
    ];
    const stored = new Map<number, string>([
      [1, await earlierReport('7001', OTHER_SHA)],
      // 2 was made before v0.2.0: its artifact has no agentcloud-report.json.
      [3, run8001],
      [4, run8001],
      [5, run8002first],
      [6, run8002rerun],
      [8, JSON.stringify(tampered)],
    ]);

    const { control, oidc, net } = setup();
    const rt = makeRuntime(checkout.dir, net.fetcher, {
      inputs: { 'send-report': 'true', 'send-history': 'true', 'github-token': 'ghs_fake' },
      env: githubEnv({ GITHUB_EVENT_NAME: 'workflow_dispatch' }),
      getIdToken: oidc.getIdToken,
      listBaselineArtifacts: async () => artifacts,
      readArtifactFile: async (artifact) => {
        const text = stored.get(artifact.id);
        return text === undefined ? null : Buffer.from(text, 'utf8');
      },
    });
    const exec = await runAction(rt.runtime);

    assert.deepEqual(rt.failures, []);
    assert.deepEqual(rt.warnings, []);
    assert.deepEqual(rt.github.lists, ['ghs_fake'], "listed with the job's token");
    assert.deepEqual(rt.github.reads.map((r) => r.artifact.id), [8, 6, 4, 2], 'reads only retained artifacts of earlier runs at this commit, newest per run');
    for (const r of rt.github.reads) {
      assert.equal(r.token, 'ghs_fake');
      assert.equal(r.file, REPORT_FILE);
      assert.equal(r.maxBytes, REPORT_MAX_BYTES);
    }
    assert.deepEqual(routes(control), [MODE, REPORTS, REPORTS, REPORTS]);
    assert.deepEqual(
      control.reports.map((r) => r.raw),
      [run8001, run8002rerun, exec.reportBytes],
      "earlier reports byte for byte, oldest first, then this run's own",
    );
    assert.deepEqual(exec.delivery.history, {
      sent: 2,
      refused: 0,
      left: { other_commit: 1, no_report: 1, unreadable: 0, invalid: 1, over_limit: 0 },
    });
    assert.equal(exec.delivery.report, 'sent');
    assert.ok(rt.infos.some((m) => /send-history sent 2 earlier runs' reports; left out 1 run at another commit/.test(m)), rt.infos.join('\n'));
  } finally {
    checkout.cleanup();
  }
});

test("DFGHR-13, DFGHR-22: send-history keeps within control's 10 reports an hour, leaving room for this run's report, and only on workflow_dispatch", async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  try {
    const earlier: { artifact: BaselineArtifact; text: string }[] = [];
    for (let i = 1; i <= 12; i++) {
      const runId = String(8100 + i);
      const rt = makeRuntime(checkout.dir, makeFakeFetch({ privatePackages: ['priv-pkg'], records: RECORDS }).fetcher, {
        env: githubEnv({ GITHUB_RUN_ID: runId }),
      });
      await runAction(rt.runtime);
      earlier.push({
        artifact: { id: i, runId, headSha: RUN.sha, createdAt: `2026-11-${String(i).padStart(2, '0')}T00:00:00Z`, expired: false },
        text: rt.artifacts[0]!.contents[REPORT_FILE]!,
      });
    }
    const history = {
      listBaselineArtifacts: async () => earlier.map((e) => e.artifact),
      readArtifactFile: async (a: BaselineArtifact) => Buffer.from(earlier.find((e) => e.artifact.id === a.id)!.text),
    };

    const { control, oidc, net } = setup({ reportsPerHour: 10 });
    const rt = makeRuntime(checkout.dir, net.fetcher, {
      inputs: { 'send-report': 'true', 'send-history': 'true', 'github-token': 'ghs_fake' },
      env: githubEnv({ GITHUB_EVENT_NAME: 'workflow_dispatch' }),
      getIdToken: oidc.getIdToken,
      ...history,
    });
    const exec = await runAction(rt.runtime);
    assert.deepEqual(rt.warnings, []);
    assert.equal(rt.github.reads.length, 9, 'over-limit artifacts are not even downloaded');
    assert.deepEqual(
      control.reports.map((r) => r.payload.envelope.workflow_run_id),
      ['8104', '8105', '8106', '8107', '8108', '8109', '8110', '8111', '8112', RUN.runId],
      "the 9 newest earlier reports, oldest first, then this run's",
    );
    assert.equal(exec.delivery.history?.left.over_limit, 3);
    assert.equal(exec.delivery.report, 'sent');

    // A push run ignores send-history: it reads no earlier run.
    const push = setup();
    const rtPush = makeRuntime(checkout.dir, push.net.fetcher, {
      inputs: { 'send-report': 'true', 'send-history': 'true', 'github-token': 'ghs_fake' },
      env: githubEnv({ GITHUB_EVENT_NAME: 'push' }),
      getIdToken: push.oidc.getIdToken,
      ...history,
    });
    const execPush = await runAction(rtPush.runtime);
    assert.deepEqual(rtPush.github.lists, []);
    assert.deepEqual(routes(push.control), [MODE, REPORTS]);
    assert.equal(execPush.delivery.history, null);
  } finally {
    checkout.cleanup();
  }
});

test("DFGHR-12: the GitHub runtime asks GitHub's OIDC endpoint for a token whose audience is the control origin, and control gets that token", async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  const token = fakeIdToken({ aud: ORIGIN, repository_id: RUN.repositoryId, repository_owner_id: RUN.ownerId, ref: 'refs/heads/main', sha: RUN.sha });
  const seen: { url: string; authorization: string }[] = [];
  const server = createServer((req, res) => {
    seen.push({ url: req.url ?? '', authorization: req.headers.authorization ?? '' });
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ value: token }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const saved = { url: process.env.ACTIONS_ID_TOKEN_REQUEST_URL, token: process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN };
  process.env.ACTIONS_ID_TOKEN_REQUEST_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}/idtoken?api-version=2.0`;
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'fake-request-token';
  try {
    const github = createGitHubRuntime();
    const { control, net } = setup();
    const rt = makeRuntime(checkout.dir, net.fetcher, {
      inputs: { 'send-report': 'true', 'agentcloud-url': `${ORIGIN}/` },
      env: githubEnv(),
      getIdToken: (audience) => github.getIdToken(audience),
    });
    const exec = await runAction(rt.runtime);
    assert.deepEqual(rt.warnings, []);
    assert.equal(exec.delivery.report, 'sent');
    assert.deepEqual(seen, [
      { url: '/idtoken?api-version=2.0&audience=https%3A%2F%2Fagent.cloud', authorization: 'Bearer fake-request-token' },
      { url: '/idtoken?api-version=2.0&audience=https%3A%2F%2Fagent.cloud', authorization: 'Bearer fake-request-token' },
    ]);
    assert.deepEqual(control.requests.map((r) => r.authorization), [`Bearer ${token}`, `Bearer ${token}`]);
  } finally {
    if (saved.url === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    else process.env.ACTIONS_ID_TOKEN_REQUEST_URL = saved.url;
    if (saved.token === undefined) delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    else process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = saved.token;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    checkout.cleanup();
  }
});

test('DFGHR-12, DFGHR-18: the control client reaches only the configured https origin on its three paths and follows no redirect', async () => {
  assert.equal(controlOrigin(''), ORIGIN);
  assert.equal(controlOrigin(undefined), ORIGIN);
  assert.equal(controlOrigin(' https://agent.cloud/ '), ORIGIN);
  assert.equal(controlOrigin('https://staging.agent.cloud'), 'https://staging.agent.cloud');
  for (const bad of ['http://agent.cloud', 'https://u:p@agent.cloud', 'https://agent.cloud/console', 'https://agent.cloud/?x=1', 'https://agent.cloud/#x', 'agent.cloud', 'ftp://agent.cloud']) {
    assert.throws(() => controlOrigin(bad), /Invalid agentcloud-url/, bad);
  }

  const seen: { url: string; redirect: RequestRedirect | undefined }[] = [];
  const answers: (() => Response)[] = [];
  const client = createControlClient({
    origin: ORIGIN,
    getIdToken: async (aud) => fakeIdToken({ aud }),
    baseBackoffMs: 0,
    fetch: (async (url: string | URL, init?: RequestInit) => {
      seen.push({ url: String(url), redirect: init?.redirect });
      return answers.shift()!();
    }) as typeof fetch,
  });

  answers.push(() => new Response(null, { status: 302, headers: { location: 'https://evil.example/mode' } }));
  const redirected = await client.mode();
  assert.equal(redirected.ok, false);
  assert.equal(!redirected.ok && redirected.refusal.code, 'runner.redirect');
  assert.equal(seen.length, 1, 'the redirect is not followed');

  answers.push(() => new Response('busy', { status: 503 }), () => Response.json({ mode: 'agent.cloud' }));
  const retried = await client.mode();
  assert.ok(retried.ok && retried.body.mode === 'agent.cloud', 'one retry after a 5xx');

  answers.push(() => Response.json({ mode: 'somewhere-else' }));
  const unknown = await client.mode();
  assert.equal(!unknown.ok && unknown.refusal.code, 'runner.mode_unknown');

  answers.push(() => Response.json({ error: { code: 'runner.rate_limited', message: 'Slow down\n::warning::injected', fix: 'Wait an hour.' } }, { status: 429 }));
  const limited = await client.sendReport('{}');
  assert.ok(!limited.ok);
  assert.equal(limited.refusal.fix, "Wait an hour.", "control's own fix comes first");
  assert.equal(limited.refusal.message, 'Slow down ::warning::injected', 'kept to one line, so it cannot start a workflow command');

  answers.push(() => Response.json({ id: 'sbi_1', repeated: false, queued: true }, { status: 202 }));
  assert.ok((await client.sendLockfiles('{}')).ok);

  assert.deepEqual(
    [...new Set(seen.map((s) => s.url))].sort(),
    [`${ORIGIN}/security/github/runner/lockfiles`, `${ORIGIN}/security/github/runner/mode`, `${ORIGIN}/security/github/runner/reports`],
  );
  assert.ok(seen.every((s) => s.redirect === 'manual'));
});

test('DFGHR-20: an invalid agentcloud-url fails the job only when sending is on, before anything is sent', async () => {
  const checkout = makeCheckout({ 'package-lock.json': lockfile('demo') });
  try {
    const on = setup();
    const rtOn = makeRuntime(checkout.dir, on.net.fetcher, {
      inputs: { 'send-report': 'true', 'agentcloud-url': 'http://agent.cloud' },
      env: githubEnv(),
      getIdToken: on.oidc.getIdToken,
    });
    await assert.rejects(runAction(rtOn.runtime), /Invalid agentcloud-url/);
    assert.deepEqual(on.net.calls, [], 'nothing was contacted');
    assert.deepEqual(rtOn.github.oidc, []);

    const off = setup();
    const rtOff = makeRuntime(checkout.dir, off.net.fetcher, { inputs: { 'agentcloud-url': 'http://agent.cloud' }, env: githubEnv() });
    const exec = await runAction(rtOff.runtime);
    assert.equal(exec.failed, false, 'with sending off the input is never read');
    assert.deepEqual(off.control.requests, []);
  } finally {
    checkout.cleanup();
  }
});

test("DFGHR-11: the envelope's action_version is this package's version", () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
  assert.equal(ACTION_VERSION, pkg.version);
});
