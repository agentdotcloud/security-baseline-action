// DFGHR-8, DFGHR-9, DFGHR-10, DFGHR-11, DFGHR-12, DFGHR-15, DFGHR-20, DFGHR-22: GitHub Actions integration using
// @actions/core, @actions/artifact and @actions/github.
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DefaultArtifactClient } from '@actions/artifact';
import * as core from '@actions/core';
import { getOctokit } from '@actions/github';
import {
  buildLockfilesPayload,
  controlOrigin,
  createControlClient,
  describeRefusal,
  envelopeFromEnv,
  fixFor,
  LOCKFILES_MAX_BYTES,
  REPORT_MAX_BYTES,
  REPORTS_PER_HOUR,
  serializeReportPayload,
  type ControlClient,
  type ControlMode,
  type RunEnvelope,
} from './agentcloud.ts';
import { acquireCheckout, type CheckoutAcquisition } from './checkout.ts';
import { collectEarlierReports, HISTORY_LIST_MAX, REPORT_FILE, type BaselineArtifact } from './history.ts';
import { evaluateFailOn, extractFindings, parseFailOn, renderSummary, serializeArtifact } from './output.ts';
import { runBaseline, shouldSendReport, type BaselineRunResult } from './runner.ts';
import type { RunnerHttpOptions } from './http.ts';

export const ARTIFACT_NAME = 'agentcloud-baseline';
/** The whole local result, for the customer: it names unchecked dependencies and is never sent. */
export const ARTIFACT_FILE = 'agentcloud-baseline.json';
export const ARTIFACT_RETENTION_DAYS = 30;
export { REPORT_FILE };

export interface ArtifactUploadRequest {
  name: string;
  files: string[];
  rootDirectory: string;
  retentionDays: number;
  /** Each file's content by file name. */
  contents: Record<string, string>;
}

export interface ActionRuntime {
  getInput(name: string): string;
  setOutput(name: string, value: string): void;
  setFailed(message: string): void;
  info(message: string): void;
  warning(message: string): void;
  writeSummary(markdown: string): Promise<void>;
  uploadArtifact(req: ArtifactUploadRequest): Promise<void>;
  /** DFGHR-12: a GitHub Actions OIDC token for this audience. Called only when sending is on. */
  getIdToken(audience: string): Promise<string>;
  /** DFGHR-22: the repository's agentcloud-baseline artifacts, listed with the job's token. Called only for send-history. */
  listBaselineArtifacts(token: string): Promise<BaselineArtifact[]>;
  /** DFGHR-22: one file of an earlier run's artifact, at most maxBytes, or null when the artifact has no such file. */
  readArtifactFile(artifact: BaselineArtifact, token: string, file: string, maxBytes: number): Promise<Buffer | null>;
  env: Readonly<Record<string, string | undefined>>;
  cwd: string;
  now?: () => number;
  /** fetch and backoff for every request the action makes: npm, OSV and, when sending is on, agent.cloud. */
  httpOptions?: RunnerHttpOptions;
}

function repositoryParts(env: Readonly<Record<string, string | undefined>>): { owner: string; repo: string } {
  const [owner, repo, extra] = (env.GITHUB_REPOSITORY ?? '').split('/');
  if (!owner || !repo || extra !== undefined) throw new Error('GITHUB_REPOSITORY is not set to owner/repository.');
  return { owner, repo };
}

function readRegularFile(path: string, maxBytes: number): Buffer | null {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return null;
  }
  if (!stat.isFile() || stat.size > maxBytes) return null;
  const bytes = readFileSync(path);
  return bytes.byteLength > maxBytes ? null : bytes;
}

export function createGitHubRuntime(): ActionRuntime {
  return {
    getInput: (name) => core.getInput(name),
    setOutput: (name, value) => core.setOutput(name, value),
    setFailed: (message) => core.setFailed(message),
    info: (message) => core.info(message),
    warning: (message) => core.warning(message),
    async writeSummary(markdown) {
      core.summary.addRaw(markdown);
      await core.summary.write();
    },
    async uploadArtifact(req) {
      const client = new DefaultArtifactClient();
      await client.uploadArtifact(req.name, req.files, req.rootDirectory, { retentionDays: req.retentionDays });
    },
    getIdToken: (audience) => core.getIDToken(audience),
    async listBaselineArtifacts(token) {
      const { owner, repo } = repositoryParts(process.env);
      const octokit = getOctokit(token);
      const found: BaselineArtifact[] = [];
      for (let page = 1; found.length < HISTORY_LIST_MAX; page++) {
        const { data } = await octokit.request('GET /repos/{owner}/{repo}/actions/artifacts', {
          owner,
          repo,
          name: ARTIFACT_NAME,
          per_page: 100,
          page,
        });
        for (const a of data.artifacts) {
          found.push({
            id: a.id,
            runId: String(a.workflow_run?.id ?? ''),
            headSha: a.workflow_run?.head_sha ?? '',
            createdAt: a.created_at ?? '',
            expired: a.expired,
          });
        }
        if (data.artifacts.length < 100) break;
      }
      return found.slice(0, HISTORY_LIST_MAX);
    },
    async readArtifactFile(artifact, token, file, maxBytes) {
      const { owner, repo } = repositoryParts(process.env);
      const dir = mkdtempSync(join(process.env.RUNNER_TEMP || tmpdir(), 'agentcloud-history-'));
      try {
        await new DefaultArtifactClient().downloadArtifact(artifact.id, {
          path: dir,
          findBy: { token, workflowRunId: Number(artifact.runId), repositoryOwner: owner, repositoryName: repo },
        });
        return readRegularFile(join(dir, file), maxBytes);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
    env: process.env,
    cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
  };
}

export type SentState = 'sent' | 'repeated' | 'refused' | 'not_sent';

export interface Delivery {
  /** The repository's mode as control answered it, or null when sending is off or the question went unanswered. */
  mode: ControlMode | null;
  report: SentState;
  lockfiles: SentState;
  history: null | { sent: number; refused: number; left: Record<string, number> };
}

export interface ActionExecution {
  result: BaselineRunResult;
  summary: string;
  artifactBytes: string;
  /** agentcloud-report.json: what runner mode sends, or null when there is no report to send. */
  reportBytes: string | null;
  sendingEnabled: boolean;
  delivery: Delivery;
  failed: boolean;
  failureMessage: string | null;
}

const isTrue = (value: string | undefined) => value?.trim().toLowerCase() === 'true';
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

interface Sending {
  client: ControlClient;
  envelope: RunEnvelope;
  mode: ControlMode;
}

/** DFGHR-12, DFGHR-15: with sending on, ask control for the repository's mode before scanning. */
async function prepareSending(
  runtime: ActionRuntime,
  origin: string,
  envelope: ReturnType<typeof envelopeFromEnv>,
  delivery: Delivery,
): Promise<Sending | null> {
  runtime.info(`Sending to agent.cloud is on (${origin}).`);
  if (!envelope.ok) {
    runtime.warning(
      `Nothing was sent to agent.cloud: this run has no ${envelope.missing.join(', ')}, which GitHub Actions sets. Fix: run the action in a GitHub Actions job.`,
    );
    return null;
  }
  const client = createControlClient({
    origin,
    getIdToken: (audience) => runtime.getIdToken(audience),
    fetch: runtime.httpOptions?.fetch,
    baseBackoffMs: runtime.httpOptions?.baseBackoffMs,
  });
  const answer = await client.mode();
  if (!answer.ok) {
    runtime.warning(`${describeRefusal("Asking agent.cloud for this repository's mode", answer.refusal)} Nothing was sent to agent.cloud.`);
    return null;
  }
  delivery.mode = answer.body.mode;
  runtime.info(
    answer.body.mode === 'runner'
      ? 'agent.cloud has this repository in runner mode: this run sends its report.'
      : 'agent.cloud has this repository in agent.cloud mode: this run sends its selected lockfiles and their package.json files.',
  );
  return { client, envelope: envelope.envelope, mode: answer.body.mode };
}

/** DFGHR-22: send the reports earlier runs kept, oldest first, before this run's own. */
async function sendHistory(runtime: ActionRuntime, sending: Sending, budget: number, delivery: Delivery): Promise<void> {
  const token = runtime.getInput('github-token').trim();
  if (!token) {
    runtime.warning('send-history found no token to read earlier runs with. Fix: leave the github-token input at its default, the job\'s own token.');
    return;
  }
  let collected;
  try {
    collected = await collectEarlierReports(
      {
        list: () => runtime.listBaselineArtifacts(token),
        read: (artifact) => runtime.readArtifactFile(artifact, token, REPORT_FILE, REPORT_MAX_BYTES),
      },
      sending.envelope,
      budget,
    );
  } catch (error) {
    runtime.warning(
      `send-history couldn't list earlier runs' ${ARTIFACT_NAME} artifacts: ${error instanceof Error ? error.message : String(error)} Fix: give the job \`permissions: actions: read\`, as workflow/agentcloud-baseline.yml does.`,
    );
    return;
  }
  const history = { sent: 0, refused: 0, left: { ...collected.left } };
  delivery.history = history;
  for (const earlier of collected.send) {
    const answer = await sending.client.sendReport(earlier.json);
    if (answer.ok) {
      history.sent++;
      runtime.info(`Sent run ${earlier.runId}'s report to agent.cloud${answer.body.repeated ? ', which already had it' : ''}.`);
      continue;
    }
    history.refused++;
    runtime.warning(describeRefusal(`Sending run ${earlier.runId}'s report to agent.cloud`, answer.refusal));
    if (answer.refusal.status !== 400) break; // the same refusal would meet every other earlier report
  }
  const { other_commit, no_report, unreadable, invalid, over_limit } = collected.left;
  const notes = [
    other_commit && `${plural(other_commit, 'run')} at another commit (agent.cloud takes a report only for the commit this run's identity token names)`,
    no_report && `${plural(no_report, 'run')} whose artifact has no ${REPORT_FILE} (made before v0.2.0 of this action)`,
    unreadable && `${plural(unreadable, 'artifact')} that couldn't be downloaded`,
    invalid && `${plural(invalid, 'report')} for another repository or run, or naming an unchecked dependency`,
    over_limit && `${plural(over_limit, 'run')} over agent.cloud's ${REPORTS_PER_HOUR} reports an hour`,
  ].filter(Boolean);
  runtime.info(
    `send-history sent ${plural(history.sent, "earlier run's report", "earlier runs' reports")}${notes.length ? `; left out ${notes.join(', ')}` : ''}.`,
  );
}

async function deliver(
  runtime: ActionRuntime,
  sending: Sending,
  acquired: CheckoutAcquisition,
  reportBytes: string | null,
  reportCount: number,
  delivery: Delivery,
): Promise<void> {
  const origin = sending.client.origin;
  const wantsHistory = isTrue(runtime.getInput('send-history'));
  if (wantsHistory && runtime.env.GITHUB_EVENT_NAME !== 'workflow_dispatch') {
    runtime.info('send-history is for a workflow_dispatch run; this run sends only its own result.');
  } else if (wantsHistory) {
    const own = sending.mode === 'runner' && reportBytes && Buffer.byteLength(reportBytes) <= REPORT_MAX_BYTES ? reportCount : 0;
    await sendHistory(runtime, sending, REPORTS_PER_HOUR - own, delivery);
  }

  if (sending.mode === 'runner') {
    // DFGHR-11: the report bodies and the run envelope, never a file.
    if (!reportBytes) {
      runtime.info('No lockfile was analyzed, so there is no report to send to agent.cloud.');
      return;
    }
    const size = Buffer.byteLength(reportBytes);
    if (size > REPORT_MAX_BYTES) {
      delivery.report = 'refused';
      runtime.warning(
        `The report wasn't sent: it is ${size} bytes, over agent.cloud's ${REPORT_MAX_BYTES}-byte limit. Fix: ${fixFor('runner.too_large', 413, origin)}`,
      );
      return;
    }
    const answer = await sending.client.sendReport(reportBytes);
    if (!answer.ok) {
      delivery.report = 'refused';
      runtime.warning(describeRefusal("Sending this run's report to agent.cloud", answer.refusal));
      return;
    }
    delivery.report = answer.body.repeated ? 'repeated' : 'sent';
    runtime.info(
      `Sent the report for ${plural(reportCount, 'lockfile')} to agent.cloud${answer.body.repeated ? ', which already had it' : ''}. Unchecked dependencies went only as counts.`,
    );
    return;
  }

  // DFGHR-15: agent.cloud mode sends the selected lockfiles and their sibling package.json files instead of a report.
  const payload = buildLockfilesPayload(acquired, sending.envelope);
  for (const path of payload.withheld) {
    runtime.warning(`${path} wasn't sent to agent.cloud: it looks like it holds a credential.`);
  }
  const size = Buffer.byteLength(payload.json);
  if (size > LOCKFILES_MAX_BYTES) {
    delivery.lockfiles = 'refused';
    runtime.warning(
      `The lockfiles weren't sent: they are ${size} bytes encoded, over agent.cloud's ${LOCKFILES_MAX_BYTES}-byte limit. Fix: ${fixFor('runner.too_large', 413, origin)}`,
    );
    return;
  }
  const answer = await sending.client.sendLockfiles(payload.json);
  if (!answer.ok) {
    delivery.lockfiles = 'refused';
    runtime.warning(describeRefusal("Sending this run's lockfiles to agent.cloud", answer.refusal));
    return;
  }
  delivery.lockfiles = answer.body.repeated ? 'repeated' : 'sent';
  runtime.info(
    `Sent ${plural(payload.lockfiles, 'lockfile')} and their package.json files to agent.cloud${answer.body.repeated ? ', which already had them' : ''}.`,
  );
}

export async function runAction(runtime: ActionRuntime = createGitHubRuntime()): Promise<ActionExecution> {
  const startedAt = (runtime.now ?? Date.now)();
  const failOn = parseFailOn(runtime.getInput('fail-on'));
  const sendingEnabled = shouldSendReport(runtime.getInput('send-report'), runtime.env);
  const workingDir = runtime.getInput('working-directory').trim() || runtime.cwd;
  const envelope = envelopeFromEnv(runtime.env, startedAt);
  const delivery: Delivery = { mode: null, report: 'not_sent', lockfiles: 'not_sent', history: null };

  // DFGHR-20: with sending off, the action asks GitHub for no token and contacts no agent.cloud host at all.
  let sending: Sending | null = null;
  if (sendingEnabled) {
    // An invalid agentcloud-url fails the job, as an invalid fail-on does: it is a mistake in the workflow file.
    const origin = controlOrigin(runtime.getInput('agentcloud-url'));
    try {
      sending = await prepareSending(runtime, origin, envelope, delivery);
    } catch (error) {
      runtime.warning(`Nothing was sent to agent.cloud: ${error instanceof Error ? error.message : String(error)}`);
    }
  } else if (isTrue(runtime.getInput('send-history'))) {
    runtime.info('send-history does nothing while sending is off: nothing was sent to agent.cloud.');
  }

  const acquired = acquireCheckout(workingDir);
  const result = await runBaseline({
    checkoutDir: workingDir,
    acquired,
    now: runtime.now,
    httpOptions: runtime.httpOptions,
  });

  const findings = extractFindings(result.reports);
  const summary = renderSummary(result);
  const artifactBytes = serializeArtifact(result);
  const reportBytes = envelope.ok && result.reports.length > 0 ? serializeReportPayload(envelope.envelope, result.reports) : null;

  await runtime.writeSummary(summary);

  const stageBase = runtime.env.RUNNER_TEMP || tmpdir();
  const stageDir = mkdtempSync(join(stageBase, 'agentcloud-baseline-'));
  try {
    const contents: Record<string, string> = { [ARTIFACT_FILE]: artifactBytes };
    // DFGHR-22: the body agent.cloud takes, kept so a later upload or send-history can send it unchanged.
    if (reportBytes) contents[REPORT_FILE] = reportBytes;
    const files = Object.entries(contents).map(([name, content]) => {
      const filePath = join(stageDir, name);
      writeFileSync(filePath, content, 'utf8');
      return filePath;
    });
    await runtime.uploadArtifact({
      name: ARTIFACT_NAME,
      files,
      rootDirectory: stageDir,
      retentionDays: ARTIFACT_RETENTION_DAYS,
      contents,
    });
  } finally {
    rmSync(stageDir, { recursive: true, force: true });
  }

  runtime.setOutput('coverage', result.coverage);
  runtime.setOutput('findings-count', String(findings.length));
  runtime.setOutput('artifact-name', ARTIFACT_NAME);
  runtime.setOutput('send-report', String(sendingEnabled));

  if (sending) {
    // A refusal, or anything else going wrong while sending, never fails the job: the summary and artifact stand.
    try {
      await deliver(runtime, sending, acquired, reportBytes, result.reports.length, delivery);
    } catch (error) {
      runtime.warning(
        `Sending to agent.cloud stopped: ${error instanceof Error ? error.message : String(error)}. The job summary and the ${ARTIFACT_NAME} artifact have the whole result.`,
      );
    }
  }

  const gate = evaluateFailOn(findings, failOn);
  if (gate.failed && gate.message) {
    runtime.setFailed(gate.message);
  }

  return {
    result,
    summary,
    artifactBytes,
    reportBytes,
    sendingEnabled,
    delivery,
    failed: gate.failed,
    failureMessage: gate.message,
  };
}
