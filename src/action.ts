// DFGHR-8, DFGHR-9, DFGHR-10, DFGHR-20: GitHub Actions integration using @actions/core and @actions/artifact.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DefaultArtifactClient } from '@actions/artifact';
import * as core from '@actions/core';
import { evaluateFailOn, extractFindings, parseFailOn, renderSummary, serializeArtifact } from './output.ts';
import { runBaseline, shouldSendReport, type BaselineRunResult } from './runner.ts';
import type { RunnerHttpOptions } from './http.ts';

export const ARTIFACT_NAME = 'agentcloud-baseline';
export const ARTIFACT_FILE = 'agentcloud-baseline.json';
export const ARTIFACT_RETENTION_DAYS = 30;

export interface ArtifactUploadRequest {
  name: string;
  files: string[];
  rootDirectory: string;
  retentionDays: number;
  content: string;
}

export interface ActionRuntime {
  getInput(name: string): string;
  setOutput(name: string, value: string): void;
  setFailed(message: string): void;
  info(message: string): void;
  writeSummary(markdown: string): Promise<void>;
  uploadArtifact(req: ArtifactUploadRequest): Promise<void>;
  env: Readonly<Record<string, string | undefined>>;
  cwd: string;
  now?: () => number;
  httpOptions?: RunnerHttpOptions;
  /** Slice 3 wires the OIDC report sender here; in slice 1 this is only invoked when DFGHR-20 sending is on. */
  onSendReport?: (result: BaselineRunResult) => Promise<void>;
}

export function createGitHubRuntime(): ActionRuntime {
  return {
    getInput: (name) => core.getInput(name),
    setOutput: (name, value) => core.setOutput(name, value),
    setFailed: (message) => core.setFailed(message),
    info: (message) => core.info(message),
    async writeSummary(markdown) {
      core.summary.addRaw(markdown);
      await core.summary.write();
    },
    async uploadArtifact(req) {
      const client = new DefaultArtifactClient();
      await client.uploadArtifact(req.name, req.files, req.rootDirectory, { retentionDays: req.retentionDays });
    },
    env: process.env,
    cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
  };
}

export interface ActionExecution {
  result: BaselineRunResult;
  summary: string;
  artifactBytes: string;
  sendingEnabled: boolean;
  failed: boolean;
  failureMessage: string | null;
}

export async function runAction(runtime: ActionRuntime = createGitHubRuntime()): Promise<ActionExecution> {
  const failOn = parseFailOn(runtime.getInput('fail-on'));
  const sendingEnabled = shouldSendReport(runtime.getInput('send-report'), runtime.env);
  const workingDir = runtime.getInput('working-directory').trim() || runtime.cwd;

  const result = await runBaseline({
    checkoutDir: workingDir,
    now: runtime.now,
    httpOptions: runtime.httpOptions,
  });

  const findings = extractFindings(result.reports);
  const summary = renderSummary(result);
  const artifactBytes = serializeArtifact(result);

  await runtime.writeSummary(summary);

  const stageBase = runtime.env.RUNNER_TEMP || tmpdir();
  const stageDir = mkdtempSync(join(stageBase, 'agentcloud-baseline-'));
  try {
    const filePath = join(stageDir, ARTIFACT_FILE);
    writeFileSync(filePath, artifactBytes, 'utf8');
    await runtime.uploadArtifact({
      name: ARTIFACT_NAME,
      files: [filePath],
      rootDirectory: stageDir,
      retentionDays: ARTIFACT_RETENTION_DAYS,
      content: artifactBytes,
    });
  } finally {
    rmSync(stageDir, { recursive: true, force: true });
  }

  runtime.setOutput('coverage', result.coverage);
  runtime.setOutput('findings-count', String(findings.length));
  runtime.setOutput('artifact-name', ARTIFACT_NAME);
  runtime.setOutput('send-report', String(sendingEnabled));

  // DFGHR-20: with sending off, never contact any agent.cloud host.
  if (sendingEnabled) {
    if (runtime.onSendReport) {
      await runtime.onSendReport(result);
    } else {
      runtime.info('Report sending is enabled; OIDC delivery ships in slice 3.');
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
    sendingEnabled,
    failed: gate.failed,
    failureMessage: gate.message,
  };
}
