// workflow/agentcloud-baseline.yml is the file setup.sh adds and the one the README shows, so they can't drift.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = (path: string) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const WORKFLOW = read('workflow/agentcloud-baseline.yml');

test("the README's workflow is workflow/agentcloud-baseline.yml exactly", () => {
  const blocks = [...read('README.md').matchAll(/^```yaml\n([\s\S]*?)^```$/gm)].map((m) => m[1]);
  assert.equal(blocks.length, 1, 'the README shows one workflow');
  assert.equal(blocks[0], WORKFLOW);
});

test('the workflow pins checkout and the v0.2.2 action by full commit SHA', () => {
  const uses = [...WORKFLOW.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
  assert.deepEqual(uses, [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'agentdotcloud/security-baseline-action@e955024ca11e7dec29fcbb898fdc702eafef9fbb',
  ]);
  assert.match(WORKFLOW, /@e955024ca11e7dec29fcbb898fdc702eafef9fbb # v0\.2\.2\n/);
});

test('DFGHR-22: a workflow_dispatch run offers send-history, off by default, and passes it to the action', () => {
  assert.match(
    WORKFLOW,
    /\n  workflow_dispatch:\n    inputs:\n      send-history:\n        description: [^\n]+\n        type: boolean\n        default: false\n/,
  );
  assert.match(WORKFLOW, /\n        with:\n          send-history: \$\{\{ inputs\.send-history \}\}\n        env:\n          AGENTCLOUD_SEND_REPORT: \$\{\{ vars\.AGENTCLOUD_SEND_REPORT \}\}\n$/);
});
