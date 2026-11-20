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

test('the workflow pins checkout and the v0.1.0 action by full commit SHA', () => {
  const uses = [...WORKFLOW.matchAll(/uses: (\S+)/g)].map((m) => m[1]);
  assert.deepEqual(uses, [
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'agentdotcloud/security-baseline-action@7b21077fdc97b2065f2d18dc582bcef8fb71a255',
  ]);
  assert.match(WORKFLOW, /@7b21077fdc97b2065f2d18dc582bcef8fb71a255 # v0\.1\.0\n/);
});
