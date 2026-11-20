// DFGHR-8, DFGHR-9, DFGHR-10, DFGHR-18, DFGHR-20: bundled GitHub Action entry point.
import * as core from '@actions/core';
import { runAction } from './action.ts';

try {
  await runAction();
} catch (error) {
  core.setFailed(error instanceof Error ? error.message : String(error));
}
