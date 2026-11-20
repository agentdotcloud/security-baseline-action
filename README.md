# agent.cloud dependency baseline

A GitHub Action that checks the npm dependencies in your repository's `package-lock.json` files for known
vulnerabilities. It runs on your own runner, GitHub-hosted or self-hosted, and shows what it found on the run's page.
Your code stays on your runner.

## What it does

1. Reads up to 25 `package-lock.json` files (lockfile versions 2 and 3) in the checkout, and the `package.json` next to
   each. It never follows a symlink or reads outside the checkout. Other lockfiles, such as `yarn.lock` or
   `pnpm-lock.yaml`, are counted in the report but not analyzed.
2. For each dependency the lockfile says came from `registry.npmjs.org`, asks the public npm registry for that exact
   name and version, and checks that the registry's tarball and integrity hash match the lockfile.
3. Asks [OSV](https://osv.dev) for known advisories on the dependencies that passed that check.
4. Writes a table to the run's summary: lockfile, package, version, advisory, severity and the version that fixes it,
   plus a coverage line saying what it could and couldn't check.
5. Uploads the full report as a JSON artifact named `agentcloud-baseline`, kept for 30 days.

The job doesn't fail on findings unless you set `fail-on`. If the runner can't reach npm or OSV, the report says which
source was unavailable and marks coverage incomplete, and the job still passes.

## What leaves your runner

- **To `registry.npmjs.org`:** for each public dependency, a request for its `name/version`. A dependency installed
  from any other registry, such as your private one, is never looked up anywhere.
- **To `api.osv.dev`:** the `name@version` pairs the registry confirmed, then each matching advisory by its ID.
- **Nothing else.** No file, no source code, no repository name, no token.
- **Nothing to agent.cloud** unless you turn sending on with the `send-report` input or the `AGENTCLOUD_SEND_REPORT`
  variable. In this version (v0.1.0) turning it on only logs a line: no version yet sends anything to agent.cloud.

The summary and the artifact are stored by GitHub with the run, like any other workflow output.

The action runs one file, `dist/index.mjs`, bundled from the source in this repository. At run time it refuses to load
any module other than Node's built-ins, even if a `node_modules` folder is on the runner.

## Use it

Add `.github/workflows/agentcloud-baseline.yml`:

```yaml
name: agent.cloud dependency baseline
on:
  push:
    branches: [main] # your default branch
    paths:
      - '**/package-lock.json'
      - '**/package.json'
      - .github/workflows/agentcloud-baseline.yml
  schedule:
    - cron: '23 7 * * 1' # weekly, Mondays 07:23 UTC
  workflow_dispatch:
permissions: {}
jobs:
  baseline:
    runs-on: ${{ fromJSON(vars.AGENTCLOUD_RUNS_ON || '"ubuntu-latest"') }}
    permissions:
      contents: read
      actions: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: agentdotcloud/security-baseline-action@<full commit SHA> # v0.1.0
        env:
          AGENTCLOUD_SEND_REPORT: ${{ vars.AGENTCLOUD_SEND_REPORT }}
```

Pin the action to the full commit SHA of the release you reviewed, not to its tag: a tag can be moved, a commit can't.
To get the commit for v0.1.0:

```sh
git ls-remote https://github.com/agentdotcloud/security-baseline-action 'refs/tags/v0.1.0^{}'
```

**Runners.** The job runs on `ubuntu-latest` unless you set the repository or organization variable
`AGENTCLOUD_RUNS_ON` to a JSON label or list of labels, for example `["self-hosted","linux"]`. No change to the file.

**Permissions.** `contents: read` lets the checkout step read the repository. The action itself uses neither of the
other two in this version. `id-token: write` is for sending the report later: GitHub's identity token proves to
agent.cloud which repository a report came from, so there's no secret to set up, and it is requested only when sending
is on. `actions: read` is for sending the reports of earlier runs once sending is on.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `fail-on` | empty | Fail the job when a finding is at or above this severity: `critical`, `high`, `moderate` or `low`. Empty never fails on findings. |
| `send-report` | `false` | Send the report to agent.cloud. The `AGENTCLOUD_SEND_REPORT` variable set to `true` also turns it on. Not yet active: see above. |
| `working-directory` | the checkout | The directory to scan. |

## Outputs

| Output | What it holds |
| --- | --- |
| `coverage` | `complete`, `partial`, `incomplete` or `none` |
| `findings-count` | Findings across all analyzed lockfiles |
| `artifact-name` | `agentcloud-baseline` |
| `send-report` | `true` or `false` |

## Build it yourself

You need Node 24.

```sh
npm ci --ignore-scripts
npm test
npm run build
git diff --exit-code dist   # the bundle you built is the one committed here
```

`src/` is the action. `vendor/security-checks/` is the dependency check itself, `@summationai/security-checks` 0.3.2,
copied unchanged with its tests. CI runs the tests and rebuilds the bundle on every pull request and every push to
`main`, and fails if `dist/` differs from what's committed.
