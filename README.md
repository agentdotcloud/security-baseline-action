# agent.cloud dependency baseline

A GitHub Action that checks the npm dependencies in your repository's `package-lock.json`, `pnpm-lock.yaml` and
`yarn.lock` files for known vulnerabilities. It runs on your own runner, GitHub-hosted or self-hosted, and shows what
it found on the run's page. Your code stays on your runner, and nothing goes to agent.cloud unless you turn sending on.

## What it does

1. Reads up to 25 lockfiles in the checkout (`package-lock.json` versions 2 and 3, `pnpm-lock.yaml` versions 6 and 9,
   and `yarn.lock` v1 and Berry), and the `package.json` next to each. It never follows a symlink or reads outside the
   checkout. Other lockfiles, such as `npm-shrinkwrap.json` or `bun.lock`, are counted in the report but not analyzed.
2. For each dependency the lockfile says came from `registry.npmjs.org`, asks the public npm registry for that exact
   name and version, and checks that the registry's tarball and integrity hash match the lockfile.
3. Asks [OSV](https://osv.dev) for known advisories on the dependencies that passed that check.
4. Writes a table to the run's summary: lockfile, package, version, advisory, severity and the version that fixes it,
   plus a coverage line saying what it could and couldn't check.
5. Uploads an artifact named `agentcloud-baseline`, kept for 30 days, with two JSON files: `agentcloud-baseline.json`,
   the whole result, which names the dependencies it couldn't check; and `agentcloud-report.json`, exactly what sending
   sends in runner mode (see below), which only counts them and shows a placeholder for their names. An administrator
   of your organization on agent.cloud can upload `agentcloud-report.json` there later, for a run at most 30 days old.
6. With sending on, sends to agent.cloud: see below.

If the runner can't reach npm or OSV, the report says which source was unavailable and marks coverage incomplete, and
the job still passes.

## Where you see the results

Each run's results are on that run's page in GitHub. With sending off, that's the only place they are.

1. In the repository, open **Actions**, pick **agent.cloud dependency baseline** from the workflows on the left, and
   open a run.
2. The run's **Summary** shows the table of findings and the coverage line.
3. The **Artifacts** section at the bottom of the same page has `agentcloud-baseline`, the two JSON files, for 30 days.

**Nothing tells you about findings unless you set `fail-on`.** The job passes even when it finds advisories, so a run
with findings looks like any other green run, and someone has to open it to see them. To be told, add `fail-on` to the
action's `with:` in your workflow, one line:

```diff
       - uses: agentdotcloud/security-baseline-action@196ebabfbec6baff7c1b6da5598a626b9542f229 # v0.3.2
         with:
+          fail-on: high # fail on high or critical; critical, high, moderate or low
           send-history: ${{ inputs.send-history }}
```

The job then fails when a finding is at or above that severity, and GitHub sends its usual failed-workflow
notification. For a push it goes to whoever pushed. For the weekly run it goes to whoever created the workflow file
or last changed its `schedule`. Each person's GitHub notification settings decide whether that's an email, a web
notification or nothing.

## What leaves your runner

With sending off, the default:

- **To `registry.npmjs.org`:** for each public dependency, a request for its `name/version`. A dependency installed
  from any other registry, such as your private one, is never looked up anywhere.
- **To `api.osv.dev`:** the `name@version` pairs the registry confirmed, then each matching advisory by its ID.
- **Nothing else.** No file, no source code, no repository name, no token. The action contacts no agent.cloud host,
  asks GitHub for no identity token and reads no other run.

Sending is on when the `send-report` input or the `AGENTCLOUD_SEND_REPORT` repository or organization variable is
`true`. Then, as well:

1. **To GitHub,** before each request to agent.cloud: a request for a fresh OIDC identity token whose audience is the
   agent.cloud origin (`agentcloud-url`, `https://agent.cloud` unless you set it). The token names the repository, its
   owner, the branch and the commit, and expires within minutes. It is how agent.cloud knows which repository is
   sending, so there's no secret to set up.
2. **To agent.cloud, before the scan:** `GET /security/github/runner/mode` with that token, asking whether agent.cloud
   has the repository in runner mode, the default, or agent.cloud mode, which an administrator turns on there.
3. **In runner mode, after the scan:** `POST /security/github/runner/reports` with `agentcloud-report.json`. It holds
   the run's identity (repository ID, owner ID, commit SHA, workflow run ID, this action's version and when it
   started) and, for each analyzed lockfile, its report: the lockfile's path, Git blob hash and SHA-256; the package
   names, versions and paths with advisories, severities and fix versions; and coverage. A dependency the action
   couldn't check, usually a package from your private registry, is sent only as a count per reason, never by name.
   A path through one, such as a public package installed in its folder, is sent with a placeholder for its name:
   `node_modules/@acme/private/node_modules/lodash` goes as `node_modules/<unchecked-1>/node_modules/lodash`. The
   placeholders are numbered by first appearance in each lockfile's report, and the same report always gets the same
   ones. The summary and `agentcloud-baseline.json` keep the whole path. No file is sent: no lockfile, no
   `package.json`. A report over 1 MiB isn't sent.
4. **In agent.cloud mode, instead of a report:** `POST /security/github/runner/lockfiles` with the run's identity
   (without the start time) and the bytes of each lockfile the action selected, at most 25, with the `package.json`
   next to it, plus the paths of the lockfiles it passed over and its counts of other lockfile types.
   agent.cloud runs the same check on those files itself. A file that looks like it holds a credential (a private
   key, a database password, or a GitHub, AWS, Slack, agent.cloud or API token) is never sent: such a lockfile is skipped
   and such a `package.json` as unreadable. The action still scans locally, so the summary and artifact are as above.
5. **With `send-history: true` on a `workflow_dispatch` run:** the action lists the repository's `agentcloud-baseline`
   artifacts through GitHub's API with the job's token, and sends each earlier run's `agentcloud-report.json` as it
   is, oldest first, before this run's own. agent.cloud takes a report only for the commit this run's identity token
   names, so only earlier runs at the same commit are sent, and at most 10 reports per repository an hour, so the
   action leaves room for this run's. Runs from before v0.2.0 kept no `agentcloud-report.json` and are left out.

If agent.cloud refuses something or can't be reached, the run's log has a warning with agent.cloud's reason and what to
do about it, and the job still passes with its summary and artifact.

The summary and the artifact are stored by GitHub with the run, like any other workflow output.

The action runs one file, `dist/index.mjs`, bundled from the source in this repository. At run time it refuses to load
any module other than Node's built-ins, even if a `node_modules` folder is on the runner.

## Set it up

The baseline is one file in each repository, `.github/workflows/agentcloud-baseline.yml`, the workflow shown
[below](#the-workflow). agent.cloud's GitHub App only reads your repositories and never writes to them, so you add the
file yourself, in either of two ways.

**One repository at a time.** agent.cloud's setup page gives you a GitHub link for each repository that opens a new
file with the workflow already filled in. Review it on GitHub and commit it, or propose it as a pull request.

**Many repositories at once.** Run `setup.sh` from a clone of this repository, signed in to the
[GitHub CLI](https://cli.github.com) as yourself. It's short: read it before you run it.

```sh
git clone --branch v0.3.3 https://github.com/agentdotcloud/security-baseline-action
cd security-baseline-action
./setup.sh --dry-run --org your-org      # what it would do, changing nothing
./setup.sh --org your-org                # every repository in your-org you can push to, except archived ones
./setup.sh your-org/web your-org/api     # or the repositories you name
```

`setup.sh` uses only your own `gh` login, never a token from agent.cloud, and talks only to GitHub. In each repository
it writes only that one file: `workflow/agentcloud-baseline.yml` from this repository, with the push trigger set to the
repository's default branch. It commits the file to the default branch. Where branch protection refuses a direct
commit, it puts the file on a new branch, `agentcloud-baseline`, and opens a pull request for you to merge. GitHub
decides which: if your login may bypass a branch's protection, as admins often can, the commit goes straight in. A
repository that already has the file is skipped, and the file is never overwritten. It prints one line per repository,
`committed`, `PR <url>`, `skipped (exists)` or `failed:` with GitHub's reason, and exits non-zero if any failed.
GitHub accepts a workflow file only from a login with the `workflow` scope; `gh auth refresh -s workflow` adds it.

## The workflow

This is `workflow/agentcloud-baseline.yml`, the file to add as `.github/workflows/agentcloud-baseline.yml`:

```yaml
name: agent.cloud dependency baseline
on:
  push:
    branches: [main] # your default branch
    paths:
      - '**/package-lock.json'
      - '**/pnpm-lock.yaml'
      - '**/yarn.lock'
      - '**/package.json'
      - .github/workflows/agentcloud-baseline.yml
  schedule:
    - cron: '23 7 * * 1' # weekly, Mondays 07:23 UTC
  workflow_dispatch:
    inputs:
      send-history:
        description: 'With sending on, also send the reports earlier runs still keep'
        type: boolean
        default: false
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
      - uses: agentdotcloud/security-baseline-action@196ebabfbec6baff7c1b6da5598a626b9542f229 # v0.3.2
        with:
          send-history: ${{ inputs.send-history }}
        env:
          AGENTCLOUD_SEND_REPORT: ${{ vars.AGENTCLOUD_SEND_REPORT }}
```

Both actions are pinned to a full commit SHA, not to a tag: a tag can be moved, a commit can't. To check that the
action's commit is v0.3.2's:

```sh
git ls-remote https://github.com/agentdotcloud/security-baseline-action 'refs/tags/v0.3.2^{}'
```

**Default branch.** If your default branch isn't `main`, put its name in `branches: [main]`. `setup.sh` does that
for you.

**Runners.** The job runs on `ubuntu-latest` unless you set the repository or organization variable
`AGENTCLOUD_RUNS_ON` to a JSON label or list of labels, for example `["self-hosted","linux"]`. No change to the file.

**Sending earlier reports.** With sending on, run the workflow by hand (the repository's Actions tab, agent.cloud
dependency baseline, Run workflow) with `send-history` ticked, and it also sends the reports earlier runs still keep,
as [above](#what-leaves-your-runner). Runs on a push or the schedule never do.

**Permissions.** `contents: read` lets the checkout step read the repository. `id-token: write` lets the action ask
GitHub for the identity token that proves to agent.cloud which repository is sending, so there's no secret to set up;
it is asked for only when sending is on. `actions: read` lets `send-history` read earlier runs' artifacts. With sending
off, the action uses neither.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `fail-on` | empty | Fail the job when a finding is at or above this severity: `critical`, `high`, `moderate` or `low`. Empty never fails on findings. |
| `send-report` | `false` | Send to agent.cloud, as [above](#what-leaves-your-runner). The `AGENTCLOUD_SEND_REPORT` variable set to `true` also turns it on. |
| `agentcloud-url` | `https://agent.cloud` | The agent.cloud to send to, as an `https://` origin. |
| `send-history` | `false` | On a `workflow_dispatch` run with sending on, also send the reports earlier runs still keep. |
| `github-token` | the job's token | What `send-history` reads earlier runs' artifacts with. |
| `working-directory` | the checkout | The directory to scan. |

## Outputs

| Output | What it holds |
| --- | --- |
| `coverage` | `complete`, `partial`, `incomplete` or `none` |
| `findings-count` | Findings across all analyzed lockfiles |
| `artifact-name` | `agentcloud-baseline` |
| `send-report` | `true` or `false`: whether sending is on |

## Build it yourself

You need Node 24.

```sh
npm ci --ignore-scripts
npm test
npm run build
git diff --exit-code dist   # the bundle you built is the one committed here
```

`src/` is the action. `vendor/security-checks/` is the dependency check itself, `@summationai/security-checks` 0.4.0,
copied unchanged with its tests. CI runs the tests and rebuilds the bundle on every pull request and every push to
`main`, and fails if `dist/` differs from what's committed.
