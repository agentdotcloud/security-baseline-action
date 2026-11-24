#!/usr/bin/env bash
# Adds agent.cloud's dependency baseline workflow to GitHub repositories, with your own gh login.
#
#   ./setup.sh [--dry-run] <owner>/<repo> [<owner>/<repo> ...]
#   ./setup.sh [--dry-run] --org <owner>    every repository in the org you can push to, except archived ones
#
# In each repository it adds one file, .github/workflows/agentcloud-baseline.yml: workflow/agentcloud-baseline.yml
# from this repository, with its push trigger set to the repository's default branch. It commits the file to the
# default branch. If GitHub refuses that because the branch is protected, it commits the file to a new branch,
# agentcloud-baseline, and opens a pull request. If the file is already there, it leaves it alone.
# Its only network calls are `gh api` requests to GitHub, made as you with the login gh already has.
# --dry-run only reads: it says what it would do and changes nothing.
set -euo pipefail

file=.github/workflows/agentcloud-baseline.yml
workflow="$(cd "$(dirname "$0")" && pwd)/workflow/agentcloud-baseline.yml"
title='Add agent.cloud dependency baseline'
topic=agentcloud-baseline
body="Adds \`$file\`, agent.cloud's dependency baseline. On your own runner it checks the npm dependencies in
package-lock.json, pnpm-lock.yaml and yarn.lock files for known vulnerabilities and shows what it found on the run's page.
See https://github.com/agentdotcloud/security-baseline-action."

usage() {
  echo "usage: $0 [--dry-run] <owner>/<repo> [<owner>/<repo> ...]" >&2
  echo "       $0 [--dry-run] --org <owner>" >&2
  exit 2
}
die() { echo "$0: $*" >&2; exit 1; }

dry_run=false
orgs=''
repos=''
while [ $# -gt 0 ]; do
  case $1 in
    --dry-run) dry_run=true ;;
    --org) [ $# -ge 2 ] || usage; orgs="$orgs $2"; shift ;;
    -h | --help) sed -n '2,/^[^#]/s/^# \{0,1\}//p' "$0"; exit 0 ;;
    -*) usage ;;
    *) [[ $1 =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || usage; repos="$repos $1" ;;
  esac
  shift
done
[ -n "$orgs$repos" ] || usage
[ -f "$workflow" ] || die "can't find $workflow: run this script from a clone of security-baseline-action"
command -v gh >/dev/null || die "needs the GitHub CLI, gh: https://cli.github.com"

err="$(mktemp)"
trap 'rm -f "$err"' EXIT
reason() { sed 's/^gh: //' "$err" | tr -s ' \n' '  ' | sed 's/ *$//'; } # GitHub's reason for the last refusal

headers="$(gh api --include user 2>/dev/null)" || die "sign in to GitHub first: gh auth login"
# GitHub takes a workflow file only from a login with the workflow scope. A token with no classic scopes lists none.
scopes="$(printf '%s\n' "$headers" | tr -d '\r' | sed -n 's/^[Xx]-[Oo][Aa]uth-[Ss]copes: *//p')"
if [ -n "$scopes" ] && [[ ", $scopes," != *', workflow,'* ]]; then
  need="your gh login needs the workflow scope to add a workflow file: gh auth refresh -s workflow"
  $dry_run || die "$need"
  echo "note: $need"
fi

for org in $orgs; do
  found="$(gh api --paginate "orgs/$org/repos?per_page=100" \
    --jq '.[] | select((.archived | not) and .permissions.push) | .full_name' 2>"$err")" || die "$org: $(reason)"
  [ -n "$found" ] || die "$org: no repositories you can push to"
  repos="$repos $found"
done

# The workflow, base64-encoded, with the push trigger on default branch $1.
content() { sed "s|branches: \[main]|branches: [$1]|" "$workflow" | base64 | tr -d '\n'; }

# Commits the file to branch $3 of repository $1, whose default branch is $2.
put() {
  gh api -X PUT "repos/$1/contents/$file" -f message="$title" -f content="$(content "$2")" -f branch="$3" \
    >/dev/null 2>"$err"
}

# Commits the file to a new branch off default branch $2 of repository $1, and prints a pull request's URL.
open_pr() {
  local sha
  sha="$(gh api "repos/$1/git/ref/heads/$2" --jq .object.sha 2>"$err")" &&
    gh api -X POST "repos/$1/git/refs" -f ref="refs/heads/$topic" -f sha="$sha" >/dev/null 2>"$err" &&
    put "$1" "$2" "$topic" &&
    gh api -X POST "repos/$1/pulls" -f title="$title" -f head="$topic" -f base="$2" -f body="$body" \
      --jq .html_url 2>"$err"
}

# Prints one line for repository $1: committed, PR <url>, skipped (exists) or failed: <GitHub's reason>.
setup() {
  local repo=$1 branch url
  branch="$(gh api "repos/$repo" --jq .default_branch 2>"$err")" || { echo "$repo: failed: $(reason)"; return 1; }
  # The branch name goes into the workflow's YAML as it is, so it has to be one that needs no quoting there.
  if ! [[ $branch =~ ^[A-Za-z0-9_./-]+$ ]]; then
    echo "$repo: failed: the default branch \"$branch\" needs the file added by hand"
    return 1
  fi
  if gh api "repos/$repo/contents/$file" >/dev/null 2>"$err"; then
    echo "$repo: skipped (exists)"
    return 0
  elif ! grep -q '(HTTP 404)' "$err"; then
    echo "$repo: failed: $(reason)"
    return 1
  fi
  if $dry_run; then
    echo "$repo: would commit $file to $branch, or open a pull request if $branch is protected"
    return 0
  fi
  if put "$repo" "$branch" "$branch"; then
    echo "$repo: committed"
    return 0
  fi
  # What GitHub says when branch protection or a ruleset refuses a direct commit.
  if ! grep -qiE 'HTTP 409|protected branch|pull request|rule violation|status check' "$err"; then
    echo "$repo: failed: $(reason)"
    return 1
  fi
  url="$(gh api "repos/$repo/pulls?head=${repo%%/*}:$topic&state=open" --jq '.[0].html_url // empty' 2>"$err")" ||
    { echo "$repo: failed: $(reason)"; return 1; }
  if [ -n "$url" ]; then
    echo "$repo: PR $url (already open)"
  elif url="$(open_pr "$repo" "$branch")"; then
    echo "$repo: PR $url"
  else
    echo "$repo: failed: $branch refused a direct commit, and opening a pull request from $topic failed: $(reason)"
    return 1
  fi
}

failed=0
for repo in $repos; do
  setup "$repo" || failed=1
done
exit $failed
