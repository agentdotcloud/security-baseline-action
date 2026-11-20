// A stand-in for `gh api` that setup.sh's tests put on PATH. It answers the GitHub REST calls setup.sh makes from a
// JSON state file (FAKE_GH_STATE), applies writes to that file, and logs every call (FAKE_GH_LOG). Errors look like
// gh's: GitHub's JSON body on stdout, `gh: <message> (HTTP <status>)` on stderr, exit 1. Anything setup.sh isn't
// expected to run, including a --jq filter not listed below, exits 2 so a test fails loudly.
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';

export interface FakeError {
  status: number;
  message: string;
}
export interface FakePull {
  number: number;
  title: string;
  head: string;
  base: string;
  body: string;
  state: 'open' | 'closed';
  html_url: string;
}
export interface FakeRepo {
  default_branch: string;
  archived?: boolean;
  push?: boolean;
  /** Refuse direct commits to the default branch with this error, as branch protection or a ruleset does. */
  protect?: FakeError;
  /** Refuse every commit with this error. */
  putError?: FakeError;
  /** Branch name to its files, path to content. */
  branches: Record<string, Record<string, string>>;
  commits?: { branch: string; path: string; message: string }[];
  pulls?: FakePull[];
}
export interface FakeState {
  signedIn?: boolean;
  /** The X-OAuth-Scopes header GitHub sends for the login; null sends none. */
  scopes?: string | null;
  repos: Record<string, FakeRepo>;
}
export interface FakeCall {
  method: string;
  endpoint: string;
  fields: Record<string, string>;
}

type Json = any;

// The only --jq filters setup.sh uses, as gh would print their results.
const JQ: Record<string, (v: Json) => string[]> = {
  '.default_branch': (v) => [v.default_branch],
  '.object.sha': (v) => [v.object.sha],
  '.html_url': (v) => [v.html_url],
  '.[0].html_url // empty': (v) => (v[0]?.html_url ? [v[0].html_url] : []),
  '.[] | select((.archived | not) and .permissions.push) | .full_name': (v) =>
    v.filter((r: Json) => !r.archived && r.permissions?.push).map((r: Json) => r.full_name),
};

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function unsupported(what: string): never {
  process.stderr.write(`fake gh: unsupported ${what}\n`);
  process.exit(2);
}

const sha = (branch: string) => `sha-of-${branch}`;

function main(argv: string[]): void {
  if (argv[0] !== 'api') unsupported(`command: gh ${argv.join(' ')}`);
  let method = '';
  let jq = '';
  let silent = false;
  let include = false;
  let endpoint = '';
  const fields: Record<string, string> = {};
  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '-X' || arg === '--method') method = argv[++i];
    else if (arg === '-f' || arg === '--raw-field') {
      const [key, ...value] = argv[++i].split('=');
      fields[key] = value.join('=');
    } else if (arg === '--jq' || arg === '-q') jq = argv[++i];
    else if (arg === '--silent') silent = true;
    else if (arg === '--include' || arg === '-i') include = true;
    else if (arg === '--paginate') continue;
    else if (arg.startsWith('-')) unsupported(`flag: ${arg}`);
    else if (endpoint) unsupported(`second endpoint: ${arg}`);
    else endpoint = arg;
  }
  method ||= Object.keys(fields).length ? 'POST' : 'GET';
  if (jq && !JQ[jq]) unsupported(`--jq filter: ${jq}`);
  appendFileSync(process.env.FAKE_GH_LOG!, `${JSON.stringify({ method, endpoint, fields })}\n`);

  const statePath = process.env.FAKE_GH_STATE!;
  const state: FakeState = JSON.parse(readFileSync(statePath, 'utf8'));
  if (state.signedIn === false) {
    process.stderr.write('To get started with GitHub CLI, please run:  gh auth login\n');
    process.exit(4);
  }
  try {
    const { status, body } = respond(state, method, endpoint, fields);
    if (method !== 'GET') writeFileSync(statePath, JSON.stringify(state));
    if (include) {
      const scopes = state.scopes === null ? '' : `X-Oauth-Scopes: ${state.scopes ?? 'repo, workflow'}\r\n`;
      process.stdout.write(`HTTP/2.0 ${status} OK\r\nContent-Type: application/json\r\n${scopes}\r\n`);
    }
    if (silent) return;
    process.stdout.write(jq ? JQ[jq](body).map((line) => `${line}\n`).join('') : JSON.stringify(body));
  } catch (error) {
    if (!(error instanceof HttpError)) throw error;
    if (!silent) process.stdout.write(JSON.stringify({ message: error.message, status: String(error.status) }));
    process.stderr.write(`gh: ${error.message} (HTTP ${error.status})\n`);
    process.exit(1);
  }
}

function respond(state: FakeState, method: string, endpoint: string, fields: Record<string, string>) {
  const [path, query = ''] = endpoint.split('?');
  const params = new URLSearchParams(query);
  const route = (pattern: RegExp, want: string) => (method === want ? path.match(pattern) : null);
  const repoOf = (name: string) => {
    const repo = state.repos[name];
    if (!repo) throw new HttpError(404, 'Not Found');
    return repo;
  };
  let m: RegExpMatchArray | null;

  if ((m = route(/^user$/, 'GET'))) return { status: 200, body: { login: 'octo' } };

  if ((m = route(/^orgs\/([^/]+)\/repos$/, 'GET'))) {
    const owned = Object.entries(state.repos).filter(([name]) => name.startsWith(`${m![1]}/`));
    if (!owned.length) throw new HttpError(404, 'Not Found');
    const body = owned.map(([full_name, r]) => ({
      full_name,
      archived: !!r.archived,
      permissions: { pull: true, push: r.push !== false },
    }));
    return { status: 200, body };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)$/, 'GET'))) {
    return { status: 200, body: { full_name: m[1], default_branch: repoOf(m[1]).default_branch } };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/contents\/(.+)$/, 'GET'))) {
    const repo = repoOf(m[1]);
    const content = repo.branches[params.get('ref') ?? repo.default_branch]?.[m[2]];
    if (content === undefined) throw new HttpError(404, 'Not Found');
    return { status: 200, body: { path: m[2], content: Buffer.from(content).toString('base64') } };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/contents\/(.+)$/, 'PUT'))) {
    const repo = repoOf(m[1]);
    const branch = fields.branch ?? repo.default_branch;
    if (repo.putError) throw new HttpError(repo.putError.status, repo.putError.message);
    if (repo.protect && branch === repo.default_branch) throw new HttpError(repo.protect.status, repo.protect.message);
    const files = repo.branches[branch];
    if (!files) throw new HttpError(404, `Branch ${branch} not found`);
    if (files[m[2]] !== undefined) throw new HttpError(422, `Invalid request.\n\n"sha" wasn't supplied.`);
    files[m[2]] = Buffer.from(fields.content, 'base64').toString('utf8');
    (repo.commits ??= []).push({ branch, path: m[2], message: fields.message });
    return { status: 201, body: { content: { path: m[2] } } };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/git\/ref\/heads\/(.+)$/, 'GET'))) {
    if (!repoOf(m[1]).branches[m[2]]) throw new HttpError(404, 'Not Found');
    return { status: 200, body: { ref: `refs/heads/${m[2]}`, object: { sha: sha(m[2]) } } };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/git\/refs$/, 'POST'))) {
    const repo = repoOf(m[1]);
    const name = fields.ref.replace(/^refs\/heads\//, '');
    if (repo.branches[name]) throw new HttpError(422, 'Reference already exists');
    const from = Object.keys(repo.branches).find((b) => sha(b) === fields.sha);
    if (!from) throw new HttpError(422, 'Object does not exist');
    repo.branches[name] = { ...repo.branches[from] };
    return { status: 201, body: { ref: fields.ref, object: { sha: fields.sha } } };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/pulls$/, 'GET'))) {
    const [owner] = m[1].split('/');
    const pulls = (repoOf(m[1]).pulls ?? []).filter(
      (p) => `${owner}:${p.head}` === params.get('head') && p.state === params.get('state'),
    );
    return { status: 200, body: pulls };
  }

  if ((m = route(/^repos\/([^/]+\/[^/]+)\/pulls$/, 'POST'))) {
    const repo = repoOf(m[1]);
    if (!repo.branches[fields.head] || !repo.branches[fields.base]) throw new HttpError(422, 'Validation Failed');
    const pulls = (repo.pulls ??= []);
    const number = pulls.length + 1;
    const pull: FakePull = {
      number,
      title: fields.title,
      head: fields.head,
      base: fields.base,
      body: fields.body,
      state: 'open',
      html_url: `https://github.com/${m[1]}/pull/${number}`,
    };
    pulls.push(pull);
    return { status: 201, body: pull };
  }

  unsupported(`request: ${method} ${endpoint}`);
}

main(process.argv.slice(2));
