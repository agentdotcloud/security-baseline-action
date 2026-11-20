// The secret shapes agent.cloud refuses in app repos, on its own with no imports, so any caller (control, and the RAGC
// foreman's scrub through control's re-export) can use exactly these patterns without pulling in anything else.
// Content that is almost certainly a secret. Each pattern is linear: no two adjacent quantifiers can share characters.
// Distinctive token prefixes match anywhere, including inside an identifier or after an escape.
const SECRETS: [RegExp, string][] = [
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/, 'a private key'],
  [/AKIA(?![0-9A-Z]{9}EXAMPLE(?![0-9A-Z]))[0-9A-Z]{16}(?![0-9A-Z])/, 'an AWS access key'],
  [/(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})/, 'a GitHub token'],
  [/(?:sk-(?:live|proj|ant)-[A-Za-z0-9_-]{20,}|sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,})/, 'an API secret key'],
  [/xox[abposr]-[A-Za-z0-9-]{10,}/, 'a Slack token'],
  // REPO-14: match the platform credential shapes, including task tokens, as control does.
  [/agc(?:(?:a|d|f|r|t)?_[A-Za-z0-9_-]{32}|(?:oa|or|pa|pr|l|pv)_[A-Za-z0-9_-]{43}|rep_[0-9a-f]{48}|j_[a-z2-7]{20}|t_[a-z2-7]{26}|e_[A-Za-z0-9_-]{22}|(?:a|e|f|g|p|pi|t|w)_(?:[A-Za-z0-9_-]{1,400}\.){1,3}[A-Za-z0-9_-]{43}|(?!(?:a|d|e|f|g|j|l|oa|or|p|pa|pi|pr|pv|r|rep|t|w)_)[a-z]{1,6}_[A-Za-z0-9_-]{32})/, 'an agent.cloud token'],
];
// A whole managed analytics catalog name is not a credential (ADB-6, REPO-14), as in control's scanner.
const CATALOG = /(?:(?<![A-Za-z0-9_.-])|(?<=\\["\\\/bfnrt])|(?<=\\u[0-9a-fA-F]{4}))agc_(?:app_[a-z](?:[a-z0-9_]{0,21}[a-z0-9])?_[0-9a-f]{16}_(?:p|r|d|canary)|(?:staging|production|dev)_(?:[0-9a-f]{16}(?:_[a-z]+)?|[a-z](?:[a-z0-9_]{0,21}[a-z0-9])?_[0-9a-f]{16}_(?:p|r|d|canary)))(?![A-Za-z0-9_-])/g;
const LOCAL_DB = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|postgres|db|database)(:|\/|$)/i;
// Proof artifacts use the same rule at worker acquisition and control intake, regardless of the database host.
const PROOF_DB = /(?:\b|(?<=\\["\\\/bfnrt])|(?<=\\u[0-9a-fA-F]{4}))postgres(?:ql)?:\/\/[^:\s/@'"]+:([^@\s'"]*)(@)?/g;
const PLACEHOLDER = new Set(['', 'password', 'postgres', 'changeme', 'example', 'test', 'pass']);
export function secretIn(data: Buffer, proof = false): string | null {
  const text = data.toString('latin1'), named = text.replace(CATALOG, ' ');
  for (const [re, what] of SECRETS) if (re.test(what === 'an agent.cloud token' ? named : text)) return what;
  if (proof) {
    if (text.includes('@')) for (const m of text.matchAll(PROOF_DB)) if (m[2] && !PLACEHOLDER.has(m[1]!)) return 'a database URL with a password';
    return null;
  }
  // A database URL with a password, unless it points at a local or docker-compose database (that's dev config).
  // No password-bearing database URL can match without @. Avoid trying the bounded
  // credential pattern at every repeated URL prefix when that separator is absent.
  if (text.includes('@')) for (const m of text.matchAll(/(?:\b|(?<=\\["\\\/bfnrt])|(?<=\\u[0-9a-fA-F]{4}))postgres(?:ql)?:\/\/[^:\s/@'"]{1,100}:[^@\s'"]{1,200}@([^\s'"`/?]{1,255})/g)) if (!LOCAL_DB.test(m[1]!)) return 'a database URL with a password';
  return null;
}
