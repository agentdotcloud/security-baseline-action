// Synthetic credential shapes, never usable credentials. Both repo scanners must agree on the escape boundary.
export const STORED_ESCAPES = [String.raw`\n`, String.raw`\t`, String.raw`\r`, String.raw`\b`, String.raw`\f`, String.raw`\"`, String.raw`\\`, String.raw`\/`, String.raw`\u0020`] as const;
export const CREDENTIAL_SHAPES = [
  ...['ghp', 'gho', 'ghu', 'ghs', 'ghr'].map((prefix) => ({ kind: 'a GitHub token', token: `${prefix}_${'G'.repeat(36)}`, bounded: false })),
  { kind: 'a GitHub token', token: `github_pat_${'G'.repeat(60)}`, bounded: false },
  { kind: 'an API secret key', token: `sk-proj-${'P'.repeat(20)}`, bounded: false },
  { kind: 'an API secret key', token: `sk_live_${'P'.repeat(20)}`, bounded: false },
  { kind: 'a Slack token', token: `xoxb-${'S'.repeat(10)}`, bounded: false },
  { kind: 'an AWS access key', token: `AKIA${'A'.repeat(16)}`, bounded: false },
  { kind: 'a database URL with a password', token: 'postgres://fixture:not-a-real-password@db.example.invalid/app', bounded: true },
  { kind: 'an agent.cloud token', token: `agct_${'T'.repeat(32)}`, bounded: false },
  { kind: 'a private key', token: '-----BEGIN PRIVATE KEY-----', bounded: false },
] as const;

export const CATALOG_NAMES = ['agc_app_wordpress_0123456789abcdef_p', 'agc_staging_checkout_0123456789abcdef_d', 'agc_production_orders_1234567890abcdef_p', 'agc_dev_work_0123456789abcdef_d', 'agc_production_0123456789abcdef_canary', 'agc_staging_0123456789abcdef', 'agc_app_agcd_abcdefghijklm_0123456789abcdef_r'];

// Encode part of the token itself, so matching raw prefixes cannot substitute for decoding each key and value.
export const encodedToken = (token: string) => `\\u${token.charCodeAt(0).toString(16).padStart(4, '0')}${token.slice(1)}`;
const SHADOWED_TOKEN = `ghp_${'G'.repeat(36)}`;
export const SHADOWED_JSON_CREDENTIALS = [
  `{"diagnostic":"${SHADOWED_TOKEN}","diagnostic":"safe"}`,
  `{"diagnostic":"${encodedToken(SHADOWED_TOKEN)}","diagnosti\\u0063":"safe"}`,
];
export const STRAY_QUOTE_CREDENTIAL = String.raw`stray " {"url":"postgres:\/\/app:fixture-only@db.example.invalid/app"}`;
export const HEX_ESCAPED_CREDENTIAL = String.raw`note: \x67hp_` + 'G'.repeat(36);
export const databaseExample = (password: string) => `DATABASE_URL=postgresql://app:${password}@db.example.invalid/app\n`;
export const escapedCredentials = CREDENTIAL_SHAPES.flatMap(({ kind, token }) => STORED_ESCAPES.map((escape) => ({
  kind, raw: `diagnostic${escape}${token}`, json: `{"diagnostic":"key${escape}${encodedToken(token)}"}`, jsonKey: `{"key${escape}${encodedToken(token)}":true}`,
})));
