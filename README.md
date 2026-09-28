# KUKARAF security policy

Shared security gate for every KUKARAF repository. One reusable workflow, one
set of rules, maintained here, called from each repo.

The existing per-repo CI (fmt, build, test, panic-safety clippy) only
catches crashes and style. Every check below targets a class of
security bug that CI couldn't see.

## Adopting it in a repo

1. Copy `templates/security.yml` to `.github/workflows/security.yml`.
2. Copy `templates/dependabot.yml` to `.github/dependabot.yml`.
3. Commit `Cargo.lock` (remove it from `.gitignore`).
4. Pin your own actions to commit SHAs (`pinact run`, or `zizmor --fix`).
5. Once it's green, make the `security / *` checks required in branch protection.

## What runs

| Job | Tool | Catches |
|---|---|---|
| `lockfile` | shell | `Cargo.lock` not committed (unreproducible builds, invisible to scanning) |
| `deps` | cargo-deny | RustSec vulnerabilities, yanked crates, crates from unknown registries/git |
| `advisories` | osv-scanner | known CVEs in *every* lockfile: Cargo, npm, Gradle, Python |
| `workflows` | zizmor | `${{ }}` shell injection, unpinned actions, over-broad tokens, cache poisoning in release jobs |
| `secrets` | gitleaks | credentials anywhere in git history |
| `sast` | semgrep | our rules in `semgrep/`, plus `p/rust`, `p/dockerfile`, `p/secrets` |
| `docker` | hadolint + check | Dockerfile mistakes; final stage running as root |

### Our semgrep rules

| Rule | Bug class |
|---|---|
| `loopback-trusted-as-auth` | peer IP == 127.0.0.1 treated as trusted; behind a same-host proxy that's everyone |
| `auth-extractor-identity-ignored` | handler checks *that* you're logged in, not *who* you are (IDOR) |
| `acts-on-arbitrary-user-row` | `FROM users ... LIMIT 1` instead of the authenticated caller |
| `shell-command-spawn` | `Command::new("sh"/"bash")`: interpolated data becomes shell |
| `websocket-without-message-limit` | axum's 64 MiB default frame size, a memory DoS |
| `secret-compared-non-constant-time` | tokens/HMACs compared with `==` |
| `innerhtml-unescaped-interpolation` | `innerHTML = \`...${x}...\`` without escaping (XSS) |
| `tauri-csp-disabled` | `"csp": null`, which turns any XSS into Tauri command execution |
| `dev-auth-bypass-in-compose` | committed `ENV=DEVELOPMENT` that disables auth |
| `html-response-from-format`, `sql-built-with-format` | injection sinks |
| `unbounded-channel`, `compose-port-on-all-interfaces` | warnings only |

Rule changes need a fixture: add `// ruleid: <id>` / `// ok: <id>` cases to
`semgrep/rust.rs`; `self-test.yml` runs `semgrep --test` on every push.

## Exceptions

Exceptions go in the calling repo, next to the code, with a reason. Never
weaken the shared rules here to silence one repo.

- semgrep: `// nosemgrep: <rule-id> -- <reason>`
- cargo-deny: `deny.toml` in the repo (start from `templates/deny.toml`), `ignore = [{ id, reason }]`
- osv-scanner: `osv-scanner.toml` with `[[IgnoredVulns]]` and `reason`
- zizmor: `# zizmor: ignore[<audit>]`
- a whole job: `with: { skip: "docker" }`

## Versioning

Callers pin `@v1`. Compatible changes (new rules that are clean on all repos,
tool bumps) move the `v1` tag. A new blocking rule that would turn existing
repos red gets `v2`, so rollout is a PR per repo rather than a surprise.
