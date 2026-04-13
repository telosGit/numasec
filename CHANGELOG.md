# Changelog

---

## [1.1.0] — Stateful Offensive Runtime

- numasec now keeps its footing mid-run: browser sessions persist, actor state survives across steps, and the runtime can recover instead of falling apart after one bad navigation.
- Browser and HTTP flows now share real working memory: cookies, tokens, headers, storage state, and auth material can move across tools instead of being rediscovered over and over.
- The browser stack grew up from “click a page” into a replayable runtime: network traffic, actor sessions, execution attempts, target profiles, and resource inventory are now first-class runtime data.
- The evidence/graph pipeline got stricter and more useful: better planner normalization, stronger finding evaluation, richer verification flow, and cleaner attack-path/report projection.
- Added runtime validation tooling and a much larger regression suite covering auth fabric, browser recovery, execution failure taxonomy, target profile storage, and resource inventory.
- `install.sh` is once again the single supported source installer, and the public README has been rewritten around the new positioning, runtime, benchmarks, and release story.
- Hardened session handling for providers that omit finish reasons, which fixes the Claude Opus / Sonnet retry loop issue reported in the wild.

---

## [1.0.5] — v2 Command/Tool UX Transition

- Documented the canonical v2 slash command taxonomy:
  - `/scope set`, `/scope show`, `/hypothesis list`, `/verify next`, `/evidence list`, `/evidence show`, `/chains list`, `/finding list`, `/remediation plan`, `/retest run`, `/report generate`
- Added explicit migration mapping from legacy commands to v2 command names.
- Marked legacy slash aliases as **soft-deprecated**:
  - `/target`, `/findings`, `/report`, `/evidence`
- Clarified compatibility policy:
  - legacy aliases remain supported across v1.x
  - no alias removals in v1.x
  - earliest removal target is v2.0+ with release-note notice
- Documented v2 primitive-first tool UX and legacy wrapper compatibility (`save_finding`, `get_findings`, `build_chains`, scanner wrappers).
- Added release cutover runbook guidance in `README.md`:
  - feature-flag sequencing for `NUMASEC_SECURITY_GRAPH_WRITE` and `NUMASEC_SECURITY_GRAPH_READ`
  - subsystem rollback steps for commands, APIs, TUI canonical views, and approval UX
  - pre-default acceptance checks using existing test suites
  - post-cutover monitoring signals using `/security/:sessionID/read/summary` and permission queues
- Clarified that `NUMASEC_SECURITY_V2_PLANNER` and `NUMASEC_SECURITY_V2_TUI` are declared but not yet active rollout gates in v1.0.5.

---

## [1.0.4] — Windows Support

- Added Windows x64, x64-baseline, and ARM64 build targets to CI
- Fixed build script: `.exe` handling, conditional `chmod`, cross-platform smoke test
- Fixed `security_shell` tool to use `cmd /c` on Windows instead of `sh -c`
- Fixed cached binary path in npm launcher to use `.numasec.exe` on win32
- numasec now ships Windows binaries via npm, GitHub Releases, and install script

---

## [1.0.0] — Pure TypeScript Rewrite

The entire project has been rewritten from scratch. numasec is now a single TypeScript application — no Python, no bridge, no runtime dependencies.

### Architecture

- Single compiled binary via `bun build`. No Python, no pip, no Docker required.
- 21 native TypeScript security tools, registered via `Tool.define()`.
- Generic payload→response scanner engine replacing ~10 individual scanners.
- BM25 knowledge base retriever with 35 YAML attack templates.
- PTES 5-phase deterministic planner with replan signals (based on [CHECKMATE](https://arxiv.org/abs/2512.11143)).
- Finding enrichment pipeline: CWE → CVSS 3.1 → OWASP Top 10 → MITRE ATT&CK.
- Attack chain grouping algorithm with URL-based clustering.
- SARIF 2.1.0, HTML (Bootstrap), and Markdown report generators.
- npm distribution with platform-specific binary packages.

### Security Tools

| Tool | What it does |
|---|---|
| `recon` | Port scan + service probe + tech fingerprint |
| `crawl` | Spider + OpenAPI + sitemap discovery |
| `dir_fuzz` | Directory brute-force |
| `js_analyze` | JS endpoint/secret extraction |
| `injection_test` | SQL/NoSQL/SSTI/CmdI/CRLF/LFI/XXE |
| `xss_test` | Reflected XSS |
| `auth_test` | JWT analysis + credential testing |
| `access_control_test` | IDOR/CSRF/CORS/mass assignment |
| `ssrf_test` | SSRF with cloud metadata |
| `upload_test` | File upload bypass |
| `race_test` | Race condition detection |
| `graphql_test` | Introspection, batching, depth attacks |
| `kb_search` | Security knowledge base search (BM25) |
| `pentest_plan` | PTES methodology planner |
| `save_finding` | Persist finding with auto-enrichment |
| `get_findings` | Retrieve findings |
| `build_chains` | Group findings into attack chains |
| `generate_report` | SARIF/HTML/Markdown report |
| `http_request` | Raw HTTP with full control |
| `security_shell` | Shell execution (nmap, sqlmap, etc.) |
| `browser` | Playwright automation |

### Agent Modes

- **pentest** — full PTES methodology (default)
- **recon** — reconnaissance only, no exploitation
- **hunt** — systematic OWASP Top 10 sweep
- **review** — secure code review, no network scanning
- **report** — finding management and deliverables

### Distribution

- `npm install -g numasec` — platform-specific binary via optionalDependencies
- `install.sh` — build from source and install `numasec` into your local bin directory
- Docker images on Docker Hub and GHCR
- GitHub Releases with per-platform archives
