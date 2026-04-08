# numasec Deep Analysis Report

> Internal analysis document. Not for public distribution.
> Generated: April 2026 | Branch: develop | Version: 4.1.3

---

## Philosophy

numasec is Claude Code for cybersecurity. Not a scanner collection. Not an MCP server. An **AI agent** that thinks like a pentester, uses tools (built-in and external via MCP), chains findings, adapts its strategy, and reports results. The 33+ built-in tools are "batteries included" for the out-of-the-box experience. The real value is the agent layer: planning, reasoning, chaining, adapting.

Everything in this analysis is evaluated through that lens. A tool scoring 6/10 in isolation might be fine if the agent compensates. A broken tool that damages credibility is P0 regardless of its score.

---

## TL;DR

The architecture is right. MCP-native, terminal-first, model-agnostic, deterministic planner. No competitor has this combination. The agent layer (planner, chain detection, OWASP tracking) is a genuine differentiator.

The problems are: a CSRF tester that doesn't test CSRF (credibility risk), OOB infrastructure that exists but no tool uses (entire blind vuln class invisible), 2 broken community templates, 3 implemented tools that are unreachable, and an OWASP coverage metric that lies. These are all fixable in weeks, not months.

The strategic gap isn't technical. It's awareness. Nobody knows numasec exists yet.

---

## Table of Contents

1. [Tool Analysis](#1-tool-analysis)
2. [Agent Layer (Planner, Chains, Coverage)](#2-agent-layer)
3. [Knowledge Base & Reporting](#3-knowledge-base--reporting)
4. [Tests & Benchmarks](#4-tests--benchmarks)
5. [Self-Security](#5-self-security)
6. [Competitive Landscape](#6-competitive-landscape)
7. [Decisions & Roadmap](#7-decisions--roadmap)

---

## 1. Tool Analysis

**32 tool modules, ~20K LOC**

Important framing: these are tools the agent uses, not standalone products. The agent can chain `sqli_tester` (detection) with `http_request` or `security_shell` wrapping sqlmap (exploitation). Scoring a tool down because it "doesn't extract data" misses the point. The agent is the brain. The tools are hands.

That said, tools that claim to do something and don't (CSRF), or that exist but can't be reached (CRLF, shodan), are real problems.

### Injection Tools

| Tool | Score | Payloads | Strength | Gap |
|------|-------|----------|----------|-----|
| sqli_tester | 7/10 | 34+ | 5-phase engine, 5 DBMS, time-based verification | No 2nd-order SQLi, no tamper scripts. Agent can delegate deep exploitation to sqlmap via security_shell. |
| nosql_tester | 4/10 | 9 | Multi-tier detection | Only 5 of 30+ MongoDB operators, MongoDB-only. Real gap. |
| cmdi_tester | 7/10 | 17 | Multi-signal detection, platform detection | No blind OOB. Biggest improvement: connect to oob_handler. |
| ssti_tester | 6/10 | 11 | Engine disambiguation (7 engines) | No blind SSTI. OOB integration would fix this. |
| crlf_tester | 5/10 | 7 | Unicode variants | **UNREACHABLE**: no MCP tool registered. Code works, just invisible. |

### Web Vulnerability Tools

| Tool | Score | Payloads | Strength | Gap |
|------|-------|----------|----------|-----|
| xss_tester | 5/10 | 14 | Playwright DOM testing, canary approach | No context-aware encoding (same payload for HTML body/JS string/attribute). Stored XSS hardcoded to Juice Shop. |
| **csrf_tester** | **3/10** | 0 | SameSite parsing | **BROKEN. Does NOT test CSRF.** Checks conditions only, never attempts cross-origin requests. Credibility risk. P0. |
| cors_tester | 5/10 | 4 | Reflected origin + null origin detection | No preflight testing. Acceptable for now, agent can reason about results. |
| idor_tester | 5/10 | 7 | UUID+numeric detection, response comparison | GET-only. Agent could use http_request for other methods, but tool should support them natively. |
| open_redirect | 6/10 | 23 | 4 strategies, allowlist bypass | Some Juice Shop-specific payloads. Needs cleanup. |

### Server-Side Tools

| Tool | Score | Payloads | Strength | Gap |
|------|-------|----------|----------|-----|
| ssrf_tester | 6/10 | 15 | IP representation variety, cloud metadata | No blind SSRF. OOB integration is the fix. |
| lfi_tester | 8/10 | 18 | Multi-depth, multi-encoding, PHP wrappers, WAF evasion | Solid. Minor gaps (no Windows UNC, no log poisoning). |
| xxe_tester | 7/10 | 4 | File-read + SSRF + error + SVG | No blind XXE. OOB integration needed. |
| host_header | 5/10 | 16 | Body + Location reflection | No password reset poisoning. Low priority. |
| upload_tester | 8/10 | 7 types | Auto form discovery, 7 bypass types | Solid. Minor gaps (no path traversal in filename). |

### Protocol & Advanced

| Tool | Score | Strength | Gap |
|------|-------|----------|-----|
| smuggling | 6/10 | Safe timing-based detection (no active smuggling) | 5s threshold causes FP on slow networks. Acceptable. |
| race_tester | 5/10 | Async concurrent burst | All requests identical, ~80% FP rate. Needs parameterization. |
| graphql | 7/10 | Introspection, depth, batch, APQ bypass | Good coverage. No dedicated MCP tool (agent calls it through injection_test). |
| auth_tester | 8/10 | JWT alg:none + weak-secret + kid, OAuth, spray | Strong. Missing RS256-to-HS256 downgrade. |

### Reconnaissance

| Tool | Score | Strength | Gap |
|------|-------|----------|-----|
| **service_prober** | **9/10** | 10 protocol probes, production-grade parsing | Gold standard. MySQL greeting, MongoDB BSON, SMB negotiate, SMTP relay. |
| browser_crawler | 8/10 | SPA detection, Playwright navigation | Hardcoded 30-route list. Otherwise excellent. |
| openapi_parser | 8/10 | Full OAS 2.0/3.x, $ref resolution | Solid. |
| cve_enricher | 7/10 | Two-layer (local + NVD), 7-day caching | No EPSS scoring. |
| python_connect | 7/10 | Zero-dep TCP scanner, SSL cert extraction | No SYN/UDP. Fine for the agent's needs. |
| crawler | 6/10 | BFS + 150 tech fingerprint rules | No JS rendering. browser_crawler compensates. |
| subdomain | 5/10 | DNS brute-force + CT logs | Only 388 prefixes (vs 5000+). Low priority improvement. |
| ~~shodan~~ | ~~3/10~~ | ~~Passive lookup~~ | **DECISION: REMOVE.** Requires external API key. Against zero-dependency philosophy. |

### Cross-Cutting Issues (by priority)

**P0 - Credibility:**
1. `csrf_tester` doesn't test CSRF. Rewrite or remove.
2. `crlf_tester` is unreachable. Register it.
3. `shodan` requires API key. Remove it.

**High impact, medium effort:**
4. **OOB handler integration.** Infrastructure exists (`oob_handler.py`), zero tools use it. Connecting it to sqli, ssrf, xxe, cmdi, ssti unlocks detection of all blind vulnerabilities. This is the single highest-ROI improvement in the entire codebase.
5. **Context-aware XSS.** Same payload for HTML body, JS string, attribute, URL. Adding context detection would be a major quality jump.

**Medium impact, low effort:**
6. Remove Juice Shop hardcoding (xss, auth, open_redirect).
7. Expand NoSQL operators from 5 to 25+.
8. Parameterize race condition requests (reduce FP from ~80% to ~20%).
9. Add RS256-to-HS256 JWT confusion.

**Low priority (agent compensates):**
10. Tool-level data extraction (agent uses http_request/security_shell).
11. Multi-method IDOR (agent can craft requests manually).
12. WAF profiling (agent adapts based on responses).

### Standouts

- **Best: `service_prober.py` (9/10)** Gold standard. 10 protocol probes with production-grade parsing.
- **Best attack tool: `auth_tester.py` (8/10)** Broad surface, responsible rate limiting.
- **Worst: `csrf_tester.py` (3/10)** Claims to test CSRF, doesn't. P0 fix.
- **Best foundation: `_encoder.py` (8/10)** Clean, stateless. Needs wider adoption across tools.

---

## 2. Agent Layer

### Planner (DeterministicPlanner)

PTES 5-phase, no LLM calls. This is a genuine differentiator. Predictable, auditable, reproducible.

**The "too conservative" critique is wrong.** Starting with SQLi/XSS/auth and expanding via replan signals is smart. It avoids wasting time on tests irrelevant to the target's tech stack. The real problem: **replan signals don't fire reliably.** If `technology_identified` doesn't trigger when it should, the planner never adds GraphQL/CORS/upload tests. Fix the signals, not the strategy.

**Quick scope (3 min) IS too short.** A full port scan alone can take longer. Most quick scans timeout before reaching vulnerability testing. Should be 5-7 min minimum.

### OWASP Coverage (CRITICAL BUG)

`http_request` is mapped to 6 OWASP categories in `OWASP_TOOL_MAP`. It's a generic HTTP tool, not a security tool. Running it inflates coverage to 60%+ without testing anything. The agent sees "60% covered" and thinks it's doing well. It isn't. **This is the most misleading metric in the system.** P0 fix: remove `http_request` from the map.

### Attack Chains

`build_chains()` groups findings by URL base path, merges via `related_finding_ids`. Works correctly. The gap: chain data exists but reports don't use it for attack narratives. The sidebar shows chains, but the markdown/HTML/SARIF reports don't tell the story of "SQLi on /api/users led to IDOR on /api/admin which led to privilege escalation." This narrative capability would be a differentiator.

### Unreachable Tools

| Tool | Status | Action |
|------|--------|--------|
| `crlf_tester.py` | Implemented, no MCP registration | **Register it** |
| `vuln_scanner.py` | Implemented, no MCP registration | **Register it** |
| `shodan.py` | Implemented, requires API key | **Remove it** |

### Tool Parameter Mapping Gaps

Features exist in the tools but the MCP bridge doesn't expose them:

| Tool | Missing Parameter | Impact |
|------|-------------------|--------|
| `xss_test` | `waf_evasion` flag | WAF evasion mode not accessible to agent |
| `xss_test` | POST body injection | Only tests URL params |
| `injection_test` | NoSQL-specific params | All NoSQL params silently ignored |
| `access_control_test` | `method` param | Can't test IDOR on POST/PUT/DELETE |
| `ssrf_test` | POST body injection | SSRF via body not testable |

---

## 3. Knowledge Base & Reporting

### Knowledge Base (34 templates, BM25 retriever)

**Architecture is excellent.** Contextual chunking (450 tokens, 60 overlap), hybrid scoring (60% BM25 + 40% semantic), graceful fallback. The design is right.

| Category | Count | Quality |
|----------|-------|---------|
| Detection | 11 (32%) | Strong on injection/auth |
| Exploitation | 5 (15%) | Step-by-step methodology |
| Payloads | 5 (15%) | XSS/SQLi/SSRF/SSTI libraries |
| Remediation | 4 (12%) | Multi-language code fixes |
| Attack Chains | 3 (9%) | Unique to numasec |
| Reference | 3 (9%) | CWE/OWASP mappings only |
| Post-Exploitation | 2 (6%) | Win/Linux privesc only |
| Protocols | 1 (3%) | Minimal |

**On the Nuclei comparison:** Comparing numasec's 34 templates to Nuclei's 12,000+ is misleading. Nuclei templates are simple HTTP matchers ("send this request, check this pattern"). numasec's tools are multi-hundred-line async Python programs that reason about responses, do multi-phase detection, and disambiguate engines. They're fundamentally different things. The real gap is CVE-specific coverage (numasec has zero), not raw count.

**BM25 issues (low priority):**
- Naive tokenizer splits `CWE-89` into two tokens
- No score threshold (returns irrelevant results at score 0)
- Category filters applied post-retrieval

### Reporting

| Format | Status | Notes |
|--------|--------|-------|
| SARIF | Production-ready | Valid 2.1.0, GitHub Code Scanning compatible. This matters most for CI/CD. |
| Markdown | Basic | Exec summary + findings table. Functional for dev consumption. |
| HTML | Internal-only | No print styles, no charts. Low priority. |
| PDF | Missing | Nice-to-have for consulting use case. Not our primary target user. Low priority. |

**Risk scoring issues (worth fixing):**
- Linear sum: 5 criticals cap at 100, same as 2. No diminishing returns.
- CVSS scores exist on findings but are NOT used in the calculation. Data is there, just ignored.
- Default confidence 0.5 everywhere. Uncalibrated.

**SARIF coverage: ~40% of spec.** Sufficient for GitHub Code Scanning. Advanced consumers (DefectDojo, SonarQube) need: `taxa` (CWE taxonomy), `baseline_state`, `code_flows`. Medium priority.

### Community Templates (6 templates)

| Template | Quality | Verdict |
|----------|---------|---------|
| security-headers | Good | Solid |
| server-info-disclosure | Good | Solid |
| debug-endpoints | Good | Good |
| cors-permissive | Fair | Incomplete, acceptable |
| **cookie-security** | **Poor** | Inverted regex logic, produces false positives on properly secured cookies. P0 fix. |
| **exposed-admin** | **Broken** | Checks status 200 on `/` with zero admin path or content matching. Every website triggers it. 100% false positive rate. P0 fix. |

---

## 4. Tests & Benchmarks

### Test Suite

| Metric | Value |
|--------|-------|
| Test files | 62 |
| Test functions | 1,273 |
| Tools tested | ~17 of 38 (**45%**) |
| Async mode | `asyncio_mode = "auto"` |
| Mock pattern | `httpx.MockTransport` |

**55% of tools have ZERO test coverage:**
`cors_tester`, `csrf_tester`, `ssrf_tester`, `cmdi_tester`, `browser_crawler`, `nosql_tester`, `graphql_tester`, `idor_tester`, `lfi_tester`, `xxe_tester`, `ssti_tester`, `open_redirect_tester`, `host_header_tester`

**Strong tests:** `test_xss_tester.py` and `test_sqli_tester.py` have multi-phase payload testing. `test_auth_tester.py` tests JWT algorithm confusion.

**Weak areas:** Some tests are trivial (`assert planner is not None`). Limited error-path testing (timeouts, network failures, malformed responses).

### Benchmarks

3 targets: Juice Shop (26 vulns), DVWA (7), WebGoat (19) = 52 total ground truth vulnerabilities.

**Issues:**
- Small sample, all OWASP-curated (not wild targets)
- Instance inflation (3 IDOR instances; finding 1 counts as TP)
- No docker-compose for reproducibility
- No state cleanup between runs

**Missing targets:** API-specific (OWASP API Top 10), GraphQL apps, modern SPAs.

---

## 5. Self-Security

### Safe

| Area | Status |
|------|--------|
| HTML report XSS | `html.escape()` on every user-supplied field |
| HTTP timeouts | `create_client()` defaults 30s, individual tools 10-15s |
| Bubblewrap sandbox | Filesystem isolation via `bwrap --unshare-all --share-net` |

### Issues

| Issue | Severity | Detail | Real Risk |
|-------|----------|--------|-----------|
| SSRF via redirect chains | Medium | `follow_redirects=True` default. Target can 302 to cloud metadata. | Low in practice: numasec runs against authorized targets. If target redirects to metadata, that's a finding about the target. Add a log warning, not a block. |
| ReDoS in YAML templates | Medium | User-supplied regex in `~/.numasec/plugins/` without timeout. | Only affects users who install malicious plugins. Add regex timeout. |
| Rate limiter defaults | Cosmetic | Code: 9999/min, 100 concurrent. Docstring claims 60/5. | Not a bug. During authorized pentests, rate-limiting yourself is counterproductive. Defaults are intentional. Fix the docstring, not the code. |
| Tool bridge output truncation | Data loss | >32KB truncated to 5 findings. Evidence capped at 1000 chars. | Worth fixing. Large scans lose data. |
| No tool execution timeout | Low | Hanging tool blocks semaphore slot. | Add a 5-minute timeout per tool execution. |

---

## 6. Competitive Landscape

### The Market

XBOW raised $237M at $1B+ valuation for AI pentesting. This validates the market exists. numasec is the open-source alternative.

### Direct Competitors

| Tool | Stars | What They Are | Fundamental Difference from numasec |
|------|-------|---------------|-------------------------------------|
| **PentAGI** | 13.9K | Multi-agent Go app wrapping existing tools (nmap, sqlmap, Metasploit) + Neo4j knowledge graph | Tool wrapper with heavy infra. numasec has purpose-built tools and zero-infra. |
| **PentestGPT** | 12.2K | GPT-4 pipeline with "Pentesting Task Tree" | Academic project, CTF-focused. No MCP, no CI/CD integration. |
| **XBOW** | N/A | Enterprise SaaS, $237M funded | Closed source, enterprise pricing. numasec is the open-source alternative. |
| **BurpGPT** | N/A | Burp Suite extension | Augments manual testing. numasec is fully autonomous. |

### numasec's Actual Moat

1. **MCP-native.** The only AI pentesting agent that speaks MCP. Works with Claude Code, Cursor, any MCP host. Users can extend it with any MCP server. This is the Claude Code parallel: composable, extensible, protocol-based.
2. **Zero infrastructure.** `pip install numasec` and go. No Neo4j, no PostgreSQL, no Docker compose with 8 services. This matters for adoption.
3. **Deterministic planner.** No LLM in the planning loop. Reproducible, auditable, predictable.
4. **Terminal-first.** Works over SSH, in containers, air-gapped environments. Security engineers live in the terminal.
5. **Purpose-built tools.** Custom async Python tools, not wrappers around nmap/sqlmap/nikto. Full control over behavior and output.

### Where numasec Loses (and whether it matters)

| Gap | Competitor | Does It Matter Now? |
|-----|-----------|---------------------|
| No knowledge graph | PentAGI | No. Premature optimization. Session-based SQLite is fine at current scale. |
| No Metasploit | PentAGI | No. Detection-first, exploitation via agent + security_shell when needed. |
| No mobile testing | XBOW | No. Stay focused on web app security. Expand later. |
| Fewer stars | PentAGI, PentestGPT | Yes. This is the awareness problem. Content + demos fix it. |
| Template count | Nuclei (12K+) | Misleading comparison. Different tool type entirely. CVE coverage is the real gap. |

### OpenCode Fork Status

OpenCode has been rewritten in Go. Upstream sync is impossible. This is fine. numasec's TUI has security-specific features (findings sidebar, OWASP heatmap, attack chains, evidence browser) that OpenCode will never have. The fork is now a standalone product.

---

## 7. Decisions & Roadmap

### Decisions Made

| Decision | Rationale |
|----------|-----------|
| **Remove `shodan.py`** | Requires external API key. Against zero-dependency philosophy. |
| **Agent quality > tool quantity** | The moat is how numasec reasons, not how many tools it has. |
| **Depth on web app security > breadth** | Don't add mobile/binary/cloud yet. Be the best at web app pentesting first. |
| **PDF is low priority** | numasec targets security engineers (SARIF, markdown), not consultants (PDF). |
| **Rate limiter defaults are intentional** | Fix the docstring, not the code. Rate-limiting during authorized pentests is counterproductive. |

### P0: Credibility Fixes (this week)

| # | Issue | Why P0 |
|---|-------|--------|
| 1 | **Rewrite `csrf_tester`** to actually perform CSRF testing | A security tool that claims to test CSRF but doesn't is a meme waiting to happen |
| 2 | **Fix `exposed-admin.yaml`** (100% FP rate) | Broken template damages trust in all community templates |
| 3 | **Fix `cookie-security.yaml`** (inverted regex) | Same as above |
| 4 | **Register `crlf_tester` and `vuln_scanner`** as MCP tools | Working code that's invisible to the agent is waste |
| 5 | **Remove `shodan.py`** | Requires API key. Dead weight. |
| 6 | **Fix OWASP coverage inflation** (remove `http_request` from `OWASP_TOOL_MAP`) | The most misleading metric in the system. Agent thinks it's at 60% when it's at 20%. |
| 7 | **Fix rate limiter docstring** | Says 60/min and 5 concurrent, code does 9999/100. Confusing. |

### P1: Highest-ROI Improvements (next 2 weeks)

| # | Improvement | Impact |
|---|------------|--------|
| 8 | **Integrate `oob_handler`** into sqli, ssrf, xxe, cmdi, ssti | Unlocks detection of ALL blind vulnerabilities. Single biggest quality jump possible. |
| 9 | **Fix planner replan signals** | Signals don't fire reliably, so the planner never adds tests beyond SQLi/XSS/auth. Fix the signals, not the conservative strategy. |
| 10 | **Context-aware XSS** (HTML/JS/attr/URL context detection) | Major false-negative reduction |
| 11 | **Fix tool parameter mapping gaps** | WAF evasion, NoSQL params, IDOR methods: features exist but agent can't access them |
| 12 | **Quick scope timeout 3min to 7min** | Current timeout kills scans before vuln testing starts |

### P2: Quality & Depth (next month)

| # | Improvement | Why |
|---|------------|-----|
| 13 | Expand NoSQL operators (5 to 25+) | Major coverage gap in a common attack surface |
| 14 | RS256-to-HS256 JWT confusion | Common attack, easy to add |
| 15 | Parameterize race condition requests | Current FP rate (~80%) makes the tool unreliable |
| 16 | Remove Juice Shop hardcoding | xss, auth, open_redirect have target-specific logic |
| 17 | Tool execution timeouts (5 min max) | Hanging tool blocks the agent |
| 18 | Use CVSS scores in risk calculation | Data exists on every finding but is ignored |
| 19 | Attack chain narratives in reports | Chain data exists, reports don't tell the story |

### P3: When There's Traction (quarter+)

| # | Feature | Trigger |
|---|---------|---------|
| 20 | SSL/TLS tool | When pentest reports feel incomplete without it |
| 21 | Compliance mapping (PCI-DSS, SOC2) | When enterprise users ask for it |
| 22 | Scan comparison / trend analysis | When users run numasec regularly (not one-off) |
| 23 | Template bounty program | When community is large enough to contribute |
| 24 | CVSS 4.0 | When adoption of 4.0 is mainstream |

### NOT Doing (explicitly deprioritized)

| Idea | Why Not |
|------|---------|
| Mobile testing | Out of scope. Web app depth first. |
| Binary exploitation | Different domain entirely. |
| Cloud misconfiguration | Premature. No demand signal yet. |
| Knowledge graph (Neo4j) | Premature optimization. SQLite is fine. |
| PDF export | Not our target user. Security engineers use SARIF and markdown. |
| Competing on template count with Nuclei | Different tool type. numasec's tools are programs, not pattern matchers. |

---

## Appendix: Tool Score Summary

| Tool | Score | Category | Notes |
|------|-------|----------|-------|
| service_prober | 9/10 | Recon | Gold standard |
| auth_tester | 8/10 | Attack | Strong, missing RS256-HS256 |
| lfi_tester | 8/10 | Attack | Solid |
| upload_tester | 8/10 | Attack | Solid |
| _encoder | 8/10 | Utility | Needs wider adoption |
| browser_crawler | 8/10 | Recon | Hardcoded routes |
| openapi_parser | 8/10 | Recon | Solid |
| cmdi_tester | 7/10 | Attack | Needs OOB |
| xxe_tester | 7/10 | Attack | Needs OOB |
| graphql_tester | 7/10 | Attack | No dedicated MCP tool |
| sqli_tester | 7/10 | Attack | Agent delegates deep exploitation to sqlmap |
| cve_enricher | 7/10 | Recon | No EPSS |
| python_connect | 7/10 | Recon | Fine for agent needs |
| vuln_scanner | 7/10 | Utility | UNREACHABLE. Register it. |
| ssti_tester | 6/10 | Attack | Needs OOB |
| ssrf_tester | 6/10 | Attack | Needs OOB |
| smuggling | 6/10 | Attack | Acceptable |
| open_redirect | 6/10 | Attack | Juice Shop specific |
| poc_validator | 6/10 | Utility | Hardcoded confidence |
| dir_fuzzer | 6/10 | Recon | No recursion |
| crawler | 6/10 | Recon | browser_crawler compensates |
| naabu | 6/10 | Recon | Thin wrapper |
| nmap | 6/10 | Recon | Thin wrapper |
| crlf_tester | 5/10 | Attack | UNREACHABLE. Register it. |
| cors_tester | 5/10 | Attack | Agent compensates |
| idor_tester | 5/10 | Attack | GET-only, agent compensates |
| host_header | 5/10 | Attack | Low priority |
| race_tester | 5/10 | Attack | ~80% FP rate |
| subdomain | 5/10 | Recon | Small wordlist |
| xss_tester | 5/10 | Attack | Needs context detection |
| nosql_tester | 4/10 | Attack | Only 5 operators |
| csrf_tester | 3/10 | Attack | **BROKEN. P0.** |
| ~~shodan~~ | - | - | **REMOVING. Requires API key.** |
