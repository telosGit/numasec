# numasec Community Templates

YAML scanner templates that extend numasec's detection capabilities without writing Python code.

## Usage

Templates in this directory are automatically loaded when numasec starts. You can also install templates from external sources:

```bash
# Install from a URL
python -m numasec.cli.templates install https://raw.githubusercontent.com/user/repo/main/my-scanner.yaml

# Install from a local directory
python -m numasec.cli.templates install ./my-templates/

# List installed templates
python -m numasec.cli.templates list

# Update all community templates
python -m numasec.cli.templates update
```

Or place `.yaml` files directly in `~/.numasec/plugins/` for auto-loading.

## Template Format

```yaml
id: unique-scanner-id        # Required: unique identifier
name: "Human-Readable Name"  # Required: display name
severity: medium              # critical | high | medium | low | info
cwe: CWE-693                 # CWE identifier

request:
  method: GET                 # HTTP method
  path: /                     # Path to test

matchers:                     # One or more detection rules
  - type: header_absent       # Check for missing headers
    headers:
      - "X-Frame-Options"
      - "Content-Security-Policy"
    description: "Missing security headers"

  - type: header_value        # Match header value with regex
    header: "Server"
    pattern: "Apache/2\\.2\\.\\d+"
    description: "Outdated Apache version"

  - type: body_regex          # Search response body with regex
    pattern: "DEBUG\\s*=\\s*True"
    description: "Debug mode enabled"

  - type: status_code         # Match specific HTTP status
    code: 200
    description: "Page accessible"
```

## Matcher Types

| Type | Description | Fields |
|------|-------------|--------|
| `header_absent` | Missing security headers | `headers` (list) |
| `header_value` | Header matches regex | `header`, `pattern` |
| `body_regex` | Body matches regex | `pattern` |
| `status_code` | HTTP status code match | `code` |

## Included Templates

| Template | Description | Severity |
|----------|-------------|----------|
| `security-headers` | Missing Strict-Transport-Security, CSP, X-Frame-Options, etc. | Medium |
| `server-info-disclosure` | Server/X-Powered-By version leaking | Low |
| `debug-endpoints` | Framework debug pages, stack traces | High |
| `cookie-security` | Missing Secure/HttpOnly/SameSite flags | Medium |
| `cors-permissive` | Wildcard CORS or credentials with permissive origin | High |
| `exposed-admin` | Admin panels accessible without auth | High |

## Contributing

1. Create a `.yaml` file following the template format above
2. Test it: templates are loaded automatically from this directory
3. Submit a PR with your template

Guidelines:
- One vulnerability class per template
- Include accurate CWE identifiers
- Write clear, actionable descriptions
- Use precise regex patterns to minimize false positives
