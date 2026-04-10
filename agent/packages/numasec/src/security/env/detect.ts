/**
 * Environment detection.
 *
 * Checks PATH for security tools and returns a structured capabilities
 * report injected into the agent system prompt at session start.
 */

import { execSync } from "child_process"
import { platform } from "os"

export interface ToolStatus {
  name: string
  available: boolean
  path?: string
  version?: string
}

export interface Environment {
  os: string
  tools: ToolStatus[]
  summary: string
}

// Tools to probe, grouped by category
const TOOL_LIST: { name: string; versionFlag?: string }[] = [
  // Recon
  { name: "nmap", versionFlag: "--version" },
  { name: "naabu", versionFlag: "-version" },
  { name: "masscan", versionFlag: "--version" },
  { name: "subfinder", versionFlag: "-version" },
  // Fuzzing
  { name: "ffuf", versionFlag: "-V" },
  { name: "gobuster", versionFlag: "version" },
  { name: "feroxbuster", versionFlag: "--version" },
  { name: "dirsearch" },
  // Injection
  { name: "sqlmap", versionFlag: "--version" },
  { name: "commix", versionFlag: "--version" },
  // Vuln scanning
  { name: "nuclei", versionFlag: "-version" },
  { name: "nikto" },
  { name: "wpscan", versionFlag: "--version" },
  // Proxy / interception
  { name: "mitmproxy", versionFlag: "--version" },
  { name: "burpsuite" },
  // Exploitation
  { name: "metasploit-framework" },
  { name: "msfconsole" },
  { name: "hydra", versionFlag: "-h" },
  // Utility
  { name: "curl", versionFlag: "--version" },
  { name: "jq", versionFlag: "--version" },
  { name: "httpx", versionFlag: "-version" },
  { name: "python3", versionFlag: "--version" },
  { name: "node", versionFlag: "--version" },
  // Browser
  { name: "chromium" },
  { name: "google-chrome" },
  { name: "playwright" },
]

function which(name: string): string | undefined {
  try {
    return execSync(`which ${name} 2>/dev/null`, { encoding: "utf-8" }).trim() || undefined
  } catch {
    return undefined
  }
}

function getVersion(name: string, flag?: string): string | undefined {
  if (!flag) return undefined
  try {
    const out = execSync(`${name} ${flag} 2>&1`, { encoding: "utf-8", timeout: 5000 })
    // Extract first line that looks like a version
    const match = out.match(/\d+\.\d+[\w.+-]*/)?.[0]
    return match
  } catch {
    return undefined
  }
}

/** Detect available security tools and OS. */
export function detectEnvironment(): Environment {
  const os = platform()
  const tools: ToolStatus[] = []
  const available: string[] = []

  for (const tool of TOOL_LIST) {
    const path = which(tool.name)
    if (path) {
      const version = getVersion(tool.name, tool.versionFlag)
      tools.push({ name: tool.name, available: true, path, version })
      available.push(version ? `${tool.name} ${version}` : tool.name)
    } else {
      tools.push({ name: tool.name, available: false })
    }
  }

  const summary = available.length > 0
    ? `Available tools: ${available.join(", ")}`
    : "No external security tools detected — using built-in scanners only."

  return { os, tools, summary }
}
