import { randomUUID } from "crypto"
import { Instance } from "../src/project/instance"
import { ProjectTable } from "../src/project/project.sql"
import { ProjectID } from "../src/project/schema"
import { ingestToolEnvelope } from "../src/security/envelope-ingestor"
import {
  SecurityActorSessionTable,
  SecurityBrowserSessionTable,
  SecurityExecutionAttemptTable,
  SecurityTargetProfileTable,
} from "../src/security/runtime/runtime.sql"
import { AccessControlTestTool } from "../src/security/tool/access-control-test"
import { BrowserTool } from "../src/security/tool/browser"
import { HttpRequestTool } from "../src/security/tool/http-request"
import { ProjectFindingsTool } from "../src/security/tool/project-findings"
import { QueryResourceInventoryTool } from "../src/security/tool/query-resource-inventory"
import { SessionTable } from "../src/session/session.sql"
import type { MessageID, SessionID } from "../src/session/schema"
import { Database, eq } from "../src/storage/db"
import type { Tool } from "../src/tool/tool"

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function number(input: unknown) {
  if (typeof input === "number" && Number.isFinite(input)) return input
  if (typeof input === "string" && input) {
    const value = Number(input)
    if (Number.isFinite(value)) return value
  }
  return 0
}

function value(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {}
  return input as Record<string, unknown>
}

function items(input: unknown) {
  if (!Array.isArray(input)) return [] as Record<string, unknown>[]
  return input.filter((item) => item && typeof item === "object" && !Array.isArray(item)) as Record<string, unknown>[]
}

function bool(input: string) {
  return input === "true" || input === "1" || input === "yes"
}

function limit(input: string, size = 1600) {
  if (input.length <= size) return input
  return input.slice(0, size)
}

function required(name: string) {
  const value = process.env[name] ?? ""
  if (value) return value
  throw new Error(`Missing required environment variable: ${name}`)
}

function optional(name: string) {
  return process.env[name] ?? ""
}

function session() {
  return `sess-runtime-live-${randomUUID()}` as SessionID
}

function jsonBlock(input: string) {
  const index = input.indexOf("{")
  if (index < 0) return {}
  try {
    const parsed = JSON.parse(input.slice(index))
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {}
    return parsed as Record<string, unknown>
  } catch {
    return {}
  }
}

const directory = new URL("..", import.meta.url).pathname

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make(`project-${sessionID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: directory,
        sandboxes: [],
      })
      .onConflictDoNothing()
      .run(),
  )
  Database.use((db) =>
    db
      .insert(SessionTable)
      .values({
        id: sessionID,
        project_id: projectID,
        slug: "runtime-live",
        directory,
        title: "runtime-live",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

function context(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "runtime-live",
    abort: new AbortController().signal,
    callID: "call-runtime-live",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  return Instance.provide({
    directory,
    fn: async () => {
      const impl = await tool.init()
      const out = await impl.execute(args as never, context(sessionID))
      if (out.envelope) {
        await ingestToolEnvelope({
          sessionID,
          tool: tool.id,
          title: out.title,
          metadata:
            typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata)
              ? (out.metadata as Record<string, unknown>)
              : {},
          envelope: out.envelope as any,
        })
      }
      return out
    },
  })
}

function step(name: string, out: Awaited<ReturnType<typeof runTool>>) {
  const meta = value(out.metadata)
  const envelope = value(out.envelope)
  return {
    name,
    title: text(out.title),
    status: text(envelope.status),
    http_status: number(meta.status),
    actor_session_id: text(meta.actorSessionID),
    navigation_index: number(meta.navigationIndex),
    recovery_attempts: number(meta.recoveryAttempts),
    target_profile_status: text(meta.targetProfileStatus),
    findings: number(meta.findings),
    count: number(meta.count),
    output: limit(text(out.output)),
  }
}

function runtimeSummary(sessionID: SessionID) {
  const actors = Database.use((db) =>
    db.select().from(SecurityActorSessionTable).where(eq(SecurityActorSessionTable.session_id, sessionID)).all(),
  )
  const browsers = Database.use((db) =>
    db.select().from(SecurityBrowserSessionTable).where(eq(SecurityBrowserSessionTable.session_id, sessionID)).all(),
  )
  const attempts = Database.use((db) =>
    db.select().from(SecurityExecutionAttemptTable).where(eq(SecurityExecutionAttemptTable.session_id, sessionID)).all(),
  )
  const profiles = Database.use((db) =>
    db.select().from(SecurityTargetProfileTable).where(eq(SecurityTargetProfileTable.session_id, sessionID)).all(),
  )

  let ok = 0
  let nonOk = 0
  let recoveryAttempts = 0
  let recovered = 0
  const codes: Record<string, number> = {}

  for (const row of attempts) {
    if (row.status === "ok") ok += 1
    if (row.status !== "ok") nonOk += 1
    const notes = value(row.notes)
    const count = number(notes.recovery_attempts)
    recoveryAttempts += count
    if (row.status === "ok" && count > 0) recovered += 1
    const code = text(row.error_code)
    if (!code) continue
    codes[code] = (codes[code] ?? 0) + 1
  }

  return {
    actor_sessions: actors.length,
    browser_sessions: browsers.length,
    execution_attempts: attempts.length,
    ok_attempts: ok,
    non_ok_attempts: nonOk,
    recovery_attempts: recoveryAttempts,
    recovered_steps: recovered,
    failure_codes: codes,
    actors: actors.map((row) => ({
      actor_label: row.actor_label,
      status: row.status,
      last_origin: row.last_origin,
      last_url: row.last_url,
    })),
    browsers: browsers.map((row) => ({
      status: row.status,
      navigation_index: row.navigation_index,
      last_origin: row.last_origin,
      last_url: row.last_url,
      last_error_code: row.last_error_code,
    })),
    profiles: profiles.map((row) => ({
      origin: row.origin,
      status: row.status,
      pacing_ms: row.pacing_ms,
      jitter_ms: row.jitter_ms,
      retry_budget: row.retry_budget,
      browser_preferred: row.browser_preferred,
      last_signal: row.last_signal,
    })),
  }
}

async function registerJuiceUser(sessionID: SessionID, target: string, actorLabel: string, steps: Record<string, unknown>[]) {
  const email = `numasec.runtime.${randomUUID().slice(0, 8)}@example.com`
  const password = "Passw0rd!123"
  const out = await runTool(
    HttpRequestTool,
    {
      url: new URL("/api/Users", target).toString(),
      method: "POST",
      actor_label: actorLabel,
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
        passwordRepeat: password,
        securityQuestionId: 1,
        securityAnswer: "numasec",
      }),
    },
    sessionID,
  )
  steps.push(step("juice:register", out))
  const status = number(value(out.metadata).status)
  if (status < 400) {
    return {
      email,
      password,
    }
  }
  throw new Error(`Juice Shop registration failed with status ${status}: ${out.output}`)
}

const mode = optional("NUMASEC_RUNTIME_LIVE_MODE") || "generic"
const target = required("NUMASEC_RUNTIME_LIVE_URL")
const actorLabel = optional("NUMASEC_RUNTIME_LIVE_ACTOR") || "live-primary"
const browserURL = optional("NUMASEC_RUNTIME_LIVE_BROWSER_URL") || target
const skipBrowser = bool(optional("NUMASEC_RUNTIME_LIVE_SKIP_BROWSER"))
const juiceAutoRegisterInput = optional("NUMASEC_RUNTIME_LIVE_JUICE_AUTO_REGISTER")
const juiceAutoRegister = juiceAutoRegisterInput ? bool(juiceAutoRegisterInput) : mode === "juice"
const loginURL =
  optional("NUMASEC_RUNTIME_LIVE_LOGIN_URL") ||
  (mode === "juice" ? new URL("/rest/user/login", target).toString() : "")
const loginEmail = optional("NUMASEC_RUNTIME_LIVE_LOGIN_EMAIL") || (mode === "juice" ? "admin@juice-sh.op" : "")
const loginPassword = optional("NUMASEC_RUNTIME_LIVE_LOGIN_PASSWORD") || (mode === "juice" ? "admin123" : "")
const authURL =
  optional("NUMASEC_RUNTIME_LIVE_AUTH_CHECK_URL") ||
  (mode === "juice" ? new URL("/rest/user/whoami", target).toString() : "")
const authMethod = optional("NUMASEC_RUNTIME_LIVE_AUTH_CHECK_METHOD") || "GET"
const authBody = optional("NUMASEC_RUNTIME_LIVE_AUTH_CHECK_BODY")
const workflowURL = optional("NUMASEC_RUNTIME_LIVE_WORKFLOW_URL")
const workflowResourceURL = optional("NUMASEC_RUNTIME_LIVE_RESOURCE_URL")
const outputPath = optional("NUMASEC_RUNTIME_LIVE_OUTPUT_PATH")

const sessionID = session()
seedSession(sessionID)

const steps: Record<string, unknown>[] = []
let loginIdentity = loginEmail
let liveActorLabel = actorLabel

let login: Awaited<ReturnType<typeof runTool>> | undefined
if (loginURL && loginEmail && loginPassword) {
  login = await runTool(
    HttpRequestTool,
    {
      url: loginURL,
      method: "POST",
      actor_label: liveActorLabel,
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: loginIdentity,
        password: loginPassword,
      }),
    },
    sessionID,
  )
  steps.push(step("login", login))
  let status = number(value(login.metadata).status)
  if (status >= 400 && juiceAutoRegister) {
    liveActorLabel = `${actorLabel}-registered`
    const registered = await registerJuiceUser(sessionID, target, liveActorLabel, steps)
    loginIdentity = registered.email
    login = await runTool(
      HttpRequestTool,
      {
        url: loginURL,
        method: "POST",
        actor_label: liveActorLabel,
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email: registered.email,
          password: registered.password,
        }),
      },
      sessionID,
    )
    steps.push(step("login:retry-registered", login))
    status = number(value(login.metadata).status)
  }
  if (status >= 400) {
    throw new Error(`Live login failed with status ${status}: ${login.output}`)
  }
}

let browser: Awaited<ReturnType<typeof runTool>> | undefined
let cookies: Awaited<ReturnType<typeof runTool>> | undefined
if (!skipBrowser) {
  browser = await runTool(
    BrowserTool,
    {
      action: "navigate",
      url: browserURL,
      actor_label: liveActorLabel,
      reset_session: true,
    },
    sessionID,
  )
  steps.push(step("browser:navigate", browser))
  const status = text(value(browser.envelope).status)
  if (status && status !== "ok") {
    throw new Error(`Live browser step failed with status ${status}: ${browser.output}`)
  }

  cookies = await runTool(
    BrowserTool,
    {
      action: "get_cookies",
      actor_label: liveActorLabel,
    },
    sessionID,
  )
  steps.push(step("browser:get_cookies", cookies))
  const cookieStatus = text(value(cookies.envelope).status)
  if (cookieStatus && cookieStatus !== "ok") {
    throw new Error(`Live browser cookie check failed with status ${cookieStatus}: ${cookies.output}`)
  }
}

let auth: Awaited<ReturnType<typeof runTool>> | undefined
if (authURL) {
  const args: Record<string, unknown> = {
    url: authURL,
    method: authMethod,
    actor_label: liveActorLabel,
  }
  if (authBody) args.body = authBody
  auth = await runTool(HttpRequestTool, args, sessionID)
  steps.push(step("auth:check", auth))
  const status = number(value(auth.metadata).status)
  if (status >= 400) {
    throw new Error(`Live auth check failed with status ${status}: ${auth.output}`)
  }
}

const inventory = await runTool(
  QueryResourceInventoryTool,
  {
    exposure: "all",
  },
  sessionID,
)
steps.push(step("inventory:query", inventory))

let workflow: Awaited<ReturnType<typeof runTool>> | undefined
if (workflowURL) {
  workflow = await runTool(
    AccessControlTestTool,
    {
      url: workflowURL,
      test_type: "workflow",
      actor_label: liveActorLabel,
      method: optional("NUMASEC_RUNTIME_LIVE_WORKFLOW_METHOD") || "POST",
      resource_url: workflowResourceURL || undefined,
      body: optional("NUMASEC_RUNTIME_LIVE_WORKFLOW_BODY") || undefined,
      action_kind: optional("NUMASEC_RUNTIME_LIVE_ACTION_KIND") || undefined,
      target_state: optional("NUMASEC_RUNTIME_LIVE_TARGET_STATE") || undefined,
    },
    sessionID,
  )
  steps.push(step("workflow:replay", workflow))
}

const projection = await runTool(ProjectFindingsTool, {}, sessionID)
steps.push(step("findings:project", projection))

const inventoryData = jsonBlock(text(inventory.output))
const resources = items(inventoryData.resources)
const actors = items(inventoryData.actors)
const groups = items(inventoryData.by_actor)

let networkResources = 0
let networkActions = 0
const actionSamples: string[] = []

for (const item of resources) {
  const row = value(item)
  if (text(row.source_kind) !== "browser_network") continue
  networkResources += 1
  const kind = text(row.action_kind)
  if (!kind) continue
  networkActions += 1
  const label = text(row.action_label) || kind
  const targetURL = text(row.url) || text(row.resource_url)
  if (actionSamples.length < 10) actionSamples.push(`${label} ${targetURL}`.trim())
}

const loginMeta = value(login?.metadata)
const browserMeta = value(browser?.metadata)
const cookieMeta = value(cookies?.metadata)
const authMeta = value(auth?.metadata)
const projectionMeta = value(projection.metadata)
const runtime = runtimeSummary(sessionID)

const loginActorSession = text(loginMeta.actorSessionID)
const browserActorSession = text(browserMeta.actorSessionID)
const cookieActorSession = text(cookieMeta.actorSessionID)
const authActorSession = text(authMeta.actorSessionID)
const browserPersisted = skipBrowser
  ? "skipped"
  : browserActorSession && cookieActorSession && browserActorSession === cookieActorSession
    ? "ok"
    : "failed"
const authPropagated = authURL
  ? number(authMeta.status) < 400 && authActorSession && (!loginActorSession || authActorSession === loginActorSession) && (!browserActorSession || authActorSession === browserActorSession)
    ? "ok"
    : "failed"
  : "not_run"

const summary = {
  session_id: sessionID,
  mode,
  target,
  actor_label: liveActorLabel,
  requested_actor_label: actorLabel,
  login_identity: loginIdentity,
  steps,
  inventory: {
    actor_count: number(value(inventory.metadata).actorCount),
    resource_count: number(value(inventory.metadata).resourceCount),
    actor_group_count: groups.length,
    action_count: number(value(inventory.metadata).actionCount),
    browser_network_resource_count: networkResources,
    browser_network_action_count: networkActions,
    browser_network_action_samples: actionSamples,
    actor_rows: actors.length,
  },
  findings: {
    raw: number(projectionMeta.raw),
    verified: number(projectionMeta.verified),
    provisional: number(projectionMeta.provisional),
    suppressed: number(projectionMeta.suppressed),
    refuted: number(projectionMeta.refuted),
    reportable: number(projectionMeta.reportable),
    promotion_gaps: number(projectionMeta.promotion_gaps),
  },
  runtime,
  kpi: {
    actor_persistence: browserPersisted,
    auth_propagation: authPropagated,
    action_mining_yield: networkActions,
    verified_finding_yield: number(projectionMeta.verified),
    recovery_attempts: runtime.recovery_attempts,
    recovered_steps: runtime.recovered_steps,
  },
}

if (outputPath) {
  await Bun.write(outputPath, JSON.stringify(summary, null, 2))
}

console.log(
  [
    `session_id=${sessionID}`,
    `mode=${mode}`,
    `target=${target}`,
    `actor_label=${liveActorLabel}`,
    `requested_actor_label=${actorLabel}`,
    `login_identity=${loginIdentity}`,
    `login_actor_session=${loginActorSession}`,
    `browser_actor_session=${browserActorSession}`,
    `browser_cookie_actor_session=${cookieActorSession}`,
    `browser_cookie_count=${number(cookieMeta.count)}`,
    `auth_check_status=${number(authMeta.status)}`,
    `auth_check_actor_session=${authActorSession}`,
    `inventory_actor_count=${number(value(inventory.metadata).actorCount)}`,
    `inventory_resource_count=${number(value(inventory.metadata).resourceCount)}`,
    `inventory_action_count=${number(value(inventory.metadata).actionCount)}`,
    `browser_network_resource_count=${networkResources}`,
    `browser_network_action_count=${networkActions}`,
    `verified_findings=${number(projectionMeta.verified)}`,
    `promotion_gaps=${number(projectionMeta.promotion_gaps)}`,
    `runtime_execution_attempts=${runtime.execution_attempts}`,
    `runtime_recovery_attempts=${runtime.recovery_attempts}`,
    `runtime_recovered_steps=${runtime.recovered_steps}`,
    workflow ? `workflow_findings=${number(value(workflow.metadata).findings)}` : "workflow_findings=not_run",
    `actor_persistence=${browserPersisted}`,
    `auth_propagation=${authPropagated}`,
    outputPath ? `artifact_path=${outputPath}` : "artifact_path=",
  ].join("\n"),
)

process.exit(0)
