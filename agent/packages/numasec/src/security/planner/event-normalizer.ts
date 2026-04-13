import type { PlannerEvent, PlannerSignal, PlannerState } from "./kernel"

type Scope = "quick" | "standard" | "deep"

interface NormalizeInput {
  event_type?: string
  event?: string
  event_payload?: Record<string, unknown>
  target?: string
  scope?: Scope
  hypothesis_id?: string
  finding_id?: string
  evidence_nodes?: string[]
}

export interface NormalizeResult {
  raw_type: string
  canonical_type: PlannerEvent["type"] | ""
  event?: PlannerEvent
  warnings: string[]
}

const ALIAS = new Map<string, PlannerEvent["type"]>([
  ["scope_set", "scope_set"],
  ["scope", "scope_set"],
  ["set_scope", "scope_set"],
  ["scope_defined", "scope_set"],
  ["hypothesis_upserted", "hypothesis_upserted"],
  ["hypothesis", "hypothesis_upserted"],
  ["hypothesis_open", "hypothesis_upserted"],
  ["hypothesis_created", "hypothesis_upserted"],
  ["hypothesis_updated", "hypothesis_upserted"],
  ["evidence_recorded", "evidence_recorded"],
  ["evidence", "evidence_recorded"],
  ["observation_recorded", "evidence_recorded"],
  ["observation", "evidence_recorded"],
  ["verification_recorded", "verification_recorded"],
  ["verification", "verification_recorded"],
  ["assertion_verified", "verification_recorded"],
  ["decision_made", "decision_made"],
  ["decision", "decision_made"],
  ["verdict", "decision_made"],
  ["finding_recorded", "decision_made"],
  ["hypothesis_invalidated", "hypothesis_invalidated"],
  ["invalidated", "hypothesis_invalidated"],
  ["hypothesis_rejected", "hypothesis_invalidated"],
  ["surface_observed", "note_recorded"],
  ["surface_mapped", "note_recorded"],
  ["evidence_collected", "note_recorded"],
  ["evidence_logged", "note_recorded"],
  ["auth_obtained", "note_recorded"],
  ["authenticated", "note_recorded"],
  ["token_obtained", "note_recorded"],
  ["credentials_obtained", "note_recorded"],
  ["login_success", "note_recorded"],
  ["note", "note_recorded"],
  ["reset", "reset"],
  ["restart", "reset"],
])

function stringValue(input: unknown): string {
  if (typeof input === "string") return input
  return ""
}

function boolValue(input: unknown): boolean | undefined {
  if (typeof input === "boolean") return input
  const value = stringValue(input).toLowerCase()
  if (["true", "1", "pass", "passed"].includes(value)) return true
  if (["false", "0", "fail", "failed"].includes(value)) return false
  return
}

function scopeValue(input: unknown): Scope {
  const value = stringValue(input)
  if (value === "quick" || value === "deep") return value
  return "standard"
}

function relationValue(input: unknown): "supports" | "refutes" | "observes" {
  const value = stringValue(input).toLowerCase()
  if (["support", "supports", "positive"].includes(value)) return "supports"
  if (["refute", "refutes", "negative"].includes(value)) return "refutes"
  return "observes"
}

function verdictValue(input: unknown): "confirmed" | "rejected" | "inconclusive" {
  if (typeof input === "boolean") return input ? "confirmed" : "rejected"
  const value = stringValue(input).toLowerCase()
  if (["confirmed", "confirm", "positive", "pass", "passed", "true"].includes(value)) return "confirmed"
  if (["rejected", "reject", "negative", "fail", "failed", "false"].includes(value)) return "rejected"
  return "inconclusive"
}

function nodeID(payload: Record<string, unknown>, input: NormalizeInput): string {
  const direct =
    stringValue(payload.node_id) ||
    stringValue(payload.evidence_node_id) ||
    stringValue(payload.evidence_id) ||
    stringValue(payload.observation_node_id) ||
    stringValue(payload.verification_node_id)
  if (direct) return direct
  const fallback = input.evidence_nodes?.[0]
  return typeof fallback === "string" ? fallback : ""
}

function eventType(input: NormalizeInput): { raw: string; canonical: PlannerEvent["type"] | "" } {
  const raw = (input.event_type ?? input.event ?? "").trim()
  if (!raw) return { raw: "", canonical: "" }
  const key = raw.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_")
  const canonical = ALIAS.get(key) ?? ""
  return { raw, canonical }
}

function objectPayload(input: NormalizeInput): Record<string, unknown> {
  const payload = input.event_payload ?? {}
  if (typeof payload === "object" && payload !== null && !Array.isArray(payload)) {
    return payload as Record<string, unknown>
  }
  return {}
}

function collectText(input: unknown, out: string[]) {
  if (typeof input === "string") {
    out.push(input)
    return
  }
  if (typeof input === "number" || typeof input === "boolean") {
    out.push(String(input))
    return
  }
  if (!input || typeof input !== "object") return
  if (Array.isArray(input)) {
    for (const item of input) collectText(item, out)
    return
  }
  const value = input as Record<string, unknown>
  for (const key of Object.keys(value)) {
    collectText(value[key], out)
  }
}

function workflowActionText(input: string) {
  return /(workflow action|action candidate|approve action|approve endpoint|claim action|claim endpoint|publish action|publish endpoint|verify action|verify endpoint|archive action|archive endpoint|delete action|delete endpoint)/i.test(input)
}

function destructiveActionText(input: string) {
  return /(destructive action|delete action|delete endpoint|archive action|archive endpoint|close action|close endpoint|remove action|remove endpoint)/i.test(input)
}

function inferSignals(raw: string, note: string, payload: Record<string, unknown>) {
  const out = new Set<PlannerSignal>()
  const push = (value: string) => {
    const text = value.toLowerCase()
    if (!text) return
    if (text.includes("waf")) out.add("waf_detected")
    if (/(auth|credential|login|token|cookie|session)/i.test(text)) out.add("auth_obtained")
    if (/(escalat|privilege|admin|root)/i.test(text)) out.add("escalation_found")
    if (/(^|[^a-z])spa([^a-z]|$)|single page|client route|javascript app/i.test(text)) out.add("spa_detected")
    if (/(^|[^a-z])api([^a-z]|$)|\/api\/|graphql|rest endpoint/i.test(text)) out.add("api_app_detected")
    if (workflowActionText(text)) out.add("workflow_actions_mined")
    if (destructiveActionText(text)) out.add("destructive_actions_mined")
  }
  push(raw)
  push(note)
  const items: string[] = []
  collectText(payload, items)
  for (const item of items) push(item)
  const bool = (value: unknown) => (typeof value === "boolean" ? value : undefined)
  if (bool(payload.auth_obtained) === true) out.add("auth_obtained")
  if (bool(payload.waf_detected) === true) out.add("waf_detected")
  if (bool(payload.escalation_found) === true) out.add("escalation_found")
  if (bool(payload.spa_detected) === true) out.add("spa_detected")
  if (bool(payload.api_app_detected) === true) out.add("api_app_detected")
  if (bool(payload.workflow_actions_mined) === true) out.add("workflow_actions_mined")
  if (bool(payload.destructive_actions_mined) === true) out.add("destructive_actions_mined")
  if (typeof payload.action_count === "number" && payload.action_count > 0) out.add("workflow_actions_mined")
  const action = stringValue(payload.action_kind).toLowerCase()
  if (action) out.add("workflow_actions_mined")
  if (["delete", "archive", "close", "remove"].includes(action)) out.add("destructive_actions_mined")
  const target = stringValue(payload.target_state).toLowerCase()
  if (["deleted", "archived", "closed"].includes(target)) out.add("destructive_actions_mined")
  return Array.from(out)
}

export function normalizePlannerEvent(input: NormalizeInput): NormalizeResult {
  const warnings: string[] = []
  const type = eventType(input)
  if (!type.raw) {
    return {
      raw_type: "",
      canonical_type: "",
      warnings,
    }
  }
  if (!type.canonical) {
    throw new Error(`plan_next received unsupported event type: ${type.raw}`)
  }
  if (type.raw.toLowerCase().replaceAll("-", "_").replaceAll(" ", "_") !== type.canonical) {
    warnings.push(`normalized event '${type.raw}' -> '${type.canonical}'`)
  }

  const payload = objectPayload(input)

  if (type.canonical === "reset") {
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: { type: "reset" },
      warnings,
    }
  }

  if (type.canonical === "note_recorded") {
    const note = stringValue(payload.note) || input.event || stringValue(payload.summary) || type.raw
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "note_recorded",
        note,
        signals: inferSignals(type.raw, note, payload),
      },
      warnings,
    }
  }

  if (type.canonical === "scope_set") {
    const target = stringValue(payload.target) || input.target || ""
    if (!target) throw new Error("plan_next requires target for scope_set event")
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "scope_set",
        target,
        scope: scopeValue(payload.scope || input.scope),
      },
      warnings,
    }
  }

  if (type.canonical === "hypothesis_upserted") {
    const hypothesisID = stringValue(payload.hypothesis_id) || input.hypothesis_id || ""
    if (!hypothesisID) throw new Error("plan_next requires hypothesis_id for hypothesis_upserted event")
    const summary = stringValue(payload.summary) || stringValue(payload.statement) || stringValue(payload.predicate)
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "hypothesis_upserted",
        hypothesis_id: hypothesisID,
        summary,
      },
      warnings,
    }
  }

  if (type.canonical === "evidence_recorded") {
    const node = nodeID(payload, input)
    if (!node) throw new Error("plan_next requires node_id for evidence_recorded event")
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "evidence_recorded",
        node_id: node,
        relation: relationValue(payload.relation || payload.signal || payload.link_type),
      },
      warnings,
    }
  }

  if (type.canonical === "verification_recorded") {
    const node = nodeID(payload, input)
    if (!node) throw new Error("plan_next requires node_id for verification_recorded event")
    const passedValue =
      boolValue(payload.passed) ??
      boolValue(payload.success) ??
      boolValue(payload.ok) ??
      boolValue(payload.verified) ??
      false
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "verification_recorded",
        node_id: node,
        passed: passedValue,
      },
      warnings,
    }
  }

  if (type.canonical === "decision_made") {
    const verdict = verdictValue(payload.verdict ?? payload.decision ?? payload.status ?? payload.confirmed)
    const findingID = stringValue(payload.finding_id) || input.finding_id || undefined
    return {
      raw_type: type.raw,
      canonical_type: type.canonical,
      event: {
        type: "decision_made",
        verdict,
        finding_id: findingID,
      },
      warnings,
    }
  }

  const reason = stringValue(payload.reason) || stringValue(payload.note) || "invalidated"
  return {
    raw_type: type.raw,
    canonical_type: "hypothesis_invalidated",
    event: {
      type: "hypothesis_invalidated",
      reason,
    },
    warnings,
  }
}

export function plannerStateOrDefault(input: unknown): PlannerState {
  if (
    input === "idle" ||
    input === "scope_defined" ||
    input === "hypothesis_open" ||
    input === "evidence_collecting" ||
    input === "decision_pending" ||
    input === "closed_positive" ||
    input === "closed_negative"
  ) {
    return input
  }
  return "idle"
}
