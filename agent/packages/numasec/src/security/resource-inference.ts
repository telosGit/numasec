import type { ActorIdentity } from "./actor-inference"

export interface ResourceSummary {
  id: string
  email: string
  role: string
  owner: string
  tenant: string
  creator: string
  state: string
}

export interface ResourceExposure {
  summary: ResourceSummary
  principal: boolean
  self: boolean
  foreign: boolean
}

export interface ResourceInventoryCandidate extends ResourceSummary {
  exposure: "self" | "foreign" | "unknown"
  source: "detail" | "collection"
}

export interface CollectionExposure {
  total: number
  foreign_count: number
  foreign_ids: string[]
  foreign_emails: string[]
  principal: boolean
  sample: string[]
  rows: ResourceSummary[]
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : ""
  return ""
}

function key(input: string) {
  return input.replace(/[^a-z0-9]+/gi, "").toLowerCase()
}

function object(input: unknown) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return
  return input as Record<string, unknown>
}

function scan(input: unknown, names: Set<string>): string {
  if (!input || typeof input !== "object") return ""
  if (Array.isArray(input)) {
    for (const item of input) {
      const value = scan(item, names)
      if (value) return value
    }
    return ""
  }
  const row = input as Record<string, unknown>
  for (const item of Object.keys(row)) {
    if (!names.has(key(item))) continue
    const value = text(row[item])
    if (value) return value
  }
  for (const item of Object.keys(row)) {
    const value = scan(row[item], names)
    if (value) return value
  }
  return ""
}

function list(input: unknown): Array<Record<string, unknown>> {
  if (Array.isArray(input)) {
    return input.map(object).filter((item): item is Record<string, unknown> => !!item)
  }
  const row = object(input)
  if (!row) return []
  const keys = ["data", "items", "results", "rows", "users", "records", "entries"]
  for (const item of keys) {
    const value = row[item]
    if (Array.isArray(value)) {
      return value.map(object).filter((next): next is Record<string, unknown> => !!next)
    }
    const next = object(value)
    if (next) return [next]
  }
  return [row]
}

function summarize(input: Record<string, unknown>) {
  return {
    id: scan(input, new Set(["id", "userid", "user_id", "resourceid", "resource_id"])),
    email: scan(input, new Set(["email", "mail", "username"])),
    role: scan(input, new Set(["role", "roles"])),
    owner: scan(input, new Set(["ownerid", "owner_id", "userid", "user_id", "accountid", "account_id", "memberid", "member_id"])),
    tenant: scan(input, new Set(["tenantid", "tenant_id", "orgid", "org_id", "organizationid", "organization_id"])),
    creator: scan(input, new Set(["createdby", "created_by", "authorid", "author_id"])),
    state: scan(input, new Set(["state", "status"])),
  } satisfies ResourceSummary
}

function principal(input: ResourceSummary) {
  return !!(input.id || input.email || input.owner || input.role || input.tenant || input.creator || input.state)
}

function self(input: ResourceSummary, actor: ActorIdentity) {
  if (actor.email && input.email && input.email.toLowerCase() === actor.email.toLowerCase()) return true
  if (actor.id && input.owner && input.owner === actor.id) return true
  if (actor.id && input.creator && input.creator === actor.id) return true
  if (actor.id && input.id && input.id === actor.id && (input.email || input.role || (!input.owner && !input.creator))) return true
  return false
}

function foreign(input: ResourceSummary, actor: ActorIdentity) {
  if (self(input, actor)) return false
  if (actor.email && input.email && input.email.toLowerCase() !== actor.email.toLowerCase()) return true
  if (actor.id && input.owner && input.owner !== actor.id) return true
  if (actor.id && input.creator && input.creator !== actor.id) return true
  if (actor.id && input.id && input.id !== actor.id && (input.email || input.role || !input.owner || !input.creator)) return true
  return false
}

export function detectCollectionExposure(body: string, actor: ActorIdentity) {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return
  }
  const rows = list(parsed).map(summarize).filter(principal)
  if (rows.length === 0) return
  const foreignRows = rows.filter((item) => foreign(item, actor))
  const sample = foreignRows
    .slice(0, 3)
    .map((item) => item.email || item.owner || item.id || item.role)
    .filter(Boolean)
  return {
    total: rows.length,
    foreign_count: foreignRows.length,
    foreign_ids: foreignRows.map((item) => item.id).filter(Boolean),
    foreign_emails: foreignRows.map((item) => item.email).filter(Boolean),
    principal: rows.some(principal),
    sample,
    rows,
  } satisfies CollectionExposure
}

export function detectResourceExposure(body: string, actor: ActorIdentity) {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return
  }
  const row = list(parsed).map(summarize).find(principal)
  if (!row) return
  return {
    summary: row,
    principal: principal(row),
    self: self(row, actor),
    foreign: foreign(row, actor),
  } satisfies ResourceExposure
}

export function inventoryCandidates(body: string, actor?: ActorIdentity) {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return [] satisfies ResourceInventoryCandidate[]
  }
  const rows = list(parsed).map(summarize).filter(principal)
  const source = rows.length > 1 ? "collection" : "detail"
  return rows.map((row) => {
    const exposure = !actor
      ? "unknown"
      : self(row, actor)
        ? "self"
        : foreign(row, actor)
          ? "foreign"
          : "unknown"
    return {
      ...row,
      exposure,
      source,
    } satisfies ResourceInventoryCandidate
  })
}
