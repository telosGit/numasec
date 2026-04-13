import { decodeJwt } from "./scanner/jwt-analyzer"

export interface ActorIdentity {
  label: string
  id: string
  email: string
  role: string
  privileged: boolean
  source: string
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

function header(input: Record<string, string> | undefined, name: string) {
  if (!input) return ""
  const want = name.toLowerCase()
  for (const item of Object.keys(input)) {
    if (item.toLowerCase() !== want) continue
    return input[item] ?? ""
  }
  return ""
}

function bearer(input: Record<string, string> | undefined) {
  const value = header(input, "authorization")
  if (!value.toLowerCase().startsWith("bearer ")) return ""
  return value.slice(7).trim()
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

function cookieID(input: string | undefined) {
  if (!input) return ""
  const match = input.match(/auth-(\d+)/i)
  if (!match?.[1]) return ""
  return match[1]
}

export function inferActorIdentity(input: {
  label: string
  headers?: Record<string, string>
  cookies?: string
  actor_id?: string
  actor_email?: string
  actor_role?: string
}) {
  const token = bearer(input.headers)
  const decoded = token ? decodeJwt(token) : null
  const payload = decoded?.payload ?? {}
  const admin = scan(payload, new Set(["admin", "isadmin", "is_admin"]))
  const id = input.actor_id ?? scan(payload, new Set(["sub", "id", "userid", "user_id"])) ?? ""
  const email = input.actor_email ?? scan(payload, new Set(["email", "mail", "username"])) ?? ""
  const role = input.actor_role ?? (scan(payload, new Set(["role", "roles"])) || (admin === "true" ? "admin" : ""))
  const cookie = cookieID(input.cookies)
  const source = input.actor_id || input.actor_email || input.actor_role ? "explicit" : token ? "jwt" : cookie ? "cookie" : "unknown"
  const actor = {
    label: input.label,
    id: id || cookie,
    email,
    role,
    privileged: /(admin|root|super|staff|support|manager|operator|internal)/i.test(role),
    source,
  } satisfies ActorIdentity
  return actor
}
