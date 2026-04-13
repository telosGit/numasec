import z from "zod"
import { eq } from "../../storage/db"
import { Tool } from "../../tool/tool"
import { Database } from "../../storage/db"
import { EvidenceNodeTable } from "../evidence.sql"
import { makeToolResultEnvelope } from "./result-envelope"

function readPayload(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null && !Array.isArray(input)) {
    return input as Record<string, unknown>
  }
  return {}
}

function text(input: unknown) {
  if (typeof input === "string") return input
  if (typeof input === "number") return String(input)
  if (typeof input === "boolean") return input ? "true" : "false"
  return ""
}

function actorKey(input: Record<string, unknown>) {
  return text(input.actor_id) || text(input.actor_email) || text(input.actor_label) || "unknown"
}

export const QueryResourceInventoryTool = Tool.define("query_resource_inventory", {
  description: "Summarize shared actor/resource inventory mined from auth, http, and access-control flows.",
  parameters: z.object({
    actor: z.string().optional().describe("Optional actor filter (matches label, id, email, or role)"),
    exposure: z.enum(["all", "self", "foreign", "unknown"]).optional().describe("Optional resource exposure filter"),
    limit: z.number().int().min(1).max(500).optional().describe("Maximum resource rows to include"),
  }),
  async execute(params, ctx) {
    const rows = Database.use((db) =>
      db
        .select()
        .from(EvidenceNodeTable)
        .where(eq(EvidenceNodeTable.session_id, ctx.sessionID))
        .orderBy(EvidenceNodeTable.time_created)
        .all(),
    )
    const observations = rows.filter((item) => item.type === "observation")
    const actors = observations
      .map((item) => readPayload(item.payload))
      .filter((item) => {
        const family = text(item.family)
        return family === "actor_inventory" || family === "actor_identity"
      })
    const resources = observations
      .map((item) => ({
        node_id: item.id,
        payload: readPayload(item.payload),
      }))
      .filter((item) => text(item.payload.family) === "resource_inventory")

    const actorFilter = (params.actor ?? "").toLowerCase()
    const exposureFilter = params.exposure ?? "all"
    const actorMap = new Map<string, Record<string, unknown>>()
    for (const actor of actors) {
      if (actorFilter) {
        const haystack = [
          text(actor.actor_label),
          text(actor.actor_id),
          text(actor.actor_email),
          text(actor.actor_role),
        ].join(" ").toLowerCase()
        if (!haystack.includes(actorFilter)) continue
      }
      actorMap.set(actorKey(actor), actor)
    }

    const filtered = resources.filter((item) => {
      const payload = item.payload
      if (actorFilter) {
        const haystack = [
          text(payload.actor_label),
          text(payload.actor_id),
          text(payload.actor_email),
          text(payload.actor_role),
        ].join(" ").toLowerCase()
        if (!haystack.includes(actorFilter)) return false
      }
      if (exposureFilter !== "all" && text(payload.exposure) !== exposureFilter) return false
      return true
    }).slice(0, params.limit ?? 200)

    const byActor = new Map<string, {
      actor_label: string
      actor_id: string
      actor_email: string
      actor_role: string
      own_values: Set<string>
      foreign_values: Set<string>
      unknown_values: Set<string>
      endpoints: Set<string>
      actions: Map<string, {
        url: string
        method: string
        action_kind: string
        target_state: string
        resource_url: string
        source_kind: string
        submit_label: string
        action_label: string
        request_content_type: string
        request_body: string
      }>
    }>()
    let actions = 0

    for (const item of filtered) {
      const payload = item.payload
      const key = actorKey(payload)
      const current = byActor.get(key) ?? {
        actor_label: text(payload.actor_label),
        actor_id: text(payload.actor_id),
        actor_email: text(payload.actor_email),
        actor_role: text(payload.actor_role),
        own_values: new Set<string>(),
        foreign_values: new Set<string>(),
        unknown_values: new Set<string>(),
        endpoints: new Set<string>(),
        actions: new Map(),
      }
      current.endpoints.add(text(payload.url))
      const value = text(payload.resource_id) || text(payload.resource_email) || text(payload.owner_id)
      if (value) {
        if (text(payload.exposure) === "self") current.own_values.add(value)
        if (text(payload.exposure) === "foreign") current.foreign_values.add(value)
        if (text(payload.exposure) === "unknown") current.unknown_values.add(value)
      }
      const action = text(payload.action_kind)
      if (action) {
        const id = `${text(payload.method)} ${text(payload.url)}`
        if (!current.actions.has(id)) {
          current.actions.set(id, {
            url: text(payload.url),
            method: text(payload.method),
            action_kind: action,
            target_state: text(payload.action_target_state),
            resource_url: text(payload.resource_url),
            source_kind: text(payload.source_kind),
            submit_label: text(payload.submit_label),
            action_label: text(payload.action_label),
            request_content_type: text(payload.request_content_type),
            request_body: text(payload.request_body),
          })
          actions += 1
        }
      }
      byActor.set(key, current)
    }

    const actorsOut = Array.from(actorMap.values()).map((item) => ({
      actor_label: text(item.actor_label),
      actor_id: text(item.actor_id),
      actor_email: text(item.actor_email),
      actor_role: text(item.actor_role),
      privileged: item.privileged === true,
      source: text(item.source),
    }))
    const resourcesOut = filtered.map((item) => ({
      node_id: item.node_id,
      actor_label: text(item.payload.actor_label),
      actor_id: text(item.payload.actor_id),
      actor_email: text(item.payload.actor_email),
      actor_role: text(item.payload.actor_role),
      url: text(item.payload.url),
      method: text(item.payload.method),
      source_kind: text(item.payload.source_kind),
      exposure: text(item.payload.exposure),
      resource_id: text(item.payload.resource_id),
      resource_email: text(item.payload.resource_email),
      owner_id: text(item.payload.owner_id),
      tenant_id: text(item.payload.tenant_id),
      creator_id: text(item.payload.creator_id),
      resource_role: text(item.payload.resource_role),
      resource_state: text(item.payload.resource_state),
      action_kind: text(item.payload.action_kind),
      action_target_state: text(item.payload.action_target_state),
      resource_url: text(item.payload.resource_url),
      request_content_type: text(item.payload.request_content_type),
      request_body: text(item.payload.request_body),
      action_label: text(item.payload.action_label),
      form_enctype: text(item.payload.form_enctype),
      form_body: text(item.payload.form_body),
      submit_label: text(item.payload.submit_label),
    }))
    const actorGroups = Array.from(byActor.values()).map((item) => ({
      actor_label: item.actor_label,
      actor_id: item.actor_id,
      actor_email: item.actor_email,
      actor_role: item.actor_role,
      own_values: Array.from(item.own_values),
      foreign_values: Array.from(item.foreign_values),
      unknown_values: Array.from(item.unknown_values),
      endpoints: Array.from(item.endpoints),
      actions: Array.from(item.actions.values()),
    }))

    return {
      title: `Resource inventory: ${resourcesOut.length} candidates`,
      metadata: {
        actorCount: actorsOut.length,
        resourceCount: resourcesOut.length,
        actorGroups: actorGroups.length,
        actionCount: actions,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "resource_inventory_query",
            actor_count: actorsOut.length,
            resource_count: resourcesOut.length,
            actor_groups: actorGroups.length,
            action_count: actions,
          },
        ],
        metrics: {
          actor_count: actorsOut.length,
          resource_count: resourcesOut.length,
          actor_groups: actorGroups.length,
          action_count: actions,
        },
      }),
      output: [
        `Actors: ${actorsOut.length}`,
        `Resource candidates: ${resourcesOut.length}`,
        `Actor groups: ${actorGroups.length}`,
        "",
        JSON.stringify(
          {
            actors: actorsOut,
            by_actor: actorGroups,
            resources: resourcesOut,
          },
          null,
          2,
        ),
      ].join("\n"),
    }
  },
})
