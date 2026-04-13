import z from "zod"
import { Effect } from "effect"
import { Tool } from "../../tool/tool"
import { EvidenceGraphStore } from "../evidence-store"
import {
  DEFAULT_INLINE_BYTES,
  encodeArtifactPayload,
  makeArtifactReference,
  persistEvidenceArtifact,
  shouldPersistArtifact,
} from "../artifact-store"
import { makeToolResultEnvelope } from "./result-envelope"
import { VerificationAssertionInput, VerifyAssertionTool } from "./verify-assertion"

const DESCRIPTION = `Record or upsert one evidence node in the canonical graph.
Use this primitive whenever an observation, artifact, hypothesis, or finding must be persisted.`

function normalizeHeaders(input: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  const keys = Object.keys(input).sort((left, right) => left.localeCompare(right))
  for (const key of keys) {
    out[key.toLowerCase()] = input[key] ?? ""
  }
  return out
}

function replayFromRequest(input: {
  url?: string
  method?: string
  headers?: Record<string, string>
  body?: string
}): string {
  const method = (input.method ?? "GET").toUpperCase()
  const url = input.url ?? ""
  const parts: string[] = [`curl -i -X ${method}`]
  if (url) parts.push(`'${url.replace(/'/g, "'\\''")}'`)
  const headers = input.headers ?? {}
  const names = Object.keys(headers).sort((left, right) => left.localeCompare(right))
  for (const name of names) {
    parts.push(`-H '${name}: ${(headers[name] ?? "").replace(/'/g, "'\\''")}'`)
  }
  if (input.body) {
    parts.push(`--data-raw '${input.body.replace(/'/g, "'\\''")}'`)
  }
  return parts.join(" ")
}

function trimFence(input: string) {
  const value = input.trim()
  const match = /^```[a-z0-9_-]*\s*([\s\S]*?)\s*```$/i.exec(value)
  if (typeof match?.[1] === "string") return match[1].trim()
  return value
}

function tryJson(input: string) {
  try {
    return {
      ok: true,
      value: JSON.parse(input),
      error: "",
    }
  } catch (cause) {
    return {
      ok: false,
      value: undefined,
      error: String(cause),
    }
  }
}

function parseJson(input: string): unknown {
  const value = trimFence(input)
  const direct = tryJson(value)
  if (direct.ok) return direct.value
  const objectStart = value.indexOf("{")
  const objectEnd = value.lastIndexOf("}")
  if (objectStart >= 0 && objectEnd > objectStart) {
    const inner = tryJson(value.slice(objectStart, objectEnd + 1))
    if (inner.ok) return inner.value
  }
  const arrayStart = value.indexOf("[")
  const arrayEnd = value.lastIndexOf("]")
  if (arrayStart >= 0 && arrayEnd > arrayStart) {
    const inner = tryJson(value.slice(arrayStart, arrayEnd + 1))
    if (inner.ok) return inner.value
  }
  throw new Error(`record_evidence payload_json parse failed: ${direct.error || "invalid JSON input"}`)
}

function parsePayload(params: {
  payload?: Record<string, unknown>
  payload_text?: string
  payload_json?: string
}): Record<string, unknown> {
  const base: Record<string, unknown> = {}
  if (params.payload) {
    for (const key of Object.keys(params.payload)) base[key] = params.payload[key]
  }
  if (typeof params.payload_text === "string" && params.payload_text.length > 0) {
    base.payload_text = params.payload_text
  }
  if (typeof params.payload_json === "string" && params.payload_json.length > 0) {
    base.payload_json = parseJson(params.payload_json)
  }
  return base
}

export const RecordEvidenceTool = Tool.define("record_evidence", {
  description: DESCRIPTION,
  parameters: z
    .object({
      type: z.string().describe("Evidence node type: observation, artifact, hypothesis, finding, etc."),
      payload: z.record(z.string(), z.any()).optional().describe("Structured node payload"),
      payload_text: z.string().optional().describe("Raw text payload (ergonomic path for long evidence)"),
      payload_json: z.string().optional().describe("Stringified JSON payload (ergonomic path for long evidence)"),
      request: z
        .object({
          url: z.string().optional(),
          method: z.string().optional(),
          headers: z.record(z.string(), z.string()).optional(),
          body: z.string().optional(),
        })
        .optional()
        .describe("Optional canonical request block"),
      response: z
        .object({
          status: z.number().int().optional(),
          headers: z.record(z.string(), z.string()).optional(),
          body: z.string().optional(),
        })
        .optional()
        .describe("Optional canonical response block"),
      replay: z.string().optional().describe("Optional reproducible replay snippet"),
      hypothesis_id: z.string().optional().describe("Optional hypothesis node id to link from"),
      relation: z.string().optional().describe("Optional relation when linking from hypothesis or parent"),
      parent_node_id: z.string().optional().describe("Optional existing node id to link from"),
      parent_relation: z.string().optional().describe("Optional relation when linking from parent_node_id"),
      fingerprint: z.string().optional().describe("Deterministic fingerprint (auto-generated if omitted)"),
      source_tool: z.string().optional().describe("Tool that produced this evidence"),
      confidence: z.number().min(0).max(1).optional().describe("Confidence score 0..1"),
      status: z.string().optional().describe("Node status, default active"),
      assertions: z.array(VerificationAssertionInput).optional().describe("Optional inline assertions to persist as verification nodes against this evidence"),
      artifact_mode: z
        .enum(["auto", "inline", "external"])
        .optional()
        .describe("Artifact storage mode: auto stores large payloads externally"),
      max_inline_bytes: z.number().int().min(512).max(1024 * 1024).optional().describe("Inline payload size threshold"),
    })
    .refine((item) => {
      if (item.payload) return true
      if (item.payload_text) return true
      if (item.payload_json) return true
      return false
    }, "record_evidence requires payload, payload_text, or payload_json"),
  async execute(params, ctx) {
    const mode = params.artifact_mode ?? "auto"
    const maxInlineBytes = params.max_inline_bytes ?? DEFAULT_INLINE_BYTES
    const payload = parsePayload({
      payload: params.payload,
      payload_text: params.payload_text,
      payload_json: params.payload_json,
    })
    if (params.request) {
      payload.request = {
        url: params.request.url ?? "",
        method: params.request.method ?? "",
        headers: normalizeHeaders(params.request.headers ?? {}),
        body: params.request.body ?? "",
      }
    }
    if (params.response) {
      payload.response = {
        status: params.response.status ?? 0,
        headers: normalizeHeaders(params.response.headers ?? {}),
        body: params.response.body ?? "",
      }
    }
    if (params.replay) payload.replay = params.replay
    if (!params.replay && params.request) payload.replay = replayFromRequest(params.request)
    payload.schema_version = "evidence_payload_v2"

    const payloadText = encodeArtifactPayload(payload)
    const payloadBytes = new TextEncoder().encode(payloadText).length
    const external = shouldPersistArtifact(payloadBytes, mode, maxInlineBytes)

    let artifact: Awaited<ReturnType<typeof persistEvidenceArtifact>> | undefined
    let content = payload
    if (external) {
      artifact = await persistEvidenceArtifact({
        sessionID: ctx.sessionID,
        payload,
        sourceTool: params.source_tool,
      })
      content = makeArtifactReference(artifact)
    }

    const row = Effect.runSync(
      EvidenceGraphStore.use((store) =>
        store.upsertNode({
          sessionID: ctx.sessionID,
          type: params.type,
          payload: content,
          fingerprint: params.fingerprint ?? artifact?.sha256,
          sourceTool: params.source_tool,
          confidence: params.confidence,
          status: params.status,
        }),
      ).pipe(Effect.provide(EvidenceGraphStore.layer)),
    )

    const hypothesisID = params.hypothesis_id ?? ""
    if (hypothesisID) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertEdge({
            sessionID: ctx.sessionID,
            fromNodeID: hypothesisID,
            toNodeID: row.id,
            relation: params.relation ?? "observes",
            weight: 1,
            metadata: {
              source: "record_evidence",
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    const parentNodeID = params.parent_node_id ?? ""
    if (parentNodeID) {
      Effect.runSync(
        EvidenceGraphStore.use((store) =>
          store.upsertEdge({
            sessionID: ctx.sessionID,
            fromNodeID: parentNodeID,
            toNodeID: row.id,
            relation: params.parent_relation ?? params.relation ?? "derives",
            weight: 1,
            metadata: {
              source: "record_evidence",
            },
          }),
        ).pipe(Effect.provide(EvidenceGraphStore.layer)),
      )
    }

    const verificationIDs: string[] = []
    if ((params.assertions ?? []).length > 0) {
      const impl = await VerifyAssertionTool.init()
      for (const item of params.assertions ?? []) {
        const out = await impl.execute(
          {
            predicate: item.predicate,
            mode: item.mode,
            require_all: item.require_all,
            control: item.control,
            typed: item.typed,
            hypothesis_id: params.hypothesis_id,
            evidence_refs: [row.id],
            persist: true,
          } as never,
          ctx,
        )
        const node = String((out.metadata as any).verificationNodeID ?? "")
        if (node) verificationIDs.push(node)
      }
    }

    return {
      title: `Evidence node: ${row.type} (${row.id})`,
      metadata: {
        id: row.id,
        type: row.type,
        status: row.status,
        fingerprint: row.fingerprint,
        payloadBytes,
        artifactID: artifact?.id ?? "",
        artifactStored: external,
        assertionVerificationIDs: verificationIDs,
      } as any,
      envelope: makeToolResultEnvelope({
        status: "ok",
        observations: [
          {
            type: "evidence_node",
            node_id: row.id,
            node_type: row.type,
            status: row.status,
            fingerprint: row.fingerprint,
          },
        ],
        artifacts: artifact
          ? [
              {
                type: "evidence_artifact",
                artifact_id: artifact.id,
                sha256: artifact.sha256,
                size_bytes: artifact.size_bytes,
                mime_type: artifact.mime_type,
                path: artifact.relative_path,
              },
            ]
          : [],
        metrics: {
          payload_bytes: payloadBytes,
          artifact_stored: artifact ? 1 : 0,
          assertions_persisted: verificationIDs.length,
        },
      }),
      output: [
        `Node ID: ${row.id}`,
        `Type: ${row.type}`,
        `Status: ${row.status}`,
        `Fingerprint: ${row.fingerprint}`,
        `Payload bytes: ${payloadBytes}`,
        `Artifact: ${artifact ? `${artifact.id} (${artifact.relative_path})` : "inline"}`,
        `Assertions: ${verificationIDs.length}`,
      ].join("\n"),
    }
  },
})
