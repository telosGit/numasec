import { describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { SessionID, MessageID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { EvidenceNodeTable } from "../../src/security/evidence.sql"
import {
  SecurityActorSessionTable,
  SecurityTargetProfileTable,
} from "../../src/security/runtime/runtime.sql"
import { SessionTable } from "../../src/session/session.sql"
import { Database } from "../../src/storage/db"
import { normalizePlannerEvent } from "../../src/security/planner/event-normalizer"
import { PlanNextTool } from "../../src/security/tool/plan-next"

function seedSession(sessionID: SessionID) {
  const projectID = ProjectID.make(`project-${sessionID}`)
  Database.use((db) =>
    db
      .insert(ProjectTable)
      .values({
        id: projectID,
        worktree: "/tmp",
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
        slug: "plan-next-tests",
        directory: "/tmp",
        title: "plan-next-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runPlanNext(args: Record<string, unknown>, sessionID = "sess-plan-next-policy" as SessionID) {
  seedSession(sessionID)
  const impl = await PlanNextTool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("plan_next tool policy integration", () => {
  test("returns policy primitive sequence with deep scope signals", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-1",
      policy_signals: ["api_app_detected", "waf_detected", "spa_detected"],
      primitive_budget: 4,
      remaining_seconds: 1200,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect((out.metadata as any).policyPrimitives).toContain("mutate_input")
    expect(out.output).toContain("Policy sequence:")
  })

  test("caps policy queue in quick scope", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "quick",
      hypothesis_id: "hyp-2",
      policy_signals: ["api_app_detected", "waf_detected"],
      primitive_budget: 4,
      remaining_seconds: 180,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect(((out.metadata as any).policyPrimitives as string[]).length).toBe(1)
    expect(out.output).toContain("Budget:")
  })

  test("surfaces authenticated authz coverage primitives after auth signal", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-auth-1",
      policy_signals: ["auth_obtained", "spa_detected"],
      primitive_budget: 4,
      remaining_seconds: 1200,
    })

    expect((out.metadata as any).primitive).toBe("observe_surface")
    expect((out.metadata as any).policyPrimitives).toContain("access_control_test")
    expect((out.metadata as any).policyPrimitives).toContain("browser")
  })

  test("accepts workflow action prioritization signals", async () => {
    const out = await runPlanNext({
      state: "hypothesis_open",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-auth-workflow-action",
      policy_signals: ["auth_obtained", "spa_detected", "workflow_actions_mined", "destructive_actions_mined"],
      primitive_budget: 4,
      remaining_seconds: 1200,
    })

    expect((out.metadata as any).policyPrimitives).toContain("query_resource_inventory")
    expect((out.metadata as any).policyPrimitives).toContain("access_control_test")
    expect((out.metadata as any).carriedSignals).toContain("workflow_actions_mined")
    expect((out.metadata as any).carriedSignals).toContain("destructive_actions_mined")
  })

  test("normalizes alias event names and uses top-level fallback fields", async () => {
    const out = await runPlanNext({
      state: "scope_defined",
      target: "https://example.com",
      scope: "standard",
      hypothesis_id: "hyp-9",
      event: "hypothesis",
      event_payload: {
        statement: "IDOR hypothesis",
      },
    })

    expect((out.metadata as any).eventRaw).toBe("hypothesis")
    expect((out.metadata as any).eventCanonical).toBe("hypothesis_upserted")
    expect(out.output).toContain("Event: hypothesis -> hypothesis_upserted")
  })

  test("accepts hypothesis_open alias used by interactive runs", async () => {
    const out = await runPlanNext({
      state: "scope_defined",
      target: "https://example.com",
      scope: "deep",
      hypothesis_id: "hyp-11",
      event_type: "hypothesis_open",
      event_payload: {
        statement: "Auth bypass hypothesis",
      },
    })

    expect((out.metadata as any).eventCanonical).toBe("hypothesis_upserted")
    expect(out.output).toContain("Event: hypothesis_open -> hypothesis_upserted")
  })

  test("accepts event_payload_json and decision aliases", async () => {
    const out = await runPlanNext({
      state: "decision_pending",
      target: "https://example.com",
      scope: "standard",
      finding_id: "SSEC-123",
      event_type: "verdict",
      event_payload_json: JSON.stringify({
        confirmed: true,
      }),
    })

    expect((out.metadata as any).eventCanonical).toBe("decision_made")
    expect(out.output).toContain("Event: verdict -> decision_made")
    expect((out.metadata as any).state).toBe("closed_positive")
  })

  test("does not coerce ambiguous verification strings into pass", () => {
    const out = normalizePlannerEvent({
      event_type: "verification",
      event_payload: {
        node_id: "node-ambiguous",
        passed: "ok",
      },
    })

    expect(out.canonical_type).toBe("verification_recorded")
    expect(out.event).toEqual({
      type: "verification_recorded",
      node_id: "node-ambiguous",
      passed: false,
    })
  })

  test("accepts descriptive surface events without breaking planner flow", async () => {
    const out = await runPlanNext(
      {
        state: "scope_defined",
        target: "https://example.com",
        scope: "deep",
        event_type: "surface_observed",
        event: "Observed surface with recon, crawl, dir_fuzz, js",
      },
      "sess-plan-next-surface" as SessionID,
    )

    expect((out.metadata as any).eventCanonical).toBe("note_recorded")
    expect((out.metadata as any).state).toBe("scope_defined")
    expect((out.metadata as any).primitive).toBe("upsert_hypothesis")
  })

  test("carries forward persisted auth state and signals across empty follow-up calls", async () => {
    const sessionID = "sess-plan-next-carry-forward" as SessionID
    const first = await runPlanNext(
      {
        state: "hypothesis_open",
        target: "https://example.com",
        scope: "deep",
        hypothesis_id: "hyp-auth-carry",
        event_type: "evidence_collected",
        event: "Authentication token obtained via default credentials",
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
      sessionID,
    )

    expect((first.metadata as any).eventCanonical).toBe("note_recorded")
    expect((first.metadata as any).policyPrimitives).toContain("query_resource_inventory")
    expect((first.metadata as any).carriedSignals).toContain("auth_obtained")

    const second = await runPlanNext(
      {
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
      sessionID,
    )

    expect((second.metadata as any).state).toBe("hypothesis_open")
    expect((second.metadata as any).hypothesis).toBe("hyp-auth-carry")
    expect((second.metadata as any).policyPrimitives).toContain("query_resource_inventory")
    expect((second.metadata as any).policyPrimitives).toContain("access_control_test")
    expect((second.metadata as any).carriedSignals).toContain("auth_obtained")
  })

  test("infers workflow action signals from descriptive notes", async () => {
    const out = await runPlanNext(
      {
        state: "hypothesis_open",
        target: "https://example.com",
        scope: "deep",
        hypothesis_id: "hyp-workflow-note",
        event_type: "note",
        event: "Resource inventory found delete action candidate on /api/Projects/7/delete",
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
      "sess-plan-next-workflow-note" as SessionID,
    )

    expect((out.metadata as any).eventCanonical).toBe("note_recorded")
    expect((out.metadata as any).carriedSignals).toContain("workflow_actions_mined")
    expect((out.metadata as any).carriedSignals).toContain("destructive_actions_mined")
    expect((out.metadata as any).policyPrimitives).toContain("access_control_test")
  })

  test("derives planner runtime signals from actor sessions, target profiles, and browser network actions", async () => {
    const sessionID = "sess-plan-next-runtime" as SessionID
    seedSession(sessionID)
    Database.use((db) =>
      db
        .insert(SecurityActorSessionTable)
        .values({
          id: "ASES-runtime" as any,
          session_id: sessionID,
          actor_label: "primary",
          browser_session_id: "" as any,
          status: "active",
          last_origin: "https://example.com",
          last_url: "https://example.com/app",
          material_summary: {
            actor_id: "7",
            actor_email: "user@example.com",
            header_keys: ["authorization"],
            cookie_names: ["session"],
          },
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(SecurityTargetProfileTable)
        .values({
          id: "TPRF-runtime" as any,
          session_id: sessionID,
          origin: "https://example.com",
          status: "blocked",
          concurrency_budget: 1,
          pacing_ms: 3000,
          jitter_ms: 750,
          retry_budget: 0,
          browser_preferred: true,
          last_signal: "waf_suspected",
          notes: {},
        })
        .run(),
    )
    Database.use((db) =>
      db
        .insert(EvidenceNodeTable)
        .values({
          id: "ENOD-runtime-network" as any,
          session_id: sessionID,
          type: "observation",
          fingerprint: "runtime-network-observation",
          status: "active",
          confidence: 0.8,
          payload: {
            family: "resource_inventory",
            source_kind: "browser_network",
            action_kind: "delete",
            action_target_state: "deleted",
            url: "https://example.com/api/projects/7/delete",
          },
          source_tool: "browser",
        })
        .run(),
    )

    const out = await runPlanNext(
      {
        state: "hypothesis_open",
        target: "https://example.com",
        scope: "deep",
        hypothesis_id: "hyp-runtime",
        primitive_budget: 4,
        remaining_seconds: 1200,
      },
      sessionID,
    )

    expect((out.metadata as any).carriedSignals).toContain("auth_obtained")
    expect((out.metadata as any).carriedSignals).toContain("waf_detected")
    expect((out.metadata as any).carriedSignals).toContain("workflow_actions_mined")
    expect((out.metadata as any).carriedSignals).toContain("destructive_actions_mined")
    expect((out.metadata as any).runtimeActorSessions).toBe(1)
    expect((out.metadata as any).runtimeTargetProfiles).toBe(1)
    expect((out.metadata as any).runtimeNetworkActions).toBe(1)
    expect(out.output).toContain("Runtime: actor_sessions=1, target_profiles=1, network_actions=1")
  })
})
