import { describe, expect, test } from "bun:test"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SecurityTargetProfileTable } from "../../src/security/runtime/runtime.sql"
import {
  ensureTargetProfile,
  noteTargetSignal,
} from "../../src/security/runtime/target-profile-store"
import { SessionTable } from "../../src/session/session.sql"
import type { SessionID } from "../../src/session/schema"
import { Database, eq } from "../../src/storage/db"

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
        slug: "target-profile-tests",
        directory: "/tmp",
        title: "target-profile-tests",
        version: "1",
      })
      .onConflictDoNothing()
      .run(),
  )
}

describe("target execution profiles", () => {
  test("seeds baseline profiles with a retry budget", async () => {
    const sessionID = "sess-target-profile-baseline" as SessionID
    seedSession(sessionID)

    const profile = await ensureTargetProfile(sessionID, "https://app.example.com/api/projects")

    expect(profile?.origin).toBe("https://app.example.com")
    expect(profile?.status).toBe("baseline")
    expect(profile?.retry_budget).toBe(1)
  })

  test("escalates throttling and blocking signals", async () => {
    const sessionID = "sess-target-profile-signals" as SessionID
    seedSession(sessionID)

    const rate = await noteTargetSignal(sessionID, "https://app.example.com/api/projects", "rate_limited")
    expect(rate?.status).toBe("throttled")
    expect(rate?.pacing_ms).toBeGreaterThanOrEqual(1500)
    expect(rate?.retry_budget).toBe(0)

    const waf = await noteTargetSignal(sessionID, "https://app.example.com/api/projects", "waf_suspected")
    expect(waf?.status).toBe("blocked")
    expect(waf?.browser_preferred).toBe(true)
    expect(waf?.pacing_ms).toBeGreaterThanOrEqual(3000)

    const row = Database.use((db) =>
      db
        .select()
        .from(SecurityTargetProfileTable)
        .where(eq(SecurityTargetProfileTable.id, waf?.id as any))
        .get(),
    )
    expect(row?.last_signal).toBe("waf_suspected")
  })
})
