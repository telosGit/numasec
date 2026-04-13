import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { ProjectTable } from "../../src/project/project.sql"
import { ProjectID } from "../../src/project/schema"
import { SessionTable } from "../../src/session/session.sql"
import { Database, eq } from "../../src/storage/db"
import { FindingTable } from "../../src/security/security.sql"
import { ingestToolEnvelope } from "../../src/security/envelope-ingestor"
import { buildBrowserInventoryEnvelope, type BrowserInventorySnapshot } from "../../src/security/tool/browser"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"
import { ProjectFindingsTool } from "../../src/security/tool/project-findings"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

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
        slug: "authz-world-model-tests",
        directory: "/tmp",
        title: "authz-world-model-tests",
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

async function runTool(tool: Tool.Info, args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await tool.init()
  const out = await impl.execute(args as never, toolContext(sessionID))
  const envelope = out.envelope as Record<string, unknown> | undefined
  if (envelope) {
    await ingestToolEnvelope({
      sessionID,
      tool: tool.id,
      title: out.title,
      metadata: typeof out.metadata === "object" && out.metadata && !Array.isArray(out.metadata) ? out.metadata as Record<string, unknown> : {},
      envelope: envelope as any,
    })
  }
  return out
}

describe("actor-aware authz projection", () => {
  test("projects collection exposure as a verified IDOR finding", async () => {
    const sessionID = "sess-authz-world-model" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Users`,
        test_type: "idor",
        headers: {
          authorization: `Bearer ${app.tokenFor(body.data.id)}`,
        },
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "idor" && item.state === "verified" && item.root_cause_key.includes("collection"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("collection")
  })

  test("projects foreign mutation on owner-backed resources as a verified IDOR finding", async () => {
    const sessionID = "sess-authz-world-model-mutation" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-mutation@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "owned-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/{id}`,
        test_type: "idor",
        parameter: "id",
        method: "PUT",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          state: "approved",
        }),
        id_values: [String(projectBody.data.id), "1"],
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "idor" && item.state === "verified" && item.root_cause_key.includes("foreign_resource_mutation"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("mutation")
  })

  test("projects restricted workflow transitions as verified workflow findings", async () => {
    const sessionID = "sess-authz-world-model-workflow" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-workflow@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "workflow-owned-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/{id}`,
        test_type: "idor",
        parameter: "id",
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          state: "approved",
        }),
        id_values: [String(projectBody.data.id)],
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "workflow" && item.state === "verified" && item.root_cause_key.includes("restricted_state_transition"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("state")
  })

  test("projects archived workflow transitions as verified workflow findings", async () => {
    const sessionID = "sess-authz-world-model-workflow-archive" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-workflow-archive@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "workflow-archived-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/{id}`,
        test_type: "idor",
        parameter: "id",
        method: "PATCH",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          state: "archived",
        }),
        id_values: [String(projectBody.data.id)],
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "workflow" && item.state === "verified" && item.root_cause_key.includes("archived"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("state")
  })

  test("replays browser-mined workflow actions into verified workflow findings", async () => {
    const sessionID = "sess-authz-world-model-browser-action" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-browser-action@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "workflow-browser-action-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    const snapshot: BrowserInventorySnapshot = {
      page_url: `${app.baseUrl}/app/projects/${projectBody.data.id}`,
      page_title: "Project detail",
      headers: {
        authorization: `Bearer ${token}`,
      },
      cookies: [],
      forms: [
        {
          action: `${app.baseUrl}/api/Projects/${projectBody.data.id}/approve`,
          method: "POST",
          fields: [
            {
              name: "confirm",
              value: "1",
              type: "hidden",
            },
          ],
          submit_label: "Approve project",
        },
      ],
      resources: [`${app.baseUrl}/api/Projects/${projectBody.data.id}`],
    }

    await ingestToolEnvelope({
      sessionID,
      tool: "browser",
      title: "Project detail",
      metadata: {},
      envelope: buildBrowserInventoryEnvelope(snapshot),
    })

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/${projectBody.data.id}/approve`,
        test_type: "workflow",
        headers: {
          authorization: `Bearer ${token}`,
        },
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "workflow" && item.state === "verified" && item.root_cause_key.includes("restricted_action_transition"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("action")
  })

  test("replays browser-mined button actions with JSON bodies into verified workflow findings", async () => {
    const sessionID = "sess-authz-world-model-browser-button" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-browser-button@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "workflow-browser-button-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    const snapshot: BrowserInventorySnapshot = {
      page_url: `${app.baseUrl}/app/projects/${projectBody.data.id}`,
      page_title: "Project detail",
      headers: {
        authorization: `Bearer ${token}`,
      },
      cookies: [],
      actions: [
        {
          url: `${app.baseUrl}/api/Projects/${projectBody.data.id}/archive`,
          method: "POST",
          source_kind: "browser_button",
          content_type: "application/json",
          body: JSON.stringify({
            confirm: true,
          }),
          label: "Archive project",
        },
      ],
      resources: [`${app.baseUrl}/api/Projects/${projectBody.data.id}`],
    }

    await ingestToolEnvelope({
      sessionID,
      tool: "browser",
      title: "Project archive button",
      metadata: {},
      envelope: buildBrowserInventoryEnvelope(snapshot),
    })

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/${projectBody.data.id}/archive`,
        test_type: "workflow",
        headers: {
          authorization: `Bearer ${token}`,
        },
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "workflow" && item.state === "verified" && item.root_cause_key.includes("archived"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("action")
  })

  test("replays browser-mined delete actions into verified destructive workflow findings", async () => {
    const sessionID = "sess-authz-world-model-browser-delete" as SessionID
    seedSession(sessionID)

    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "world-model-browser-delete@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const token = app.tokenFor(body.data.id)

    const project = await fetch(`${app.baseUrl}/api/Projects`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "workflow-browser-delete-resource",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    const snapshot: BrowserInventorySnapshot = {
      page_url: `${app.baseUrl}/app/projects/${projectBody.data.id}`,
      page_title: "Project detail",
      headers: {
        authorization: `Bearer ${token}`,
      },
      cookies: [],
      forms: [
        {
          action: `${app.baseUrl}/api/Projects/${projectBody.data.id}/delete`,
          method: "POST",
          fields: [
            {
              name: "confirm",
              value: "1",
              type: "hidden",
            },
          ],
          submit_label: "Delete project",
        },
      ],
      resources: [`${app.baseUrl}/api/Projects/${projectBody.data.id}`],
    }

    await ingestToolEnvelope({
      sessionID,
      tool: "browser",
      title: "Project delete detail",
      metadata: {},
      envelope: buildBrowserInventoryEnvelope(snapshot),
    })

    await runTool(
      AccessControlTestTool,
      {
        url: `${app.baseUrl}/api/Projects/${projectBody.data.id}/delete`,
        test_type: "workflow",
        headers: {
          authorization: `Bearer ${token}`,
        },
      },
      sessionID,
    )
    await runTool(ProjectFindingsTool, {}, sessionID)

    const rows = Database.use((db) =>
      db
        .select()
        .from(FindingTable)
        .where(eq(FindingTable.session_id, sessionID))
        .all(),
    )
    const hit = rows.find((item) => item.family === "workflow" && item.state === "verified" && item.root_cause_key.includes("destructive_action_transition"))
    expect(hit).toBeDefined()
    expect(hit?.title.toLowerCase()).toContain("delete")
  })
})
