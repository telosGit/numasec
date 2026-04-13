import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import type { Tool } from "../../src/tool/tool"
import type { MessageID, SessionID } from "../../src/session/schema"
import { AccessControlTestTool } from "../../src/security/tool/access-control-test"
import { startSecurityTarget, type SecurityTargetFixture } from "../fixture/security-target"

let app: SecurityTargetFixture

beforeAll(() => {
  app = startSecurityTarget()
})

afterAll(() => {
  app.stop()
})

function toolContext(sessionID: SessionID): Tool.Context {
  return {
    sessionID,
    messageID: `msg-${sessionID}` as MessageID,
    agent: "test",
    abort: new AbortController().signal,
    callID: "call-access-control-differential-test",
    extra: {},
    messages: [],
    metadata() {},
    ask: async () => {},
  }
}

async function runTool(args: Record<string, unknown>, sessionID: SessionID) {
  const impl = await AccessControlTestTool.init()
  return impl.execute(args as never, toolContext(sessionID))
}

describe("access_control_test differential IDOR", () => {
  test("flags single-actor foreign resource access when a user can read a known foreign record", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "single-idor@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const out = await runTool(
      {
        url: `${app.baseUrl}/api/Users/{id}`,
        test_type: "idor",
        parameter: "id",
        headers: {
          authorization: `Bearer ${app.tokenFor(body.data.id)}`,
        },
        id_values: [String(body.data.id), "1"],
      },
      "sess-access-idor-single" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("known foreign resource access confirmed")
    expect(JSON.stringify(out.envelope)).toContain("foreign_resource_access")
  })

  test("flags cross-actor path access when both actors can read each other's resource", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "idor-user@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }
    const regTwo = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "idor-user-two@example.com",
        password: "Test12345!",
      }),
    })
    expect(regTwo.status).toBe(201)
    const bodyTwo = (await regTwo.json()) as {
      data: {
        id: number
      }
    }
    const userID = String(body.data.id)
    const foreignID = String(bodyTwo.data.id)

    const out = await runTool(
      {
        url: `${app.baseUrl}/api/Users/{id}`,
        test_type: "idor",
        parameter: "id",
        headers: {
          authorization: `Bearer ${app.tokenFor(body.data.id)}`,
        },
        secondary_headers: {
          authorization: `Bearer ${app.tokenFor(bodyTwo.data.id)}`,
        },
        id_values: [userID, foreignID],
      },
      "sess-access-idor-diff" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("cross-actor access confirmed")
    expect(JSON.stringify(out.envelope)).toContain("cross_actor_access")
  })

  test("flags collection exposure when a low-privilege actor sees foreign user records", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "collection-idor@example.com",
        password: "Test12345!",
      }),
    })
    expect(reg.status).toBe(201)
    const body = (await reg.json()) as {
      data: {
        id: number
      }
    }

    const out = await runTool(
      {
        url: `${app.baseUrl}/api/Users`,
        test_type: "idor",
        headers: {
          authorization: `Bearer ${app.tokenFor(body.data.id)}`,
        },
      },
      "sess-access-idor-collection" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("collection exposure confirmed")
    expect(JSON.stringify(out.envelope)).toContain("collection_foreign_records")
  })

  test("flags foreign mutation when a low-privilege actor updates another actor's owned resource", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "mutation-idor@example.com",
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
        name: "user-project",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    const out = await runTool(
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
      "sess-access-idor-mutation" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("foreign resource mutation confirmed")
    expect(JSON.stringify(out.envelope)).toContain("foreign_resource_mutation")
  })

  test("flags restricted workflow transitions when a low-privilege actor advances their own resource state", async () => {
    const reg = await fetch(`${app.baseUrl}/api/Users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email: "workflow-owner@example.com",
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
        name: "workflow-project",
      }),
    })
    expect(project.status).toBe(201)
    const projectBody = (await project.json()) as {
      data: {
        id: number
      }
    }

    const out = await runTool(
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
      "sess-access-workflow-transition" as SessionID,
    )

    expect((out.metadata as any).findings).toBeGreaterThanOrEqual(1)
    expect(out.output).toContain("Workflow abuse")
    expect(JSON.stringify(out.envelope)).toContain("restricted_state_transition")
  })
})
