import { describe, expect, test } from "bun:test"
import type { SessionID } from "../../src/session/schema"
import {
  classifyBrowserFailure,
  classifyHttpFailure,
} from "../../src/security/runtime/execution-failure"
import { executeHttpWithRecovery } from "../../src/security/runtime/http-execution"

describe("execution failure taxonomy", () => {
  test("classifies browser origin initialization failures as recoverable", () => {
    const failure = classifyBrowserFailure(
      new Error("SecurityError: Failed to read the 'localStorage' property from 'Window': Access is denied for this document."),
    )

    expect(failure.code).toBe("origin_uninitialized")
    expect(failure.retryable).toBe(true)
    expect(failure.strategy).toBe("reload_last_origin")
  })

  test("classifies browser network resolution failures as transient network errors", () => {
    const failure = classifyBrowserFailure(
      new Error("goto: net::ERR_NAME_NOT_RESOLVED at https://actor.invalid/"),
    )

    expect(failure.code).toBe("transient_network")
    expect(failure.retryable).toBe(true)
    expect(failure.strategy).toBe("reload_requested_url")
  })

  test("classifies HTTP rate limits", () => {
    const failure = classifyHttpFailure({
      response: {
        status: 429,
        statusText: "Too Many Requests",
        headers: {},
        setCookies: [],
        body: "slow down",
        url: "https://app.example.com/api",
        redirectChain: [],
        elapsed: 10,
      },
    })

    expect(failure?.code).toBe("rate_limited")
    expect(failure?.retryable).toBe(false)
  })

  test("classifies WAF fingerprints", () => {
    const failure = classifyHttpFailure({
      response: {
        status: 403,
        statusText: "Forbidden",
        headers: {
          server: "cloudflare",
        },
        setCookies: [],
        body: "Attention Required! | Cloudflare",
        url: "https://app.example.com/api",
        redirectChain: [],
        elapsed: 10,
      },
    })

    expect(failure?.code).toBe("waf_suspected")
    expect(failure?.retryable).toBe(false)
  })

  test("classifies stale authenticated HTTP state", () => {
    const failure = classifyHttpFailure({
      actorSessionID: "ASES-test",
      response: {
        status: 401,
        statusText: "Unauthorized",
        headers: {},
        setCookies: [],
        body: '{"status":"error"}',
        url: "https://app.example.com/api/private",
        redirectChain: [],
        elapsed: 10,
      },
    })

    expect(failure?.code).toBe("auth_stale")
    expect(failure?.retryable).toBe(false)
  })

  test("retries transient network failures once", async () => {
    const server = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch() {
        return new Response("ok")
      },
    })
    const url = server.url.origin + "/offline"
    server.stop(true)

    const result = await executeHttpWithRecovery({
      sessionID: "sess-execution-retry" as SessionID,
      toolName: "test",
      action: "transient",
      url,
      attemptBudget: 1,
      request: {
        method: "GET",
        timeout: 100,
      },
    })

    expect(result.failure?.code).toBe("transient_network")
    expect(result.recovery?.attempts).toBe(2)
    expect(result.recovery?.recovered).toBe(false)
  })
})
