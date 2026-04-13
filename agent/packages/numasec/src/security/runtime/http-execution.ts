import type { SessionID } from "../../session/schema"
import { httpRequest, type HttpRequestOptions } from "../http-client"
import {
  classifyHttpFailure,
  type ExecutionFailure,
  type RecoveryTelemetry,
} from "./execution-failure"
import { recordExecutionAttempt } from "./execution-attempt"
import {
  applyTargetProfile,
  noteTargetSignal,
  type TargetExecutionProfile,
} from "./target-profile-store"

export interface HttpExecutionInput {
  sessionID: SessionID
  toolName: string
  action: string
  url: string
  actorSessionID?: string
  request: HttpRequestOptions
  attemptBudget?: number
}

export interface HttpExecutionResult {
  response: Awaited<ReturnType<typeof httpRequest>>
  failure?: ExecutionFailure
  recovery?: RecoveryTelemetry
  profile?: TargetExecutionProfile
}

export async function executeHttpWithRecovery(input: HttpExecutionInput): Promise<HttpExecutionResult> {
  const profile = await applyTargetProfile(input.sessionID, input.url)
  const budget = Math.max(0, input.attemptBudget ?? profile?.retry_budget ?? 1)
  const first = await httpRequest(input.url, input.request)
  const initial = classifyHttpFailure({
    response: first,
    actorSessionID: input.actorSessionID,
  })
  if (initial) {
    await noteTargetSignal(input.sessionID, input.url, initial.code).catch(() => undefined)
  }
  if (!initial) {
    await noteTargetSignal(input.sessionID, input.url, "success").catch(() => undefined)
  }
  await recordExecutionAttempt({
    sessionID: input.sessionID,
    toolName: input.toolName,
    action: input.action,
    status: initial ? "error" : "ok",
    errorCode: initial?.code,
    actorSessionID: input.actorSessionID,
    notes: {
      status: first.status,
      elapsed: first.elapsed,
      url: first.url,
      redirects: first.redirectChain.length,
    },
  }).catch(() => undefined)
  if (!initial) return { response: first, profile }
  if (!initial.retryable || budget <= 0) {
    return {
      response: first,
      failure: initial,
      profile,
    }
  }

  let count = 1
  let failure: ExecutionFailure = initial
  let response = first
  while (count <= budget && failure.retryable && failure.strategy === "retry_same_request") {
    count += 1
    response = await httpRequest(input.url, input.request)
    const next = classifyHttpFailure({
      response,
      actorSessionID: input.actorSessionID,
    })
    if (next) {
      await noteTargetSignal(input.sessionID, input.url, next.code).catch(() => undefined)
    }
    if (!next) {
      await noteTargetSignal(input.sessionID, input.url, "success").catch(() => undefined)
    }
    await recordExecutionAttempt({
      sessionID: input.sessionID,
      toolName: input.toolName,
      action: input.action,
      status: next ? "retry_error" : "recovered",
      errorCode: next?.code ?? "",
      actorSessionID: input.actorSessionID,
      notes: {
        attempt: count,
        status: response.status,
        elapsed: response.elapsed,
        url: response.url,
        redirects: response.redirectChain.length,
        recovery_strategy: initial.strategy,
      },
    }).catch(() => undefined)
    if (!next) {
      return {
        response,
        profile,
        recovery: {
          initial_code: initial.code,
          attempts: count,
          strategy: initial.strategy,
          recovered: true,
        },
      }
    }
    failure = next
  }

  return {
    response,
    failure,
    profile,
    recovery: {
      initial_code: initial.code,
      attempts: count,
      strategy: initial.strategy,
      recovered: false,
    },
  }
}
