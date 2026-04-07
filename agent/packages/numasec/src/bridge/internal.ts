/**
 * Internal MCP server registration.
 *
 * Registers the Python numasec MCP server as an internal MCP server
 * (name: "__internal__"). Tools discovered via MCP protocol are exposed
 * with bare names (no prefix) so they match agent permission rules.
 *
 * Health monitoring restarts the server on crash (max 3 times in 60s).
 */
import { MCP } from "@/mcp"
import { ensurePythonEnv } from "./setup"
import { Log } from "@/util/log"
import { Instance } from "@/project/instance"
import type { Config } from "@/config/config"

const log = Log.create({ service: "bridge.internal" })

const SERVER_NAME = "__internal__"
const HEALTH_INTERVAL_MS = 30_000
const MAX_RESTARTS = 3
const RESTART_WINDOW_MS = 60_000
const TOOL_TIMEOUT_MS = 300_000 // 5 min per tool call (scans are slow)

let healthTimer: ReturnType<typeof setInterval> | undefined
let restartTimestamps: number[] = []
let degraded = false
let serverConfig: Config.Mcp | undefined
let registrationPromise: Promise<void> | undefined
let instanceDir: string | undefined

export function isDegraded(): boolean {
  return degraded
}

export function isRegistered(): boolean {
  return registrationPromise !== undefined
}

/**
 * Returns the in-flight registration promise, if any.
 * Call `await waitForRegistration()` before MCP.tools() to avoid
 * a race where tools are resolved before the internal server registers.
 */
export function waitForRegistration(): Promise<void> | undefined {
  return registrationPromise
}

/**
 * Register the Python MCP server as the internal scanner backend.
 * Called lazily on first security tool call or at app startup.
 * Safe to call multiple times — subsequent calls await the first registration.
 */
export async function registerInternalServer(): Promise<void> {
  if (registrationPromise) return registrationPromise
  registrationPromise = doRegisterInternalServer()
  return registrationPromise.catch((error) => {
    registrationPromise = undefined
    throw error
  })
}

async function doRegisterInternalServer(): Promise<void> {
  try {
    instanceDir = Instance.directory

    const env = await ensurePythonEnv()
    log.info("python env ready", { python: env.pythonPath, root: env.projectRoot })

    serverConfig = {
      type: "local" as const,
      command: [env.pythonPath, "-m", "numasec"],
      timeout: TOOL_TIMEOUT_MS,
      environment: { PYTHONUNBUFFERED: "1" },
    }

    const result = await MCP.add(SERVER_NAME, serverConfig)
    const rawStatus = result.status
    const internalStatus = "status" in rawStatus && typeof rawStatus.status === "string"
      ? rawStatus as MCP.Status
      : (rawStatus as Record<string, MCP.Status>)[SERVER_NAME]

    if (internalStatus?.status === "connected") {
      log.info("internal MCP server connected")
      startHealthMonitor()
    } else {
      log.error("internal MCP server failed to connect", { status: internalStatus })
      registrationPromise = undefined
    }
  } catch (error) {
    log.error("failed to register internal MCP server", { error: String(error) })
    registrationPromise = undefined
    throw error
  }
}

/**
 * Shut down the internal MCP server and stop health monitoring.
 */
export async function shutdownInternalServer(): Promise<void> {
  if (healthTimer) {
    clearInterval(healthTimer)
    healthTimer = undefined
  }
  if (registrationPromise) {
    try {
      await MCP.disconnect(SERVER_NAME)
    } catch {
      // ignore
    }
    registrationPromise = undefined
  }
}

function startHealthMonitor(): void {
  if (healthTimer) clearInterval(healthTimer)

  healthTimer = setInterval(async () => {
    if (degraded || !instanceDir) return

    try {
      // Health check runs from setInterval (no active Instance context),
      // so wrap in Instance.provide for MCP.status() to access state.
      await Instance.provide({
        directory: instanceDir,
        fn: async () => {
          const statuses = await MCP.status()
          const internal = statuses[SERVER_NAME]

          if (!internal || internal.status !== "connected") {
            log.warn("internal MCP server not connected, attempting restart", { status: internal })
            await attemptRestart()
          }
        },
      })
    } catch (error) {
      log.warn("health check failed", { error: String(error) })
    }
  }, HEALTH_INTERVAL_MS)
}

async function attemptRestart(): Promise<void> {
  const now = Date.now()
  restartTimestamps = restartTimestamps.filter((t) => now - t < RESTART_WINDOW_MS)
  restartTimestamps.push(now)

  if (restartTimestamps.length > MAX_RESTARTS) {
    log.error("max restarts exceeded, entering degraded mode", {
      restarts: restartTimestamps.length,
      window: RESTART_WINDOW_MS,
    })
    degraded = true
    return
  }

  log.info("restarting internal MCP server", { attempt: restartTimestamps.length })

  try {
    await MCP.disconnect(SERVER_NAME)
  } catch {
    // ignore disconnect errors
  }

  if (!serverConfig || !instanceDir) return

  // Reset registration so a fresh attempt can proceed
  registrationPromise = undefined

  try {
    await Instance.provide({
      directory: instanceDir,
      fn: async () => {
        const result = await MCP.add(SERVER_NAME, serverConfig!)
        const rawStatus = result.status
        const internalStatus = "status" in rawStatus && typeof rawStatus.status === "string"
          ? rawStatus as MCP.Status
          : (rawStatus as Record<string, MCP.Status>)[SERVER_NAME]

        if (internalStatus?.status === "connected") {
          log.info("internal MCP server reconnected")
          registrationPromise = Promise.resolve()
        } else {
          log.error("reconnection failed", { status: internalStatus })
        }
      },
    })
  } catch (error) {
    log.error("restart failed", { error: String(error) })
  }
}
