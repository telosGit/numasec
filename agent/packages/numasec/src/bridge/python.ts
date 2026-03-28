import { spawn, type ChildProcess } from "child_process"
import { Log } from "../util/log"
import { ulid } from "ulid"
import readline from "readline"
import { ensurePythonEnv } from "./setup"

const log = Log.create({ service: "python-bridge" })

const HEALTH_INTERVAL_MS = 30_000
const HEALTH_TIMEOUT_MS = 5_000
const MAX_RESTARTS = 3
const RESTART_WINDOW_MS = 60_000
const RESTART_DELAY_MS = 1_000

interface PendingCall {
  resolve: (value: any) => void
  reject: (reason: any) => void
  timer: ReturnType<typeof setTimeout>
}

interface JsonRpcRequest {
  id: string
  method: string
  params: Record<string, any>
}

interface JsonRpcResponse {
  id: string
  result?: any
  error?: { message: string; code?: number; data?: any }
}

export type WorkerStatus = {
  healthy: boolean
  pid: number | null
  restartCount: number
  lastPing: number
  degraded: boolean
}

export class PythonBridge {
  private static _instance: PythonBridge | null = null
  private process: ChildProcess | null = null
  private pending = new Map<string, PendingCall>()
  private ready = false
  private startPromise: Promise<void> | null = null
  private pythonPath: string | null = null
  private readonly defaultTimeout = 300_000 // 5 min per call

  // Health monitoring state
  private healthTimer: ReturnType<typeof setInterval> | null = null
  private healthy = false
  private lastPing = 0
  private degraded = false
  private restartCount = 0
  private restartTimestamps: number[] = []
  private restarting = false

  static instance(): PythonBridge {
    if (!PythonBridge._instance) {
      PythonBridge._instance = new PythonBridge()
    }
    return PythonBridge._instance
  }

  getStatus(): WorkerStatus {
    return {
      healthy: this.healthy,
      pid: this.process?.pid ?? null,
      restartCount: this.restartCount,
      lastPing: this.lastPing,
      degraded: this.degraded,
    }
  }

  async start(): Promise<void> {
    if (this.ready) return
    if (this.startPromise) return this.startPromise

    this.startPromise = this._start()
    return this.startPromise
  }

  private async _start(): Promise<void> {
    const env = await ensurePythonEnv()
    this.pythonPath = env.pythonPath

    log.info("starting python bridge", { python: this.pythonPath, cwd: env.projectRoot })

    this.process = spawn(this.pythonPath, ["-m", "numasec.worker"], {
      cwd: env.projectRoot,
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        PYTHONUNBUFFERED: "1",
      },
    })

    this.process.on("exit", (code, signal) => {
      log.warn("python worker exited", { code, signal })
      this.ready = false
      this.healthy = false
      this.startPromise = null
      this.stopHealthCheck()
      // Reject all pending calls
      for (const [, pending] of this.pending) {
        clearTimeout(pending.timer)
        pending.reject(new Error(`Python worker exited with code ${code}`))
      }
      this.pending.clear()
      // Trigger auto-restart unless already restarting or degraded
      if (!this.restarting && !this.degraded) {
        this.scheduleRestart()
      }
    })

    this.process.on("error", (err) => {
      log.error("python worker error", { error: err.message })
      this.ready = false
      this.healthy = false
      this.startPromise = null
      this.stopHealthCheck()
      if (!this.restarting && !this.degraded) {
        this.scheduleRestart()
      }
    })

    // Read stderr for logging
    if (this.process.stderr) {
      const stderrReader = readline.createInterface({ input: this.process.stderr })
      stderrReader.on("line", (line) => {
        log.debug("python worker stderr", { line })
      })
    }

    // Read stdout for JSON-RPC responses
    if (this.process.stdout) {
      const stdoutReader = readline.createInterface({ input: this.process.stdout })
      stdoutReader.on("line", (line) => {
        try {
          const response: JsonRpcResponse = JSON.parse(line)
          const pending = this.pending.get(response.id)
          if (!pending) {
            log.warn("received response for unknown request", { id: response.id })
            return
          }
          this.pending.delete(response.id)
          clearTimeout(pending.timer)
          if (response.error) {
            pending.reject(new Error(response.error.message))
          } else {
            pending.resolve(response.result)
          }
        } catch (e) {
          log.debug("non-json output from worker", { line })
        }
      })
    }

    // Wait for the worker to signal it's ready
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Python worker failed to start within 30s"))
      }, 30_000)

      const checkReady = (line: string) => {
        try {
          const msg = JSON.parse(line)
          if (msg.ready === true) {
            clearTimeout(timeout)
            this.ready = true
            resolve()
          }
        } catch {
          // Not JSON, ignore
        }
      }

      if (this.process?.stdout) {
        const reader = readline.createInterface({ input: this.process.stdout })
        reader.on("line", (rawLine) => {
          checkReady(rawLine)
          try {
            const response: JsonRpcResponse = JSON.parse(rawLine)
            const pending = this.pending.get(response.id)
            if (pending) {
              this.pending.delete(response.id)
              clearTimeout(pending.timer)
              if (response.error) {
                pending.reject(new Error(response.error.message))
              } else {
                pending.resolve(response.result)
              }
            }
          } catch {
            // Not JSON-RPC
          }
        })
      }
    })

    this.healthy = true
    this.lastPing = Date.now()
    this.startHealthCheck()
    log.info("python bridge ready")
  }

  private startHealthCheck(): void {
    this.stopHealthCheck()
    this.healthTimer = setInterval(() => {
      this.pingWorker()
    }, HEALTH_INTERVAL_MS)
  }

  private stopHealthCheck(): void {
    if (this.healthTimer) {
      clearInterval(this.healthTimer)
      this.healthTimer = null
    }
  }

  private async pingWorker(): Promise<void> {
    if (!this.ready || !this.process) return

    try {
      const id = ulid()
      const request: JsonRpcRequest = { id, method: "ping", params: {} }
      const result = await new Promise<any>((resolve, reject) => {
        const timer = setTimeout(() => {
          this.pending.delete(id)
          reject(new Error("Health check timed out"))
        }, HEALTH_TIMEOUT_MS)

        this.pending.set(id, { resolve, reject, timer })

        const line = JSON.stringify(request) + "\n"
        this.process?.stdin?.write(line, (err) => {
          if (err) {
            this.pending.delete(id)
            clearTimeout(timer)
            reject(new Error(`Health check write failed: ${err.message}`))
          }
        })
      })

      const parsed = typeof result === "string" ? JSON.parse(result) : result
      if (parsed && parsed.status === "ok") {
        this.healthy = true
        this.lastPing = Date.now()
        log.debug("health check passed", { pid: parsed.pid, memory_mb: parsed.memory_mb })
      } else {
        this.markUnhealthy("unexpected ping response")
      }
    } catch (err: any) {
      this.markUnhealthy(err.message)
    }
  }

  private markUnhealthy(reason: string): void {
    log.warn("worker marked unhealthy", { reason })
    this.healthy = false
    if (!this.restarting && !this.degraded) {
      this.stopHealthCheck()
      this.killProcess()
      this.scheduleRestart()
    }
  }

  private killProcess(): void {
    if (this.process) {
      try {
        this.process.kill("SIGTERM")
      } catch {
        // Already dead
      }
      this.process = null
      this.ready = false
    }
  }

  private scheduleRestart(): void {
    const now = Date.now()
    // Prune timestamps outside the restart window
    this.restartTimestamps = this.restartTimestamps.filter(
      (ts) => now - ts < RESTART_WINDOW_MS,
    )

    if (this.restartTimestamps.length >= MAX_RESTARTS) {
      log.error("max restarts exceeded, entering degraded mode", {
        restarts: this.restartTimestamps.length,
        window: RESTART_WINDOW_MS,
      })
      this.degraded = true
      return
    }

    this.restarting = true
    this.restartTimestamps.push(now)
    this.restartCount++

    log.info("scheduling worker restart", {
      attempt: this.restartCount,
      delay: RESTART_DELAY_MS,
    })

    setTimeout(async () => {
      this.restarting = false
      this.startPromise = null
      try {
        await this.start()
        log.info("worker restarted successfully", { attempt: this.restartCount })
      } catch (err: any) {
        log.error("worker restart failed", { error: err.message })
        if (!this.degraded) {
          this.scheduleRestart()
        }
      }
    }, RESTART_DELAY_MS)
  }

  async restart(): Promise<void> {
    log.info("manual restart requested")
    this.degraded = false
    this.restartTimestamps = []
    this.restarting = false
    this.stopHealthCheck()
    this.killProcess()
    for (const [, pending] of this.pending) {
      clearTimeout(pending.timer)
      pending.reject(new Error("Python bridge restarting (manual)"))
    }
    this.pending.clear()
    this.startPromise = null
    await this.start()
  }

  async call(method: string, params: Record<string, any> = {}, timeout?: number): Promise<any> {
    if (this.degraded) {
      const status = this.getStatus()
      throw new Error(
        `Python bridge is in degraded mode (${status.restartCount} restarts, ` +
          `last ping: ${status.lastPing ? new Date(status.lastPing).toISOString() : "never"}). ` +
          `Call restart() to attempt recovery.`,
      )
    }

    await this.start()

    const id = ulid()
    const request: JsonRpcRequest = { id, method, params }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`Python bridge call timed out after ${(timeout ?? this.defaultTimeout) / 1000}s: ${method}`))
      }, timeout ?? this.defaultTimeout)

      const parseResult = (result: any) => {
        // Worker returns JSON-encoded strings for special methods — parse them
        if (typeof result === "string") {
          try {
            return JSON.parse(result)
          } catch {
            return result
          }
        }
        return result
      }

      this.pending.set(id, { resolve: (r) => resolve(parseResult(r)), reject, timer })

      const line = JSON.stringify(request) + "\n"
      this.process?.stdin?.write(line, (err) => {
        if (err) {
          this.pending.delete(id)
          clearTimeout(timer)
          reject(new Error(`Failed to write to Python bridge: ${err.message}`))
        }
      })
    })
  }

  async stop(): Promise<void> {
    this.stopHealthCheck()
    this.killProcess()
    this.startPromise = null
  }
}

export function getWorkerStatus(): WorkerStatus {
  return PythonBridge.instance().getStatus()
}
