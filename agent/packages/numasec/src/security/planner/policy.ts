import { nextPlannerStep, type PlannerKernel, type PlannerSignal, type PlannerStep } from "./kernel"

export type PlannerPolicySignal = PlannerSignal

export interface PlannerPolicyBudget {
  remaining_seconds?: number
  primitive_budget?: number
}

export interface PlannerPolicyEvidence {
  supports: number
  refutes: number
  observes: number
  verification_passed: boolean | null
  waf_detected: boolean
  auth_obtained: boolean
  escalation_found: boolean
  spa_detected: boolean
  api_app_detected: boolean
  workflow_actions_mined: boolean
  destructive_actions_mined: boolean
}

export interface PlannerPolicyDecision {
  primary: PlannerStep
  steps: PlannerStep[]
  evidence: PlannerPolicyEvidence
  budget: {
    remaining_seconds: number
    primitive_budget: number
  }
}

const MAX_PRIMITIVE_BUDGET = 4

function workflowActionText(input: string) {
  return /(workflow action|action candidate|approve action|approve endpoint|claim action|claim endpoint|publish action|publish endpoint|verify action|verify endpoint|archive action|archive endpoint|delete action|delete endpoint)/i.test(input)
}

function destructiveActionText(input: string) {
  return /(destructive action|delete action|delete endpoint|archive action|archive endpoint|close action|close endpoint|remove action|remove endpoint)/i.test(input)
}

function defaultSeconds(scope: PlannerKernel["scope"]) {
  if (scope === "quick") return 180
  if (scope === "deep") return 1800
  return 600
}

function defaultBudget(scope: PlannerKernel["scope"]) {
  if (scope === "quick") return 1
  if (scope === "deep") return 3
  return 2
}

function readBudget(kernel: PlannerKernel, budget?: PlannerPolicyBudget) {
  const secondsValue = budget?.remaining_seconds ?? defaultSeconds(kernel.scope)
  const seconds = Number.isFinite(secondsValue) ? Math.max(1, Math.floor(secondsValue)) : defaultSeconds(kernel.scope)
  const budgetValue = budget?.primitive_budget ?? defaultBudget(kernel.scope)
  const budgetFloor = Number.isFinite(budgetValue) ? Math.max(1, Math.floor(budgetValue)) : defaultBudget(kernel.scope)
  const budgetCap = Math.min(MAX_PRIMITIVE_BUDGET, budgetFloor)
  if (kernel.scope === "quick") {
    return {
      remaining_seconds: seconds,
      primitive_budget: 1,
    }
  }
  if (seconds <= 120) {
    return {
      remaining_seconds: seconds,
      primitive_budget: 1,
    }
  }
  return {
    remaining_seconds: seconds,
    primitive_budget: budgetCap,
  }
}

function readEvidence(kernel: PlannerKernel, signals?: PlannerPolicySignal[]): PlannerPolicyEvidence {
  const out: PlannerPolicyEvidence = {
    supports: 0,
    refutes: 0,
    observes: 0,
    verification_passed: null,
    waf_detected: false,
    auth_obtained: false,
    escalation_found: false,
    spa_detected: false,
    api_app_detected: false,
    workflow_actions_mined: false,
    destructive_actions_mined: false,
  }

  for (const item of kernel.history) {
    if (item.type === "evidence_recorded") {
      if (item.relation === "supports") out.supports += 1
      if (item.relation === "refutes") out.refutes += 1
      if (item.relation === "observes") out.observes += 1
    }
    if (item.type === "verification_recorded") {
      out.verification_passed = item.passed
    }
  }

  for (const note of kernel.notes) {
    const text = note.toLowerCase()
    if (text.includes("waf")) out.waf_detected = true
    if (text.includes("auth") || text.includes("credential")) out.auth_obtained = true
    if (text.includes("escalat")) out.escalation_found = true
    if (text.includes("spa")) out.spa_detected = true
    if (text.includes("api")) out.api_app_detected = true
    if (workflowActionText(text)) out.workflow_actions_mined = true
    if (destructiveActionText(text)) out.destructive_actions_mined = true
  }

  for (const item of kernel.signals) {
    if (item === "waf_detected") out.waf_detected = true
    if (item === "auth_obtained") out.auth_obtained = true
    if (item === "escalation_found") out.escalation_found = true
    if (item === "spa_detected") out.spa_detected = true
    if (item === "api_app_detected") out.api_app_detected = true
    if (item === "workflow_actions_mined") out.workflow_actions_mined = true
    if (item === "destructive_actions_mined") out.destructive_actions_mined = true
  }

  const list = signals ?? []
  for (const item of list) {
    if (item === "waf_detected") out.waf_detected = true
    if (item === "auth_obtained") out.auth_obtained = true
    if (item === "escalation_found") out.escalation_found = true
    if (item === "spa_detected") out.spa_detected = true
    if (item === "api_app_detected") out.api_app_detected = true
    if (item === "workflow_actions_mined") out.workflow_actions_mined = true
    if (item === "destructive_actions_mined") out.destructive_actions_mined = true
  }

  return out
}

function inventoryStep(evidence: PlannerPolicyEvidence): PlannerStep {
  if (evidence.destructive_actions_mined) {
    return {
      primitive: "query_resource_inventory",
      description: "Review shared actor/resource inventory and mined destructive workflow action candidates before replaying delete or archive paths",
    }
  }
  if (evidence.workflow_actions_mined) {
    return {
      primitive: "query_resource_inventory",
      description: "Review shared actor/resource inventory and mined workflow action candidates before replaying approve, claim, or publish paths",
    }
  }
  return {
    primitive: "query_resource_inventory",
    description: "Review shared actor/resource inventory before choosing the next authorization or workflow target",
  }
}

function accessStep(evidence: PlannerPolicyEvidence): PlannerStep {
  if (evidence.destructive_actions_mined) {
    return {
      primitive: "access_control_test",
      description: "Replay mined destructive workflow actions with access_control_test before generic differential authorization checks",
    }
  }
  if (evidence.workflow_actions_mined) {
    return {
      primitive: "access_control_test",
      description: "Replay mined workflow action candidates with access_control_test before generic differential authorization checks",
    }
  }
  return {
    primitive: "access_control_test",
    description: "Pivot confirmed auth/session access into differential authorization coverage",
  }
}

function addStep(steps: PlannerStep[], step: PlannerStep, limit: number) {
  if (steps.length >= limit) return
  if (steps.some((item) => item.primitive === step.primitive)) return
  steps.push(step)
}

function readPolicySteps(kernel: PlannerKernel, evidence: PlannerPolicyEvidence, limit: number) {
  const primary = nextPlannerStep(kernel)
  const steps: PlannerStep[] = [primary]
  const workflow = evidence.workflow_actions_mined || evidence.destructive_actions_mined
  if (limit <= 1) return steps

  if (kernel.state === "hypothesis_open") {
    if (evidence.auth_obtained || workflow) {
      addStep(
        steps,
        {
          primitive: "observe_surface",
          description: evidence.auth_obtained
            ? "Re-observe authenticated routes to expand reachable attack surface"
            : "Re-observe workflow routes to expand reachable action surface",
        },
        limit,
      )
      if (evidence.spa_detected) {
        addStep(steps, { primitive: "browser", description: "Drive the authenticated SPA to collect cookies, routes, and hidden state-changing flows" }, limit)
      }
      addStep(
        steps,
        workflow
          ? inventoryStep(evidence)
          : {
              primitive: "query_resource_inventory",
              description: "Summarize authenticated actors and mined own/foreign resource candidates before access-control sweeps",
            },
        limit,
      )
      addStep(
        steps,
        workflow
          ? accessStep(evidence)
          : {
              primitive: "access_control_test",
              description: "Run authenticated differential access-control checks with session material and alternate actors when available",
            },
        limit,
      )
    }
    if (evidence.spa_detected) {
      addStep(steps, { primitive: "observe_surface", description: "Focus observation on SPA routes and JavaScript-exposed endpoints" }, limit)
    }
    if (evidence.api_app_detected) {
      addStep(steps, { primitive: "mutate_input", description: "Generate API-focused payload variants for discovered parameters" }, limit)
    }
    if (evidence.waf_detected) {
      addStep(steps, { primitive: "mutate_input", description: "Generate low-noise payload mutations for WAF-aware probing" }, limit)
    }
    return steps
  }

  if (kernel.state === "evidence_collecting") {
    if (evidence.supports === 0 && evidence.refutes === 0 && evidence.observes > 0) {
      addStep(steps, { primitive: "extract_observation", description: "Normalize raw observations into structured evidence before verification" }, limit)
    }
    if (evidence.refutes > evidence.supports) {
      addStep(steps, { primitive: "upsert_hypothesis", description: "Refine hypothesis because refuting evidence outweighs supporting evidence" }, limit)
    }
    if (evidence.waf_detected) {
      addStep(steps, { primitive: "mutate_input", description: "Prepare alternate payload encodings to continue evidence collection under WAF constraints" }, limit)
    }
    return steps
  }

  if (kernel.state === "decision_pending") {
    if (evidence.verification_passed === false) {
      addStep(steps, { primitive: "upsert_hypothesis", description: "Re-open and revise the hypothesis because verification failed" }, limit)
    }
    if (evidence.verification_passed === true) {
      addStep(steps, { primitive: "derive_attack_paths", description: "Queue chain derivation after persisting a confirmed finding" }, limit)
    }
    if (evidence.escalation_found) {
      addStep(steps, { primitive: "derive_attack_paths", description: "Escalation signal detected; prioritize attack path derivation" }, limit)
    }
    return steps
  }

  if (kernel.state === "closed_positive") {
    if (evidence.escalation_found) {
      addStep(steps, { primitive: "upsert_hypothesis", description: "Open follow-on hypothesis for privilege escalation validation" }, limit)
    }
    if (evidence.auth_obtained || workflow) {
      if (evidence.spa_detected) {
        addStep(steps, { primitive: "browser", description: "Refresh authenticated SPA routes and hidden actions before the next authz/workflow cycle" }, limit)
      }
      addStep(steps, inventoryStep(evidence), limit)
      addStep(steps, accessStep(evidence), limit)
    }
    addStep(steps, { primitive: "plan_next", description: "Continue deterministic planning with the next hypothesis cycle" }, limit)
    return steps
  }

  if (kernel.state === "closed_negative") {
    if (evidence.supports > 0) {
      addStep(steps, { primitive: "upsert_hypothesis", description: "Recycle supporting evidence into a narrower follow-up hypothesis" }, limit)
    }
    if (evidence.api_app_detected || evidence.spa_detected) {
      addStep(steps, { primitive: "observe_surface", description: "Expand discovery for API or SPA components before ending the cycle" }, limit)
    }
    return steps
  }

  if (kernel.state === "scope_defined") {
    if (evidence.api_app_detected || evidence.spa_detected) {
      addStep(steps, { primitive: "observe_surface", description: "Collect baseline observations for API or SPA scope before deep testing" }, limit)
    }
    return steps
  }

  return steps
}

export function selectPlannerPrimitives(
  kernel: PlannerKernel,
  input?: {
    signals?: PlannerPolicySignal[]
    budget?: PlannerPolicyBudget
  },
): PlannerPolicyDecision {
  const evidence = readEvidence(kernel, input?.signals)
  const budget = readBudget(kernel, input?.budget)
  const steps = readPolicySteps(kernel, evidence, budget.primitive_budget)
  const primary = steps[0] ?? nextPlannerStep(kernel)
  return {
    primary,
    steps,
    evidence,
    budget,
  }
}
