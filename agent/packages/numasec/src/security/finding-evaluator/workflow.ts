import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, text, type FindingCandidate, type FindingEvaluator } from "./base"

export const WorkflowEvaluator: FindingEvaluator = {
  family: "workflow",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "workflow", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = text(value.url)
      const method = text(value.method) || "PATCH"
      const parameter = text(value.parameter)
      const kind = text(value.kind) || "signal"
      const target = text(value.target_state || value.target || value.state)
      const action = text(value.action_kind)
      const description =
        kind === "restricted_state_transition"
          ? `A low-privilege actor successfully moved a resource into a restricted workflow state${target ? ` (${target})` : ""}.`
          : kind === "destructive_action_transition"
            ? `A low-privilege actor successfully invoked a destructive workflow action${action ? ` (${action})` : ""} and removed the resource${target ? ` (${target})` : ""}.`
          : kind === "restricted_action_transition"
            ? `A low-privilege actor successfully invoked a restricted workflow action${action ? ` (${action})` : ""}${target ? ` and moved the resource into ${target}` : ""}.`
          : text(value.evidence) || "A low-privilege actor reached a restricted workflow transition."
      out.push({
        family: "workflow",
        title: text(value.title) || "Workflow abuse indicated",
        description,
        severity: (value.technical_severity ?? "high") as any,
        state: "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.7,
        url,
        method,
        parameter,
        payload: text(value.payload),
        root_cause_key: `workflow|${url}|${method}|${parameter}|${kind}|${target}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Enforce explicit role and state-machine authorization checks before approving, claiming, archiving, deleting, publishing, or otherwise advancing workflow state.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
