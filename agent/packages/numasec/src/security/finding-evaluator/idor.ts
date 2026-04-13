import { evidenceRefs, familyNodes, hypothesisRef, passed, payload, type FindingCandidate, type FindingEvaluator } from "./base"

export const IdorEvaluator: FindingEvaluator = {
  family: "idor",
  evaluate(input) {
    const out: FindingCandidate[] = []
    const rows = familyNodes(input, "idor", "verification").filter(passed)
    for (const row of rows) {
      const value = payload(row)
      const url = String(value.url ?? "")
      const method = String(value.method ?? "GET")
      const parameter = String(value.parameter ?? "")
      const kind = String(value.kind ?? "signal")
      const description =
        kind === "collection_foreign_records" || kind === "collection_cross_actor_exposure"
          ? "A low-privilege actor received collection results containing resources or identities that belong to other actors."
          : kind === "foreign_resource_mutation" || kind === "cross_actor_mutation"
            ? "A low-privilege actor successfully changed a resource that appears to belong to another actor."
          : kind === "foreign_resource_access" || kind === "cross_actor_access"
            ? "A known foreign resource remained accessible to an actor that should only access its own resources."
            : String(value.evidence ?? "") ||
              "Authenticated enumeration returned multiple resource identifiers with accessible data. Treat as access-control vulnerability pending stronger ownership differential proof."
      out.push({
        family: "idor",
        title: String(value.title ?? "IDOR indicated"),
        description,
        severity: (value.technical_severity ?? "high") as any,
        state: kind === "resource_enumeration" ? "provisional" : "verified",
        confidence: typeof row.confidence === "number" ? row.confidence : 0.7,
        url,
        method,
        parameter,
        payload: String(value.payload ?? ""),
        root_cause_key: `idor|${url}|${method}|${parameter}|${kind}`,
        source_hypothesis_id: hypothesisRef(input, row.id),
        evidence_refs: [row.id, ...evidenceRefs(input.edges, row.id)],
        negative_control_refs: [],
        impact_refs: [],
        remediation: "Enforce object-level authorization checks for every resource access and mutation.",
        reportable: true,
        suppression_reason: "",
        node_ids: [row.id],
      })
    }
    return out
  },
}
