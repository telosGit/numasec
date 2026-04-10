import { z } from "zod"
import { Tool } from "../../tool/tool"
import { loadTemplates } from "../kb/loader"
import { buildRetriever, type KnowledgeRetriever } from "../kb/retriever"

let cached: KnowledgeRetriever | undefined

function getRetriever() {
  if (cached) return cached
  const templates = loadTemplates()
  cached = buildRetriever(templates)
  return cached
}

export const KbSearchTool = Tool.define("kb_search", {
  description:
    "Search the numasec security knowledge base for vulnerability detection patterns, exploitation techniques, payloads, remediation guidance, and attack chain templates. Returns relevant knowledge chunks ranked by BM25 relevance. Use this to look up specific vulnerability types, CWE-based remediation, OWASP testing methodology, or payload lists before testing.",
  parameters: z.object({
    query: z.string().describe("Natural language search query (e.g. 'SQL injection bypass WAF', 'JWT algorithm confusion', 'SSRF cloud metadata')"),
    category: z.string().optional().describe("Filter by category: detection, exploitation, payloads, remediation, reference, attack_chains, post-exploitation, protocols"),
    cwe: z.string().optional().describe("Filter by CWE ID (e.g. 'CWE-89')"),
    top_k: z.number().optional().describe("Number of results to return (default 5)"),
  }),
  async execute(params, ctx) {
    await ctx.ask({
      permission: "kb_search",
      patterns: [],
      always: ["*"],
      metadata: { query: params.query } as Record<string, any>,
    })
    const retriever = await getRetriever()
    const results = retriever.query(params.query, {
      topK: params.top_k ?? 5,
      category: params.category,
      cwe: params.cwe,
    })
    if (results.length === 0) {
      return {
        title: `KB search: "${params.query}" — no results`,
        metadata: {} as any,
        output: "No matching knowledge base entries found. Try broader search terms or different category.",
      }
    }
    const lines = results.map(
      (r, i) =>
        `## Result ${i + 1} (score: ${r.score.toFixed(3)}) — ${r.category}/${r.templateId}\n**Section:** ${r.section}\n\n${r.text}`,
    )
    return {
      title: `KB search: "${params.query}" — ${results.length} results`,
      metadata: { count: results.length, categories: [...new Set(results.map((r) => r.category))] } as any,
      output: lines.join("\n\n---\n\n"),
    }
  },
})
