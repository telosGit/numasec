const files = [
  "test/security/access-control-differential.test.ts",
  "test/security/auth-fabric-unification.test.ts",
  "test/security/browser-inventory.test.ts",
  "test/security/browser-runtime.test.ts",
  "test/security/execution-failure.test.ts",
  "test/security/phase0-floor.test.ts",
  "test/security/plan-next.test.ts",
  "test/security/planner-policy.test.ts",
  "test/security/resource-inventory.test.ts",
  "test/security/target-profile-store.test.ts",
]

const proc = Bun.spawn({
  cmd: ["bun", "test", "--timeout", "30000", ...files],
  cwd: new URL("..", import.meta.url).pathname,
  stdout: "inherit",
  stderr: "inherit",
})

const code = await proc.exited
process.exit(code)
