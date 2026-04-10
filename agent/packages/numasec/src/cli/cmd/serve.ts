import { Server } from "../../server/server"
import { cmd } from "./cmd"
import { withNetworkOptions, resolveNetworkOptions } from "../network"
import { Flag } from "../../flag/flag"
import { Workspace } from "../../control-plane/workspace"
import { Project } from "../../project/project"
import { Installation } from "../../installation"
import { Instance } from "../../project/instance"

export const ServeCommand = cmd({
  command: "serve",
  builder: (yargs) => withNetworkOptions(yargs),
  describe: "starts a headless numasec server",
  handler: async (args) => {
    if (!Flag.NUMASEC_SERVER_PASSWORD) {
      console.log("Warning: NUMASEC_SERVER_PASSWORD is not set; server is unsecured.")
    }
    const opts = await resolveNetworkOptions(args)
    // Security tools are now native TypeScript — no Python bridge needed
    await Instance.provide({
      directory: process.cwd(),
      fn: async () => {},
    })
    const server = Server.listen(opts)
    console.log(`numasec server listening on http://${server.hostname}:${server.port}`)

    await new Promise(() => {})
    await server.stop()
  },
})
