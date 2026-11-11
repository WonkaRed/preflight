// The MCP server over stdio, the entry a host launches: `node mcp/main.ts` (see README.md). stdout is the protocol
// channel, so everything this file says goes to stderr.
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { describeError, printable } from "../src/text.ts";
import { loadServerConfig } from "./config.ts";
import { createPreflightServer } from "./server.ts";

let config;
try {
  config = await loadServerConfig(process.env);
} catch (error) {
  console.error(`preflight-mcp: ${printable(describeError(error))}`);
  process.exit(1);
}

serveStdio(() => createPreflightServer(config));
console.error(config.call === undefined ? "preflight-mcp on stdio: read-only, preflight_check_contract only" : `preflight-mcp on stdio: guarded calls enabled for ${config.call.allowedContracts.length} contract(s) on testnet, decision log ${config.call.logPath}`);
