# Preflight MCP server

An [MCP](https://modelcontextprotocol.io) server (stdio) that lets any agent framework ask Preflight's guard one question:
**is the code at this NEAR address the code an auditor checked?** It is a thin face on the guard in [`../src`](../src): the
decisions, the policy and the decision log are the guard's own, not a second copy.

| Tool | Needs | What it does |
| --- | --- | --- |
| `preflight_check_contract` | nothing, no key | Read-only. Hashes the code deployed at an account right now, asks the registry about that exact hash, and returns `allow`, `warn` or `block` with the code hash, the verdict and its auditor, the rule ids and the reasons. `network` is `testnet` (default) or `mainnet` (read-only). The registry asked is always the operator's, never the caller's: the tool has no registry field (an extra field is refused, not ignored), so injected text cannot point it at a registry that says allow. Mainnet is refused unless the operator sets `PREFLIGHT_MAINNET_REGISTRY`. |
| `preflight_guarded_call` | key directory and policy file | Sends a function call on testnet through the real `GuardedAgent.guardedCall`: policy, key scope, code hash check, decision logged before signing, then sign and send. The model never sees a key. Not registered at all without the two. |
| `preflight_decision_log` | key directory and policy file | Read-only. The last N entries (1 to 100) of the guard's decision log, oldest first. |

## Try it: no key, a few seconds

Needs Node 22.22.2 or newer and network access to testnet.

```sh
make -C guard mcp-check
```

It starts the server as a host would (a child process over stdio, with no key), lists its tools, calls
`preflight_check_contract` on the three demo contracts deployed on testnet ([`docs/testnet-deployment.json`](../../docs/testnet-deployment.json))
and exits 1 if the answers are not the promised ones. Output of a real run:

```
npm run --silent mcp-check
preflight-mcp on stdio: read-only, preflight_check_contract only
MCP server started over stdio with no key. Tools offered: preflight_check_contract

shop-patched.preflight-guard.testnet (patched)
  decision:  allow
  code hash: EsZaoDQ34VbQYxz1iYrND8v3Z9nV7bpXvaytPjetdiZ
  verdict:   Safe, auditor auditor.preflight-guard.testnet
  rule ids:  none
  reason:    registry verdict Safe: published by auditor.preflight-guard.testnet, report https://github.com/WonkaRed/preflight/blob/main/docs/testnet-reports/shop-patched.json

shop-vulnerable.preflight-guard.testnet (vulnerable)
  decision:  block
  code hash: 8pqFHzB4UP7wR25AD7cSgyXGimPbEFBSKuKCc9ZRh8wT
  verdict:   Unsafe, auditor auditor.preflight-guard.testnet
  rule ids:  PF001
  reason:    registry verdict Unsafe (PF001): published by auditor.preflight-guard.testnet, report https://github.com/WonkaRed/preflight/blob/main/docs/testnet-reports/shop-vulnerable.json

shop-swapped.preflight-guard.testnet (swapped)
  decision:  warn
  code hash: 7uZs6XN2c9HsGHDPco6tHt28SEjkr5V23UKu8EHs2xSX
  verdict:   none for this code hash
  rule ids:  none
  reason:    code hash 7uZs6XN2c9HsGHDPco6tHt28SEjkr5V23UKu8EHs2xSX has no verdict in the registry: unaudited code, or code changed since its audit

Self-check passed: patched allow, vulnerable block, swapped warn.
```

`shop-swapped` held the audited code when it was audited and was redeployed afterwards, so the address is the same and the
code is not: no verdict for the new hash, `warn`.

## Add it to an agent

First `npm ci` in `guard/` once. Every snippet below runs the same command, `node --disable-warning=ExperimentalWarning <abs path>/guard/mcp/main.ts`;
replace the path with yours. The server logs to stderr only (stdout is the protocol).

Claude Code (checked against `claude mcp add`; run `/mcp` in a session to see it):

```sh
claude mcp add preflight -- node --disable-warning=ExperimentalWarning /abs/path/to/preflight/guard/mcp/main.ts
```

Or in a project's `.mcp.json` (what `claude mcp add --scope project` writes):

```json
{
  "mcpServers": {
    "preflight": {
      "type": "stdio",
      "command": "node",
      "args": ["--disable-warning=ExperimentalWarning", "/abs/path/to/preflight/guard/mcp/main.ts"],
      "env": {}
    }
  }
}
```

Codex (`codex mcp add preflight -- node ...` writes this to `~/.codex/config.toml`):

```toml
[mcp_servers.preflight]
command = "node"
args = ["--disable-warning=ExperimentalWarning", "/abs/path/to/preflight/guard/mcp/main.ts"]
```

Any other MCP client: a stdio server with `command` `node` and the same `args`. The server speaks both the 2025 (`initialize`) and
the 2026-07-28 (`server/discover`) protocol eras on stdio, both covered by the tests.

## Guarded calls (testnet only)

Off by default. Both environment variables must be set, or neither (one alone stops the server with a message):

- `PREFLIGHT_MCP_KEYS`: a directory with one `<contract id>.key` per allowed contract, one line `ed25519:...`, the agent's
  function-call key scoped to that contract (`npm run scope-key` makes one). The directory is yours: keep it private.
- `PREFLIGHT_MCP_POLICY`: a JSON policy file. Every field is required except `registryId` and `logPath`; an unknown field is an error.

```json
{
  "accountId": "agent.example.testnet",
  "allowedContracts": ["shop-patched.example.testnet"],
  "maxDepositPerCall": "0",
  "maxTotalDeposit": "0",
  "registryId": "registry.example.testnet",
  "logPath": "decisions.jsonl"
}
```

Amounts are yoctoNEAR decimal strings. `registryId` is the registry both tools use on testnet (default: the recorded deployment's,
`registry.preflight-guard.testnet`). `logPath` is relative to the policy file (default `decisions.jsonl` beside it). Every account
id must end in `.testnet`, and before every call the server asks the configured RPC for its `chain_id` and sends nothing unless it
says `testnet`, so there is no mainnet path through this tool: the tool has no network field (an extra field is refused, not ignored).
A full-access key is refused by the guard. A `warn` is refused too: no human is in the loop to approve it.

Inputs are checked before any handler runs: account ids and method names against the guard's grammars, `args` a JSON object of at
most 16 KiB, `deposit` a canonical decimal string that fits 128 bits. Gas is fixed at 30 Tgas, not the model's to set. Errors come
back as plain tool errors, never stack traces, and an RPC URL (which can carry an API key) is replaced by `[rpc url]` in every error, reason and verdict link the server returns.

Other environment: `PREFLIGHT_TESTNET_RPC` and `PREFLIGHT_MAINNET_RPC` (default `https://test.rpc.fastnear.com` and
`https://free.rpc.fastnear.com`; a URL with a user name or password in it is refused at startup, so put no credential there),
and `PREFLIGHT_MAINNET_REGISTRY` (a mainnet registry account id; none by default, so mainnet checks are refused).

`PREFLIGHT_MCP_MUTABILITY` turns on the checks that need no auditor (guard README, "Who can replace the code"): `keys` adds to a
check with no registry verdict whether a full-access key can replace the code; `pin-warn` and `pin-block` also remember the code
hash of every contract a check allows (or a guarded call signs for) and hold or refuse it when it changes. Unset, they are off.
`PREFLIGHT_MCP_PINS` is an absolute directory (a pin mode only; a relative path or an empty value stops the start, because it would follow the host's working directory) that keeps `testnet.json`
and `mainnet.json` across restarts; pins are per network, and without it they last as long as the process. Run one server process per pin
directory: a lock file beside each pin file makes a second process refuse to start. In a pin mode `preflight_check_contract` is
no longer read-only: when it allows a contract it records the code hash in the pin store (nothing on chain), and the tool's
description and `readOnlyHint` say so. To accept a changed contract, stop the server, delete that account's entry from the pin file and
start it again (a running server keeps its pins in memory and would write the entry back). `pin-warn` and `pin-block` behave the same for
`preflight_guarded_call`: the MCP agent has no approver, so a `warn` is refused either way, and the difference shows only in the
decision (`warn` or `block`) a check reports. The facts arrive in the `reasons` of both tools; no output field was added.

The demo shops' keys are not in this repository, so against the recorded deployment only the checks run; to try guarded calls
use a deployment of your own (`npm run testnet-deploy`).

## Limits

- A verdict is only as good as its auditor. `allow` means the registry holds a `Safe` verdict for this exact code hash; it says nothing
  about code nobody audited, and the registry is only as trustworthy as the operator who configured it.
- There is one auditor today, and the registry is on testnet. Mainnet code can be read, but there is no mainnet registry to ask unless an operator runs one and names it.
- The total-deposit cap lasts as long as the server process.
- The decision log is read from the file the guard writes; a line that is not a decision entry makes the tool report that, not guess.
- Node 22.22.2 or newer runs the TypeScript directly; there is no build step.

## Tests

`make -C guard test` runs them with the chain faked ([`../testkit`](../testkit)); no network, no real key. The stdio tests start
`main.ts` and `check.ts` as real processes.
