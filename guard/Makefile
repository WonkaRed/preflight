.PHONY: build test demo demo-llm demo-llm-replay testnet-verify testnet-demo testnet-demo-llm mcp-check

# Node >= 22.22.2 (see package.json "engines"; .npmrc makes npm refuse an older Node). Dependencies are
# installed from the lockfile whenever it changes: the first run needs network access.
node_modules/.package-lock.json: package.json package-lock.json
	npm ci

# Typecheck everything (src, tests, testkit, demo, scripts) under strict TypeScript. There is no emit step:
# Node runs the .ts files directly.
build: node_modules/.package-lock.json
	npm run --silent build

test: build
	npm test

# The scripted attack demo, offline.
demo: node_modules/.package-lock.json
	npm run --silent demo

# The same attack with a locally run language model as the agent. Needs PREFLIGHT_LLM_ENDPOINT (a model server on this
# machine, e.g. http://127.0.0.1:18020) and PREFLIGHT_LLM_MODEL in the environment. Offline otherwise: same fake RPC node.
demo-llm: node_modules/.package-lock.json
	npm run --silent demo-llm

# Two recorded model answers (docs/guard-llm-demo-runs.txt) through the real guard on the fake chain. Needs no model, no key,
# no network: deterministic.
demo-llm-replay: node_modules/.package-lock.json
	npm run --silent demo-llm-replay

# Read-only check of the recorded testnet deployment against the chain. Needs network, no keys.
testnet-verify: node_modules/.package-lock.json
	npm run --silent testnet-verify

# The attack scenario against the deployed testnet contracts, with real transactions. Needs the agent's key files:
# make -C guard testnet-demo AGENT_KEYS=/path/to/dir (the directory holds agent-key-for-<shop>.key).
AGENT_KEYS ?= $(PREFLIGHT_AGENT_KEYS)
# The values travel in the environment, never spliced into the shell command, so a value with quotes or $(...) is only text.
testnet-demo: export PREFLIGHT_AGENT_KEYS := $(AGENT_KEYS)
testnet-demo: export TESTNET_DEMO_LOG := $(LOG)
testnet-demo: node_modules/.package-lock.json
	npm run --silent testnet-demo -- $${TESTNET_DEMO_LOG:+--log "$$TESTNET_DEMO_LOG"}

# The same attack with a locally run language model as the agent, against the deployed testnet contracts, with real
# transactions: needs the agent's key files (AGENT_KEYS as above) and PREFLIGHT_LLM_ENDPOINT / PREFLIGHT_LLM_MODEL in the
# environment, so it cannot be run without the keys. Each run that reaches the real task releases one funded order.
testnet-demo-llm: export PREFLIGHT_AGENT_KEYS := $(AGENT_KEYS)
testnet-demo-llm: export TESTNET_DEMO_LOG := $(LOG)
testnet-demo-llm: node_modules/.package-lock.json
	npm run --silent testnet-demo-llm -- $${TESTNET_DEMO_LOG:+--log "$$TESTNET_DEMO_LOG"}

# The MCP server (mcp/README.md) started as a host would start it, asked about the three testnet demo contracts. Read-only: needs
# network, no key.
mcp-check: node_modules/.package-lock.json
	npm run --silent mcp-check
