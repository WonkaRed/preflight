# Checking a deployed contract: what `preflight account` reads and how it exits

[Getting started](getting-started.md) shows one run. This page holds the rest of the detail.

## What it reads

It is read-only: only public JSON-RPC views (account, code, access keys, the first state key, a view call of `contract_source_metadata`, the protocol config), all pinned to one block shown in the report. It holds no key, signs nothing and sends no transaction.

## The six checks

PFW01 to PFW06 are: access keys, upgrade-style exports, NEP-330 source metadata, a contract that was never initialized, the storage balance floor, and the shape of a NEP-141 token. Each finding says what was read and what it does not prove.

## Output, endpoint and exit status

`--json` prints the machine-readable report (layout in [SPEC.md](../SPEC.md), "Deployed contracts"). Without `--rpc` the endpoint is the public mainnet node `https://free.rpc.fastnear.com`, which rate-limits bursts of requests; that is reported as an error, never as a clean contract.

Exit status: 0 no finding of severity low or above, 1 at least one finding, 2 the account id or URL is invalid or the account has no contract, 3 the chain could not be read (timeout, HTTP error, bad response, or a run over 2 minutes).
