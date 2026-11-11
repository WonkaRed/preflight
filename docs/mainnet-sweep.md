# `preflight account` on 142 mainnet contracts

- Run: 2026-11-11, 05:44 to 06:00 UTC
- Tool: preflight as published in this repository (account mode runs the deployed-account rules PFW01 to PFW06, not the 26 source rules), release build, `preflight account <id> --json`
- RPC: https://free.rpc.fastnear.com (the tool default, no key), one account at a time, 2 s pause between accounts
- Read-only: public JSON-RPC view and query calls only; no transaction, no key, no account created, nobody contacted

## Sample

145 accounts were listed; 142 were checked; 3 were skipped because the account exists but has no contract code (the tool exits with status 2 and prints nothing to check). No account failed to read: no exit status 3, no HTTP 429 during the sweep.

The list is a convenience sample, not a random one, built by fixed rules with no hand picking:

- 50 fungible-token contracts: the first two pages (25 each) of a public block-explorer API token listing, in its default order
- 25 NFT contracts: the first page of the same API's NFT listing, in its default order
- 35 contracts created by a public DAO factory: 35 evenly spaced entries (index k*2122/35) of the list the factory returns from its public view method (2122 entries)
- 35 staking pools: 35 evenly spaced entries (index k*351/35, sorted by account id) of the validator set the node returns (351 entries)

The 142 checked accounts run 61 distinct code hashes, so many of them share the same code. 13 of them run code installed as a global contract. The account list and the per-account output are not published: the table below is counts only, and a count of keys or method names is not a claim that any contract is unsafe.

## Results (142 contracts checked)

| Check | What it means in plain words | Accounts that triggered it | Percent |
|---|---|---|---|
| PFW01 (medium) | The account holds at least one full-access key. Whoever holds it can replace the code, delete the account or add keys | 32 | 22.5% |
| PFW01 (medium) | The account holds a function-call key aimed at itself with no method list, which can call any method on the contract | 0 | 0.0% |
| PFW02 (info) | The contract exports a method named like `upgrade`, `update_contract`, `migrate`, `state_migrate` or `set_owner...`. Names only | 75 | 52.8% |
| PFW03 (info) | The contract does not export NEP-330 source metadata, so its code cannot be tied to published source from chain data | 95 | 66.9% |
| PFW03 (info) | The contract exports NEP-330 metadata with a version or a link (self-declared, not checked against the code) | 47 | 33.1% |
| PFW03 (low) | The contract exports NEP-330 metadata but the call fails, is not JSON, or declares neither version nor link | 0 | 0.0% |
| PFW04 (medium) | The contract exports an initialization method and the account stores no state at all | 0 | 0.0% |
| PFW05 (low) | The balance plus locked stake is below the cost of the storage the account uses | 0 | 0.0% |
| PFW06 (low) | The contract exports `ft_transfer_call` but no method with "resolve" in its name | 0 | 0.0% |
| PFW06 (info) | The contract exports `ft_transfer` but not `storage_deposit` | 1 | 0.7% |
| Any check not evaluated | A check could not be decided (for example state too large to read) | 0 | 0.0% |
| Exit status 1 (a finding of severity low or above) | At least one of the low, medium, high or critical findings above | 32 | 22.5% |

Percent is of the 142 checked accounts; one account can trigger several rows. An info finding does not change the exit status.

## Limits

1. The mode reads one block of one account: access-key list, export names, the NEP-330 metadata call, the first state key, balance and storage. It does not read what the code does, so a method named like an upgrade method may be locked down and a method with another name may not be.
2. A full-access key shows that a key exists, not who holds it or how it is guarded (a multisig, a DAO or a timelock may hold it); PFW01 is a count of keys, not a count of insecure contracts.
3. PFW02 and PFW06 match export names only; PFW03 metadata is written by the contract itself; PFW04 and PFW05 are zero here, which says nothing about contracts outside this sample.
4. The sample is 142 well-known or listed contracts, not a random draw: token and NFT listings in one explorer's default order (which may include accounts of individual users), a strided slice of one DAO factory and of the validator set. Shared code means the 142 results are not 142 independent designs.
5. The run is a single snapshot on one public node; the tool trusts that node's answers, and a re-run of 5 accounts later returned identical findings (block height and balances differed).
