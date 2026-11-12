# Mainnet survey: can the code at a well-known address be replaced by a key?

Having a key that can replace code is a design choice, not a defect; this table only shows that an address alone does not pin the code.

Read on 2026-11-12 from NEAR mainnet through the RPC endpoint free.rpc.fastnear.com, with read-only calls (`view_account`, `view_access_key_list`): no keys, no transactions. The code hash is the base58 SHA-256 of the deployed wasm that the account reports. A full-access key can deploy new code to its account at any time; the count is the number of such keys the account holds on the date read.

| Account | Code hash | Full-access keys | Date read |
|---|---|---|---|
| `wrap.near` | `DL2f5xmZ44cQRP6vBMt94rvseH5d5KKnAGis2WkTAsh1` | 0 | 2026-11-12 |
| `v2.ref-finance.near` | `GZmkbfVLcN7ErxU9RDxP24YTaKmoVixhM6XyycP15Qvi` | 0 | 2026-11-12 |
| `aurora` | `HrtBWvCMmVXRLG9vsYAFT7LfJ6mZtCSNTvYnXMF6fwzT` | 1 | 2026-11-12 |
| `meta-pool.near` | `J6pS9R23vzbwxGB8eMq4qrn8UhciEYHsVbR9UJPyLNxh` | 0 | 2026-11-12 |
| `linear-protocol.near` | `5LiDVDd1gh7ofVNbiA9VXrWwkv2m8tw46jZqYeuoC3SG` | 0 | 2026-11-12 |
| `usdt.tether-token.near` | `51tHbmQkA8qAi8c6MoUor5mCx6CnL6tZyC2sqQifKPZC` | 0 | 2026-11-12 |
| `intents.near` | `BtA1BEFNS619KkvXFsgcpQ21Tb5yMm32aaUkn7xNothk` | 0 | 2026-11-12 |
| `contract.main.burrow.near` | `6Nek1MZ8cwJJ2xMQAUWup9V5AToYS9rkTxJfwo6BCpFa` | 0 | 2026-11-12 |
| `token.sweat` | `9EUtV11wgCZ4N16xa24ETnn8E78GjeSit1r7gMyQZ6Zi` | 0 | 2026-11-12 |
| `app.nearcrowd.near` | `5TQM4DuBtW4M6L3tWbeo88Pv7b5fe9oziMhMybcyLLMD` | 15 | 2026-11-12 |

Not established: whether the contract can upgrade itself through one of its own methods (a key count cannot show that, so zero full-access keys does not mean the code is fixed), and when the code last changed (RPC reports code changes one block at a time, so the guard cannot look back). A count of 0 therefore shows only that the account holds no full-access key, not that nothing can replace its code.

Reproduce it with `make -C guard mainnet-survey`. The table is a snapshot: a later read can differ.
