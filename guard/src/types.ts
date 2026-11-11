// Interface from SPEC.md section 7 ("Guard") and the registry's Verdict from section 6.

export type Decision = "allow" | "warn" | "block";

export type VerdictStatus = "Safe" | "Warn" | "Unsafe";

/** The registry's verdict struct, as `get_verdict` returns it as JSON. */
export interface Verdict {
  code_hash: string;
  status: VerdictStatus;
  rule_ids: string[];
  report_url: string;
  report_sha256: string;
  auditor: string;
  /** `U64` in the contract, which near-sdk serializes as a decimal string. */
  published_at_ms: string;
}

export interface GuardConfig {
  /** NEAR JSON-RPC endpoint used for `view_account`, `view_code` and the registry view call. */
  rpcUrl: string;
  /** Account id the registry contract is deployed to. */
  registryId: string;
  /** Deadline in milliseconds of one RPC query, rate-limit retries and waits included (default 10000). A timeout is a `block`. */
  timeoutMs?: number;
  /**
   * Waits in milliseconds before each retry of a query the node answers with HTTP 429 (default 500, 1000, 2000,
   * 4000; at most 10 entries; `[]` never retries), all within `timeoutMs`. Still rate limited after the last one is a `block`.
   */
  rateLimitBackoffMs?: readonly number[];
}

export interface GuardResult {
  decision: Decision;
  contractId: string;
  /** Base58 SHA-256 of the deployed wasm; null when the account has no contract or the code could not be read. */
  codeHash: string | null;
  verdict: Verdict | null;
  /** Why `decision` was reached; never empty. */
  reasons: string[];
}
