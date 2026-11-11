// A fake NEAR JSON-RPC node for the tests and the offline demo. It is a real HTTP server on 127.0.0.1, so the
// guard's `fetch` and near-api-js's provider run their real code paths; only the chain behind it is made up.
// Response bodies follow the shapes in https://docs.near.org/api/rpc/contracts and nearcore's views.rs.
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { baseEncode, decodeSignedTransaction, encodeTransaction, type PublicKey } from "near-api-js";
import { codeHashOf } from "../src/check.ts";
import type { Verdict } from "../src/types.ts";

type Json = Record<string, unknown>;

const BLOCK_HASH = "56xEo2LorUFVNbkFhCncFSWNiobdp1kzm14nZ47b5JVW"; // from the NEAR RPC docs examples
const BLOCK_HEIGHT = 187440904;
const NO_CODE_HASH = "11111111111111111111111111111111";

export type KeyPermission = "FullAccess" | { FunctionCall: { allowance: string; receiver_id: string; method_names: string[] } };

export interface FakeAccount {
  /** Local contract code. Omit for an account without a contract. */
  wasm?: Uint8Array;
  /** The account uses a global contract published under this code hash (immutable). */
  globalCodeHash?: string;
  /** The account uses the global contract published by this account (mutable); `wasm` is what it currently resolves to. */
  globalPublisher?: string;
}

/** Makes one request type misbehave instead of answering from the fake chain. */
export type Fault =
  | { kind: "hang" }
  | { kind: "drop" } // closes the connection without answering: what a node that is down looks like, on a port this fake still holds
  | { kind: "http"; status: number; times?: number } // `times`: answer that many requests this way, then from the chain
  | { kind: "body"; text: string }
  | { kind: "json"; body: Json };

export interface SentCall {
  signerId: string;
  receiverId: string;
  publicKey: string;
  methodName: string;
  args: string;
  /** The exact bytes the transaction carried. */
  argsBytes: Uint8Array;
  deposit: bigint;
  gas: bigint;
}

function rpcError(name: string, info: Json, data: string): Json {
  return { jsonrpc: "2.0", error: { name: "HANDLER_ERROR", cause: { info, name }, code: -32000, message: "Server error", data }, id: "dontcare" };
}

function ok(result: Json): Json {
  return { jsonrpc: "2.0", result, id: "dontcare" };
}

/** What a node answers when it refuses a transaction at validation (the access key's allowance is too low): `send_tx` throws, the transaction never lands. */
export const REFUSED: Json = { jsonrpc: "2.0", error: { name: "HANDLER_ERROR", cause: { info: {}, name: "INVALID_TRANSACTION" }, code: -32000, message: "Server error", data: { TxExecutionError: { InvalidTxError: { InvalidAccessKeyError: { NotEnoughAllowance: { account_id: "agent.test.near", allowance: "1", cost: "2", public_key: "ed25519:11111111111111111111111111111111" } } } } } }, id: "dontcare" };

/** A `tx` answer for a transaction that landed and succeeded: faulted in next to `REFUSED`, it shows no one asked. */
export const LANDED: Json = { jsonrpc: "2.0", result: { final_execution_status: "FINAL", status: { SuccessValue: "" }, transaction: {}, transaction_outcome: {}, receipts_outcome: [] }, id: "dontcare" };

export class FakeNear {
  readonly accounts = new Map<string, FakeAccount>();
  /** Registry state: verdicts keyed by code hash. */
  readonly verdicts = new Map<string, Verdict>();
  /** Access keys keyed by `accountId|publicKey`. */
  readonly keys = new Map<string, KeyPermission>();
  /** Every transaction the fake chain accepted, as the base64 of the signed bytes the client sent. */
  readonly receivedTransactions: string[] = [];
  /** Every function call the fake chain accepted, decoded. */
  readonly sent: SentCall[] = [];
  /** Every `query` request type received, in order. */
  readonly queries: string[] = [];
  /** The params of every `query` request, in the same order as `queries`. */
  readonly queryParams: Json[] = [];
  /** Faults by `request_type` (or the JSON-RPC method name for non-query calls). */
  readonly faults = new Map<string, Fault>();
  /** How many of the next `send_tx` requests answer InvalidNonce (the signed transaction is not applied), as a chain does for a stale nonce. */
  staleNonces = 0;
  /** How many of the next `send_tx` requests are applied and then answered HTTP 429 (a node that took the transaction and throttled the reply). */
  lateRateLimits = 0;
  /** What the registry's `get_auditors` answers. */
  auditors: string[] = ["auditor.test.near"];
  /** What `status` reports as `chain_id`. */
  chainId = "testnet";
  /** Ids of the transactions the chain applied; a second send of one is refused like a reused nonce. */
  readonly #landed = new Set<string>();
  #server: Server | undefined;
  #nonce = 1;

  readonly registryId: string;

  constructor(registryId: string) {
    this.registryId = registryId;
  }

  addKey(accountId: string, publicKey: string, permission: KeyPermission): void {
    this.keys.set(`${accountId}|${publicKey}`, permission);
  }

  /** Publishes a verdict for the code currently deployed on `accountId`, like an auditor calling `publish_verdict`. */
  publish(accountId: string, status: Verdict["status"], ruleIds: string[] = []): string {
    const wasm = this.accounts.get(accountId)?.wasm;
    if (wasm === undefined) throw new Error(`${accountId} has no code to publish a verdict for`);
    const codeHash = codeHashOf(wasm);
    this.verdicts.set(codeHash, {
      code_hash: codeHash,
      status,
      rule_ids: ruleIds,
      report_url: `https://preflight.invalid/reports/${codeHash.slice(0, 8)}.json`,
      report_sha256: createHash("sha256").update(codeHash).digest("hex"),
      auditor: "auditor.test.near",
      published_at_ms: "1762790400000",
    });
    return codeHash;
  }

  async start(): Promise<string> {
    const server = createServer((request, response) => {
      this.#handle(request)
        // A bug in the fake must fail the test that hit it, not leave the client waiting.
        .catch((error: unknown) => ({ status: 500, text: `fake RPC bug: ${String(error)}` }))
        .then((reply) => {
          if (reply === "hang") return; // never answered; the client's timeout ends it
          if (reply === "drop") return void response.socket?.destroy();
          response.writeHead(reply.status, { "content-type": "application/json" });
          response.end(reply.text);
        });
    });
    this.#server = server;
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    const server = this.#server;
    if (server === undefined) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  async #handle(request: IncomingMessage): Promise<{ status: number; text: string } | "hang" | "drop"> {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { method: string; params: Json };
    const requestType = body.method === "query" ? String(body.params["request_type"]) : body.method;
    if (body.method === "query") {
      this.queries.push(requestType);
      this.queryParams.push(body.params);
    }

    if (body.method === "send_tx" && this.lateRateLimits > 0) {
      this.lateRateLimits -= 1;
      this.#answer(body.method, body.params);
      return { status: 429, text: "too many requests" };
    }
    const fault = this.faults.get(requestType);
    if (fault?.kind === "hang") return "hang";
    if (fault?.kind === "drop") return "drop";
    if (fault?.kind === "http") {
      if (fault.times === undefined || fault.times > 0) {
        if (fault.times !== undefined) fault.times -= 1;
        return { status: fault.status, text: "upstream error" };
      }
    }
    if (fault?.kind === "body") return { status: 200, text: fault.text };
    return { status: 200, text: JSON.stringify(fault?.kind === "json" ? fault.body : this.#answer(body.method, body.params)) };
  }

  #answer(method: string, params: Json): Json {
    if (method === "block") {
      return ok({ author: "validator.test.near", header: { hash: BLOCK_HASH, height: BLOCK_HEIGHT, timestamp: 1762790400000000000 }, chunks: [] });
    }
    if (method === "status") return ok({ chain_id: this.chainId, version: { version: "fake", build: "fake" } });
    if (method === "tx") {
      const known = this.#landed.has(String(params["tx_hash"]));
      return known ? ok({ final_execution_status: "FINAL", status: { SuccessValue: "" }, transaction: { hash: String(params["tx_hash"]) }, transaction_outcome: {}, receipts_outcome: [] }) : rpcError("UNKNOWN_TRANSACTION", {}, "unknown transaction");
    }
    if (method === "send_tx" && this.staleNonces > 0) {
      this.staleNonces -= 1;
      return { jsonrpc: "2.0", error: { name: "HANDLER_ERROR", cause: { info: {}, name: "INVALID_TRANSACTION" }, code: -32000, message: "Server error", data: { TxExecutionError: { InvalidTxError: { InvalidNonce: { ak_nonce: 9, tx_nonce: 1 } } } } }, id: "dontcare" };
    }
    if (method === "send_tx") return this.#sendTx(String(params["signed_tx_base64"]));
    if (method !== "query") return rpcError("METHOD_NOT_FOUND", {}, `no such method ${method}`);

    const accountId = String(params["account_id"]);
    const at = { block_hash: BLOCK_HASH, block_height: BLOCK_HEIGHT };
    switch (params["request_type"]) {
      case "view_account": {
        const account = this.accounts.get(accountId);
        if (account === undefined) return rpcError("UNKNOWN_ACCOUNT", { requested_account_id: accountId, ...at }, `account ${accountId} does not exist while viewing`);
        // nearcore views.rs: `code_hash` is the local contract's hash, all zero for global contracts; the global
        // reference is reported in separate fields.
        const local = account.wasm !== undefined && account.globalCodeHash === undefined && account.globalPublisher === undefined;
        return ok({
          amount: "999788200694421800000000",
          ...at,
          code_hash: local ? codeHashOf(account.wasm as Uint8Array) : NO_CODE_HASH,
          locked: "0",
          storage_usage: 410,
          ...(account.globalCodeHash !== undefined ? { global_contract_hash: account.globalCodeHash } : {}),
          ...(account.globalPublisher !== undefined ? { global_contract_account_id: account.globalPublisher } : {}),
        });
      }
      case "view_code": {
        const wasm = this.accounts.get(accountId)?.wasm;
        if (wasm === undefined) return rpcError("NO_CONTRACT_CODE", { contract_account_id: accountId, ...at }, `contract code of account ${accountId} does not exist`);
        return ok({ ...at, code_base64: Buffer.from(wasm).toString("base64"), hash: codeHashOf(wasm) });
      }
      case "call_function": {
        if (accountId === this.registryId && params["method_name"] === "get_auditors") {
          return ok({ ...at, logs: [], result: [...Buffer.from(JSON.stringify(this.auditors))] });
        }
        if (accountId !== this.registryId || params["method_name"] !== "get_verdict") {
          return ok({ ...at, error: `wasm execution failed with error: MethodResolveError(MethodNotFound)`, logs: [] });
        }
        const args = JSON.parse(Buffer.from(String(params["args_base64"]), "base64").toString("utf8")) as { code_hash: string };
        const verdict = this.verdicts.get(args.code_hash) ?? null;
        return ok({ ...at, logs: [], result: [...Buffer.from(JSON.stringify(verdict))] });
      }
      case "view_access_key_list": {
        const keys = [...this.keys.entries()].filter(([id]) => id.startsWith(`${accountId}|`)).map(([id, permission]) => ({ public_key: id.slice(accountId.length + 1), access_key: { nonce: 0, permission } }));
        return ok({ ...at, keys });
      }
      case "view_access_key": {
        const permission = this.keys.get(`${accountId}|${String(params["public_key"])}`);
        if (permission === undefined) return ok({ ...at, error: `access key ${String(params["public_key"])} does not exist while viewing`, logs: [] });
        return ok({ nonce: this.#nonce, permission, ...at });
      }
      default:
        return rpcError("REQUEST_VALIDATION_ERROR", {}, `unsupported request_type ${String(params["request_type"])}`);
    }
  }

  #sendTx(signedTxBase64: string): Json {
    const { transaction } = decodeSignedTransaction(Buffer.from(signedTxBase64, "base64"));
    const id = baseEncode(createHash("sha256").update(encodeTransaction(transaction)).digest());
    if (this.#landed.has(id)) {
      return { jsonrpc: "2.0", error: { name: "HANDLER_ERROR", cause: { info: {}, name: "INVALID_TRANSACTION" }, code: -32000, message: "Server error", data: { TxExecutionError: { InvalidTxError: { InvalidNonce: { ak_nonce: 9, tx_nonce: 9 } } } } }, id: "dontcare" };
    }
    const action = transaction.actions[0];
    const addKey = action?.addKey;
    const call = action?.functionCall;
    if (addKey !== undefined) {
      // Apply the key like the chain would, so a key created by addScopedKey can then sign calls.
      const permission = addKey.accessKey.permission.functionCall;
      this.addKey(transaction.receiverId, ed25519String(addKey.publicKey), permission === undefined
        ? "FullAccess"
        : { FunctionCall: { allowance: String(permission.allowance), receiver_id: permission.receiverId, method_names: permission.methodNames } });
    } else if (call !== undefined) {
      this.sent.push({
        signerId: transaction.signerId,
        receiverId: transaction.receiverId,
        publicKey: transaction.publicKey.toString(),
        methodName: call.methodName,
        args: Buffer.from(call.args).toString("utf8"),
        argsBytes: Uint8Array.from(call.args),
        deposit: BigInt(call.deposit),
        gas: BigInt(call.gas),
      });
    } else {
      throw new Error("the fake chain only understands function calls and AddKey");
    }
    this.#nonce += 1;
    this.receivedTransactions.push(signedTxBase64);
    this.#landed.add(id);
    return ok({
      final_execution_status: "FINAL",
      status: { SuccessValue: "" },
      transaction: { signer_id: transaction.signerId, receiver_id: transaction.receiverId, hash: id },
      transaction_outcome: { id, block_hash: BLOCK_HASH, outcome: { logs: [], receipt_ids: [], gas_burnt: 0, tokens_burnt: "0", executor_id: transaction.signerId, status: { SuccessReceiptId: id } }, proof: [] },
      receipts_outcome: [],
    });
  }
}

/** The decoded AddKey public key is a plain borsh object at runtime, not a PublicKey; the fake handles ed25519 only. */
function ed25519String(publicKey: PublicKey): string {
  const data = publicKey.ed25519Key?.data;
  if (data === undefined) throw new Error("the fake chain only understands ed25519 keys");
  // borsh decodes fixed-size arrays to plain arrays
  return `ed25519:${baseEncode(Uint8Array.from(data))}`;
}

/** Stand-in wasm: the guard only hashes the bytes, so a labelled blob is enough to give each contract its own hash. */
export function fakeWasm(label: string): Uint8Array {
  return Buffer.concat([Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]), Buffer.from(label)]);
}
