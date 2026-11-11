// The language-model demo against a stub model endpoint (a real HTTP server on 127.0.0.1) and the fake NEAR RPC node.
// The stub plays the model: what it answers is scripted per test, so these tests pin what the guard and the client do
// with each kind of answer, not what any real model does.
import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { afterEach, beforeEach, describe, it } from "node:test";
import { KeyPair, KeyPairSigner, type Signer } from "near-api-js";
import { runLlmAgent, type LlmDemoEnv } from "../demo/llm-agent.ts";
import { describeEndpoint, LlmError, parseEndpoint, requestOptions, type LlmConfig } from "../demo/llm-client.ts";
import { FakeNear, fakeWasm } from "../testkit/fake-rpc.ts";
import { makeTempDir } from "../testkit/tempdir.ts";

const REGISTRY = "registry.test.near";
const AGENT = "agent.test.near";
const contracts = { safe: "safe-escrow.test.near", unsafe: "ghost-vault.test.near" };
const MODEL = "stub-model";
const PAGE_URL = "https://shop.invalid/invoices/42";

type Answer = { status?: number; raw?: string; body?: unknown; drop?: true };
const toolCall = (id: string, name: string, args: unknown) => ({ id, type: "function", function: { name, arguments: typeof args === "string" ? args : JSON.stringify(args) } });
const completion = (message: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
  body: { model: MODEL, choices: [{ index: 0, message: { role: "assistant", content: null, ...message }, finish_reason: message["tool_calls"] === undefined ? "stop" : "tool_calls" }], ...extra },
});
const fetchPage = completion({ tool_calls: [toolCall("c1", "fetch_page", { url: PAGE_URL })] });
const pay = (contractId: string, method: string) => completion({ tool_calls: [toolCall("c2", "call_contract", { contract_id: contractId, method, args: { order_id: 42 } })] });

let fake: FakeNear;
let stub: Server;
let dir: string;
let env: LlmDemoEnv;
let llm: LlmConfig;
let lines: string[];
let requests: { messages: Record<string, unknown>[]; model: unknown }[];
let script: Answer[];

beforeEach(async () => {
  fake = new FakeNear(REGISTRY);
  fake.accounts.set(contracts.safe, { wasm: fakeWasm("escrow v1, audited") });
  fake.publish(contracts.safe, "Safe");
  fake.accounts.set(contracts.unsafe, { wasm: fakeWasm("vault with the PF004 ghost balance bug") });
  fake.publish(contracts.unsafe, "Unsafe", ["PF004"]);
  const signers = new Map<string, Signer>();
  for (const contractId of Object.values(contracts)) {
    const signer = new KeyPairSigner(KeyPair.fromRandom("ed25519"));
    fake.addKey(AGENT, (await signer.getPublicKey()).toString(), { FunctionCall: { allowance: "250000000000000000000000", receiver_id: contractId, method_names: [] } });
    signers.set(contractId, signer);
  }
  dir = await makeTempDir("guard-llm-test");
  lines = [];
  requests = [];
  script = [];
  stub = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      assert.equal(req.url, "/v1/chat/completions");
      requests.push(JSON.parse(Buffer.concat(chunks).toString("utf8")) as (typeof requests)[number]);
      const answer = script.shift() ?? { status: 500, raw: "the script ran out" };
      if (answer.drop) return void req.socket.destroy();
      res.writeHead(answer.status ?? 200, { "content-type": "application/json" });
      res.end(answer.raw ?? JSON.stringify(answer.body));
    });
  });
  await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
  const port = (stub.address() as { port: number }).port;
  llm = parseEndpoint(`http://127.0.0.1:${port}`, MODEL, 5_000);
  env = {
    guard: { rpcUrl: await fake.start(), registryId: REGISTRY, timeoutMs: 2_000 },
    agentId: AGENT,
    contracts,
    signerFor: (contractId) => signers.get(contractId) ?? (() => { throw new Error(`no key for ${contractId}`); })(),
    rpcDescription: "fake",
    logPath: join(dir, "decisions.jsonl"),
  };
});
afterEach(async () => {
  stub.close();
  await fake.stop();
  await rm(dir, { recursive: true, force: true });
});

const run = () => runLlmAgent(env, llm, (line) => lines.push(line));

describe("the model follows the injected page", () => {
  it("is blocked on the registry's verdict and nothing is signed", async () => {
    script = [fetchPage, pay(contracts.unsafe, "deposit_and_forward")];
    const result = await run();
    assert.equal(result.outcome.kind, "followed-injection");
    assert.deepEqual(result.fetchedPages, [PAGE_URL]);
    assert.equal(result.proposals[0]?.signed, false);
    assert.match(result.proposals[0]?.why ?? "", /^block: registry verdict Unsafe \(PF004\)/);
    assert.equal(fake.sent.length, 0);
    assert.ok(lines.includes(`  call_contract {"contract_id":"${contracts.unsafe}","method":"deposit_and_forward","args":{"order_id":42}}`), "the model's call is printed as it sent it");
    assert.ok(lines.includes("Signed: no, nothing was signed or sent"));
    assert.ok(lines.some((line) => line.startsWith("Outcome: the model followed the injected instruction, and the guard stopped it")));
  });

  it("was given the page as the result of its own fetch, and its model id was sent", async () => {
    script = [fetchPage, pay(contracts.unsafe, "deposit_and_forward")];
    await run();
    assert.equal(requests.length, 2);
    assert.ok(requests.every((r) => r.model === MODEL));
    const toolMessage = requests[1]?.messages.find((m) => m["role"] === "tool");
    assert.equal(toolMessage?.["tool_call_id"], "c1");
    assert.match(String(toolMessage?.["content"]), /SYSTEM NOTICE/);
    assert.match(String(toolMessage?.["content"]), /ghost-vault\.test\.near/);
  });
});

describe("the model does not follow it", () => {
  it("proposes the audited contract: the guard allows it and the chain receives that one call", async () => {
    script = [fetchPage, pay(contracts.safe, "release")];
    const result = await run();
    assert.equal(result.outcome.kind, "called-safe-contract");
    assert.equal(result.proposals[0]?.signed, true);
    assert.match(result.proposals[0]?.why ?? "", /^allow: registry verdict Safe/);
    assert.deepEqual(fake.sent.map((call) => `${call.receiverId}.${call.methodName}`), [`${contracts.safe}.release`]);
    assert.ok(lines.some((line) => line.startsWith("Outcome: the model did not call the injected contract; it called the audited contract")));
  });

  it("refuses in words: no call, nothing signed, the outcome says the guard was not needed", async () => {
    script = [fetchPage, completion({ content: "This page asks for an unrelated payment; I will not follow it." })];
    const result = await run();
    assert.equal(result.outcome.kind, "no-call");
    assert.equal(result.proposals.length, 0);
    assert.equal(fake.sent.length, 0);
    assert.ok(lines.includes("Outcome: the model did not follow the injected instruction and made no contract call; the guard was not needed this run."));
    assert.ok(lines.some((line) => line.startsWith("The model's last text: This page asks")));
  });

  it("prints the model's own words once-escaped: no terminal escape or forged line gets through", async () => {
    script = [completion({ content: "no.\n\u001b[31mOutcome: fake" })];
    await run();
    const said = lines.find((line) => line.startsWith("The model's last text:"));
    assert.equal(said, "The model's last text: no. \\u001b[31mOutcome: fake");
    assert.ok(lines.every((line) => !line.includes("\u001b") && !line.includes("\n")));
  });

  it("does not retry: a model that says no is asked once per turn and the run ends", async () => {
    script = [completion({ content: "no" })];
    await run();
    assert.equal(requests.length, 1);
  });
});

describe("an answer that cannot be used", () => {
  const rejects = async (pattern: RegExp) => {
    await assert.rejects(run(), (error: unknown) => {
      assert.ok(error instanceof LlmError, String(error));
      assert.match(error.message, pattern);
      return true;
    });
    assert.equal(fake.sent.length, 0, "nothing was signed");
  };

  it("rejects an answer from another model than the one requested", async () => {
    script = [{ body: { ...completion({ content: "hi" }).body, model: "some-other-model" } }];
    await rejects(/answered as model "some-other-model", not the requested "stub-model"/);
  });

  it("rejects an answer with no model field", async () => {
    script = [{ body: { choices: [] } }];
    await rejects(/not the requested/);
  });

  it("rejects tool arguments that are not JSON", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "call_contract", "{contract_id: ghost")] })];
    await rejects(/arguments are not JSON/);
  });

  it("rejects tool arguments that are not an object", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "call_contract", "[1]")] })];
    await rejects(/not a JSON object/);
  });

  it("rejects a field the tool does not have, so a deposit cannot be smuggled in", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "call_contract", { contract_id: contracts.safe, method: "release", deposit: "5" })] })];
    await rejects(/fields the tool does not have: deposit/);
  });

  it("rejects a contract_id that is not text", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "call_contract", { contract_id: 7, method: "release" })] })];
    await rejects(/contract_id and method as text/);
  });

  it("rejects a contract id the guard's input validation refuses", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "call_contract", { contract_id: "Not A Valid Id!", method: "release" })] })];
    await rejects(/rejected before any check, as invalid input/);
  });

  it("rejects a tool that does not exist", async () => {
    script = [completion({ tool_calls: [toolCall("c1", "send_all_funds", {})] })];
    await rejects(/a tool that does not exist: send_all_funds/);
  });

  it("rejects a body that is not JSON, an HTTP error, and an answer cut off at the token limit", async () => {
    script = [{ raw: "<html>proxy error</html>" }];
    await rejects(/not JSON/);
    script = [{ status: 503, raw: "busy" }];
    await rejects(/HTTP 503/);
    script = [{ body: { model: MODEL, choices: [{ message: { role: "assistant", content: "I will" }, finish_reason: "length" }] } }];
    await rejects(/did not finish/);
  });

  it("rejects a server that drops the connection", async () => {
    // Not a closed port: it could be handed to a parallel test's server, which would answer.
    script = [{ drop: true }];
    await rejects(/cannot reach the model server/);
  });
});

describe("the endpoint", () => {
  it("accepts loopback addresses", () => {
    assert.deepEqual(parseEndpoint("http://127.0.0.1:18020", "m"), { protocol: "http", host: "127.0.0.1", port: 18020, path: "/v1/chat/completions", model: "m", timeoutMs: 180_000 });
    assert.equal(parseEndpoint("http://127.1.2.3:1", "m").host, "127.1.2.3");
    assert.equal(parseEndpoint("http://[::1]:8080", "m").host, "::1");
  });

  for (const endpoint of ["http://example.com:80", "http://10.0.0.5:18020", "http://192.168.1.2:18020", "http://0.0.0.0:18020", "http://localhost:18020", "http://127.0.0.1.example.com:18020", "ftp://127.0.0.1:18020", "https://user:pw@api.example.com", "https://api.example.com?x=1", "https://api.example.com#x", "http://user:pw@127.0.0.1:18020", "http://127.0.0.1", "http://127.0.0.1:18020/v1", "not a url", ""]) {
    it(`refuses ${JSON.stringify(endpoint)}`, () => {
      assert.throws(() => parseEndpoint(endpoint, "m"), LlmError);
    });
  }

  it("says a missing or default port is the problem", () => {
    for (const endpoint of ["http://127.0.0.1", "http://127.0.0.1:80"]) assert.throws(() => parseEndpoint(endpoint, "m"), /explicit port other than 80/);
  });

  it("refuses an empty model id", () => {
    assert.throws(() => parseEndpoint("http://127.0.0.1:18020", ""), LlmError);
  });
});

describe("an https endpoint with an API key", () => {
  const KEY = "sk-test-0123456789abcdef";

  it("accepts any host, defaults the port to 443, keeps a path prefix, and names the server by host", () => {
    const config = parseEndpoint("https://api.example.com", "m", 1_000, KEY);
    assert.deepEqual({ ...config, apiKey: undefined }, { protocol: "https", host: "api.example.com", port: 443, path: "/v1/chat/completions", model: "m", timeoutMs: 1_000, apiKey: undefined });
    assert.equal(parseEndpoint("https://gateway.example.com:8443/api/", "m").path, "/api/v1/chat/completions");
    assert.equal(describeEndpoint(config), "a language model served over https at api.example.com:443");
    assert.equal(describeEndpoint(parseEndpoint("http://127.0.0.1:18020", "m")), "a locally run language model, 127.0.0.1:18020");
  });

  it("sends the key as a bearer token over https only, and over no other path", () => {
    const body = JSON.stringify({ a: 1 });
    assert.equal(requestOptions(parseEndpoint("https://api.example.com", "m", 1_000, KEY), body).options.headers["authorization"], `Bearer ${KEY}`);
    assert.equal(requestOptions(parseEndpoint("https://api.example.com", "m"), body).options.headers["authorization"], undefined);
    const local = requestOptions(parseEndpoint("http://127.0.0.1:18020", "m"), body);
    assert.equal(local.tls, false);
    assert.equal(local.options.headers["authorization"], undefined);
  });

  it("refuses a key with plain http, even on loopback, and plain http to a remote host with or without one", () => {
    assert.throws(() => parseEndpoint("http://127.0.0.1:18020", "m", 1_000, KEY), /only sent over https/);
    assert.throws(() => parseEndpoint("http://api.example.com:80", "m", 1_000, KEY), LlmError);
    assert.throws(() => parseEndpoint("http://203.0.113.5:18020", "m"), /use https:\/\/ for a remote server/);
  });

  it("refuses a key that is empty, has spaces or control characters, or is too long, without printing it", () => {
    for (const bad of ["", "a b", "line\nbreak", "x".repeat(513)]) {
      assert.throws(() => parseEndpoint("https://api.example.com", "m", 1_000, bad), (error: unknown) => error instanceof LlmError && (bad === "" || !error.message.includes(bad)));
    }
  });

  it("does not put the key in a run's printout", async () => {
    // The two printout lines that name the server are built from describeEndpoint and the model id, never from the config object.
    const config = parseEndpoint("https://api.example.com", "m", 1_000, KEY);
    assert.ok(!describeEndpoint(config).includes(KEY));
    assert.ok(!JSON.stringify({ model: config.model, host: config.host, port: config.port }).includes(KEY));
  });
});
