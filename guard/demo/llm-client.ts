// A strict client for a language model served through the OpenAI-compatible chat completions API.
// Nothing the model says is trusted except the tool calls it proposes, and those only after the checks below.
// Two kinds of endpoint: plain HTTP on this machine (a loopback address, no credentials), or HTTPS anywhere, where an
// API key from the environment is sent as a bearer token and nowhere else. No redirects, no proxy, bounded time and size.
import { request as httpRequest, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

export class LlmError extends Error {}

export interface LlmConfig {
  /** `http` only for a loopback address; `https` for any host. */
  protocol: "http" | "https";
  /** Host and port, parsed from `PREFLIGHT_LLM_ENDPOINT`. */
  host: string;
  port: number;
  /** The path the chat completions request goes to: the endpoint's own path prefix (https only) plus `/v1/chat/completions`. */
  path: string;
  /** The API key from `PREFLIGHT_LLM_API_KEY`, https only. It is sent as a bearer token and never printed, logged or recorded. */
  apiKey?: string;
  /** The model id the caller asked for. An answer from any other model is rejected. */
  model: string;
  timeoutMs: number;
}

export interface ToolCall {
  id: string;
  name: string;
  /** The model's argument text exactly as it sent it. */
  arguments: string;
}

export interface ModelTurn {
  content: string | null;
  toolCalls: ToolCall[];
}

export type Message = Record<string, unknown>;

const PATH = "/v1/chat/completions";
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_TOOL_CALLS = 8;
const MAX_ID_LENGTH = 200;

const MAX_KEY_LENGTH = 512;

/**
 * `http://127.0.0.1:18020` (or `[::1]`, or any 127.x.x.x address) or `https://<host>[:port][/path prefix]` becomes a
 * host, port and path; anything else throws. Plain http to any other host is refused: nothing goes off this machine in
 * the clear. A key is accepted only with https.
 */
export function parseEndpoint(raw: string, model: string, timeoutMs = 180_000, apiKey?: string): LlmConfig {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new LlmError("PREFLIGHT_LLM_ENDPOINT is not a URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new LlmError("PREFLIGHT_LLM_ENDPOINT must be an http:// URL on this machine or an https:// URL");
  if (url.username !== "" || url.password !== "") throw new LlmError("PREFLIGHT_LLM_ENDPOINT must not carry credentials; the API key goes in PREFLIGHT_LLM_API_KEY");
  if (url.search !== "" || url.hash !== "") throw new LlmError("PREFLIGHT_LLM_ENDPOINT must not carry a query or a fragment");
  const host = url.hostname.startsWith("[") ? url.hostname.slice(1, -1) : url.hostname;
  if (model === "" || model.length > 200) throw new LlmError("PREFLIGHT_LLM_MODEL must be a model id of 1 to 200 characters");
  const prefix = url.pathname === "/" ? "" : url.pathname.replace(/\/$/, "");
  if (url.protocol === "https:") {
    if (apiKey !== undefined && (apiKey.length > MAX_KEY_LENGTH || !/^[\x21-\x7e]+$/.test(apiKey))) throw new LlmError(`PREFLIGHT_LLM_API_KEY must be 1 to ${MAX_KEY_LENGTH} printable characters with no spaces`);
    return { protocol: "https", host, port: url.port === "" ? 443 : Number(url.port), path: `${prefix}${PATH}`, model, timeoutMs, ...(apiKey !== undefined && { apiKey }) };
  }
  const loopback = (isIP(host) === 4 && host.startsWith("127.")) || host === "::1";
  if (!loopback) throw new LlmError("a plain http:// PREFLIGHT_LLM_ENDPOINT must be a loopback address (an IP literal such as 127.0.0.1 or [::1]); use https:// for a remote server");
  if (prefix !== "") throw new LlmError(`PREFLIGHT_LLM_ENDPOINT is the server's base address only; the demo adds ${PATH}`);
  if (url.port === "") throw new LlmError("PREFLIGHT_LLM_ENDPOINT needs an explicit port other than 80");
  if (apiKey !== undefined) throw new LlmError("PREFLIGHT_LLM_API_KEY is set but the endpoint is plain http: a key is only sent over https");
  return { protocol: "http", host, port: Number(url.port), path: PATH, model, timeoutMs };
}

/** How the run's printout names the server: a loopback server is "locally run", an https one is named by host. Never the key. */
export const describeEndpoint = (config: LlmConfig): string =>
  config.protocol === "http" ? `a locally run language model, ${config.host}:${config.port}` : `a language model served over https at ${config.host}:${config.port}`;

/** The request exactly as it goes out, so the one place a key is attached can be tested without a server. */
export function requestOptions(config: LlmConfig, body: string): { options: RequestOptions & { headers: Record<string, string | number> }; tls: boolean } {
  const headers: Record<string, string | number> = { "content-type": "application/json", "content-length": Buffer.byteLength(body) };
  if (config.protocol === "https" && config.apiKey !== undefined) headers["authorization"] = `Bearer ${config.apiKey}`;
  return { options: { host: config.host, port: config.port, path: config.path, method: "POST", headers, timeout: config.timeoutMs }, tls: config.protocol === "https" };
}

function post(config: LlmConfig, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const { options, tls } = requestOptions(config, body);
    const req = (tls ? httpsRequest : httpRequest)(
      options,
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy(new LlmError(`the model server's answer is over ${MAX_RESPONSE_BYTES} bytes`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode !== 200) reject(new LlmError(`the model server answered HTTP ${res.statusCode}`));
          else resolve(text);
        });
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new LlmError(`the model server did not answer within ${config.timeoutMs} ms`)));
    req.on("error", (error) => reject(error instanceof LlmError ? error : new LlmError(`cannot reach the model server: ${error.message}`)));
    req.end(body);
  });
}

/** A short rendering of a value the server sent, for an error message. */
const shown = (value: unknown): string => (JSON.stringify(value) ?? "nothing").slice(0, 100);
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** One chat completion. Throws `LlmError` for any answer that is not exactly a finished assistant message from the requested model. */
export async function complete(config: LlmConfig, messages: Message[], tools: unknown[]): Promise<ModelTurn> {
  const text = await post(config, JSON.stringify({ model: config.model, messages, tools, tool_choice: "auto", max_tokens: 4096, stream: false }));
  let answer: unknown;
  try {
    answer = JSON.parse(text);
  } catch {
    throw new LlmError("the model server's answer is not JSON");
  }
  if (!isObject(answer)) throw new LlmError("the model server's answer is not a JSON object");
  if (answer["model"] !== config.model) throw new LlmError(`the server answered as model ${shown(answer["model"])}, not the requested ${JSON.stringify(config.model)}; answer rejected`);
  const choice = Array.isArray(answer["choices"]) ? answer["choices"][0] : undefined;
  if (!isObject(choice) || !isObject(choice["message"])) throw new LlmError("the answer has no assistant message");
  if (choice["finish_reason"] !== "stop" && choice["finish_reason"] !== "tool_calls") throw new LlmError(`the model's answer did not finish (finish_reason ${shown(choice["finish_reason"])})`);
  const message = choice["message"];
  if (message["role"] !== "assistant") throw new LlmError("the answer's message is not from the assistant");
  const content = message["content"];
  if (content !== null && content !== undefined && typeof content !== "string") throw new LlmError("the message content is neither text nor null");
  const rawCalls = message["tool_calls"] ?? [];
  if (!Array.isArray(rawCalls) || rawCalls.length > MAX_TOOL_CALLS) throw new LlmError(`tool_calls is not a list of at most ${MAX_TOOL_CALLS}`);
  const toolCalls = rawCalls.map((raw): ToolCall => {
    const fn = isObject(raw) ? raw["function"] : undefined;
    if (!isObject(raw) || !isObject(fn) || raw["type"] !== "function") throw new LlmError("a tool call is not a function call object");
    const { id } = raw;
    if (typeof id !== "string" || id === "" || id.length > MAX_ID_LENGTH) throw new LlmError("a tool call has no usable id");
    if (typeof fn["name"] !== "string" || typeof fn["arguments"] !== "string") throw new LlmError("a tool call's name or arguments are not text");
    return { id, name: fn["name"], arguments: fn["arguments"] };
  });
  return { content: typeof content === "string" ? content : null, toolCalls };
}
