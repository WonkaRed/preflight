// `npm run testnet-verify`: read-only, no keys. Checks the recorded deployment against the chain: every contract's code hash
// as the RPC reports it, the registry's verdict for each, the registry's allowlist and keys, the agent's keys (none full-access once the deployment record says its setup key was deleted), and what the guard decides
// about each shop right now. Prints one line per check (`OK` or `FAIL`; one `NOTE` line when a self-deployed agent still holds its setup key); exit status 0 when all pass, 1 when one fails, 3 when the chain
// could not be read.
//   npm run testnet-verify -- [--rpc <url>] [--deployment <file>] [--reports <dir>]
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { checkContract } from "../src/check.ts";
import { rpcQuery } from "../src/rpc.ts";
import { describeError, printable } from "../src/text.ts";
import { DEFAULT_DEPLOYMENT, DEFAULT_TESTNET_RPC, SHOP_ROLES, chainCodeHash, loadDeployment, viewJson } from "../demo/testnet-deployment.ts";

const USAGE = "usage: testnet-verify [--rpc <url>] [--deployment <file>] [--reports <dir>]";
let failures = 0;
const report = (ok: boolean, line: string): void => {
  if (!ok) failures += 1;
  console.log(printable(`${ok ? "OK" : "FAIL"}  ${line}`));
};
// A line that says what was expected and what was found, so "OK ... block" reads as "the guard blocked, as expected".
const expectation = (what: string, expected: string, got: string, detail = ""): void => report(expected === got, `${what}: expected ${expected}, got ${got}${detail}`);

try {
  const { values } = (() => {
    try {
      return parseArgs({ options: { rpc: { type: "string" }, deployment: { type: "string" }, reports: { type: "string" } }, strict: true });
    } catch (error) {
      console.error(`${printable(describeError(error))}\n${USAGE}`);
      return process.exit(2);
    }
  })();
  const rpc = values.rpc ?? process.env["PREFLIGHT_TESTNET_RPC"] ?? DEFAULT_TESTNET_RPC;
  const reports = values.reports ?? join(import.meta.dirname, "..", "..", "docs", "testnet-reports");
  const deployment = await loadDeployment(values.deployment ?? DEFAULT_DEPLOYMENT);
  const account = (role: string): string => deployment.accounts[role] ?? "";
  const registryId = account("registry");
  console.log(printable(`Preflight testnet deployment under ${deployment.parent}, read from ${rpc} (finality: final)`));

  for (const [label, role, hashKey] of [["registry", "registry", "registry"], ["shop-vulnerable", "vulnerable", "vulnerable"], ["shop-patched", "patched", "patched"], ["shop-swapped", "swapped", "swapped"]] as const) {
    const onChain = await chainCodeHash(rpc, account(role));
    report(onChain === deployment.codeHashes[hashKey], `${account(role)} (${label}) holds code ${onChain}, recorded ${deployment.codeHashes[hashKey]}`);
  }

  const auditors = await viewJson(rpc, registryId, "get_auditors", {});
  report(Array.isArray(auditors) && auditors.length === 1 && auditors[0] === account("auditor"), `registry allowlist is ${JSON.stringify(auditors)}`);
  const keys = await rpcQuery(rpc, { request_type: "view_access_key_list", finality: "final", account_id: registryId });
  report(Array.isArray(keys["keys"]) && keys["keys"].length === 0, `registry ${registryId} has ${Array.isArray(keys["keys"]) ? keys["keys"].length : "an unreadable number of"} access keys (none: nobody can redeploy it)`);

  const agentId = account("agent");
  type Held = { public_key: string; access_key: { permission: unknown } };
  const agentList = (await rpcQuery(rpc, { request_type: "view_access_key_list", finality: "final", account_id: agentId }))["keys"];
  const held = Array.isArray(agentList) ? (agentList as Held[]) : [];
  const functionCall = (key: Held): { receiver_id: string; method_names: string[] } | undefined => (key.access_key.permission as { FunctionCall?: { receiver_id: string; method_names: string[] } } | null)?.FunctionCall;
  const fullAccess = held.filter((key) => functionCall(key) === undefined).length;
  // `testnet-deploy` leaves the agent its setup full-access key (`--more-orders` needs it); only a record with the delete step promises none.
  const setupKeyDeleted = deployment.transactions.some((tx) => tx.step === "delete-agent-full-access-key");
  const allowedFullAccess = setupKeyDeleted ? 0 : 1;
  if (setupKeyDeleted) expectation(`the agent ${agentId}`, "no full-access key", fullAccess === 0 ? "no full-access key" : `${fullAccess} full-access key(s)`, ` (it holds ${held.length} access keys)`);
  else if (fullAccess > allowedFullAccess) report(false, `the agent ${agentId}: expected at most 1 full-access key (its setup key), got ${fullAccess}`);
  else console.log(`NOTE  the agent ${agentId} holds ${fullAccess} full-access key(s): this record has no delete-agent-full-access-key step, so its setup key is expected; the function-call keys are checked below as for any deployment`);
  const scopedKeys = (keys: string[]): string => JSON.stringify([...keys].sort());
  const compared = held.filter((key) => setupKeyDeleted || functionCall(key) !== undefined);
  report(
    scopedKeys(compared.map((key) => `${key.public_key} ${functionCall(key)?.method_names.join("+") || "any method"}@${functionCall(key)?.receiver_id ?? "full access"}`)) ===
      scopedKeys(SHOP_ROLES.map((role) => `${deployment.agentKeys[role]} release@${account(role)}`)),
    `the agent's ${setupKeyDeleted ? "access" : "function-call"} keys are exactly the ${SHOP_ROLES.length} recorded function-call keys, each limited to release on one shop`,
  );

  const expected = { vulnerable: "Unsafe", patched: "Safe" } as const;
  for (const role of ["vulnerable", "patched"] as const) {
    const hash = await chainCodeHash(rpc, account(role));
    const verdict = (await viewJson(rpc, registryId, "get_verdict", { code_hash: hash })) as { status?: string; rule_ids?: string[]; auditor?: string; code_hash?: string; report_sha256?: string } | null;
    report(verdict?.status === expected[role] && verdict.code_hash === hash, `registry verdict for the code on ${account(role)}: ${verdict === null ? "none" : `${verdict.status} ${(verdict.rule_ids ?? []).join(",")} by ${verdict.auditor}`}`);
    const reportFile = join(reports, `shop-${role}.json`);
    const reportSha = await readFile(reportFile).then((bytes) => createHash("sha256").update(bytes).digest("hex"), () => undefined);
    report(reportSha !== undefined && verdict?.report_sha256 === reportSha, `the verdict's report_sha256 ${verdict?.report_sha256 ?? "(no verdict)"} ${reportSha === undefined ? `cannot be compared: ${reportFile} is unreadable` : `${verdict?.report_sha256 === reportSha ? "is" : "is NOT"} the SHA-256 of ${reportFile}`}`);
  }
  const swappedHash = await chainCodeHash(rpc, account("swapped"));
  const swappedVerdict = await viewJson(rpc, registryId, "get_verdict", { code_hash: swappedHash });
  expectation(`registry verdict for the code now on ${account("swapped")} (${swappedHash})`, "no verdict", swappedVerdict === null ? "no verdict" : "a verdict", " (the code was swapped after its audit)");
  const audited = await viewJson(rpc, registryId, "get_verdict", { code_hash: deployment.codeHashes["swappedAudited"] ?? "" });
  expectation(`registry verdict for the build ${account("swapped")} held before the swap (${deployment.codeHashes["swappedAudited"]})`, "a verdict", audited === null ? "no verdict" : "a verdict");

  console.log("What the guard decides about each shop now (the expected decision, the one the guard gave, then its first reason):");
  const decisions = { vulnerable: "block", patched: "allow", swapped: "warn" } as const;
  for (const role of ["vulnerable", "patched", "swapped"] as const) {
    const result = await checkContract(account(role), { rpcUrl: rpc, registryId, timeoutMs: 20_000 });
    expectation(account(role), decisions[role], result.decision, ` (${result.reasons[0]})`);
  }
  console.log(failures === 0 ? "All checks passed." : `${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
} catch (error) {
  console.error(`testnet-verify failed: ${printable(describeError(error))}`);
  process.exit(3);
}
