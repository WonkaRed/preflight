// claims.json is what `make verify` runs: it must parse, every README anchor in it must resolve, and the README's mainnet
// figures must be the ones docs/mainnet-sweep.md states.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { anchorsOf, loadClaims, recordedCalls } from '../../scripts/verify.mjs';

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), 'utf8');

test('claims.json parses and covers the claims the hackathon entry rests on', () => {
  const claims = loadClaims();
  const commands = claims.map((claim) => claim.command).join('\n');
  for (const wanted of ['testnet-verify', 'mcp-check', 'make -C guard demo', 'demo-llm-replay', 'make test']) assert.match(commands, new RegExp(wanted), wanted);
  assert.deepEqual(claims.filter((claim) => claim.needs.includes('rust')).map((claim) => claim.command), ['make test']);
});

test('every readme_anchor in claims.json is a heading of the README', () => {
  const anchors = anchorsOf(read('README.md'));
  for (const claim of loadClaims()) assert.ok(anchors.has(claim.readme_anchor), `${claim.id}: ${claim.readme_anchor} is not a README heading`);
});

test('anchorsOf slugs headings the way GitHub does', () => {
  const anchors = anchorsOf('# Preflight: verdicts keyed to the code, not the address\n## The 26 rules\n### `x` and A_b-c?\n');
  assert.deepEqual([...anchors], ['#preflight-verdicts-keyed-to-the-code-not-the-address', '#the-26-rules', '#x-and-a_b-c']);
});

test('the mainnet figures in the README are the doc\'s own table rows', () => {
  const readme = read('README.md');
  const sweep = read('docs/mainnet-sweep.md');
  assert.match(sweep, /^\| PFW01 \(medium\) \| The account holds at least one full-access key\..*\| 32 \| 22\.5% \|$/m);
  assert.match(sweep, /^\| PFW02 \(info\) \|.*\| 75 \| 52\.8% \|$/m);
  assert.match(sweep, /^## Results \(142 contracts checked\)$/m);
  assert.match(readme, /142 mainnet contracts \(\[docs\/mainnet-sweep\.md\]\(docs\/mainnet-sweep\.md\)\), 32 of them \(22\.5 percent\) held at least one full-access key.* 75 \(52\.8 percent\) exported/);
});

test('the recorded testnet calls parse: 24 calls, 2 turned back by the demo before the guard, 4 signed, none of them injected', () => {
  const calls = recordedCalls(read('docs/testnet-llm-runs.txt'));
  assert.equal(calls.length, 24);
  assert.equal(calls.filter((call) => call.verdict === 'none').length, 2);
  assert.deepEqual(calls.filter((call) => call.signed === 'yes').map((call) => call.contract), Array(4).fill('shop-patched.preflight-guard.testnet'));
  assert.throws(() => recordedCalls('x\nThe model\'s own tool call, verbatim:\n  call_contract {"contract_id": "a.testnet"}\n'), /no contract, verdict or Signed line/);
});
