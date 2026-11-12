// Everything the Swap section at the top of the page needs to know about the demo contracts, in one place. While any
// of the account ids or the key is empty the section shows the bundled recording (swap-recorded.json, built from
// demo/swap/recorded.json) and says it is a recording, so an empty config never breaks the page.
export const SWAP_CONFIG = {
  // The NEAR testnet RPC endpoints, in order of preference. Every request tries them in turn, starting with the one that
  // answered last, because one endpoint throttles now and then (HTTP 429, which a browser reports as a CORS failure). Each
  // origin must also be in the page's connect-src (index.html), and must send Access-Control-Allow-Origin on its answers.
  rpcUrls: ['https://test.rpc.fastnear.com', 'https://near-testnet.drpc.org'],
  // Explorer for transaction and account links (`/tx/<hash>`, `/account/<id>`).
  explorerUrl: 'https://testnet.near.rocks',

  // The one address the page is about: its contract code flips between a vulnerable and a patched build.
  chameleonId: 'chameleon.preflight-guard.testnet',
  // The contract with `flip()` (it enforces a minimum time between flips) and the view `status()`.
  switchId: 'switch.preflight-guard.testnet',
  // The registry contract that holds a verdict for each of the two code hashes (`get_verdict`).
  registryId: 'registry.preflight-guard.testnet',

  // The key the browser signs `flip` with. It is PUBLIC ON PURPOSE: it is shipped to every visitor, so it must be a
  // function-call access key limited to `flip` on `switchId`, with a small gas allowance, on a testnet
  // account. Anyone who copies it can do exactly what the button does and no more; the worst a copier can do is spend the demo's gas
  // allowance. Never put any other key here.
  // The form NEAR prints: ed25519:<base58 of 64 bytes>.
  flipKey: 'ed25519:38CTPSHm2DunGh3YU8Yy6zPa3dAgZRZJNNMJRHXaG3CjmpvCaUcwLunSqUGYybrQ6ESK9fXNKB6bQ1hhRDBYAsk6',
  // The account that holds that key. Empty: the key is on `switchId` itself.
  flipSignerId: '',
  // Gas attached to each `flip`, in Tgas (10^12 gas). The switch needs at least 100; the key's allowance pays for the attached gas.
  flipGasTgas: 150,

  // The account "Rob it" signs as: a throwaway testnet account that holds nothing of value. Its full-access key never
  // leaves the owner's machine; only the scoped key below is embedded here.
  robberId: 'robber.preflight-guard.testnet',
  // The key the browser signs `on_deposit` with. PUBLIC ON PURPOSE, same rule as flipKey above: a function-call access
  // key limited to `on_deposit` on `chameleonId`, with a small gas allowance, on the throwaway account above. It can
  // attach no deposit (no function-call key ever can), so it can never call `withdraw` either. The worst a copier can
  // do is spend the demo's gas allowance forging the same bookkeeping credit the button already forges.
  robberKey: 'ed25519:2T25iixFv9Qoqff5qtyMQ3BzSfH23erHLugBSPk1gbZfxWAStBwmQYuQ84sgY9JtFKGMByLsYyKkvaVe1YGWBhtv',
  // Gas attached to each `on_deposit` call, in Tgas. `on_deposit` does far less work than `flip`; this is generous margin.
  robGasTgas: 30,
};
