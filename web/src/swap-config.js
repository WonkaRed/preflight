// Everything the Swap section at the top of the page needs to know about the demo contracts, in one place. While any
// of the account ids or the key is empty the section shows the bundled recording (swap-recorded.json, built from
// demo/swap/recorded.json) and says it is a recording, so an empty config never breaks the page.
export const SWAP_CONFIG = {
  // The NEAR testnet RPC the page reads and sends through. Its origin must also be in the page's connect-src (index.html).
  rpcUrl: 'https://test.rpc.fastnear.com',
  // Explorer for transaction and account links (`/tx/<hash>`, `/account/<id>`).
  explorerUrl: 'https://testnet.near.rocks',

  // The one address the page is about: its contract code flips between a vulnerable and a patched build.
  chameleonId: 'chameleon.preflight-guard.testnet',
  // The contract with `flip()` (at least 10 s between flips) and the view `status()`.
  switchId: 'switch.preflight-guard.testnet',
  // The registry contract that holds a verdict for each of the two code hashes (`get_verdict`).
  registryId: 'registry.preflight-guard.testnet',

  // The key the browser signs `flip` with. It is PUBLIC ON PURPOSE: it is shipped to every visitor, so it must be a
  // function-call access key limited to `flip` on `switchId`, with a small gas allowance, on a demo account that holds
  // nothing. Anyone who copies it can do exactly what the button does and no more. Never put any other key here.
  // The form NEAR prints: ed25519:<base58 of 64 bytes>.
  flipKey: 'ed25519:38CTPSHm2DunGh3YU8Yy6zPa3dAgZRZJNNMJRHXaG3CjmpvCaUcwLunSqUGYybrQ6ESK9fXNKB6bQ1hhRDBYAsk6',
  // The account that holds that key. Empty: the key is on `switchId` itself.
  flipSignerId: '',
  // Gas attached to each `flip`, in Tgas (10^12 gas). The switch needs at least 100; the key's allowance pays for the attached gas.
  flipGasTgas: 150,
};
