#!/usr/bin/env bash
# Read-only, no keys: the switch's status, the chameleon's code hash on chain, and what two kinds of check decide
# about it. Needs Node.js 22.22.2 or newer and network access to testnet; installs the dependencies of this directory
# and of the guard (whose `checkContract` it runs) from their lockfiles on first use. Run it, flip the chameleon on the web page (or with `npm run flip`), run it again.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$here/../../guard"
for dir in "$guard" "$here"; do
  [ -d "$dir/node_modules/near-api-js" ] || npm --prefix "$dir" ci --no-audit --no-fund >&2
done
exec node --disable-warning=ExperimentalWarning "$here/scripts/check.ts" "$@"
