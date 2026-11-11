# Runs the whole test suite in a clean Linux image: `docker build -t preflight .`
# The build downloads the crates, the NEAR sandbox binary and the npm packages of guard/, so it needs network access.
# Debian 13 (trixie) rather than 12: the nearcore 2.14.0 sandbox binary needs glibc 2.39, bookworm has 2.36.
# Node for guard/ (its tests and typecheck) and web/: copied from the official Node 24 image, which is Debian 13 too,
# so the binary finds the libraries it was built against. Node 24 satisfies guard/package.json "engines" (>= 22.22.2);
# the tag gives the current 24.x. The two links are the ones the Node release
# tarball ships, as the official image's own Dockerfile installs it (github.com/nodejs/docker-node, 24/trixie-slim).
FROM node:24-trixie-slim AS node

FROM rust:1-trixie
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && node --version && npm --version

WORKDIR /preflight
COPY . .
# rust-toolchain.toml pins the compiler; rustup installs it (and the wasm32 target) on first use.
RUN make test
