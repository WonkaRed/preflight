// Shared by the tests: the built scanner module, the fixtures as scan requests, and the native CLI to compare with.
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { dirname } from 'node:path';
import { loadScanner } from '../src/scanner.js';
import { REPO_ROOT } from '../tools/site-data.mjs';

export const DIST = new URL('../dist/', import.meta.url);
export const scanner = loadScanner(await WebAssembly.compile(readFileSync(new URL('preflight.wasm', DIST))));

/** Every file under `dir` (relative to the repository root) as the scanner receives it: `[{ path, text }]`. */
export function filesUnder(dir, prefix = '') {
  return readdirSync(`${REPO_ROOT}${dir}`, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory()
      ? filesUnder(`${dir}/${entry.name}`, `${prefix}${entry.name}/`)
      : [{ path: `${prefix}${entry.name}`, text: readFileSync(`${REPO_ROOT}${dir}/${entry.name}`, 'utf8') }]);
}

export const fixtureDirs = () =>
  readdirSync(`${REPO_ROOT}fixtures`)
    .filter((name) => /^pf\d{3}_/.test(name))
    .flatMap((slug) => ['vulnerable', 'patched'].map((variant) => `fixtures/${slug}/${variant}`));

/** The `Cargo.toml` text of every directory above `dir`, nearest first, `null` where there is none: what the command line finds on disk. */
export function manifestsAbove(dir) {
  const above = [];
  for (let up = dirname(realpathSync(`${REPO_ROOT}${dir}`)); ; up = dirname(up)) {
    above.push(existsSync(`${up}/Cargo.toml`) ? readFileSync(`${up}/Cargo.toml`, 'utf8') : null);
    if (up === dirname(up)) return above;
  }
}

export const request = (dir) => ({ target: dir, files: filesUnder(dir), above: manifestsAbove(dir) });

let cli;
/** What `preflight --json <dir>` prints, run from the repository root exactly as a person would. Exit 1 means findings. */
export function cliJson(dir) {
  if (!cli) {
    execFileSync('cargo', ['build', '--locked', '--quiet', '-p', 'preflight'], { cwd: REPO_ROOT, env: { ...process.env, RUSTUP_TOOLCHAIN: '' }, stdio: 'inherit' });
    const meta = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--format-version', '1', '--no-deps'], { cwd: REPO_ROOT, maxBuffer: 64 << 20 }));
    cli = `${meta.target_directory}/debug/preflight`;
  }
  const run = spawnSync(cli, ['--json', dir], { cwd: REPO_ROOT, encoding: 'utf8' });
  if (run.status !== 0 && run.status !== 1) throw new Error(`preflight --json ${dir} exited ${run.status}: ${run.stderr}`);
  return run.stdout;
}
