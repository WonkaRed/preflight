// Assembles web/dist: the static page, the scanner compiled to WebAssembly, and the data generated from the repository.
// The folder is self-contained, so any static host can serve it as is. Run by `make -C web build`, after cargo has
// built the wasm module.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { REPO_ROOT, siteData } from './site-data.mjs';

const web = fileURLToPath(new URL('..', import.meta.url));
const dist = `${web}dist`;
const WASM = 'wasm32-unknown-unknown/web/preflight_web.wasm';

export const targetDir = () =>
  JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--format-version', '1', '--no-deps'], { cwd: REPO_ROOT, maxBuffer: 64 << 20 })).target_directory;

if (import.meta.url === `file://${process.argv[1]}`) {
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(dist);
  for (const name of readdirSync(`${web}src`)) copyFileSync(`${web}src/${name}`, `${dist}/${name}`);
  copyFileSync(`${targetDir()}/${WASM}`, `${dist}/preflight.wasm`);
  writeFileSync(`${dist}/site-data.json`, JSON.stringify(siteData()));
}
