// Reads a public GitHub repository into the file list the scanner takes: two api.github.com requests (the commit the
// ref points at, then that commit's file list) and one raw.githubusercontent.com request per file, all pinned to that
// commit so one scan never mixes two pushes. No token, so GitHub's limit of 60 API requests per hour per IP applies
// (a scan costs 2). Everything that comes back is untrusted text; this module only returns it.
import { plural } from './report.js';

export const LIMITS = { rustFiles: 300, manifests: 100, totalBytes: 4 * 1024 * 1024, fileBytes: 1024 * 1024 };
const PARALLEL = 6;
const TIMEOUT_MS = 20_000;
const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com';

/** A problem with the request or with GitHub's answer; `message` is written for the person who typed the repo. */
export class GitHubError extends Error {}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._\/-]{1,200}$/;
const SEGMENT = /^(?!\.{1,2}$)[^\\\u0000-\u001F\u007F]+$/u;

/** Turns the three form fields into a checked `{ owner, repo, ref, path }`; throws `GitHubError` naming the field. */
export function parseSpec({ repo, ref = '', path = '' }) {
  const text = repo.trim().replace(/^https:\/\/github\.com\//i, '').replace(/\/+$/, '').replace(/\.git$/i, '');
  const [owner, name, ...extra] = text.split('/');
  if (!OWNER.test(owner ?? '') || !REPO.test(name ?? '') || extra.length) {
    throw new GitHubError('Repository: enter it as owner/repo, for example near/near-sdk-rs.');
  }
  const branch = ref.trim() || 'HEAD';
  if (!REF.test(branch) || branch.includes('..') || branch.startsWith('/') || branch.endsWith('/')) {
    throw new GitHubError('Branch, tag or commit: use letters, digits, ".", "_", "-" and "/", or leave it empty for the default branch.');
  }
  const segments = path.split('/').map((s) => s.trim()).filter(Boolean);
  if (!segments.every((s) => SEGMENT.test(s))) {
    throw new GitHubError('Sub-path: enter a folder inside the repository, such as examples/lockable-fungible-token.');
  }
  return { owner, repo: name, ref: branch, path: segments.join('/') };
}

/** The report's target label: `owner/repo@ref:path`, with the ref and path left out when they were not given. */
export const describeSpec = ({ owner, repo, ref, path }) =>
  `${owner}/${repo}${ref === 'HEAD' ? '' : `@${ref}`}${path ? `:${path}` : ''}`;

const encodePath = (path) => path.split('/').map(encodeURIComponent).join('/');

/** Rust sources and manifests under `path`, relative to it, skipping `target` and dot directories as the CLI does. */
function candidates(tree, path) {
  const prefix = path ? `${path}/` : '';
  return tree
    .filter((entry) => entry.type === 'blob' && entry.mode !== '120000' && entry.path.startsWith(prefix))
    .map((entry) => ({ full: entry.path, path: entry.path.slice(prefix.length), size: entry.size ?? 0 }))
    .filter(({ path: rel }) => {
      const parts = rel.split('/');
      const name = parts.pop();
      return (name.endsWith('.rs') || name === 'Cargo.toml') && !parts.some((p) => p === 'target' || p.startsWith('.'));
    })
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/**
 * The `Cargo.toml` of each directory above `path`, nearest first, `null` where the repository has none (or it is over
 * the size limit, which `notes` then says): cargo takes the build profile from the workspace root, which is usually
 * above a sub-path, and the command line reads it from disk the same way.
 */
function ancestorManifests(tree, path, notes) {
  const blobs = new Map(tree.filter((e) => e.type === 'blob' && e.mode !== '120000').map((e) => [e.path, e.size ?? 0]));
  const parts = path ? path.split('/') : [];
  return parts.map((_, i) => {
    const dir = parts.slice(0, parts.length - 1 - i).join('/');
    const full = dir ? `${dir}/Cargo.toml` : 'Cargo.toml';
    if (!blobs.has(full)) return null;
    if (blobs.get(full) > LIMITS.fileBytes) {
      notes.push(`${full} is over ${LIMITS.fileBytes / 1048576} MB and was not read, so the build profile it sets was not seen.`);
      return null;
    }
    return { full };
  });
}

const NAMED = 10;
const names = (files) => files.slice(0, NAMED).map((f) => f.path).join(', ') + (files.length > NAMED ? `, and ${files.length - NAMED} more` : '');

/**
 * Applies the limits, in path order, manifests first so a large source tree cannot crowd them out: no file over
 * `fileBytes`, at most `manifests` manifests and `rustFiles` Rust files, `totalBytes` for everything. Returns what to
 * download and a sentence for everything left out.
 */
export function plan(files) {
  const notes = [];
  const isRust = (f) => f.path.endsWith('.rs');
  const manifests = files.filter((f) => !isRust(f));
  const rust = files.filter(isRust);
  let bytes = 0;
  const take = (list, cap) => list.filter((f) => {
    if (cap.count === 0 || f.size > LIMITS.fileBytes || bytes + f.size > LIMITS.totalBytes) return false;
    cap.count -= 1;
    bytes += f.size;
    return true;
  });
  const manifestsRead = take(manifests, { count: LIMITS.manifests });
  const rustRead = take(rust, { count: LIMITS.rustFiles });
  const tooBig = files.filter((f) => f.size > LIMITS.fileBytes);
  const left = (list, read) => list.length - read.length - tooBig.filter((f) => list.includes(f)).length;
  if (left(rust, rustRead) > 0) {
    notes.push(`Only ${rustRead.length} of ${rust.length} Rust files were read (the limit is ${LIMITS.rustFiles} files or ${LIMITS.totalBytes / 1048576} MB in all, in path order). The other ${left(rust, rustRead)} were not scanned. Enter a sub-path to scan the rest.`);
  }
  if (left(manifests, manifestsRead) > 0) {
    notes.push(`Only ${manifestsRead.length} of ${manifests.length} Cargo.toml files were read (the limit is ${LIMITS.manifests} files, within the same ${LIMITS.totalBytes / 1048576} MB).`);
  }
  if (tooBig.length) {
    notes.push(`${plural(tooBig.length, 'file')} ${tooBig.length === 1 ? 'is' : 'are'} over ${LIMITS.fileBytes / 1048576} MB and ${tooBig.length === 1 ? 'was' : 'were'} not read: ${names(tooBig)}.`);
  }
  return { download: [...manifestsRead, ...rustRead], notes };
}

function rateLimited(response, where) {
  const remaining = response.headers.get('x-ratelimit-remaining');
  if (remaining !== '0' && response.status !== 429) return null;
  const reset = Number(response.headers.get('x-ratelimit-reset'));
  const when = reset > 0 ? ` It resets at ${new Date(reset * 1000).toLocaleTimeString()}.` : ' Try again in a few minutes.';
  const limit = where === 'api.github.com' ? ' (GitHub allows 60 requests per hour without a sign-in, and a scan uses 2)' : '';
  return new GitHubError(`${where} is rate-limiting this connection${limit}.${when}`);
}

/** Git submodules (`type: commit`) under `path`: their code lives in another repository, so the tree has no files for them. */
const submodules = (tree, path) => tree.filter((e) => e.type === 'commit' && e.path.startsWith(path ? `${path}/` : ''));

function statusError(response, where, label) {
  const limited = rateLimited(response, where);
  if (limited) return limited;
  if (response.status === 404) return new GitHubError(`${label} was not found. Check the owner, repository and branch; private repositories cannot be read.`);
  if (response.status === 409) return new GitHubError(`${label} is an empty repository.`);
  return new GitHubError(`${where} answered ${response.status} for ${label}.`);
}

/**
 * Reads the repository. Returns `{ target, files: [{ path, text }], above, notes }`: `files` and `above` are what
 * `scanner.scan` takes, and `notes` lists every limit that left something out. Throws `GitHubError` for anything the person can act on.
 */
export async function fetchRepo(input, { fetch: fetchImpl = fetch, signal, onProgress = () => {} } = {}) {
  const spec = parseSpec(input);
  const label = describeSpec(spec);
  const failed = new AbortController();
  // One request, its status and its body, all under one timeout. Every way it can go wrong ends as a GitHubError (or
  // the caller's own abort), so nothing a hostile or flaky answer does reaches the page as a raw exception.
  const get = async (url, where, read) => {
    try {
      const signals = [failed.signal, AbortSignal.timeout(TIMEOUT_MS), ...(signal ? [signal] : [])];
      const response = await fetchImpl(url, { credentials: 'omit', signal: AbortSignal.any(signals) });
      if (!response.ok) throw statusError(response, where, label);
      return await response[read]();
    } catch (error) {
      if (error instanceof GitHubError || signal?.aborted) throw error;
      if (error.name === 'TimeoutError') throw new GitHubError(`${where} did not answer within ${TIMEOUT_MS / 1000} seconds.`);
      if (error instanceof SyntaxError) throw new GitHubError(`${where} sent an answer for ${label} that this page cannot read.`);
      throw new GitHubError(`Could not reach ${where}. Check the connection; a blocker may also be stopping requests to it.`);
    }
  };
  const unreadable = () => new GitHubError(`api.github.com sent an answer for ${label} that this page cannot read.`);

  onProgress('Finding the commit');
  const commit = await get(`${API}/repos/${spec.owner}/${spec.repo}/commits/${encodePath(spec.ref)}`, 'api.github.com', 'json');
  const sha = commit?.sha;
  if (typeof sha !== 'string' || !/^[0-9a-f]{40,64}$/.test(sha)) throw unreadable();

  onProgress('Reading the file list');
  const listing = await get(`${API}/repos/${spec.owner}/${spec.repo}/git/trees/${sha}?recursive=1`, 'api.github.com', 'json');
  const wellFormed = (e) => e && typeof e.path === 'string' && typeof e.type === 'string' && (e.size === undefined || Number.isFinite(e.size));
  if (!Array.isArray(listing?.tree) || !listing.tree.every(wellFormed)) throw unreadable();

  const found = candidates(listing.tree, spec.path);
  if (!found.some((f) => f.path.endsWith('.rs'))) {
    throw new GitHubError(`${label} has no Rust files${spec.path ? ' in that folder. Check the sub-path, or leave it empty to scan the whole repository' : ''}.`);
  }
  const { download, notes } = plan(found);
  if (listing.truncated) notes.unshift('GitHub cut the file list of this repository short, so some files may be missing from the scan. Enter a sub-path to narrow it.');
  const skipped = submodules(listing.tree, spec.path);
  if (skipped.length) notes.push(`Skipped ${plural(skipped.length, 'Git submodule')}, whose code lives in another repository: ${names(skipped)}.`);

  const ancestors = ancestorManifests(listing.tree, spec.path, notes);
  const jobs = [...download, ...ancestors.filter(Boolean)];
  const texts = new Array(jobs.length);
  let next = 0;
  let done = 0;
  const worker = async () => {
    try {
      while (next < jobs.length) {
        const index = next++;
        const url = `${RAW}/${spec.owner}/${spec.repo}/${sha}/${encodePath(jobs[index].full)}`;
        texts[index] = await get(url, 'raw.githubusercontent.com', 'text');
        onProgress(`Downloading files (${++done} of ${jobs.length})`);
      }
    } catch (error) {
      failed.abort();
      throw error;
    }
  };
  onProgress(`Downloading files (0 of ${jobs.length})`);
  await Promise.all(Array.from({ length: Math.min(PARALLEL, jobs.length) }, worker));
  const files = download.map(({ path }, i) => ({ path, text: texts[i] }));
  let nextAbove = download.length;
  const above = ancestors.map((manifest) => (manifest ? texts[nextAbove++] : null));
  return { target: label, files, above, notes };
}
