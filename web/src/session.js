// What the page does when a scan starts, finishes or fails, apart from how it looks (`view`), so it can be tested
// without a browser. Rules: the newest scan owns the result pane, so starting one ends the GitHub scan in flight and
// drops anything an older scan finishes later; the pane is replaced with "Scanning ..." at once, so an old result is
// never read as the new one's; and every way a scan can end is shown as a result or a problem, except being replaced.
import { fetchRepo, GitHubError } from './github.js';
import { ScanCancelled } from './scan-client.js';
import { ScanFailed } from './scanner.js';

const UNREADABLE_HINT = 'Preflight reports a file it cannot parse instead of skipping it, so a scan never quietly covers less than you gave it.';

/** `[title, problems, hint]` for the problem pane, or `null` for a scan that was replaced by a newer one. */
export function describeFailure(error) {
  if (error instanceof ScanCancelled) return null;
  if (error instanceof GitHubError) return ['GitHub could not be read', [error.message]];
  if (error instanceof ScanFailed) return ['The scan could not finish', [error.message], UNREADABLE_HINT];
  return ['The page hit an unexpected error', [`${error?.name}: ${error?.message}`], 'This is a bug in this page, not a verdict on the code.'];
}

/**
 * `scanner.scan(request, { signal })` runs a scan; `view` has `pending(label)`, `report(report, { chip, notes })`,
 * `problem(title, problems, hint)`, `progress(text)` and `running(on)`.
 */
export function createSession({ scanner, view, readRepo = fetchRepo }) {
  let latest = 0;
  let controller = null;

  function begin(label) {
    const ticket = ++latest;
    controller?.abort();
    if (label) view.pending(label);
    return () => ticket === latest;
  }
  const fail = (error) => {
    const failure = describeFailure(error);
    if (failure) view.problem(...failure);
  };

  return {
    /** Shows a problem with the input itself; it still replaces whatever scan was running. */
    refuse(title, problems) {
      begin();
      view.problem(title, problems);
    },

    async source(request, chip) {
      const mine = begin();
      try {
        const report = await scanner.scan(request);
        if (mine()) view.report(report, { chip });
      } catch (error) {
        if (mine()) fail(error);
      }
    },

    async github(input) {
      const mine = begin(input.repo.trim() || 'the repository');
      const own = new AbortController();
      controller = own;
      view.running(true);
      try {
        const read = await readRepo(input, { signal: own.signal, onProgress: (text) => { if (mine()) view.progress(text); } });
        if (mine()) view.progress('Scanning');
        const report = await scanner.scan({ target: read.target, files: read.files, above: read.above }, { signal: own.signal });
        if (mine()) view.report(report, { chip: 'GitHub', notes: read.notes });
      } catch (error) {
        if (!mine()) return;
        if (own.signal.aborted) view.problem('Scan cancelled', ['The scan was stopped before it finished, so there is no result.']);
        else fail(error);
      } finally {
        if (controller === own) {
          controller = null;
          view.running(false);
        }
      }
    },

    cancel() {
      controller?.abort();
    },
  };
}
