// What the page needs from the repository besides the scanner: the bundled examples and where each rule's proof lives.
// Both are read from `fixtures/` and `exploits/` at build time, so nothing is copied by hand and a rule added later
// gets its proof links without a change here.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

// Single-file fixtures whose vulnerable version fires a rule that reads well at a glance, in display order.
export const EXAMPLES = ['pf001_callback', 'pf002_one_yocto', 'pf007_unguarded_admin', 'pf012_div_before_mul', 'pf020_uninitialized_default'];

const read = (path) => readFileSync(`${REPO_ROOT}${path}`, 'utf8');
const ruleId = (slug) => slug.slice(0, 5).toUpperCase();

/** `{ examples: [{ id, rule, vulnerable, patched }], proofs: { PF001: { fixture, exploit } } }` with repo-relative paths. */
export function siteData() {
  const proofs = {};
  for (const slug of readdirSync(`${REPO_ROOT}fixtures`).filter((name) => /^pf\d{3}_/.test(name)).sort()) {
    const exploit = `exploits/tests/${slug}.rs`;
    if (!existsSync(`${REPO_ROOT}${exploit}`)) throw new Error(`${exploit} is missing: fixtures/${slug} has no exploit test`);
    for (const variant of ['vulnerable', 'patched']) {
      if (!existsSync(`${REPO_ROOT}fixtures/${slug}/${variant}`)) throw new Error(`fixtures/${slug}/${variant} is missing`);
    }
    proofs[ruleId(slug)] = { fixture: `fixtures/${slug}`, exploit };
  }
  const examples = EXAMPLES.map((slug) => ({
    id: slug,
    rule: ruleId(slug),
    vulnerable: read(`fixtures/${slug}/vulnerable/src/lib.rs`),
    patched: read(`fixtures/${slug}/patched/src/lib.rs`),
  }));
  return { examples, proofs };
}
