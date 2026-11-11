// The one place the page learns where the Preflight repository lives. Every finding links its rule's fixture pair and
// sandbox exploit test as `${REPO_TREE_URL}/<path>`. A fork points this at its own tree; while it is empty the paths
// are shown as plain text instead of links that would 404.
export const REPO_TREE_URL = 'https://github.com/WonkaRed/preflight/tree/main';
