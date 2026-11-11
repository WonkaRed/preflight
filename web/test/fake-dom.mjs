// A DOM stand-in for the tests: it records what a renderer builds and refuses every way of parsing markup.
export function fakeDocument() {
  const markup = () => { throw new Error('markup parsing is forbidden'); };
  const node = (tag) => {
    const el = { tag, attrs: {}, kids: [], setAttribute(k, v) { this.attrs[k] = v; }, append(...n) { this.kids.push(...n); }, replaceChildren(...n) { this.kids = n; }, addEventListener() {} };
    for (const name of ['innerHTML', 'outerHTML']) Object.defineProperty(el, name, { set: markup });
    el.insertAdjacentHTML = markup;
    return el;
  };
  return { createElement: node, createTextNode: (text) => ({ text }) };
}
export function walk(n, visit) { visit(n); (n.kids || []).forEach((k) => walk(k, visit)); }
