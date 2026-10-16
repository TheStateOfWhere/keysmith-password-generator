import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

class Element {
  children = []; listeners = new Map(); attributes = new Map(); value = ''; checked = false; disabled = false; text = '';
  classList = { toggle() {} };
  get valueAsNumber() { return Number(this.value); }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.text = String(value); this.children = []; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  dispatch(type) { this.listeners.get(type)?.({ preventDefault() {} }); }
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('password styling permits native partial selection and inline component boundaries', async () => {
  const css = await readFile(new URL('../dist/styles.css', import.meta.url), 'utf8');
  const style = /\.password\{([^}]+)\}/.exec(css)[1];
  assert.match(style, /user-select:text/);
  assert.match(css, /\.password\{display:block\}/);
  assert.doesNotMatch(css, /user-select\s*:\s*all/);
});

test('component, full and all copies are exact; failures and stale completions give safe feedback', async () => {
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  const elements = new Map(ids.map(id => [id, new Element()]));
  const get = id => elements.get(id);
  get('profile').value = 'readable';
  get('count').value = '1'; get('suffix').value = '6'; get('min-word').value = '4'; get('max-word').value = '12'; get('show').checked = true;
  const saved = new Map(['document', 'window', 'navigator', 'isSecureContext', 'crypto'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const writes = [];
  let fail = false, pending = null, selectionTouches = 0, randomIndex = 0;
  // Public deterministic fixture randomness: no real generated secrets in test reports.
  const fixtureRandom = [0, 0, 0, 0, 8, 0, 8, 0, 8];
  const clipboard = { async writeText(value) {
    if (fail) throw new Error('Fixture clipboard denied');
    if (pending) await pending;
    writes.push(value);
  } };
  const globals = {
    document: { getElementById: get, createElement: () => new Element(), getSelection() { selectionTouches++; } },
    window: { addEventListener() {}, getSelection() { selectionTouches++; } },
    navigator: { clipboard }, isSecureContext: true,
    crypto: { getRandomValues(buffer) { buffer[0] = fixtureRandom[randomIndex++ % fixtureRandom.length]; return buffer; } },
  };
  for (const [key, value] of Object.entries(globals)) Object.defineProperty(globalThis, key, { configurable: true, value });
  try {
    await import('../dist/app.js?copy-regression');
    get('settings-form').dispatch('submit');
    const row = get('passwords').children[0];
    const [top, text, disclosure] = row.children;
    const controls = disclosure.children[1];
    assert.equal(disclosure.children[0].textContent, "Copy a word or suffix");
    const original = text.textContent, parts = original.split('.');
    assert.equal(parts.length, 4);
    assert.ok(!/\s/.test(original), 'Fixture rendering must contain no whitespace');
    assert.equal(text.children.length, 4);
    assert.equal(text.children.flatMap(child => child.children).filter(child => child.className === 'dot').length, 3);
    // Password text and its spans have no click/double-click/pointer/selection handlers.
    assert.equal(text.listeners.size, 0);
    for (const child of text.children) assert.equal(child.listeners.size, 0);
    assert.equal(controls.children.length, 4);
    assert.equal(controls.attributes.get('role'), 'group');
    for (let i = 0; i < 4; i++) {
      const button = controls.children[i];
      assert.equal(button.type, 'button');
      assert.equal(button.attributes.get('aria-label'), `Copy ${i === 3 ? 'suffix' : `word ${i + 1}`} of password 1`);
      button.dispatch('click'); await settle();
      assert.ok(writes.at(-1) === parts[i], 'Component clipboard must match exactly');
      assert.match(get('status').textContent, /^Copied\./);
      assert.ok(get('status').textContent.includes(`${i === 3 ? 'Suffix' : `Word ${i + 1}`} of password 1 copied.`));
      assert.ok(!get('status').textContent.includes(parts[i]), 'Feedback omits copied value.');
    }
    top.children[1].dispatch('click'); await settle();
    assert.ok(writes.at(-1) === original, 'Full clipboard must preserve case, separators and suffix');
    assert.match(get('status').textContent, /Password 1 copied\./);
    get('manual').checked = true; get('manual').dispatch('change');
    assert.ok(get('passwords').children[0].children[1].textContent === original, 'Manual mode must preserve exact text');
    get('show').checked = false; get('show').dispatch('change');
    assert.ok(!get('passwords').textContent.includes(original), 'Hidden rendering must not expose the fixture');
    get('passwords').children[0].children[2].children[1].children[3].dispatch('click'); await settle();
    assert.ok(writes.at(-1) === parts[3], 'Hidden suffix copy must still be exact');
    get('show').checked = true; get('show').dispatch('change');
    get('count').value = '5'; get('count').dispatch('input'); get('settings-form').dispatch('submit');
    const all = get('passwords').children.map(row => row.children[1].textContent).join('\n');
    get('copy-all').dispatch('click'); await settle();
    assert.ok(writes.at(-1) === all, 'Copy All must preserve exactly one newline between passwords');
    assert.match(get('status').textContent, /All passwords copied\./);
    const currentControls = get('passwords').children[0].children[2].children[1];
    fail = true; const successfulWrites = writes.length;
    currentControls.children[0].dispatch('click'); await settle();
    assert.equal(writes.length, successfulWrites);
    assert.match(get('status').textContent, /^Clipboard unavailable\./);
    assert.ok(!get('status').textContent.includes(original), 'Feedback must not contain password text');
    get('passwords').children[0].children[0].children[1].dispatch('click'); await settle();
    assert.match(get('status').textContent, /^Clipboard unavailable\./);
    fail = false;
    Object.defineProperty(globalThis, 'isSecureContext', { configurable: true, value: false });
    currentControls.children[1].dispatch('click'); await settle();
    assert.equal(writes.length, successfulWrites);
    assert.match(get('status').textContent, /^Clipboard unavailable\./);
    Object.defineProperty(globalThis, 'isSecureContext', { configurable: true, value: true });
    globals.navigator.clipboard = undefined;
    currentControls.children[2].dispatch('click'); await settle();
    assert.match(get('status').textContent, /^Clipboard unavailable\./);
    globals.navigator.clipboard = clipboard;
    let finish;
    pending = new Promise(resolve => { finish = resolve; });
    currentControls.children[0].dispatch('click'); await settle();
    assert.doesNotMatch(get('status').textContent, /^Copied\./);
    get('clear').dispatch('click');
    finish(); await settle();
    assert.match(get('status').textContent, /^Passwords cleared/);
    assert.equal(selectionTouches, 0);
  } finally {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else delete globalThis[key];
    }
  }
});
