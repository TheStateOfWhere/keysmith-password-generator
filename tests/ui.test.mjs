import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { DEFAULTS, eligibleWords, meetsEntropyPolicy } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';

// Exercise the real application event handlers with a minimal DOM surface.
// This validates policy interaction; it is not visual/browser layout testing.
class Element {
  children = []; listeners = new Map(); value = ''; checked = false; disabled = false; text = '';
  classList = { toggle() {} };
  get valueAsNumber() { return this.value === '' ? NaN : Number(this.value); }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.text = String(value); this.children = []; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.text = ''; this.children = children; }
  setAttribute() {}
  addEventListener(type, fn) { this.listeners.set(type, fn); }
  dispatch(type, fields = {}) { this.listeners.get(type)?.({ preventDefault() {}, ...fields }); }
}

test('UI defaults, all word ranges, invalid settings, generation bypass, and clearing enforce the real policy', async () => {
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(match => [match[1], new Element()]));
  const get = id => elements.get(id);
  for (const id of ['suffix', 'min-word', 'max-word']) get(id).value = new RegExp('id="' + id + '"[^>]+value="([^"]+)"').exec(html)[1];
  get('profile').value = 'readable';
  get('count').value = '1'; get('show').checked = true;
  const windowEvents = new Map();
  globalThis.document = { getElementById: get, createElement: () => new Element() };
  globalThis.window = { addEventListener: (type, fn) => windowEvents.set(type, fn) };
  try {
    await import('../dist/app.js');
    assert.equal(get('suffix').valueAsNumber, DEFAULTS.suffixLength);
    assert.equal(get('max-word').valueAsNumber, DEFAULTS.maxWordLength);
    assert.equal(get('generate').disabled, false);
    get('settings-form').dispatch('invalid');
    assert.equal(get('advanced').open, true);
    get('advanced').open = false;
    get('settings-form').dispatch('submit');
    assert.match(get('status').textContent, /1 password generated/);
    assert.equal(get('copy-all').disabled, false);
    assert.equal(get('passwords').children.length, 1);
    for (let minWordLength = 4; minWordLength <= 12; minWordLength++) for (let maxWordLength = minWordLength; maxWordLength <= 12; maxWordLength++) {
      get('min-word').value = String(minWordLength); get('max-word').value = String(maxWordLength);
      get('max-word').dispatch('input');
      const n = eligibleWords(WORDS, { minWordLength, maxWordLength, suffixLength: 6 }).length;
      assert.equal(get('generate').disabled, !meetsEntropyPolicy(n, 6));
      assert.equal(get('word-count').textContent, n.toLocaleString());
      assert.equal(get('copy-all').disabled, true);
      if (!meetsEntropyPolicy(n, 6)) {
        get('settings-form').dispatch('submit'); // Programmatic submission must also fail.
        assert.match(get('strength-note').textContent, /Generation blocked/);
        assert.equal(get('copy-all').disabled, true);
      }
    }
    get('min-word').value = '4'; get('max-word').value = '12';
    for (const value of ['4', '5', '', 'NaN', 'Infinity', '65', '5.5']) {
      get('suffix').value = value; get('suffix').dispatch('input');
      assert.equal(get('generate').disabled, true);
      get('settings-form').dispatch('submit'); assert.equal(get('copy-all').disabled, true);
    }
    get('suffix').value = '6'; get('suffix').dispatch('input');
    assert.equal(get('generate').disabled, false);
    get('settings-form').dispatch('invalid');
    assert.equal(get('advanced').open, true);
    get('advanced').open = false;
    const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    try {
      Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
      get('suffix').dispatch('input'); assert.equal(get('generate').disabled, true);
      get('settings-form').dispatch('submit'); assert.match(get('status').textContent, /Secure browser randomness is unavailable/);
      assert.equal(get('copy-all').disabled, true);
    } finally { Object.defineProperty(globalThis, 'crypto', cryptoDescriptor); }
    get('suffix').dispatch('input'); assert.equal(get('generate').disabled, false);
    get('settings-form').dispatch('submit');
    const revealed = get('passwords').children[0].children[1].textContent;
    assert.ok(/^[A-Z][a-z]+\.[A-Z]+\.[A-Z][a-z]+\.[23456789_@#%*+-]{6}$/.test(revealed), 'Rendered password format failed; value omitted.');
    get('show').checked = false; get('show').dispatch('change');
    assert.ok(!get('passwords').textContent.includes(revealed));
    assert.ok(get('passwords').textContent.includes('••••••••••••••••'));
    windowEvents.get('pagehide')(); assert.equal(get('copy-all').disabled, true);
  } finally { delete globalThis.document; delete globalThis.window; }
});
