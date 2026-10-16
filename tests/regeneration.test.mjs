import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { eligibleWords, meetsEntropyPolicy, validatePassword } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';

class Element {
  children = []; listeners = new Map(); attributes = new Map(); value = ''; checked = false; disabled = false; text = ''; parent = null;
  classList = { values: new Set(), toggle(name, on) { on ? this.values.add(name) : this.values.delete(name); } };
  get valueAsNumber() { return this.value === '' ? NaN : Number(this.value); }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  set textContent(value) { this.text = String(value); this.children = []; }
  append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
  replaceChildren(...children) { this.text = ''; this.children = []; this.append(...children); }
  replaceWith(next) { const index = this.parent.children.indexOf(this); this.parent.children[index] = next; next.parent = this.parent; this.parent = null; }
  querySelector(selector) { return this.children.find(child => `.${child.className}` === selector) || this.children.map(child => child.querySelector(selector)).find(Boolean); }
  focus() { globalThis.document.activeElement = this; }
  setAttribute(name, value) { this.attributes.set(name, value); }
  addEventListener(type, handler) { this.listeners.set(type, handler); }
  dispatch(type) { this.listeners.get(type)?.({ preventDefault() {} }); }
}
const settle = () => new Promise(resolve => setImmediate(resolve));
let harnessId = 0;
async function harness(run, invalidReplacement = false) {
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  const ids = [...html.matchAll(/id="([^"]+)"/g)].map(match => match[1]);
  const elements = new Map(ids.map(id => [id, new Element()]));
  const get = id => elements.get(id);
  get('profile').value = 'readable';
  get('count').value = '5'; get('suffix').value = '6'; get('min-word').value = '4'; get('max-word').value = '12'; get('show').checked = true;
  const names = ['document', 'window', 'navigator', 'isSecureContext', 'crypto', 'fixtureReplacement'];
  const saved = new Map(names.map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]));
  const writes = [];
  let sequence = [0, 0, 0, 0, 8, 0, 8, 0, 8], offset = 0, failAfter = Infinity;
  const fixtureCrypto = { getRandomValues(buffer) {
    if (offset >= failAfter) throw new Error('Injected fixture randomness failure');
    buffer[0] = sequence[offset++ % sequence.length]; return buffer;
  } };
  const globals = { document: { getElementById: get, createElement: () => new Element() }, window: { addEventListener() {} },
    navigator: { clipboard: { async writeText(value) { writes.push(value); } } }, isSecureContext: true, crypto: fixtureCrypto,
    fixtureReplacement: () => 'invalid-public-fixture' };
  for (const [key, value] of Object.entries(globals)) Object.defineProperty(globalThis, key, { configurable: true, value });
  try {
    if (invalidReplacement) {
      // Fault injection into a test-only module copy: no production hooks or core changes.
      let source = await readFile(new URL('../dist/app.js', import.meta.url), 'utf8');
      for (const name of ['dictionary', 'core', 'profiles', 'policy', 'random-password', 'profile-output'])
        source = source.replace("'./" + name + ".js'", JSON.stringify(new URL('../dist/' + name + '.js', import.meta.url).href));
      const dispatch = 'const replacement = context.generate();';
      assert.ok(source.includes(dispatch), 'Test injection must target the real regeneration dispatcher call');
      source = source.replace(dispatch, 'const replacement = globalThis.fixtureReplacement();');
      await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
    } else await import(`../dist/app.js?regeneration-${++harnessId}`);
    const rows = () => get('passwords').children;
    const values = () => rows().map(row => row.children[1].textContent);
    const regenerate = index => rows()[index].children[0].children[2].dispatch('click');
    const alternate = () => { sequence = [1, 2, 3, 1, 9, 2, 10, 3, 11]; offset = 0; failAfter = Infinity; };
    const reset = () => { sequence = [0, 0, 0, 0, 8, 0, 8, 0, 8]; offset = 0; failAfter = Infinity; };
    await run({ get, rows, values, regenerate, alternate, reset, writes, fixtureCrypto, failAfterCalls(n) { offset = 0; failAfter = n; } });
  } finally {
    for (const [key, descriptor] of saved) descriptor ? Object.defineProperty(globalThis, key, descriptor) : delete globalThis[key];
  }
}

test('single and maximum batches replace one entry only, validate policy, retain other cards and never auto-copy', async () => {
  await harness(async ({ get, rows, values, regenerate, alternate, reset, writes }) => {
    for (const [quantity, s, index] of [
      [1, { minWordLength: 4, maxWordLength: 12, suffixLength: 6 }, 0],
      [5, { minWordLength: 6, maxWordLength: 11, suffixLength: 7 }, 2],
      [20, { minWordLength: 8, maxWordLength: 8, suffixLength: 8 }, 19],
      [20, { minWordLength: 4, maxWordLength: 12, suffixLength: 64 }, 0],
    ]) {
      reset();
      get('count').value = String(quantity); get('min-word').value = String(s.minWordLength); get('max-word').value = String(s.maxWordLength); get('suffix').value = String(s.suffixLength);
      get('advanced').open = quantity === 20;
      get('settings-form').dispatch('submit');
      const before = values(), originalRows = [...rows()];
      // A changed deterministic source guarantees a different fixture, without real secrets.
      alternate();
      const copyCount = writes.length;
      regenerate(index);
      const after = values();
      assert.equal(after.length, quantity);
      assert.ok(after[index] !== before[index], 'Selected deterministic fixture must change');
      for (let i = 0; i < quantity; i++) if (i !== index) {
        assert.ok(after[i] === before[i], 'Other passwords must remain byte-for-byte identical');
        assert.equal(rows()[i], originalRows[i], 'Other DOM cards must remain untouched');
      }
      const pool = eligibleWords(WORDS, s);
      assert.ok(meetsEntropyPolicy(pool.length, s.suffixLength));
      assert.ok(validatePassword(after[index], pool, s), 'Replacement must satisfy the complete password policy');
      assert.equal(writes.length, copyCount, 'Regeneration must never write to clipboard');
      assert.equal(get('advanced').open, quantity === 20);
      assert.equal(document.activeElement, rows()[index].children[0].children[2]);
      assert.match(get('status').textContent, /regenerated and validated/);
    }
  });
});

test('programmatic setting changes invalidate old entries before regeneration', async () => {
  await harness(async ({ get, rows, regenerate, alternate }) => {
    get('settings-form').dispatch('submit');
    get('min-word').value = '8'; get('max-word').value = '8'; get('suffix').value = '9'; alternate(); regenerate(2);
    assert.equal(get('copy-all').disabled, true);assert.equal(rows().length, 1);assert.match(get('status').textContent, /Settings changed/);
    get('settings-form').dispatch('submit');
    const s = { minWordLength: 8, maxWordLength: 8, suffixLength: 9 };
    for (const row of rows()) assert.ok(validatePassword(row.children[1].textContent, eligibleWords(WORDS, s), s));
  });
});

test('hidden and large-text state survive regeneration and every copy action uses the replacement', async () => {
  await harness(async ({ get, rows, values, regenerate, alternate, reset, writes }) => {
    get('settings-form').dispatch('submit'); const before = values();
    get('show').checked = false; get('show').dispatch('change');
    get('manual').checked = true; get('manual').dispatch('change');
    alternate(); regenerate(1);
    assert.equal(writes.length, 0);
    assert.equal(get('show').checked, false); assert.equal(get('manual').checked, true);
    assert.ok(get('passwords').classList.values.has('manual-mode'));
    for (const row of rows()) assert.equal(row.children[1].textContent, '••••••••••••••••');
    rows()[1].children[0].children[1].dispatch('click'); await settle();
    const replacement = writes.at(-1);
    assert.ok(replacement !== before[1], 'Hidden full copy must contain the replacement');
    for (let i = 0; i < 4; i++) {
      rows()[1].children[2].children[1].children[i].dispatch('click'); await settle();
      assert.ok(writes.at(-1) === replacement.split('.')[i], 'Component copies use replacement exactly');
    }
    get('copy-all').dispatch('click'); await settle();
    const expected = [...before]; expected[1] = replacement;
    assert.ok(writes.at(-1) === expected.join('\n'), 'Copy All includes only the selected replacement');
    get('show').checked = true; get('show').dispatch('change');
    assert.ok(values()[1] === replacement);
  });
});

test('mid-generation randomness failures preserve the entire unchanged batch', async () => {
  await harness(async ({ get, rows, values, regenerate, writes, fixtureCrypto, failAfterCalls }) => {
    get('settings-form').dispatch('submit'); const before = values(), originalRows = [...rows()];
    const verifyPreserved = () => {
      for (let i = 0; i < before.length; i++) { assert.ok(values()[i] === before[i]); assert.equal(rows()[i], originalRows[i]); }
      assert.match(get('status').textContent, /Existing password preserved/);
      assert.equal(writes.length, 0);
      assert.ok(!before.some(value => get('status').textContent.includes(value)), 'Error feedback must contain no passwords');
    };
    failAfterCalls(5); regenerate(2); verifyPreserved();
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    regenerate(2); verifyPreserved();
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: fixtureCrypto });
  });
});

test('replacement failing final validation leaves original cards and clipboard untouched', async () => {
  await harness(async ({ get, rows, values, regenerate, writes }) => {
    get('settings-form').dispatch('submit'); const before = values(), originalRows = [...rows()];
    regenerate(3);
    for (let i = 0; i < before.length; i++) { assert.ok(values()[i] === before[i]); assert.equal(rows()[i], originalRows[i]); }
    assert.match(get('status').textContent, /Existing password preserved/);
    assert.equal(writes.length, 0);
  }, true);
});

test('cleared and replaced card actions cannot overwrite later values', async () => {
  await harness(async ({ get, rows, values, regenerate, alternate }) => {
    get('settings-form').dispatch('submit'); const stale = rows()[2].children[0].children[2];
    alternate(); regenerate(2); const after = values(); stale.dispatch('click');
    assert.ok(values().every((value, i) => value === after[i]));
    const cleared = rows()[0].children[0].children[2]; get('clear').dispatch('click');
    get('settings-form').dispatch('submit'); const next = values(); cleared.dispatch('click');
    assert.ok(values().every((value, i) => value === next[i]));
  });
});
test('pending copy feedback cannot overwrite a successful regeneration message', async () => {
  await harness(async ({ get, rows, regenerate, alternate }) => {
    get('settings-form').dispatch('submit');
    let finish;
    navigator.clipboard.writeText = () => new Promise(resolve => { finish = resolve; });
    rows()[0].children[0].children[1].dispatch('click');
    alternate(); regenerate(0);
    finish(); await settle();
    assert.match(get('status').textContent, /regenerated and validated/);
  });
});