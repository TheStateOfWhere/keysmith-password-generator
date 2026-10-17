import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('advanced disclosure contains only advanced controls and preserves native validation', async () => {
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  const advanced = /<details\b([^>]*id="advanced"[^>]*)>([\s\S]*?)<\/details>/.exec(html);
  assert.ok(advanced);
  assert.match(advanced[1], /id="advanced"/);
  assert.doesNotMatch(advanced[1], /\bopen\b/);
  assert.match(advanced[2], /<summary>Advanced Settings<\/summary>/);
  for (const id of ['suffix', 'min-word', 'max-word']) {
    assert.match(advanced[2], new RegExp(`id="${id}"[^>]*required`));
  }
  for (const id of ['count', 'generate']) {
    assert.match(html, new RegExp(`id="${id}"`));
    assert.doesNotMatch(advanced[2], new RegExp(`id="${id}"`));
  }
  assert.match(html, /Secure passwords\. Easy on the eyes\./);
  assert.doesNotMatch(html, /PRECISION OVER GUESSWORK|class="notes"/);
  assert.match(html, /aria-label="Security and privacy"/);
  assert.match(html, /<svg[^>]*[\s\S]*?<\/svg>/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(html, /id="status" role="status" aria-live="polite"/);
  assert.match(html, /id="word-count"/);
  assert.match(html, /id="entropy"/);
});

test('approved themes retain keyboard focus and unconstrained password panels', async () => {
  const css = await readFile(new URL('../dist/styles.css', import.meta.url), 'utf8');
  assert.match(css, /summary:focus-visible/);
  assert.doesNotMatch(css, /\.password-list\{[^}]*min-height/);
});
