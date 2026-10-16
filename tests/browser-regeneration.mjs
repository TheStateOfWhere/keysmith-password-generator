import {openSettings,closeSettings} from './browser-dialog.mjs';
// Local Edge verification with deterministic public fixtures only.
// Uses the same external Playwright/runtime environment variables as browser-selection.mjs.
import assert from 'node:assert/strict';
import { screenshotDirectory } from './browser-artifacts.mjs';
const screenshotPath = await screenshotDirectory('regeneration');
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.KEYSMITH_PLAYWRIGHT_MODULE || 'playwright');
const root = fileURLToPath(new URL('../', import.meta.url));
const server = spawn(process.execPath, ['scripts/serve.mjs'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
let browser;
try {
  await new Promise((resolve, reject) => { server.stdout.once('data', resolve); server.once('error', reject); server.once('exit', () => reject(new Error('Preview server exited'))); });
  browser = await chromium.launch({ headless: true, ...(process.env.KEYSMITH_BROWSER_PATH ? { executablePath: process.env.KEYSMITH_BROWSER_PATH } : {}) });
  const context = await browser.newContext({ viewport: { width: 1280, height: 1000 }, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await context.newPage();
  await page.addInitScript(() => {
    let offset = 0, sequence = [0, 0, 0, 0, 8, 0, 8, 0, 8], fail = false;
    globalThis.fixtureSource = (alternate = false, failure = false) => {
      offset = 0; fail = failure; sequence = alternate ? [1, 2, 3, 1, 9, 2, 10, 3, 11] : [0, 0, 0, 0, 8, 0, 8, 0, 8];
    };
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues(buffer) {
      if (fail) throw new Error('Injected public fixture failure');
      buffer[0] = sequence[offset++ % sequence.length]; return buffer;
    } } });
    globalThis.fixtureWrites = [];
    Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: async value => { globalThis.fixtureWrites.push(value); } });
  });
  await page.goto('http://127.0.0.1:4173/');
  const advanced = page.locator('#advanced');
  const values = () => page.locator('.password').allTextContents();
  const countWrites = () => page.evaluate(() => globalThis.fixtureWrites.length);
  const screenshot = name => page.screenshot({ path: screenshotPath(`${name}.png`), fullPage: true });
  async function configure(quantity, min, max, suffix, open, hidden, manual) {
    await page.evaluate(() => globalThis.fixtureSource());
    await closeSettings(page);await page.locator('#count').selectOption(String(quantity));
    await openSettings(page);await advanced.evaluate(el => { el.open = true; });
    await openSettings(page);await page.locator('#min-word').fill(String(min)); await openSettings(page);await page.locator('#max-word').fill(String(max)); await openSettings(page);await page.locator('#suffix').fill(String(suffix));
    await advanced.evaluate((el, open) => { el.open = open; }, open);
    await closeSettings(page);await page.locator('#show').setChecked(true); await closeSettings(page);await page.locator('#manual').setChecked(manual);
    await closeSettings(page);await page.locator('#generate').click();
    const baseline = await values();
    await closeSettings(page);await page.locator('#show').setChecked(!hidden);
    return baseline;
  }
  for (const scenario of [
    { quantity: 1, min: 4, max: 12, suffix: 6, open: false, hidden: false, manual: false, index: 0 },
    { quantity: 5, min: 6, max: 11, suffix: 7, open: true, hidden: true, manual: true, index: 2 },
    { quantity: 20, min: 8, max: 8, suffix: 8, open: false, hidden: false, manual: false, index: 19 },
    { quantity: 20, min: 4, max: 12, suffix: 64, open: true, hidden: true, manual: false, index: 0 },
  ]) {
    const { quantity, min, max, suffix, open, hidden, manual, index } = scenario;
    const before = await configure(quantity, min, max, suffix, open, hidden, manual);
    await page.evaluate(() => { globalThis.fixtureRows = [...document.querySelectorAll('.password-row')]; globalThis.fixtureSource(true); });
    const writesBefore = await countWrites();
    await page.getByRole('button', { name: `Regenerate password ${index + 1}`, exact: true }).click();
    assert.equal(await countWrites(), writesBefore, 'Regenerate must not copy');
    assert.ok(await page.evaluate(index => [...document.querySelectorAll('.password-row')].every((row, i) => i === index || row === globalThis.fixtureRows[i]), index), 'Unselected DOM cards remain untouched');
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), `Regenerate password ${index + 1}`);
    assert.equal(await advanced.evaluate(el => el.open), open);
    assert.equal(await page.locator('#manual').isChecked(), manual);
    assert.equal(await page.locator('#show').isChecked(), !hidden);
    if (hidden) for (const text of await values()) assert.equal(text, '••••••••••••••••');
    if (quantity === 5) await screenshot('regeneration-hidden');
    await closeSettings(page);await page.locator('#show').setChecked(true);
    const after = await values();
    assert.equal(after.length, quantity);
    assert.ok(after[index] !== before[index], 'Selected public fixture changes');
    for (let i = 0; i < quantity; i++) if (i !== index) assert.ok(after[i] === before[i], 'Other values stay byte-for-byte identical');
    assert.ok(await page.evaluate(async ({ index, min, max, suffix }) => {
      const { validatePassword, eligibleWords, meetsEntropyPolicy } = await import('/core.js');
      const { WORDS } = await import('/dictionary.js');
      const s = { minWordLength: min, maxWordLength: max, suffixLength: suffix };
      const pool = eligibleWords(WORDS, s);
      return meetsEntropyPolicy(pool.length, suffix) && validatePassword(document.querySelectorAll('.password')[index].textContent, pool, s);
    }, { index, min, max, suffix }), 'Replacement satisfies all password policies');
    const card = page.locator('.password-row').nth(index);
    await card.getByRole('button', { name: `Copy password ${index + 1}`, exact: true }).click();
    assert.ok(await page.evaluate(() => globalThis.fixtureWrites.at(-1)) === after[index], 'Full copy uses replacement');
    for (let part = 0; part < 4; part++) {
      if(part===0)await card.locator('.component-disclosure summary').click();
      await card.locator('.component-copy button').nth(part).click();
      assert.ok(await page.evaluate(() => globalThis.fixtureWrites.at(-1)) === after[index].split('.')[part], 'Component copy uses replacement');
    }
    await closeSettings(page);await (await page.locator('#copy-all').isVisible()?page.locator('#copy-all'):page.locator('.copy-password').first()).click();
    assert.ok(await page.evaluate(() => globalThis.fixtureWrites.at(-1)) === after.join('\n'), 'Copy All uses exact updated batch');
    await page.evaluate(() => globalThis.fixtureSource(false, true));
    const copyCount = await countWrites();
    await card.getByRole('button', { name: `Regenerate password ${index + 1}`, exact: true }).click();
    const failed = await values();
    assert.ok(failed.every((value, i) => value === after[i]), 'Failed replacement preserves entire batch');
    assert.equal(await countWrites(), copyCount);
    assert.ok((await page.locator('#status').textContent()).includes('Existing password preserved'));
    assert.ok(!(await page.locator('#status').textContent()).includes(after[index]), 'Failure feedback contains no password');
  }
  // Review screenshots and keyboard/selection checks after successful regeneration.
  await configure(5, 4, 12, 6, false, false, false);
  await page.evaluate(() => globalThis.fixtureSource(true));
  await page.getByRole('button', { name: 'Regenerate password 3', exact: true }).focus();
  await page.keyboard.press('Enter');
  await screenshot('regeneration-desktop');
  const word = page.locator('.password-row').nth(2).locator('.segment').first();
  await word.dblclick();
  assert.ok(await page.evaluate(() => window.getSelection().toString()) === await word.textContent(), 'Native word selection survives regeneration');
  const selectionParts = await page.locator('.password-row').nth(2).locator('.segment').allTextContents();
  async function point(segment, offset) {
    return page.locator('.password-row').nth(2).locator('.segment').nth(segment).evaluate((el, offset) => {
      const range = document.createRange(); range.setStart(el.firstChild, offset); range.collapse(true);
      const rect = range.getBoundingClientRect(); return { x: rect.x, y: rect.y + rect.height / 2 };
    }, offset);
  }
  const start = await point(0, 1), end = await point(1, 2);
  await page.evaluate(()=>getSelection()?.removeAllRanges()); await page.mouse.move(start.x, start.y); await page.mouse.down();
  await page.mouse.move(end.x, end.y, { steps: 12 }); await page.mouse.up();
  const selectedFixture = `${selectionParts[0].slice(1)}.${selectionParts[1].slice(0, 2)}`;
  assert.ok(await page.evaluate(() => window.getSelection().toString()) === selectedFixture, 'Native substring selection includes separators exactly after regeneration');
  await page.keyboard.press('Control+c');
  assert.ok(await page.evaluate(() => navigator.clipboard.readText()) === selectedFixture, 'Ctrl+C copies the exact regenerated substring');
  await page.evaluate(()=>getSelection()?.removeAllRanges());
  await page.setViewportSize({ width: 390, height: 844 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile layout has no horizontal overflow');
  for (const button of await page.locator('.password-row button:visible').all()) {
    const bounds = await button.boundingBox(); assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 390, 'Card actions fit mobile width');
  }
  await screenshot('regeneration-mobile');
  await page.setViewportSize({ width: 320, height: 844 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Small viewport fits regenerate controls');
  await page.setViewportSize({ width: 1280, height: 1000 });await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
  await configure(1, 4, 12, 6, false, false, false);
  await page.evaluate(() => globalThis.fixtureSource(true));
  await page.getByRole('button', { name: 'Regenerate password 1', exact: true }).click();
  await screenshot('regeneration-one');
  console.log('PASS: Edge one/5/20 batches, current settings, hidden/manual/disclosure states, policy validation, unchanged entries/cards, keyboard focus, exact copies, no automatic clipboard writes, preserved failure state, and mobile layout. Only deterministic public fixtures used.');
} finally { await browser?.close(); server.kill(); }