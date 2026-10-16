import {openSettings,closeSettings,selectProfile} from './browser-dialog.mjs';
// Local Edge checks use deterministic public fixtures only; no production hooks.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { screenshotDirectory } from './browser-artifacts.mjs';
const screenshot=await screenshotDirectory('profiles');
const {chromium}=createRequire(import.meta.url)(process.env.KEYSMITH_PLAYWRIGHT_MODULE||'playwright');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});let browser;
try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Local preview stopped')));});
 browser=await chromium.launch({headless:true,...(process.env.KEYSMITH_BROWSER_PATH?{executablePath:process.env.KEYSMITH_BROWSER_PATH}:{})});
 const context=await browser.newContext({viewport:{width:1280,height:1000},permissions:['clipboard-read','clipboard-write']});await context.route('**/favicon.ico', route=>route.fulfill({status:204}));const page=await context.newPage();
 const errors=[];page.on('pageerror',()=>errors.push('Page error'));const logs=[];page.on('console',msg=>logs.push({type:msg.type(),location:msg.location(),browserResourceFailure:msg.text().startsWith('Failed to load resource:')}));
 await page.addInitScript(()=>{
  let wordOffset=0,rank=0;globalThis.fixtureWrites=[];globalThis.fixtureFailCopy=false;globalThis.fixtureFailRandom=false;globalThis.fixtureLeaks=0;
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){if(globalThis.fixtureFailRandom)throw Error('Public fixture RNG failure');
   if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][wordOffset++%9];return b;}}});
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>{if(globalThis.fixtureFailCopy)throw Error('Public fixture clipboard failure');globalThis.fixtureWrites.push(value);}});
  for(const name of ['fetch','XMLHttpRequest','WebSocket'])Object.defineProperty(globalThis,name,{configurable:true,value:()=>{globalThis.fixtureLeaks++;throw Error('Unexpected network use');}});
  Object.defineProperty(Storage.prototype,'setItem',{configurable:true,value:function(key,value){if(this===window.localStorage&&key==='keysmith.theme'&&['automatic','light','dark','emerald','amethyst'].includes(value))return;globalThis.fixtureLeaks++;throw Error('Unexpected persistent write');}});
 });
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});const startUrl=page.url(),requests=[];page.on('request',r=>requests.push(r.resourceType()));
 assert.equal(await page.locator('#profile').inputValue(),'readable');await closeSettings(page);await page.locator('#generate').click();assert.equal(await page.locator('.component-copy button').count(),4);
 await page.screenshot({path:screenshot('readable-desktop.png'),fullPage:true});
 await openSettings(page);await openSettings(page);await page.locator('#profile').focus();await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
 assert.equal(await page.locator('#profile').inputValue(),'strong-random');assert.equal(await page.locator('#copy-all').isDisabled(),true);
 assert.equal(await page.locator('#readable-settings').isVisible(),false);assert.equal(await page.locator('#strong-settings').isVisible(),true);
 assert.equal(await page.locator('#suffix').isDisabled(),true);assert.equal(await page.locator('#strong-length').inputValue(),'20');
 assert.equal(await page.locator('#strong-ambiguous').isChecked(),true);await closeSettings(page);await page.locator('#generate').click();
 assert.equal(await page.locator('.component-copy').count(),0);const strong=await page.locator('.password').textContent();assert.equal(strong.length,20);assert.ok(!/[lLiIoO01]/.test(strong));
 for(const pattern of [/[A-Z]/,/[a-z]/,/[2-9]/,/[-_@#%*+]/])assert.ok(pattern.test(strong));
 assert.match(await page.locator('.row-metrics').textContent(),/Configured rules met/);
 // Native substring selection and Ctrl+C remain available on literal output.
 await page.locator('.password').evaluate(el=>{const range=document.createRange();range.setStart(el.firstChild,2);range.setEnd(el.firstChild,7);const s=getSelection();s.removeAllRanges();s.addRange(range);});
 await page.keyboard.press('Control+c');assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),strong.slice(2,7));
 await page.locator('.row-top button').first().click();assert.equal(await page.evaluate(()=>fixtureWrites.at(-1)),strong);
 await page.screenshot({path:screenshot('strong-desktop.png'),fullPage:true});
 await openSettings(page);await page.locator('#strong-exclusions').fill('ABab');assert.equal(await page.locator('#copy-all').isDisabled(),true);
 await openSettings(page);await page.locator('#strong-symbols').uncheck();await openSettings(page);await page.locator('#strong-digits').uncheck();await openSettings(page);await page.locator('#strong-length').fill('64');await closeSettings(page);await page.locator('#generate').click();
 assert.ok(/^[A-Za-z]{64}$/.test(await page.locator('.password').textContent()));assert.ok(!/[ABab]/.test(await page.locator('.password').textContent()));
 await openSettings(page);await selectProfile(page,'custom-policy');assert.equal(await page.locator('#copy-all').isDisabled(),true);
 await openSettings(page);await page.locator('#custom-digits').uncheck();assert.equal(await page.locator('#generate').isDisabled(),true);assert.match(await page.locator('#strength-note').textContent(),/Enable digits/);
 await openSettings(page);await page.locator('#custom-digits').check();await openSettings(page);await page.locator('#custom-min-uppercase').fill('100');assert.equal(await page.locator('#generate').isDisabled(),true);
 assert.match(await page.locator('#strength-note').textContent(),/Increase length/);await openSettings(page);await page.locator('#custom-min-uppercase').fill('1');
 await openSettings(page);await page.locator('#custom-symbol-list').fill('A!');assert.equal(await page.locator('#generate').isDisabled(),true);await openSettings(page);await page.locator('#custom-symbol-list').fill(' .<>&');
 await openSettings(page);await page.locator('#custom-length').fill('128');for(const id of ['uppercase','lowercase','digits','symbols']){await openSettings(page);await page.locator('#custom-min-'+id).fill('32');}
 await closeSettings(page);await page.locator('#generate').click();assert.equal(await page.locator('.password span').count(),0);assert.equal((await page.locator('.password').textContent()).length,128);
 await page.screenshot({path:screenshot('custom-desktop.png'),fullPage:true});
 for(const profile of ['strong-random','custom-policy']){
  await openSettings(page);await selectProfile(page,profile);
  for(const quantity of [1,5,20]){
   await closeSettings(page);await page.locator('#count').selectOption(String(quantity));await closeSettings(page);await page.locator('#generate').click();const before=await page.locator('.password').allTextContents();
   const writeCount=await page.evaluate(()=>fixtureWrites.length);const index=quantity-1;await page.locator('.regenerate').nth(index).click();
   const after=await page.locator('.password').allTextContents();assert.notEqual(after[index],before[index]);assert.ok(after.every((v,i)=>i===index||v===before[i]));
   assert.equal(await page.evaluate(()=>fixtureWrites.length),writeCount);assert.equal(await page.locator('.regenerate').nth(index).evaluate(el=>el===document.activeElement),true);
   await closeSettings(page);await (await page.locator('#copy-all').isVisible()?page.locator('#copy-all'):page.locator('.copy-password').first()).click();assert.equal(await page.evaluate(()=>fixtureWrites.at(-1)),after.join('\n'));
   await page.evaluate(()=>fixtureFailCopy=true);await closeSettings(page);await (await page.locator('#copy-all').isVisible()?page.locator('#copy-all'):page.locator('.copy-password').first()).click();assert.match(await page.locator('#status').textContent(),/Clipboard unavailable/);await page.evaluate(()=>fixtureFailCopy=false);
   await closeSettings(page);await page.locator('#show').uncheck();assert.ok((await page.locator('.password').allTextContents()).every(v=>v==='••••••••••••••••'));
   await closeSettings(page);await page.locator('#manual').check();await page.evaluate(()=>fixtureFailRandom=true);await page.locator('.regenerate').nth(index).click();assert.match(await page.locator('#status').textContent(),/Existing password preserved/);
   await page.evaluate(()=>fixtureFailRandom=false);await closeSettings(page);await page.locator('#show').check();assert.equal(await page.locator('.password').nth(index).textContent(),after[index]);
  }
 }
 for(const width of [320,390]){
  await page.setViewportSize({width,height:844});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await closeSettings(page);await page.locator('#count').selectOption('1');await closeSettings(page);await page.locator('#generate').click();
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No horizontal overflow at mobile width');
  const dims=await page.locator('.regenerate').first().boundingBox();assert.ok(dims.width>=44&&dims.height>=44);
  assert.equal(await page.locator('#policy-status').getAttribute('aria-live'),'polite');
  await page.screenshot({path:screenshot('custom-mobile-'+width+'.png'),fullPage:true});
 }
 // Native validation focuses the empty required input; inactive controls are excluded.
 await openSettings(page);await page.locator('#custom-length').fill('');await page.locator('#settings-form').evaluate(form=>form.requestSubmit());
 assert.equal(await page.locator('#custom-length').evaluate(el=>document.activeElement===el),true);
 await openSettings(page);await selectProfile(page,'strong-random');assert.equal(await page.locator('#custom-length').isDisabled(),true);await closeSettings(page);await page.locator('#generate').click();assert.equal(await page.locator('.password').count(),1);
 assert.equal(await page.evaluate(()=>fixtureLeaks),0);assert.equal(page.url(),startUrl);assert.equal(requests.length,0);assert.deepEqual(errors,[]);assert.deepEqual(logs,[]);
 console.log('PASS: Edge profiles, keyboard/native selection, exact copy/failure feedback, policy errors, 1/5/20 batches, regeneration isolation, hidden/manual states, 320/390px wrapping, labels/focus, and no network/storage/log/URL leakage. Public-fixture screenshots: '+screenshot('custom-mobile-320.png'));
}finally{await browser?.close();server.kill();}
