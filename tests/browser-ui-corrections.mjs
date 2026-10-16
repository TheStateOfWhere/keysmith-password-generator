import {openSettings,closeSettings,selectProfile} from './browser-dialog.mjs';
// Public-fixture Edge regressions for Stage 5A findings. No production hooks.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';import {spawn} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';import {screenshotDirectory} from './browser-artifacts.mjs';
const screenshot=await screenshotDirectory('ui-corrections');
const {chromium}=createRequire(import.meta.url)(process.env.PASSWORDFORGE_PLAYWRIGHT_MODULE||'playwright');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});let browser;
const results={boundaries:[],layouts:[],programmatic:[],errorLayouts:[],screenshots:[]};
try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Local preview stopped')));});
 browser=await chromium.launch({headless:true,...(process.env.PASSWORDFORGE_BROWSER_PATH?{executablePath:process.env.PASSWORDFORGE_BROWSER_PATH}:{})});results.browser=browser.version();
 const context=await browser.newContext({viewport:{width:1280,height:900},permissions:['clipboard-read','clipboard-write']});await context.route('**/favicon.ico',r=>r.fulfill({status:204}));
 const page=await context.newPage(),errors=[],logs=[],requests=[];page.on('pageerror',()=>errors.push('Page error'));page.on('console',msg=>logs.push({type:msg.type(),location:msg.location(),expectedNumericFixtureWarning:msg.type()==='warning'&&msg.text()==='The specified value "20x" cannot be parsed, or is out of range.' }));
 await page.addInitScript(()=>{
  let word=0,rank=0;globalThis.fixtureWrites=[];globalThis.fixtureDraws=0;globalThis.fixtureScrolls=[];globalThis.fixtureLeaks=0;
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){fixtureDraws++;if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][word++%9];return b;}}});
  globalThis.fixtureClipboard=navigator.clipboard.writeText.bind(navigator.clipboard);
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>{fixtureWrites.push(value);}});
  const scroll=HTMLElement.prototype.scrollIntoView;HTMLElement.prototype.scrollIntoView=function(options){fixtureScrolls.push(options);return scroll.call(this,options);};
  for(const name of ['fetch','XMLHttpRequest','WebSocket'])Object.defineProperty(globalThis,name,{configurable:true,value:()=>{fixtureLeaks++;throw Error('Unexpected network API');}});
  Object.defineProperty(Storage.prototype,'setItem',{configurable:true,value:function(key,value){if(this===window.localStorage&&key==='passwordforge.theme'&&['automatic','light','dark','emerald','amethyst'].includes(value))return;fixtureLeaks++;throw Error('Unexpected storage write');}});
 });
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});const originalUrl=page.url();page.on('request',r=>requests.push(r.resourceType()));
 const generate=page.locator('#generate');
 const shot=async name=>{const path=screenshot(name+'.png');await page.screenshot({path,fullPage:false});results.screenshots.push(path);};
 const activate=async id=>{await openSettings(page);await selectProfile(page,id);};
 const resetField=async(id)=>{await openSettings(page);await page.locator('#'+id).fill(id==='custom-symbol-list'?'-_@#%*+':'');};
 async function verifyBlocked(id,expected){
  assert.equal(await page.locator('#'+id).inputValue(),expected);assert.equal(await generate.isDisabled(),true);
  assert.equal(await page.locator('#'+id).getAttribute('aria-invalid'),'true');assert.match(await page.locator('#'+id+'-error').textContent(),/256/);
  assert.ok((await page.locator('#'+id).getAttribute('aria-describedby')).includes(id+'-error'));
  const before=await page.evaluate(()=>fixtureDraws);await page.locator('#settings-form').evaluate(form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
  assert.equal(await page.evaluate(()=>fixtureDraws),before);assert.equal(await page.locator('.password').count(),0);assert.equal(await page.locator('#copy-all').isDisabled(),true);
 }
 for(const [id,profile,text]of [['strong-exclusions','strong-random','A'.repeat(256)+'Z'],['custom-exclusions','custom-policy','A'.repeat(256)+'Z'],['custom-symbol-list','custom-policy','!'.repeat(256)+'+']]){
  await activate(profile);await resetField(id);await closeSettings(page);await generate.click();const previousWrites=await page.evaluate(()=>fixtureWrites.length);
  await page.locator('.row-top button').first().evaluate(el=>globalThis.fixtureOldCopy=el);await resetField(id);await page.locator('#'+id).focus();await page.keyboard.press('Control+a');
  await page.evaluate(text=>fixtureClipboard(text),text);await page.keyboard.press('Control+v');await verifyBlocked(id,text);
  await page.evaluate(()=>fixtureOldCopy.click());assert.equal(await page.evaluate(()=>fixtureWrites.length),previousWrites);
  results.boundaries.push({field:id,method:'native Ctrl+V',attemptedLength:257,retainedLength:(await page.locator('#'+id).inputValue()).length,generationBlocked:true});
  if(id==='custom-exclusions')await shot('after-exclusion-paste');
  await page.locator('#'+id).fill(id==='custom-symbol-list'?'!'.repeat(256):'A'.repeat(256));assert.equal(await generate.isDisabled(),false);
  await resetField(id);await page.locator('#'+id).focus();await page.keyboard.press('Control+a');await page.keyboard.insertText(text);await verifyBlocked(id,text);await resetField(id);
 }
 // Native textarea keyboard/newline editing retains invalid control characters.
 await activate('custom-policy');await openSettings(page);await page.locator('#custom-exclusions').focus();await page.keyboard.insertText('A\nZ');
 assert.equal(await page.locator('#custom-exclusions').inputValue(),'A\nZ');assert.equal(await generate.isDisabled(),true);assert.match(await page.locator('#custom-exclusions-error').textContent(),/ASCII/);await resetField('custom-exclusions');
 // Real drag/drop, with a test-only draggable element carrying public fixture text.
 await page.evaluate(()=>{const el=document.createElement('div');el.id='fixture-drag';el.textContent='Public policy fixture';el.draggable=true;
  Object.assign(el.style,{position:'fixed',top:'0',left:'0',zIndex:'999',background:'white'});el.addEventListener('dragstart',e=>e.dataTransfer.setData('text/plain','A'.repeat(256)+'Z'));document.querySelector('#custom-policy-inline').prepend(el);});
 await openSettings(page);await page.locator('#custom-exclusions').scrollIntoViewIfNeeded();await page.dragAndDrop('#fixture-drag','#custom-exclusions');await verifyBlocked('custom-exclusions','A'.repeat(256)+'Z');
 await page.locator('#fixture-drag').evaluate(el=>el.remove());results.boundaries.push({field:'custom-exclusions',method:'native drag/drop',retainedLength:257,generationBlocked:true});await resetField('custom-exclusions');
 // Property writes without events are revalidated at all password-action boundaries.
 for(const action of ['copy','copy-all','regenerate','submit','focusin']){
  await activate('strong-random');await resetField('strong-exclusions');await closeSettings(page);await generate.click();
  const before=await page.evaluate(()=>({draws:fixtureDraws,writes:fixtureWrites.length}));
  if(action==='focusin')await openSettings(page);
  await page.evaluate(action=>{document.getElementById('strong-exclusions').value='A'.repeat(256)+'Z';
   if(action==='copy')document.querySelector('.row-top button').click();
   if(action==='copy-all')document.getElementById('copy-all').click();
   if(action==='regenerate')document.querySelector('.regenerate').click();
   if(action==='submit')document.getElementById('settings-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
   if(action==='focusin')document.getElementById('strong-exclusions').focus();},action);
  assert.equal(await page.locator('.password').count(),0,action);assert.equal(await generate.isDisabled(),true);
  assert.equal(await page.evaluate(()=>fixtureDraws),before.draws);assert.equal(await page.evaluate(()=>fixtureWrites.length),before.writes);results.programmatic.push({action,blocked:true});await resetField('strong-exclusions');
 }
 // Native Ctrl+C must not export stale text after an eventless policy update.
 await activate('strong-random');await resetField('strong-exclusions');await closeSettings(page);await generate.click();
 await page.locator('.password').evaluate(el=>{const r=document.createRange();r.selectNodeContents(el);const s=getSelection();s.removeAllRanges();s.addRange(r);});
 await page.evaluate(()=>{document.getElementById('strong-exclusions').value='A'.repeat(256)+'Z';});
 await page.evaluate(()=>fixtureClipboard('public clipboard sentinel'));await page.keyboard.press('Control+c');
 assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),'public clipboard sentinel');assert.equal(await page.locator('.password').count(),0);await resetField('strong-exclusions');
 results.programmatic.push({action:'native Ctrl+C',blocked:true});
 // Numeric native constraints reject invalid values rather than clamping them.
 await openSettings(page);await page.locator('#strong-length').fill('129');assert.equal(await page.locator('#strong-length').inputValue(),'129');assert.equal(await generate.isDisabled(),true);
 await page.locator('#strong-length').evaluate(el=>{el.value='20x';el.dispatchEvent(new Event('input',{bubbles:true}));});assert.equal(await page.locator('#strong-length').inputValue(),'');assert.equal(await generate.isDisabled(),true);await openSettings(page);await page.locator('#strong-length').fill('20');
 // An autofill-like input notification and a large property value use the same gate.
 await page.locator('#strong-exclusions').evaluate(el=>{el.value='A'.repeat(1_000_000);el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertReplacementText'}));});
 assert.equal((await page.locator('#strong-exclusions').inputValue()).length,1_000_000);assert.equal(await generate.isDisabled(),true);await resetField('strong-exclusions');
 // Inline errors stay next to the edited checkbox and recover on correction.
 for(const width of [320,390]){
  await page.setViewportSize({width,height:844});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await activate('custom-policy');await openSettings(page);await page.locator('#custom-digits').uncheck();
  const control=await page.locator('#custom-digits').boundingBox(),message=await page.locator('#custom-digits-error').boundingBox();
  assert.ok(message.y>=control.y&&message.y-control.y<90,'Error is adjacent to its control');
  assert.ok(message.y>=0&&message.y+message.height<=844,'Inline error is visible while editing');assert.equal(await page.locator('#custom-digits').getAttribute('aria-invalid'),'true');
  results.errorLayouts.push({width,controlTop:control.y,errorTop:message.y,errorBottom:message.y+message.height,viewportHeight:844});
  assert.match(await page.locator('#custom-digits-error').textContent(),/Enable digits/);await shot('after-inline-error-'+width);
  assert.equal(await page.locator('#policy-status').getAttribute('aria-live'),'polite');assert.equal(await page.locator('#strength-note').getAttribute('aria-live'),null);assert.equal(await page.locator('#status').textContent(),'');
  await openSettings(page);await page.locator('#custom-digits').check();assert.equal(await page.locator('#custom-digits').getAttribute('aria-invalid'),'false');assert.equal(await page.locator('#custom-digits-error').isVisible(),false);
 }
 // Result visibility, focus preservation, reduced motion, and all four layouts.
 for(const width of [320,390,768,1280])for(const profile of ['readable','strong-random','custom-policy']){
  await page.setViewportSize({width,height:900});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await activate(profile);await page.emulateMedia({reducedMotion:width===390?'reduce':'no-preference'});
  await closeSettings(page);await generate.focus();const before=await page.evaluate(()=>fixtureScrolls.length);await page.keyboard.press('Enter');
  const rect=await page.locator('.password').first().boundingBox();assert.ok(rect.y>=0&&rect.y+rect.height<=900,'Generated password fits the viewport');
  assert.ok(await page.evaluate(()=>{const b=document.activeElement.getBoundingClientRect();return b.top>=0&&b.bottom<=innerHeight;}),'Keyboard focus remains visible');
  const calls=await page.evaluate(before=>fixtureScrolls.slice(before),before);assert.ok(calls.every(c=>c.behavior==='instant'));
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);assert.equal(overflow,false);
  results.layouts.push({width,profile,resultTop:rect.y,resultBottom:rect.y+rect.height,scrollCalls:calls.length,focusPreserved:true,reducedMotion:width===390});
  if(profile==='strong-random'&&width===1280)await shot('after-strong-generation');
  if(profile==='custom-policy'&&width===320)await shot('after-custom-generation-320');
 }
 // No needless scrolling for an already-visible Readable result.
 await page.setViewportSize({width:1280,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await activate('readable');await closeSettings(page);await generate.focus();await page.keyboard.press('Enter');const before=await page.evaluate(()=>fixtureScrolls.length);
 await page.keyboard.press('Enter');assert.equal(await page.evaluate(()=>fixtureScrolls.length),before);
 await activate('custom-policy');await openSettings(page);await page.locator('#custom-length').fill('128');await closeSettings(page);await page.locator('#manual').check();for(const width of [320,390,768,1280]){
  await page.setViewportSize({width,height:900});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await closeSettings(page);await generate.click();assert.equal((await page.locator('.password').textContent()).length,128);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:screenshot('long-password-'+width+'.png'),fullPage:true});
 }
 assert.equal(await page.evaluate(()=>fixtureLeaks),0);assert.equal(page.url(),originalUrl);assert.deepEqual(errors,[]);assert.deepEqual(logs.filter(entry=>!entry.expectedNumericFixtureWarning),[]);assert.equal(logs.filter(entry=>entry.expectedNumericFixtureWarning).length,1);assert.deepEqual(requests,[]);
 await writeFile(screenshot('results.png').replace(/\.png$/,'.json'),JSON.stringify(results,null,2)+'\n');
 console.log('PASS: native paste/typing/drag-drop, complete raw values and structured errors, no-event/autofill-like updates, stale-copy guards, adjacent accessible errors, focus-preserving instant result scrolling, reduced motion, and 320/390/768/1280 layouts. Screenshots: '+screenshot('after-strong-generation.png'));
}finally{await browser?.close();server.kill();}
