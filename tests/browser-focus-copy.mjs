import {openSettings,closeSettings,selectProfile} from './browser-dialog.mjs';
// Public-fixture Edge regressions for Stage 5A findings. No production hooks.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';import {spawn} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';import {screenshotDirectory} from './browser-artifacts.mjs';
const screenshot=await screenshotDirectory('focus-copy');
const {chromium}=createRequire(import.meta.url)(process.env.KEYSMITH_PLAYWRIGHT_MODULE||'playwright');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});let browser;
const results={activation:[],copy:[],errors:[],screenshots:[]};
try{
 await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Local preview stopped')));});
 browser=await chromium.launch({headless:true,...(process.env.KEYSMITH_BROWSER_PATH?{executablePath:process.env.KEYSMITH_BROWSER_PATH}:{})});results.browser=browser.version();
 const context=await browser.newContext({viewport:{width:1280,height:900},permissions:['clipboard-read','clipboard-write']});await context.route('**/favicon.ico',r=>r.fulfill({status:204}));
 const page=await context.newPage(),errors=[],logs=[],requests=[];page.on('pageerror',()=>errors.push('Page error'));page.on('console',msg=>logs.push({type:msg.type(),location:msg.location(),expectedNumericFixtureWarning:msg.type()==='warning'&&msg.text()==='The specified value "20x" cannot be parsed, or is out of range.' }));
 await page.addInitScript(()=>{
  let word=0,rank=0;globalThis.fixtureWrites=[];globalThis.fixtureDraws=0;globalThis.fixtureScrolls=[];globalThis.fixtureLeaks=0;
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){fixtureDraws++;if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][word++%9];return b;}}});
  globalThis.fixtureClipboard=navigator.clipboard.writeText.bind(navigator.clipboard);
  Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>{fixtureWrites.push(value);}});
  const scroll=HTMLElement.prototype.scrollIntoView;HTMLElement.prototype.scrollIntoView=function(options){fixtureScrolls.push(options);return scroll.call(this,options);};
  for(const name of ['fetch','XMLHttpRequest','WebSocket'])Object.defineProperty(globalThis,name,{configurable:true,value:()=>{fixtureLeaks++;throw Error('Unexpected network API');}});
  Object.defineProperty(Storage.prototype,'setItem',{configurable:true,value:function(key,value){if(this===window.localStorage&&key==='keysmith.theme'&&['zevyrn','midnight','aurora','dusk','slate'].includes(value))return;fixtureLeaks++;throw Error('Unexpected storage write');}});
 });
 await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});const originalUrl=page.url();page.on('request',r=>requests.push(r.resourceType()));

 const generate=page.locator('#generate');
 for(const width of [320,390,768,1280])for(const profile of ['readable','strong-random','custom-policy'])for(const activation of ['Enter','Space','pointer','programmatic','programmatic-click']){
  await page.reload({waitUntil:'networkidle'});await page.setViewportSize({width,height:900});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await page.emulateMedia({reducedMotion:width===390?'reduce':'no-preference'});
  await openSettings(page);await selectProfile(page,profile);await closeSettings(page);await generate.focus();
  if(activation==='Enter'||activation==='Space')await page.keyboard.press(activation);
  else if(activation==='pointer'){await closeSettings(page);await generate.click();}
  else if(activation==='programmatic-click')await generate.evaluate(el=>el.click());
  else await page.locator('#settings-form').evaluate(el=>el.requestSubmit());
  assert.equal(await page.locator('.password').count(),1,width+'/'+profile+'/'+activation);
  const state=await page.evaluate(()=>{const el=document.activeElement,b=el.getBoundingClientRect(),r=document.querySelector('.password').getBoundingClientRect();return {card:el.classList.contains('password-row'),generate:el.id==='generate',top:b.top,bottom:b.bottom,resultTop:r.top,resultBottom:r.bottom,outline:getComputedStyle(el).outlineStyle,label:el.getAttribute('aria-label'),tabIndex:el.tabIndex,scrolls:fixtureScrolls,overflow:document.documentElement.scrollWidth>innerWidth};});
  assert.ok(state.resultTop>=0&&state.resultBottom<=900);assert.equal(state.overflow,false);assert.ok(state.scrolls.every(s=>s.behavior==='instant'));
  if(activation==='Enter'||activation==='Space'){
   assert.ok(state.top>=0&&state.bottom<=900,'Keyboard focus visible');assert.equal(state.outline,'solid');
   if(state.card){if(width===320&&activation==='Enter'){const path=screenshot(profile+'-focused-result.png');await page.screenshot({path});results.screenshots.push(path);}assert.equal(state.tabIndex,-1);assert.match(state.label,/Generated password 1.*validated/);assert.equal(await page.locator('#status').textContent(),'');await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.activeElement.getAttribute('aria-label')),'Copy password 1');}
   else {assert.equal(state.generate,true);await page.keyboard.press('Tab');assert.equal(await page.locator('.privacy-note summary').evaluate(e=>e===document.activeElement),true);}
  }else assert.equal(state.generate,true,'Pointer/programmatic generation does not transfer focus');
  results.activation.push({width,profile,activation,...state});
  if(width===320&&activation==='Enter'){const path=screenshot(profile+'-keyboard.png');await page.screenshot({path});results.screenshots.push(path);}
 }
 // No additional scroll when the result and Generate are already visible.
 await page.reload();await page.setViewportSize({width:1280,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await closeSettings(page);await generate.focus();await page.keyboard.press('Enter');const before=await page.evaluate(()=>fixtureScrolls.length);await page.keyboard.press('Enter');assert.equal(await page.evaluate(()=>fixtureScrolls.length),before);
 for(const hidden of [false,true])for(const kind of ['policy','label','password']){
  await page.reload();await openSettings(page);await selectProfile(page,'strong-random');if(hidden){await closeSettings(page);await page.locator('#show').uncheck();}await closeSettings(page);await generate.click();
  if(kind==='label')await openSettings(page);
  if(kind==='policy') {await openSettings(page);await page.locator('#strong-exclusions').focus();}
  await page.evaluate(kind=>{
   const field=document.getElementById('strong-exclusions');field.value='A'.repeat(256)+'Z';
   if(kind==='policy')field.select();else{document.activeElement.blur();const r=document.createRange();r.selectNodeContents(document.querySelector(kind==='password'?'.password':'#profile-help'));getSelection().removeAllRanges();getSelection().addRange(r);}
   globalThis.fixtureCopyPrevented=null;document.addEventListener('copy',e=>{fixtureCopyPrevented=e.defaultPrevented;},{once:true});
  },kind);
  await page.evaluate(()=>fixtureClipboard('public sentinel'));await page.keyboard.press('Control+c');assert.equal(await page.evaluate(()=>fixtureCopyPrevented),kind==='password');
  const copied=await page.evaluate(()=>navigator.clipboard.readText());if(kind==='password')assert.equal(copied,'public sentinel');else if(kind==='policy')assert.equal(copied,'A'.repeat(256)+'Z');else assert.match(copied,/Random characters/);
  assert.equal(await page.locator('.password').count(),0);assert.equal(await generate.isDisabled(),true);results.copy.push({hidden,kind,blocked:kind==='password'});
 }
 // Old component/button callbacks cannot copy after invalid eventless edits.
 for(const action of ['component','individual','all','regenerate']){
  await page.reload();await closeSettings(page);await generate.click();const draws=await page.evaluate(()=>fixtureDraws);
  await page.evaluate(action=>{document.getElementById('suffix').value='1';document.querySelector(action==='component'?'.component-copy button':action==='individual'?'.row-top button':action==='all'?'#copy-all':'.regenerate').click();},action);
  assert.equal(await page.locator('.password').count(),0);assert.equal(await page.evaluate(()=>fixtureWrites.length),0);assert.equal(await page.evaluate(()=>fixtureDraws),draws);
 }
 // Error reveal leaves its checkbox focused and both control/description visible.
 for(const width of [320,390,768,1280]){
  await page.reload();await page.setViewportSize({width,height:844});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);await openSettings(page);await selectProfile(page,'custom-policy');await openSettings(page);await page.locator('#custom-digits').uncheck();
  assert.equal(await page.evaluate(()=>document.activeElement.id),'custom-digits');const control=await page.locator('#custom-digits').boundingBox(),error=await page.locator('#custom-digits-error').boundingBox();
  assert.ok(control.y>=0&&error.y+error.height<=844);assert.equal(await page.locator('#custom-digits').getAttribute('aria-invalid'),'true');
  const before=await page.evaluate(()=>scrollY);await page.locator('#custom-digits').evaluate(el=>el.dispatchEvent(new Event('change',{bubbles:true})));assert.equal(await page.evaluate(()=>scrollY),before,'Already visible error does not scroll');
  results.errors.push({width,controlTop:control.y,errorBottom:error.y+error.height});
  await openSettings(page);await page.locator('#custom-digits').check();assert.equal(await page.locator('#custom-digits-error').isVisible(),false);
 }
 assert.equal(await page.evaluate(()=>fixtureLeaks),0);assert.deepEqual(errors,[]);assert.deepEqual(logs,[]);
 await writeFile(screenshot('results.png').replace(/\.png$/,'.json'),JSON.stringify(results,null,2)+'\n');
 console.log('PASS: 60 profile/viewport/activation cases, visible keyboard focus and Tab order, native policy/label/stale/hidden copies, component/full/all/regeneration guards, four inline-error layouts, instant reduced-motion scrolling.');
}finally{await browser?.close();server.kill();}
