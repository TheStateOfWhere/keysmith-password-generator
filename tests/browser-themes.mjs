import {openSettings,closeSettings,selectProfile} from './browser-dialog.mjs';
// Local-only Edge verification. Passwords are deterministic public fixtures.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';
import {screenshotDirectory} from './browser-artifacts.mjs';
const {chromium}=createRequire(import.meta.url)(process.env.PASSWORDFORGE_PLAYWRIGHT_MODULE||'playwright');
const artifact=await screenshotDirectory('themes');
const root=fileURLToPath(new URL('../',import.meta.url));
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:root,stdio:['ignore','pipe','pipe']});
let browser;
const themes=['automatic','light','dark','emerald','amethyst'];
const results={cases:[],contrast:[],storage:[],screenshots:[]};
async function setup(options={}){
  const context=await browser.newContext({viewport:{width:1280,height:1000},colorScheme:'light',reducedMotion:'reduce',
    ...(options.saved!==undefined?{storageState:{cookies:[],origins:[{origin:'http://127.0.0.1:4173',localStorage:[{name:'passwordforge.theme',value:options.saved}]}]}}:{})});
  await context.route('**/favicon.ico',r=>r.fulfill({status:204}));
  await context.route('**/styles.css',async r=>{await new Promise(resolve=>setTimeout(resolve,150));await r.continue();});
  if(options.scriptFailure)await context.route('**/theme.js',r=>r.abort());
  await context.addInitScript(({readFail,writeFail})=>{
    globalThis.themeFixture={draws:0,copies:[],writes:[],unsafe:0,firstFrame:null};let word=0,rank=0;
    Object.defineProperty(globalThis,'crypto',{configurable:true,value:{getRandomValues(b){themeFixture.draws++;if(b instanceof Uint8Array){b.fill(0);b[b.length-1]=rank++%256;}else b[0]=[0,0,0,0,8,0,8,0,8][word++%9];return b;}}});
    Object.defineProperty(navigator.clipboard,'writeText',{configurable:true,value:async value=>{themeFixture.copies.push(value);}});
    const get=Storage.prototype.getItem,set=Storage.prototype.setItem;
    Storage.prototype.getItem=function(key){if(readFail)throw new DOMException('Denied','SecurityError');return get.call(this,key);};
    Storage.prototype.setItem=function(key,value){
      if(this!==window.localStorage||key!=='passwordforge.theme'||!['automatic','light','dark','emerald','amethyst'].includes(value)){themeFixture.unsafe++;throw Error('Forbidden persistence');}
      if(writeFail)throw new DOMException('Denied','QuotaExceededError');
      themeFixture.writes.push([key,value]);return set.call(this,key,value);
    };
    for(const name of ['fetch','XMLHttpRequest','WebSocket'])Object.defineProperty(globalThis,name,{configurable:true,value:()=>{themeFixture.unsafe++;throw Error('Forbidden network use');}});
    requestAnimationFrame(()=>{themeFixture.firstFrame={theme:document.documentElement.dataset.theme,background:getComputedStyle(document.documentElement).backgroundColor};});
  },options);
  const page=await context.newPage();const logs=[],errors=[],requests=[];
  page.on('console',m=>logs.push(m.type()));page.on('pageerror',()=>errors.push('Page error'));
  await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
  page.on('request',r=>requests.push(r.resourceType()));
  return {context,page,logs,errors,requests};
}
const background=page=>page.evaluate(()=>getComputedStyle(document.documentElement).backgroundColor);
const snapshot=page=>page.evaluate(()=>({passwords:[...document.querySelectorAll('.password')].map(e=>e.textContent),
  settings:[...document.querySelector('#settings-form').elements].map(e=>[e.id,e.value,e.checked,e.disabled]),
  show:document.querySelector('#show').checked,manual:document.querySelector('#manual').checked,
  entropy:document.querySelector('#entropy').textContent,status:document.querySelector('#status').textContent,
  copies:themeFixture.copies,draws:themeFixture.draws,copyDisabled:document.querySelector('#copy-all').disabled,
  cards:[...document.querySelectorAll('.password-row')].map(e=>e.outerHTML)}));
async function contrast(page,label){
  const report=await page.evaluate(()=>{
    const failures=[];let textChecks=0,controlChecks=0,focusChecks=0;
    const rgb=s=>s.match(/[\d.]+/g).map(Number);
    const composite=(f,b)=>{const a=f[3]??1;return [0,1,2].map(i=>f[i]*a+b[i]*(1-a));};
    const bg=e=>{const chain=[];for(let p=e;p;p=p.parentElement)chain.unshift(p);let b=[255,255,255];for(const p of chain)b=composite(rgb(getComputedStyle(p).backgroundColor),b);return b;};
    const luminance=a=>a.map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
    const ratio=(f,b)=>{const a=luminance(f),c=luminance(b);return (Math.max(a,c)+.05)/(Math.min(a,c)+.05);};
    for(const e of document.querySelectorAll('body *')){
      if(!e.getClientRects().length||e.matches(':disabled')||e.closest('fieldset:disabled')||e.classList.contains('sr-only')||e.closest('svg'))continue;
      const cs=getComputedStyle(e);
      const ownText=[...e.childNodes].some(n=>n.nodeType===3&&n.textContent.trim());
      if(ownText||e.matches('input,select,textarea')){
        const value=ratio(composite(rgb(cs.color),bg(e)),bg(e));textChecks++;
        if(value<4.5)failures.push({element:e.id||e.tagName,kind:'text',ratio:value});
      }
      if(e.matches('input[type=number],input[type=text],textarea,select,button:not(.primary)')&&parseFloat(cs.borderTopWidth)>0){
        controlChecks++;const value=ratio(rgb(cs.borderTopColor),bg(e));
        if(value<3)failures.push({element:e.id||e.tagName,kind:'control border',ratio:value});
      }
      if(e===document.activeElement&&cs.outlineStyle!=='none'){
        focusChecks++;const value=ratio(rgb(cs.outlineColor),bg(e.parentElement));
        if(value<3)failures.push({element:e.id||e.tagName,kind:'focus',ratio:value});
      }
    }
    return {failures,textChecks,controlChecks,focusChecks};
  });
  assert.deepEqual(report.failures,[],label+' rendered contrast');results.contrast.push({label,...report});
}
try{
  await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Local preview stopped')));});
  browser=await chromium.launch({headless:true,...(process.env.PASSWORDFORGE_BROWSER_PATH?{executablePath:process.env.PASSWORDFORGE_BROWSER_PATH}:{})});results.browser=browser.version();
  const f=await setup();const {page}=f;
  assert.equal(await page.locator('#theme').inputValue(),'automatic');
  for(const profile of ['readable','strong-random','custom-policy']){
    await openSettings(page);await selectProfile(page,profile);await closeSettings(page);await page.locator('#count').selectOption('5');
    if(profile==='custom-policy'){await openSettings(page);await page.locator('#custom-length').fill('128');}
    await closeSettings(page);await page.locator('#generate').click();await closeSettings(page);await (await page.locator('#copy-all').isVisible()?page.locator('#copy-all'):page.locator('.copy-password').first()).click();
    for(const hidden of [false,true]){
      await closeSettings(page);await page.locator('#show').setChecked(!hidden);await closeSettings(page);await page.locator('#manual').check();
      for(const theme of themes){
        const before=await snapshot(page);await closeSettings(page);await page.locator('#theme').selectOption(theme);
        assert.deepEqual(await snapshot(page),before,'Theme changes preserve password/settings/copy/randomness state');
        await closeSettings(page);await page.locator('#theme').focus();await contrast(page,profile+'/'+theme+'/'+hidden);
        if(!hidden){await closeSettings(page);await page.locator('#generate').hover();await contrast(page,profile+'/'+theme+'/primary-hover');await page.locator('.row-top button').first().hover();await contrast(page,profile+'/'+theme+'/copy-hover');}
        if(!hidden){await closeSettings(page);await page.locator('#settings-summary').click();assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.matches(':modal')),true);await page.locator('#profile').focus();await contrast(page,profile+'/'+theme+'/settings-dialog');await closeSettings(page);}
        for(const width of [320,390,768,1280]){
          await page.setViewportSize({width,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
          assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'No horizontal overflow');
          const box=await page.locator('#theme').boundingBox();assert.ok(box.height>=44);
          results.cases.push({profile,theme,hidden,width});
          if(profile==='custom-policy'&&theme==='amethyst'&&!hidden&&width<=390){const path=artifact('amethyst-long-mobile-'+width+'.png');await page.screenshot({path,fullPage:true});results.screenshots.push(path);}
        }
        if(profile==='readable'&&!hidden){const path=artifact(theme+'-desktop.png');await page.screenshot({path,fullPage:true});results.screenshots.push(path);}
      }
    }
    await closeSettings(page);await page.locator('#show').check();await closeSettings(page);await page.locator('#manual').uncheck();
    const before=await page.locator('.password').allTextContents();await page.locator('.regenerate').nth(1).click();
    const after=await page.locator('.password').allTextContents();assert.ok(after.every((v,i)=>i===1||v===before[i]));
    await page.locator('.row-top button').first().click();assert.ok(await page.evaluate(v=>themeFixture.copies.at(-1)===v,after[0]));
    if(profile==='readable'){await page.locator('.component-disclosure summary').first().click();await page.locator('.component-copy button').first().click();assert.ok(await page.evaluate(v=>themeFixture.copies.at(-1)===v,after[0].split('.')[0]));}
  }
  // Maximum literal-policy batch remains literal in both display modes.
  await closeSettings(page);await page.locator('#count').selectOption('20');
  await closeSettings(page);await page.locator('#generate').click();
  const maximumBatch=await page.locator('.password').allTextContents();
  assert.equal(maximumBatch.length,20);
  assert.ok(maximumBatch.every(value=>value.length===128));
  for(const width of [320,390,768,1280]){
    await page.setViewportSize({width,height:1000});await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));await closeSettings(page);
    for(const manual of [false,true]){
      await closeSettings(page);await page.locator('#manual').setChecked(manual);
      assert.deepEqual(await page.locator('.password').allTextContents(),maximumBatch);
      assert.equal(await page.locator('.password .segment').count(),0);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    }
  }
  // Visible field errors, hover and keyboard focus must pass actual rendered colors.
  await openSettings(page);await page.locator('#custom-exclusions').fill('A'.repeat(257));assert.equal(await page.locator('#generate').isDisabled(),true);
  for(const theme of themes){const before=await snapshot(page);await closeSettings(page);await page.locator('#theme').selectOption(theme);assert.deepEqual(await snapshot(page),before,'Invalid settings and stale copy state preserved');assert.equal(await page.locator('#copy-all').isDisabled(),true);await closeSettings(page);await page.locator('#theme').hover();await contrast(page,'errors/hover/'+theme);await openSettings(page);await page.locator('#custom-exclusions').focus();await contrast(page,'settings/errors/'+theme);await closeSettings(page);}
  await openSettings(page);await page.locator('#custom-exclusions').fill('');await closeSettings(page);await page.locator('#theme').focus();
  await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
  assert.equal(await page.locator('#theme').inputValue(),'light');assert.equal(await page.evaluate(()=>document.activeElement.id),'theme');
  await page.keyboard.press('Escape');await page.keyboard.press('Tab');assert.equal(await page.locator('[data-profile]').first().evaluate(e=>document.activeElement===e),true);
  assert.deepEqual(f.requests,[],'No theme/profile interaction requests before reload');
  await closeSettings(page);await page.locator('#theme').selectOption('automatic');const automaticState=await snapshot(page);const automaticWrites=await page.evaluate(()=>themeFixture.writes);await page.emulateMedia({colorScheme:'dark'});assert.equal(await background(page),'rgb(17, 24, 39)');
  await page.emulateMedia({colorScheme:'light'});assert.equal(await background(page),'rgb(246, 247, 249)');assert.deepEqual(await snapshot(page),automaticState);assert.deepEqual(await page.evaluate(()=>themeFixture.writes),automaticWrites);
  for(const theme of ['light','dark','emerald','amethyst']){
    await closeSettings(page);await page.locator('#theme').selectOption(theme);const b=await background(page);await page.emulateMedia({colorScheme:'dark'});assert.equal(await background(page),b);await page.emulateMedia({colorScheme:'light'});assert.equal(await background(page),b);
    await page.reload({waitUntil:'networkidle'});assert.equal(await page.locator('#theme').inputValue(),theme);
    assert.equal(await page.evaluate(()=>themeFixture.firstFrame.theme),theme);
    assert.equal(await page.evaluate(()=>themeFixture.firstFrame.background),b);results.storage.push({theme,reload:true,firstFrame:true});
  }
  // After the last reload, isolate requests from theme changes.
  f.requests.length=0;await closeSettings(page);await page.locator('#theme').selectOption('emerald');await page.waitForTimeout(100);assert.deepEqual(f.requests,[]);
  assert.equal(await page.evaluate(()=>themeFixture.unsafe),0);assert.equal(await page.evaluate(()=>sessionStorage.length),0);
  assert.deepEqual(await page.evaluate(()=>Object.keys(localStorage)),['passwordforge.theme']);
  assert.deepEqual(f.errors,[]);assert.deepEqual(f.logs,[]);
  await page.emulateMedia({forcedColors:'active'});await closeSettings(page);await page.locator('#theme').focus();
  assert.equal(await page.evaluate(()=>matchMedia('(forced-colors: active)').matches),true);
  assert.notEqual(await page.locator('#theme').evaluate(e=>getComputedStyle(e).outlineStyle),'none');
  const forced=artifact('forced-colors.png');await page.screenshot({path:forced,fullPage:true});results.screenshots.push(forced);await f.context.close();
  for(const options of [{saved:'bogus'},{saved:'dark',readFail:true},{writeFail:true},{scriptFailure:true}]){
    const t=await setup(options);
    assert.equal(await t.page.locator('#theme').inputValue(),'automatic');
    if(options.scriptFailure){assert.equal(await t.page.locator('#theme').isDisabled(),true);await t.page.emulateMedia({colorScheme:'dark'});assert.equal(await background(t.page),'rgb(17, 24, 39)');}
    else{
      await t.page.locator('#theme').selectOption('amethyst');assert.equal(await t.page.evaluate(()=>document.documentElement.dataset.theme),'amethyst');
      if(options.writeFail){assert.equal(await t.page.locator('#theme-save-status').isVisible(),true);await contrast(t.page,'save-failure');}
      if(options.readFail)assert.equal(await t.page.locator('#theme-save-status').isVisible(),false); // successful save recovers
    }
    assert.equal(await t.page.evaluate(()=>themeFixture.unsafe),0);assert.deepEqual(t.errors,[]);
    results.storage.push({...options,pass:true});await t.context.close();
  }
  results.result='PASS';await writeFile(artifact('results.png').replace(/\.png$/,'.json'),JSON.stringify(results,null,2)+'\n');
  console.log('PASS: '+results.cases.length+' profile/theme/hidden/viewport cases; '+results.contrast.length+' rendered contrast checks; persistence, first frame, OS changes, denied storage, script fallback, keyboard and forced colors.');
}finally{await browser?.close();server.kill();}
