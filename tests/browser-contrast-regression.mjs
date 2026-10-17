// Isolated contrast controls; never change the application's approved styling.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {writeFile} from 'node:fs/promises';
import {auditContrast} from './browser-contrast.mjs';
import {screenshotDirectory} from './browser-artifacts.mjs';
const {chromium}=createRequire(import.meta.url)(process.env.KEYSMITH_PLAYWRIGHT_MODULE||'playwright');
const artifact=await screenshotDirectory('contrast-regression');
const server=spawn(process.execPath,['scripts/serve.mjs'],{cwd:fileURLToPath(new URL('../',import.meta.url)),stdio:['ignore','pipe','pipe']});
let browser;
const results={controls:[],eligibility:[],actualArrows:[],disabledControls:[]};
try {
  await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',()=>reject(Error('Local server stopped')));});
  browser=await chromium.launch({headless:true,...(process.env.KEYSMITH_BROWSER_PATH?{executablePath:process.env.KEYSMITH_BROWSER_PATH}:{})});
  results.browser=browser.version();
  const context=await browser.newContext({viewport:{width:1280,height:1000}}), page=await context.newPage();
  await page.goto('http://127.0.0.1:4173/',{waitUntil:'networkidle'});
  await page.locator('#theme').selectOption('midnight');
  await page.locator('#count').selectOption('5');await page.locator('#generate').click();
  const measured=await page.evaluate(auditContrast,{selector:'#generate span,#batch-generate span',details:true});
  assert.equal(measured.textChecks,2);assert.deepEqual(measured.failures,[]);
  for (const id of ['generate','batch-generate']) {
    const styles=await page.locator('#'+id+' span').evaluate(element=>{
      const range=document.createRange();range.selectNodeContents(element);
      return {foreground:getComputedStyle(element).color,root:getComputedStyle(document.documentElement).backgroundColor,gradient:getComputedStyle(element.parentElement).backgroundImage,parent:element.parentElement.getBoundingClientRect().toJSON(),text:range.getBoundingClientRect().toJSON()};
    });
    // Independent dense calculation from fresh computed CSS and DOM geometry.
    // This does not call the helper's parser, projection, compositor or bounds.
    const colors=[...styles.gradient.matchAll(/rgb\((\d+), (\d+), (\d+)\)/g)].map(m=>m.slice(1).map(Number));
    assert.equal(colors.length,2);
    const foreground=styles.foreground.match(/[\d.]+/g).map(Number),root=styles.root.match(/[\d.]+/g).map(Number);
    const lum=c=>c.map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
    const contrast=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
    const angle=parseFloat(styles.gradient.match(/linear-gradient\(([-\d.]+)deg/)[1])*Math.PI/180;
    const ux=Math.sin(angle),uy=-Math.cos(angle),box=styles.parent,rect=styles.text;
    const extent=Math.abs(ux*box.width)+Math.abs(uy*box.height);
    const positions=[rect.left,rect.right].flatMap(x=>[rect.top,rect.bottom].map(y=>.5+((x-box.left-box.width/2)*ux+(y-box.top-box.height/2)*uy)/extent));
    const start=Math.min(...positions),end=Math.max(...positions);
    const color=t=>colors[0].map((v,i)=>v+(colors[1][i]-v)*Math.max(0,Math.min(1,t)));
    let fullMinimum=Infinity,regionMinimum=Infinity;
    for(let i=0;i<=10000;i++){
      fullMinimum=Math.min(fullMinimum,contrast(foreground,color(i/10000)));
      regionMinimum=Math.min(regionMinimum,contrast(foreground,color(start+(end-start)*i/10000)));
    }
    const helper=measured.measurements.find(m=>m.parent===id);
    assert.ok(helper.ratio>=4.5);
    assert.ok(helper.ratio<=regionMinimum+1e-9,'Conservative lower bound must not overstate contrast');
    assert.ok(regionMinimum-helper.ratio<.02,'Bound must closely enclose independent region measurement');
    results.actualArrows.push({id,styles,oldBackgroundOnlyRatio:contrast(foreground,root),independentFullGradientMinimum:fullMinimum,independentRegionMinimum:regionMinimum,helperLowerBound:helper.ratio,helperSampledMinimum:helper.sampledMinimum,projection:helper.gradientRegions});
  }
  // The existing native-disabled policy includes the control's descendants.
  await page.locator('#theme').selectOption('zevyrn');await page.locator('[data-profile="custom-policy"]').click();
  await page.locator('#custom-exclusions').fill('A'.repeat(257));
  assert.equal(await page.locator('#generate').isDisabled(),true);
  const disabled=await page.evaluate(auditContrast,{selector:'#generate span,#batch-generate span',details:true});
  assert.equal(disabled.textChecks,0,'Native disabled descendants are ineligible under the existing policy');
  assert.deepEqual(disabled.failures,[]);
  for(const id of ['generate','batch-generate']){
    const state=await page.locator('#'+id).evaluate(e=>({disabled:e.disabled,opacity:getComputedStyle(e).opacity,gradient:getComputedStyle(e).backgroundImage,nativeDisabledAncestor:e.querySelector('span').closest(':disabled')?.id}));
    assert.equal(state.disabled,true);assert.equal(state.nativeDisabledAncestor,id);
    results.disabledControls.push({id,...state,excluded:true});
  }
  await context.close();
  // These fixtures live in a different browser context, not the application.
  const fixtures=await browser.newContext({viewport:{width:800,height:600}}), probe=await fixtures.newPage();
  async function eligibility(name,markup,measured,failed,body='white'){
    await probe.setContent(`<style>body{background:${body}}button,[role=button]{border:0;background:white;color:white;font:24px Arial}</style>${markup}`);
    const result=await probe.evaluate(auditContrast,{selector:'[data-probe]',details:true});
    assert.deepEqual(result.measurements.map(m=>m.element).sort(),[...measured].sort(),name+' measured elements');
    assert.deepEqual(result.failures.map(m=>m.element).sort(),[...failed].sort(),name+' failures');
    assert.equal(result.textChecks,measured.length,name+' eligibility count');
    results.eligibility.push({name,pass:true,...result});
  }
  const native='<button id="control" data-probe disabled>Disabled <span id="child" data-probe>child</span></button>';
  const enabled='<button id="control" data-probe>Enabled <span id="child" data-probe>child</span></button>';
  await eligibility('native disabled control and child excluded',native,[],[]);
  await eligibility('enabled low-contrast control and child still fail',enabled,['control','child'],['control','child']);
  await eligibility('opacity alone never disables eligibility',enabled.replace('data-probe>Enabled','data-probe style="opacity:.6">Enabled'),['control','child'],['control','child']);
  await eligibility('enabled reduced-opacity high-contrast control is measured',enabled.replace('data-probe>Enabled','data-probe style="opacity:.6;background:black;color:white">Enabled'),['control','child'],[],'black');
  await eligibility('unrelated sibling remains checked',native+'<span id="sibling" data-probe style="color:white;background:white">sibling</span>',['sibling'],['sibling']);
  await eligibility('native inherited fieldset disability preserved','<fieldset disabled>'+enabled+'</fieldset>',[],[]);
  await eligibility('disabled attribute on nonnative element is not semantic','<div id="control" role="button" disabled data-probe>Enabled <span id="child" data-probe>child</span></div>',['control','child'],['control','child']);
  await eligibility('ARIA-only disabled control stays eligible under native-only policy',enabled.replace('id="control"','id="control" aria-disabled="true"'),['control','child'],['control','child']);
  await eligibility('aria-disabled false remains eligible',enabled.replace('id="control"','id="control" aria-disabled="false"'),['control','child'],['control','child']);
  async function control(name,style,expected,child='',position='left:160px',body='#fff') {
    await probe.setContent(`<style>body{margin:0;background:${body}}#paint{position:absolute;left:30px;top:30px;width:400px;height:100px;${style}}#probe{position:absolute;top:30px;${position};font:24px Arial;background:transparent;${child}}</style><div id="paint"><span id="probe">X</span></div>`);
    const result=await probe.evaluate(auditContrast,{selector:'#probe',details:true});
    assert.equal(result.failures.length===0,expected,name);
    results.controls.push({name,expectedPass:expected,pass:true,...result});
  }
  await control('high-contrast gradient','background:linear-gradient(110deg,#000,#123);color:white',true);
  await control('low-contrast gradient','background:linear-gradient(90deg,#777,#888);color:#808080',false);
  await control('measure favorable region only when text actually occupies it','background:linear-gradient(90deg,#000,#fff 50%,#000);color:black',true,'','left:195px');
  await control('same gradient, actual dark text region fails','background:linear-gradient(90deg,#000,#fff 50%,#000);color:black',false,'','left:5px');
  await control('transparent child does not mask white ancestor','background:linear-gradient(90deg,#fff,#fff);color:white',false);
  await control('transparent gradient preserves black underlay','background-color:black;background-image:linear-gradient(90deg,rgba(255,255,255,0),rgba(255,255,255,0));color:white',true);
  await control('transparent gradient preserves white underlay','background-color:white;background-image:linear-gradient(90deg,rgba(0,0,0,0),rgba(0,0,0,0));color:white',false);
  await control('partly transparent gradient composites instead of becoming opaque','background-color:black;background-image:linear-gradient(90deg,rgba(255,255,255,.25),rgba(255,255,255,.25));color:white',true);
  await control('solid background high contrast','background:black;color:white',true);
  await control('solid background low contrast','background:#777;color:#777',false);
  await control('narrow low-contrast stop cannot be missed','background:linear-gradient(90deg,#000 0%,#000 49.98%,#fff 49.99%,#000 50%,#000 100%);color:white',false,'','left:195px');
  await control('gradient is not painted below a 3px decorative strip','background-color:white;background-image:linear-gradient(90deg,#000,#000);background-size:100% 3px;background-repeat:no-repeat;color:black',true);
  await probe.setContent('<input id="probe" type="text" value="test" style="background:black;color:white;border:2px solid black">');
  const border=await probe.evaluate(auditContrast,{selector:'#probe',details:true});
  assert.ok(border.failures.some(f=>f.kind==='control border'));results.controls.push({name:'solid control border still fails',expectedPass:false,pass:true,...border});
  await probe.setContent('<button id="paint" style="background:radial-gradient(black,white)"><span id="probe">X</span></button>');
  await assert.rejects(probe.evaluate(auditContrast,{selector:'#probe'}),/Unsupported background image/);
  results.controls.push({name:'unsupported paint fails explicitly',pass:true});
  await fixtures.close();results.status='PASS';
  const path=artifact('results.png').replace(/\.png$/,'.json');await writeFile(path,JSON.stringify(results,null,2)+'\n');
  console.log('PASS: '+results.controls.length+' gradient/solid contrast controls; '+results.eligibility.length+' semantic eligibility controls; 2 actual Midnight arrows. '+path);
} finally {await browser?.close();server.kill();}
