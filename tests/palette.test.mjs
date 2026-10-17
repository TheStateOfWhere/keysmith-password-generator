import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const tokens=JSON.parse(await readFile(new URL('./approved-theme-tokens.json',import.meta.url),'utf8'));
const css=await readFile(new URL('../public/styles.css',import.meta.url),'utf8');
const luminance=h=>h.match(/[a-f\d]{2}/gi).map(v=>parseInt(v,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
const ratio=(a,b)=>(Math.max(luminance(a),luminance(b))+.05)/(Math.min(luminance(a),luminance(b))+.05);
const blend=(a,b,t)=>'#'+a.match(/[a-f\d]{2}/gi).map((v,i)=>Math.round(parseInt(v,16)+(parseInt(b.slice(1+i*2,3+i*2),16)-parseInt(v,16))*t).toString(16).padStart(2,'0')).join('');
for(const [theme,t] of Object.entries(tokens)){
 test(theme+' matches the approved palette and accessible action roles',()=>{
  const block=css.match(new RegExp(':root\\[data-theme='+theme.toLowerCase()+'\\]\\{([^}]+)\\}'))[1];
  for(const [key,value] of Object.entries(t))if(typeof value==='string')assert.ok(block.includes('--'+key+':'+value+';'),key);
  for(const bg of ['surface','background','soft']){
   for(const fg of ['text','muted','accent','success','error'])assert.ok(ratio(t[fg],t[bg])>=4.5,fg+' on '+bg);
   for(const fg of ['focus','control-border'])assert.ok(ratio(t[fg],t[bg])>=3,fg+' on '+bg);
  }
  assert.ok(ratio(t['on-accent'],t.accent)>=4.5);
  for(let j=1;j<t['gradient-stops'].length;j++)for(let i=0;i<=1000;i++)assert.ok(ratio(t['on-gradient'],blend(t['gradient-stops'][j-1],t['gradient-stops'][j],i/1000))>=4.5,'gradient label');
 });
}
test('approved action separation, touch targets and script-failure default remain explicit',async()=>{
 assert.match(css,/\.primary\{background:var\(--accent\);color:var\(--on-accent\)\}/);
 assert.match(css,/#generate,#batch-generate,#settings-generate\{background:var\(--gradient\)/);
 assert.match(css,/button,select,summary,textarea,input:not\(\[type=checkbox\]\),\.brand,footer a\{min-width:44px;min-height:44px\}/);
 const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
 assert.match(html,/<html lang="en" data-theme="zevyrn">/);
 assert.match(html,/<title>Zevyrn<\/title>/);
 assert.doesNotMatch(html,/KeySmith|zevyrn\.preview\.theme/);
});
