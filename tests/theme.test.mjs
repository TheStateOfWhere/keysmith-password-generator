import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';

const source = await readFile(new URL('../public/theme.js', import.meta.url), 'utf8');
const themes = ['automatic', 'light', 'dark', 'emerald', 'amethyst'];
function fixture(saved, {readFails=false, writeFails=false, getterFails=false}={}) {
  const attributes = {}, listeners = {}, writes = [], reads = [];
  const selector = {value:'automatic', disabled:true, addEventListener(name, fn){listeners[name]=fn;}};
  const message = {textContent:'', hidden:true};
  const document = {documentElement:{setAttribute(key,value){attributes[key]=value;}},
    getElementById(id){return id==='theme'?selector:message;},
    addEventListener(name, fn){listeners[name]=fn;}};
  const storage = {getItem(key){reads.push(key);if(readFails)throw Error('Denied');return saved;},
    setItem(key,value){if(writeFails)throw Error('Quota');writes.push([key,value]);}};
  const window = {};
  Object.defineProperty(window,'localStorage',{get(){if(getterFails)throw Error('Denied');return storage;}});
  const sandbox = {window,document};
  for(const key of ['crypto','fetch','navigator','console'])Object.defineProperty(sandbox,key,{get(){throw Error('Forbidden access: '+key);}});
  vm.runInNewContext(source,sandbox);
  return {attributes,selector,message,writes,reads,ready(){listeners.DOMContentLoaded();},change(value){selector.value=value;listeners.change();}};
}
for(const theme of themes)test('restores '+theme+' before selector initialization',()=>{
  const f=fixture(theme);assert.equal(f.attributes['data-theme'],theme);assert.equal(f.selector.disabled,true);
  assert.deepEqual(f.writes,[]);f.ready();assert.equal(f.selector.value,theme);assert.equal(f.selector.disabled,false);
  f.change(theme);assert.deepEqual(f.writes,[['keysmith.theme',theme]]);assert.deepEqual(f.reads,['keysmith.theme']);
});
test('missing and invalid preferences fall back without rewriting storage',()=>{
  for(const value of [null,undefined,'','DARK','dark ','<script>','__proto__','{"theme":"dark"}',42]){
    const f=fixture(value);f.ready();assert.equal(f.attributes['data-theme'],'automatic');assert.deepEqual(f.writes,[]);
  }
});
test('denied reads and storage getter use Automatic with session notice',()=>{
  for(const options of [{readFails:true},{getterFails:true}]){
    const f=fixture('dark',options);f.ready();assert.equal(f.selector.value,'automatic');
    assert.equal(f.message.hidden,false);assert.match(f.message.textContent,/session/);
  }
});
test('failed writes retain active preference and accessible feedback',()=>{
  const f=fixture(null,{writeFails:true});f.ready();f.change('emerald');
  assert.equal(f.attributes['data-theme'],'emerald');assert.equal(f.selector.value,'emerald');
  assert.equal(f.message.hidden,false);assert.deepEqual(f.writes,[]);
});
test('successful saving clears earlier read-failure notice',()=>{
  const f=fixture(null,{readFails:true});f.ready();f.change('amethyst');
  assert.equal(f.message.hidden,true);assert.deepEqual(f.writes,[['keysmith.theme','amethyst']]);
});
test('untrusted selector value can persist only Automatic',()=>{
  const f=fixture(null);f.ready();f.change('password-value');
  assert.equal(f.selector.value,'automatic');assert.deepEqual(f.writes,[['keysmith.theme','automatic']]);
});
test('early external script, labelled native control, and unchanged CSP',async()=>{
  const html=await readFile(new URL('../public/index.html',import.meta.url),'utf8');
  assert.ok(html.indexOf('<script src="./theme.js"></script>')<html.indexOf('<link rel="stylesheet"'));
  assert.match(html,/<label for="theme">Theme<\/label>/);assert.match(html,/id="theme"[^>]*disabled/);
  assert.doesNotMatch(html,/unsafe-inline|<script[^>]*>\s*[^<\s]/);
  assert.match(html,/connect-src 'none'/);assert.doesNotMatch(source,/innerHTML|JSON\.stringify|crypto|Math\.random|fetch\(|sendBeacon|console\.|sessionStorage|indexedDB/);
});
test('built theme is exact source and referenced by the served entry point',async()=>{
  assert.equal(await readFile(new URL('../dist/theme.js',import.meta.url),'utf8'),source);
  const html=await readFile(new URL('../dist/index.html',import.meta.url),'utf8');
  assert.match(html,/<script src="\.\/theme\.js"><\/script>/);
});
