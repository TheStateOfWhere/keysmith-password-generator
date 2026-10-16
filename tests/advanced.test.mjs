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
  assert.match(html, /Strong passwords\. Made simple\./);
  assert.doesNotMatch(html, /PRECISION OVER GUESSWORK|class="notes"/);
  assert.match(html, /aria-label="Security and privacy"/);
  assert.match(html, /<svg[^>]*[\s\S]*?<\/svg>/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.match(html, /id="status" role="status" aria-live="polite"/);
  assert.match(html, /id="word-count"/);
  assert.match(html, /id="entropy"/);
});

function luminance(hex) {
  const values = hex.match(/[0-9a-f]{2}/gi).map(n => parseInt(n, 16) / 255).map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4);
  return values[0] * .2126 + values[1] * .7152 + values[2] * .0722;
}
function contrast(a, b) {
  const values = [luminance(a), luminance(b)].sort((a, b) => b - a);
  return (values[0] + .05) / (values[1] + .05);
}
test('redesign text palette has AA contrast on its intended backgrounds', async () => {
  const css = await readFile(new URL('../dist/styles.css', import.meta.url), 'utf8');
  const palettes = [
    {text:['181d34','546078','4744cf','176346','B91C1C'],backgrounds:['ffffff','f6f7f9'],accent:'4744cf',buttonText:'ffffff'},
    ...[
      {accent:'aecbff',fg:'f2f5fc',muted:'bdc7d9',backgrounds:['111827','1c2637'],border:'64748B'},
      {accent:'8be1bb',fg:'effbf4',muted:'b8d4c6',backgrounds:['101f1b','19332a'],border:'82948e'},
      {accent:'d1befc',fg:'f8f2ff',muted:'cfc0df',backgrounds:['20192c','30253e'],border:'9786aa'}
    ].map(p=>({...p,text:[p.fg,p.muted,p.accent,'FDA4AF','91e5bd'],buttonText:'142138'}))
  ];
  for(const p of palettes){
    assert.ok(css.includes('#'+p.accent));
    for(const fg of p.text)for(const bg of p.backgrounds)assert.ok(contrast(fg,bg)>=4.5,`${fg} on ${bg}`);
    assert.ok(contrast(p.buttonText,p.accent)>=4.5);
    for(const bg of p.backgrounds.slice(0,2))assert.ok(contrast(p.border||'64748B',bg)>=3);
  }
  assert.match(css, /summary:focus-visible/);
  assert.doesNotMatch(css, /\.password-list\{[^}]*min-height/);
});
