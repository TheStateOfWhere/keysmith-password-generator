// Open the active profile's actual configuration surface.
import assert from 'node:assert/strict';
export async function openSettings(page){
 if(await page.locator('#profile').inputValue()==='custom-policy'){
  await closeSettings(page);
  assert.equal(await page.locator('#custom-policy-inline').isVisible(),true);
  return;
 }
 if(!await page.locator('#settings-disclosure').evaluate(e=>e.open))await page.locator('#settings-summary').click();
 assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.matches(':modal')),true);
}
export async function closeSettings(page){
 if(await page.locator('#settings-disclosure').evaluate(e=>e.open))await page.locator('#settings-close').click();
}
export async function selectProfile(page,value){
 if(!await page.locator('#settings-disclosure').evaluate(e=>e.open))await page.locator('#settings-summary').click();
 await page.locator('#profile').selectOption(value);
 assert.equal(await page.locator('[data-profile="'+value+'"]').getAttribute('aria-pressed'),'true');
 if(value==='custom-policy'){
  assert.equal(await page.locator('#settings-disclosure').evaluate(e=>e.open),false);
  assert.equal(await page.locator('#custom-policy-inline').isVisible(),true);
 }
}
