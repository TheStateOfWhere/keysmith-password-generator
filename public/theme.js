/* Theme preference only. No access to password settings, output or randomness. */
(() => {
  'use strict';
  // Keep the existing preference key and map legacy names without rewriting storage.
  const key = 'keysmith.theme';
  const themes = ['zevyrn', 'midnight', 'aurora', 'dusk', 'slate'];
  const legacy = {automatic:'zevyrn', light:'zevyrn', dark:'midnight', emerald:'aurora', amethyst:'dusk'};
  const valid = value => typeof value === 'string' && themes.includes(value);
  let selected = 'zevyrn';
  let storageUnavailable = false;
  try {
    const saved = window.localStorage.getItem(key);
    if (valid(saved)) selected = saved;
    else if (typeof saved === 'string' && Object.hasOwn(legacy, saved)) selected = legacy[saved];
  } catch { storageUnavailable = true; }
  document.documentElement.setAttribute('data-theme', selected);

  document.addEventListener('DOMContentLoaded', () => {
    const selector = document.getElementById('theme');
    const message = document.getElementById('theme-save-status');
    if (!selector || !message) return;
    const feedback = () => {
      message.textContent = storageUnavailable
        ? 'Theme applies for this session; saving is unavailable.' : '';
      message.hidden = !storageUnavailable;
    };
    selector.value = selected;
    selector.disabled = false;
    feedback();
    selector.addEventListener('change', () => {
      selected = valid(selector.value) ? selector.value : 'zevyrn';
      selector.value = selected;
      document.documentElement.setAttribute('data-theme', selected);
      try {
        window.localStorage.setItem(key, selected);
        storageUnavailable = false;
      } catch { storageUnavailable = true; }
      feedback();
    });
  }, { once: true });
})();
