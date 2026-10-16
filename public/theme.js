/* Theme preference only. No access to password settings, output or randomness. */
(() => {
  'use strict';
  const key = 'keysmith.theme';
  const themes = ['automatic', 'light', 'dark', 'emerald', 'amethyst'];
  const valid = value => typeof value === 'string' && themes.includes(value);
  let selected = 'automatic';
  let storageUnavailable = false;
  try {
    const saved = window.localStorage.getItem(key);
    if (valid(saved)) selected = saved;
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
      selected = valid(selector.value) ? selector.value : 'automatic';
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
