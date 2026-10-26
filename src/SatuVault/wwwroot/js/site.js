// SatuVault: authenticator-code dialog, reveal / copy / load-for-edit, plain copy buttons, confirm dialog.
// Secrets arrive only as fetch() responses and are never written into the page HTML.
(() => {
  'use strict';

  const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? '';
  const base = meta('base');
  const HIDE_AFTER_MS = 30_000;

  const dialog = document.getElementById('code-dialog');
  const input = document.getElementById('code-input');
  const errorBox = document.getElementById('code-error');
  const title = document.getElementById('code-title');
  const submit = document.getElementById('code-submit');

  /**
   * Ask for a code and call send(code) until it succeeds or the user cancels.
   * send resolves { ok: true, data } or { ok: false, error, final }.
   */
  function withCode(heading, send) {
    return new Promise((resolve) => {
      title.textContent = heading;
      errorBox.hidden = true;
      input.value = '';
      dialog.showModal();
      input.focus();

      const finish = (result) => {
        dialog.close();
        cleanup();
        resolve(result);
      };
      const onSubmit = async (e) => {
        e.preventDefault();
        submit.disabled = true;
        try {
          const r = await send(input.value.trim());
          if (r.ok) return finish(r.data);
          errorBox.textContent = r.error;
          errorBox.hidden = false;
          input.value = '';
          input.focus();
          if (r.final) submit.disabled = true;
          else submit.disabled = false;
        } catch {
          errorBox.textContent = 'Network error. Try again.';
          errorBox.hidden = false;
          submit.disabled = false;
        }
      };
      // Submit as soon as six digits are in (typed or pasted).
      const onInput = () => {
        input.value = input.value.replace(/\D/g, '').slice(0, 6);
        if (input.value.length === 6 && !submit.disabled) dialog.querySelector('form').requestSubmit();
      };
      const onCancel = () => finish(null);
      const cleanup = () => {
        dialog.querySelector('form').removeEventListener('submit', onSubmit);
        input.removeEventListener('input', onInput);
        document.getElementById('code-cancel').removeEventListener('click', onCancel);
        dialog.removeEventListener('cancel', onCancel);
        submit.disabled = false;
      };
      dialog.querySelector('form').addEventListener('submit', onSubmit);
      input.addEventListener('input', onInput);
      document.getElementById('code-cancel').addEventListener('click', onCancel);
      dialog.addEventListener('cancel', onCancel);
    });
  }

  async function reveal(itemId, body) {
    const res = await fetch(`${base}api/items/${encodeURIComponent(itemId)}/reveal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': meta('csrf') },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (res.ok) return { ok: true, data: json.values };
    return { ok: false, error: json.error ?? `Error ${res.status}`, final: res.status === 423 || res.status === 403 || res.status === 404 };
  }

  /** Copy and show the outcome on the button; returns false when the browser refused. */
  async function copyText(button, text) {
    try {
      await navigator.clipboard.writeText(text);
      flash(button, 'Copied', 'is-done');
      return true;
    } catch {
      flash(button, 'Copy failed', 'is-failed');
      return false;
    }
  }

  // Swap the button's label (keeping its icon) for two seconds.
  function flash(button, text, cls) {
    const texts = [];
    const walk = document.createTreeWalker(button, NodeFilter.SHOW_TEXT);
    while (walk.nextNode()) if (walk.currentNode.textContent.trim()) texts.push(walk.currentNode);
    const label = texts.at(-1);
    if (button.dataset.flashing) return;
    button.dataset.flashing = '1';
    button.classList.add(cls);
    if (!label) {
      setTimeout(() => { button.classList.remove(cls); delete button.dataset.flashing; }, 2000);
      return;
    }
    const old = label.textContent;
    label.textContent = text;
    setTimeout(() => {
      label.textContent = old;
      button.classList.remove(cls);
      delete button.dataset.flashing;
    }, 2000);
  }

  const MASK = '••••••••';
  const hideTimers = new WeakMap();

  // Show a revealed value with a visible countdown, then mask it again.
  function showFor(out, value) {
    clearInterval(hideTimers.get(out));
    out.textContent = value === '' ? '(empty)' : value;
    out.classList.add('shown');
    let counter = out.nextElementSibling?.classList.contains('countdown') ? out.nextElementSibling : null;
    if (!counter) {
      counter = document.createElement('span');
      counter.className = 'countdown';
      counter.setAttribute('aria-live', 'off');
      out.after(counter);
    }
    const until = Date.now() + HIDE_AFTER_MS;
    const tick = () => {
      const left = Math.ceil((until - Date.now()) / 1000);
      if (left > 0) { counter.textContent = `hides in ${left}s`; return; }
      clearInterval(hideTimers.get(out));
      out.textContent = MASK;
      out.classList.remove('shown');
      counter.remove();
    };
    tick();
    hideTimers.set(out, setInterval(tick, 1000));
  }

  // Reveal or copy one secret field: <button data-secret data-action="reveal|copy" data-item data-field [data-version] [data-target]>
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-secret]');
    if (!btn) return;
    e.preventDefault();
    const { action, item, field, version, target } = btn.dataset;
    const values = await withCode(action === 'copy' ? `Copy ${field}` : `Reveal ${field}`, (code) =>
      reveal(item, { code, action, field, version: version ? Number(version) : null }));
    if (!values) return;
    const value = values[field] ?? '';
    if (action === 'copy') {
      if (!(await copyText(btn, value))) return;
      // Best effort: browsers only allow clipboard writes while the page has focus.
      setTimeout(() => { if (document.hasFocus()) navigator.clipboard.writeText('').catch(() => {}); }, HIDE_AFTER_MS);
    } else {
      showFor(document.querySelector(target), value);
    }
  });

  // Edit form: load the current secrets into the inputs (one code), so they can be changed or cleared.
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-load-secrets]');
    if (!btn) return;
    e.preventDefault();
    const values = await withCode('Load current secrets', (code) => reveal(btn.dataset.item, { code, action: 'edit' }));
    if (!values) return;
    const form = btn.closest('form');
    for (const [name, field] of [['Input.Password', 'password'], ['Input.SecretText', 'secret'], ['Input.Notes', 'notes']]) {
      const el = form.elements.namedItem(name);
      if (el) el.value = values[field] ?? '';
    }
    form.elements.namedItem('Input.SecretLoaded').value = 'true';
    btn.disabled = true;
    btn.textContent = 'Secrets loaded: saving replaces all fields';
  });

  // Non-secret copy (hostname, IP): <button data-copy-text="...">
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy-text]');
    if (!btn) return;
    e.preventDefault();
    await copyText(btn, btn.dataset.copyText);
  });

  // Show/hide typed password in forms.
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-toggle-visibility]');
    if (!btn) return;
    e.preventDefault();
    const el = document.getElementById(btn.dataset.toggleVisibility);
    const show = el.type === 'password';
    el.type = show ? 'text' : 'password';
    btn.textContent = show ? 'Hide' : 'Show';
    btn.setAttribute('aria-pressed', String(show));
  });

  // <form data-confirm="Delete X?" [data-confirm-ok="Delete"]>: themed confirm dialog, then submit.
  const confirmDialog = document.getElementById('confirm-dialog');
  document.addEventListener('submit', (e) => {
    const form = e.target;
    const msg = form.dataset?.confirm;
    if (!msg || form.dataset.confirmed) return;
    e.preventDefault();
    const submitter = e.submitter;
    document.getElementById('confirm-title').textContent = msg;
    document.getElementById('confirm-text').textContent = form.dataset.confirmDetail ?? '';
    const ok = document.getElementById('confirm-ok');
    ok.textContent = form.dataset.confirmOk ?? submitter?.textContent.trim() ?? 'Confirm';
    const cancel = document.getElementById('confirm-cancel');
    const done = (go) => {
      confirmDialog.close();
      ok.removeEventListener('click', onOk);
      cancel.removeEventListener('click', onCancel);
      confirmDialog.removeEventListener('cancel', onCancel);
      if (!go) return;
      form.dataset.confirmed = '1';
      form.requestSubmit(submitter);
    };
    const onOk = (ev) => { ev.preventDefault(); done(true); };
    const onCancel = () => done(false);
    ok.addEventListener('click', onOk);
    cancel.addEventListener('click', onCancel);
    confirmDialog.addEventListener('cancel', onCancel);
    confirmDialog.showModal();
    cancel.focus();
  });
})();
