/* Local-only controls: no requests, frameworks, or external resources. */
'use strict';
for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copy);
    if (!code) return;
    let copied = false;
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(code.textContent);
        copied = true;
      }
    } catch (_) { /* file:// clipboard permission may require the local fallback. */ }
    if (!copied) {
      const text = document.createElement('textarea');
      text.value = code.textContent;
      text.className = 'sr-only';
      document.body.appendChild(text);
      text.select();
      try { copied = document.execCommand('copy'); } catch (_) { copied = false; }
      text.remove();
      button.focus();
    }
    button.textContent = copied ? 'Copied' : 'Select KQL to copy';
    document.getElementById('copy-status').textContent = copied ? 'KQL copied to clipboard.' : 'Clipboard unavailable. Select the KQL text and copy it manually.';
    if (!copied) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(code);
      selection.removeAllRanges();
      selection.addRange(range);
    }
    setTimeout(() => { button.textContent = 'Copy KQL'; }, 2200);
  });
}
for (const input of document.querySelectorAll('[data-filter]')) {
  const table = document.getElementById(input.dataset.filter);
  if (!table) continue;
  const rows = Array.from(table.tBodies[0].rows);
  const texts = rows.map(row => row.textContent.toLocaleLowerCase());
  input.addEventListener('input', () => {
    const terms = input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
    let shown = 0;
    rows.forEach((row, index) => {
      const matches = terms.every(term => texts[index].includes(term));
      row.hidden = !matches;
      shown += Number(matches);
    });
    const count = document.getElementById('filter-count');
    if (count) count.textContent = `${shown} of ${rows.length} rows`;
    const empty = document.getElementById('no-filter-results');
    if (empty) empty.hidden = shown !== 0;
  });
}
