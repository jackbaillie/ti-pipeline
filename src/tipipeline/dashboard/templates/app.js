/* Local-only enhancements: copy buttons and table filters. No network requests. */
'use strict';

const liveStatus = document.getElementById('live-status');
const formatCount = n => n.toLocaleString('en-GB');

/* Copy KQL ------------------------------------------------------------------ */

async function copyText(text) {
  try {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (_) {
    /* file:// pages may refuse clipboard access; fall through to execCommand. */
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.className = 'visually-hidden';
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try { copied = document.execCommand('copy'); } catch (_) { copied = false; }
  area.remove();
  return copied;
}

for (const button of document.querySelectorAll('[data-copy]')) {
  button.addEventListener('click', async () => {
    const code = document.getElementById(button.dataset.copy);
    if (!code) return;
    const copied = await copyText(code.textContent);
    button.focus();
    button.textContent = copied ? 'Copied' : 'Select KQL to copy';
    liveStatus.textContent = copied ? 'Copied.' : 'Clipboard unavailable; select and copy the query.';
    if (!copied) {
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
    setTimeout(() => { button.textContent = 'Copy KQL'; }, 2200);
  });
}

/* Filterable tables ---------------------------------------------------------
   A table with data-initial-rows shows that many rows until "Show all" is
   pressed. Typing in the filter searches every row. Without JavaScript the
   button stays hidden and every row is visible. */

for (const input of document.querySelectorAll('[data-filter]')) {
  const table = document.getElementById(input.dataset.filter);
  if (!table) continue;
  const rows = Array.from(table.tBodies[0].rows);
  const texts = rows.map(row => row.textContent.toLocaleLowerCase());
  const limit = Number(table.dataset.initialRows) || rows.length;
  const count = document.getElementById(`${table.id}-count`);
  const empty = document.getElementById(`${table.id}-empty`);
  const showAll = document.querySelector(`[data-show-all="${table.id}"]`);
  let expanded = rows.length <= limit;

  const update = () => {
    const terms = input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
    let matched = 0;
    rows.forEach((row, index) => {
      const matches = terms.every(term => texts[index].includes(term));
      const inView = expanded || terms.length > 0 || index < limit;
      row.hidden = !(matches && inView);
      matched += Number(matches);
    });
    const shown = rows.filter(row => !row.hidden).length;
    if (count) {
      count.textContent = shown === rows.length
        ? `${formatCount(rows.length)} rows`
        : `Showing ${formatCount(shown)} of ${formatCount(rows.length)}`;
    }
    if (empty) empty.hidden = matched !== 0;
    if (showAll) showAll.hidden = expanded || terms.length > 0;
  };

  input.addEventListener('input', update);
  if (showAll) {
    showAll.addEventListener('click', () => {
      expanded = true;
      update();
      table.closest('[tabindex]')?.focus();
    });
  }
  update();
}
