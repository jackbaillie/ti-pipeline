/* Local-only enhancements: copy buttons, table and list filters, opening
   collapsed sections for linked anchors. No network requests. Without
   JavaScript every page still reads; filters stay hidden. */
'use strict';

const liveStatus = document.getElementById('live-status');
const formatCount = n => n.toLocaleString('en-GB');
const PRIORITY_RANK = { high: 0, medium: 1, low: 2 };

for (const element of document.querySelectorAll('[data-js]')) element.hidden = false;

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
   Rows with data-status other than "qualified" stay hidden until a checkbox
   with that value (data-table="<table id>") is ticked. A table with
   data-initial-rows shows that many matching rows until "Show all" is
   pressed; typing in the filter searches every row. */

for (const table of document.querySelectorAll('table[id]')) {
  const controls = document.querySelectorAll(`[data-table="${table.id}"]`);
  if (!controls.length) continue;
  const input = Array.from(controls).find(c => c.type === 'search');
  const toggles = Array.from(controls).filter(c => c.type === 'checkbox');
  const rows = Array.from(table.tBodies[0].rows);
  const texts = rows.map(row => row.textContent.toLocaleLowerCase());
  const limit = Number(table.dataset.initialRows) || rows.length;
  const count = document.getElementById(`${table.id}-count`);
  const empty = document.getElementById(`${table.id}-empty`);
  const showAll = document.querySelector(`[data-show-all="${table.id}"]`);
  let expanded = false;

  const update = () => {
    const terms = input ? input.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean) : [];
    const included = new Set(['qualified']);
    for (const toggle of toggles) {
      if (toggle.checked) toggle.value.split(' ').forEach(value => included.add(value));
    }
    let matched = 0;
    rows.forEach((row, index) => {
      const eligible = (!row.dataset.status || included.has(row.dataset.status))
        && terms.every(term => texts[index].includes(term));
      row.hidden = !(eligible && (expanded || terms.length > 0 || matched < limit));
      matched += Number(eligible);
    });
    const shown = rows.filter(row => !row.hidden).length;
    if (count) {
      count.textContent = shown === matched
        ? `${formatCount(matched)} rows`
        : `Showing ${formatCount(shown)} of ${formatCount(matched)}`;
    }
    if (empty) empty.hidden = matched !== 0;
    if (showAll) {
      showAll.hidden = shown === matched;
      showAll.textContent = `Show all ${formatCount(matched)}`;
    }
  };

  input?.addEventListener('input', update);
  toggles.forEach(toggle => toggle.addEventListener('change', update));
  showAll?.addEventListener('click', () => {
    expanded = true;
    update();
    table.closest('[tabindex]')?.focus();
  });
  update();
}

/* Story and hunt filters ----------------------------------------------------
   Items carry data-match tokens "customer|priority-rank|theme". An item shows
   when one token satisfies every chosen facet. Filters are kept in the URL
   so a filtered view can be linked (the overview heat grid does this). */

for (const form of document.querySelectorAll('form[data-filters]')) {
  const scope = document.getElementById(form.dataset.filters);
  if (!scope) continue;
  form.hidden = false;
  const items = Array.from(scope.querySelectorAll('[data-match]'));
  const texts = items.map(item => (item.dataset.search || item.textContent).toLocaleLowerCase());
  const tokens = items.map(item => item.dataset.match.split(' ').filter(Boolean).map(t => t.split('|')));
  const groups = Array.from(scope.querySelectorAll('[data-group]'));
  const count = form.querySelector('[data-filter-count]');
  const empty = document.querySelector('[data-filter-empty]');
  const field = name => form.elements.namedItem(name);

  const params = new URLSearchParams(window.location.search);
  for (const name of ['customer', 'priority', 'theme', 'q']) {
    const control = field(name);
    if (control && params.has(name)) control.value = params.get(name);
  }

  const update = () => {
    const customer = field('customer')?.value || '';
    const priority = field('priority')?.value || '';
    const theme = field('theme')?.value || '';
    const terms = (field('q')?.value || '').toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
    const rank = priority in PRIORITY_RANK ? PRIORITY_RANK[priority] : null;
    const faceted = Boolean(customer || theme || rank !== null);
    let shown = 0;
    items.forEach((item, index) => {
      const facets = !faceted || tokens[index].some(([c, r, t]) =>
        (!customer || c === customer) && (rank === null || Number(r) <= rank) && (!theme || t === theme));
      item.hidden = !(facets && terms.every(term => texts[index].includes(term)));
      shown += Number(!item.hidden);
    });
    for (const group of groups) {
      const visible = group.querySelectorAll('[data-match]:not([hidden])').length;
      group.hidden = visible === 0;
      const groupCount = group.querySelector('[data-group-count]');
      if (groupCount) groupCount.textContent = visible;
    }
    if (count) {
      count.textContent = shown === items.length
        ? `${formatCount(items.length)} shown`
        : `Showing ${formatCount(shown)} of ${formatCount(items.length)}`;
    }
    if (empty) empty.hidden = shown !== 0;

    const query = new URLSearchParams();
    for (const name of ['customer', 'priority', 'theme', 'q']) {
      const value = field(name)?.value;
      if (value) query.set(name, value);
    }
    const search = query.toString();
    try {
      history.replaceState(null, '', search ? `?${search}${location.hash}` : `${location.pathname}${location.hash}`);
    } catch (_) {
      /* Some browsers refuse URL changes on file:// pages; filtering still works. */
    }
  };

  form.addEventListener('input', update);
  form.addEventListener('submit', event => event.preventDefault());
  update();
}

/* Linked anchors inside collapsed sections ---------------------------------- */

function revealTarget() {
  const id = decodeURIComponent(window.location.hash.slice(1));
  const target = id && document.getElementById(id);
  if (!target) return;
  for (let details = target.closest('details'); details; details = details.parentElement.closest('details')) {
    details.open = true;
  }
  target.querySelector(':scope > details')?.setAttribute('open', '');
  target.scrollIntoView({ block: 'start' });
}

window.addEventListener('hashchange', revealTarget);
revealTarget();
