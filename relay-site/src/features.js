import { FEATURES, TELEMETRY_URL } from './content.js';

const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};

function inspector(items) {
  const wrap = el('div', 'inspector');
  const row = el('div', 'nodes');
  const detail = el('div', 'detail', items[0].detail);
  const buttons = items.map((item, i) => {
    const b = el('button', null, item.label);
    b.setAttribute('aria-pressed', i === 0 ? 'true' : 'false');
    b.addEventListener('click', () => {
      buttons.forEach((x) => x.setAttribute('aria-pressed', 'false'));
      b.setAttribute('aria-pressed', 'true');
      detail.textContent = item.detail;
    });
    row.append(b);
    return b;
  });
  wrap.append(row, detail);
  return wrap;
}

function telemetry() {
  const box = el('div', 'telemetry');
  if (!TELEMETRY_URL) {
    box.append(el('p', 'muted',
      'No telemetry connected. Relay availability and latency appear here only once measurements are published.'));
    return box;
  }
  const pre = el('pre', null, 'Loading telemetry…');
  box.append(pre, el('p', 'muted', 'Live data. Timestamp and methodology must accompany any figure.'));
  fetch(TELEMETRY_URL)
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then((d) => { pre.textContent = JSON.stringify(d, null, 2); })
    .catch(() => { pre.textContent = 'Telemetry unavailable right now.'; });
  return box;
}

function list(items) {
  const ul = el('ul');
  items.forEach((t) => ul.append(el('li', null, t)));
  return ul;
}

export function renderFeatures(root) {
  for (const f of FEATURES) {
    const sec = el('section', 'feature');
    sec.id = f.id;

    const head = el('div', 'head');
    head.append(el('span', 'no', f.no), el('span', `badge ${f.status}`, f.status));

    sec.append(
      head,
      el('h2', null, f.title),
      el('p', null, f.summary),
      el('p', 'purpose', `Technical purpose: ${f.purpose}`),
    );

    if (f.visual === 'inspector') sec.append(inspector(f.items));
    if (f.visual === 'telemetry') sec.append(telemetry());
    if (f.visual !== 'inspector' && f.items) sec.append(list(f.items));

    root.append(sec);
  }
}
