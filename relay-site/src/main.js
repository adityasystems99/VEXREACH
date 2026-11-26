import { makeLayout, renderScene } from './scene/index.js';
import { getScatteredPetals } from './scene/bloom.js';
import { clamp, seg } from './scene/util.js';
import { COPY, PETAL_FRAMES } from './content.js';
import { renderFeatures } from './features.js';

const journey = document.getElementById('journey');
const canvas = document.getElementById('scene');
const ctx = canvas.getContext('2d');
const copyRoot = document.getElementById('copy');
const progressRoot = document.getElementById('progress');
const petalRoot = document.getElementById('petal-frames');
const petalDetail = document.getElementById('petal-detail');
const startPanel = document.getElementById('start-panel');

const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
if (reduced) document.documentElement.classList.add('reduced');

// Copy blocks occupy START..START+SPAN
const START = 0.04;
const SPAN = 0.86;

const blocks = COPY.map((c) => {
  const el = document.createElement('div');
  el.className = 'copy-block';
  if (c.title) {
    const h = document.createElement('h2');
    h.className = 'script';
    h.textContent = c.title;
    el.append(h);
  }
  if (c.sub) {
    const p = document.createElement('p');
    p.textContent = c.sub;
    el.append(p);
  }
  if (c.cta) {
    const a = document.createElement('a');
    a.className = 'cta';
    a.href = c.cta.href;
    a.textContent = c.cta.label;
    el.append(a);
  }
  copyRoot.append(el);
  return el;
});

const ticks = COPY.map(() => {
  const t = document.createElement('span');
  progressRoot.append(t);
  return t;
});

const scrollCue = document.createElement('div');
scrollCue.className = 'scroll-cue';
scrollCue.textContent = 'Scroll to scatter the dandelion ↓';
document.querySelector('.stage').append(scrollCue);

let activePetal = -1;
let pulseStart = -1;
let dirty = true;

function closeStartPanel() {
  startPanel.hidden = true;
  if (activePetal === PETAL_FRAMES.length - 1) activePetal = -1;
  syncPetalSelection();
  dirty = true;
}

function showFeatureDetail(item) {
  petalDetail.innerHTML = '';
  const badge = document.createElement('span');
  badge.className = 'petal-detail-no';
  badge.textContent = `${item.no} · ${item.tag}`;

  const title = document.createElement('strong');
  title.className = 'petal-detail-title';
  title.textContent = item.title;

  const text = document.createElement('p');
  text.className = 'petal-detail-text';
  text.textContent = item.summary;

  const actions = document.createElement('div');
  actions.className = 'petal-detail-actions';

  const jumpBtn = document.createElement('a');
  jumpBtn.className = 'petal-detail-link';
  jumpBtn.href = `#${item.id}`;
  jumpBtn.textContent = 'Inspect details ↓';
  jumpBtn.addEventListener('click', () => {
    petalDetail.hidden = true;
  });

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'petal-detail-close';
  closeBtn.textContent = '×';
  closeBtn.setAttribute('aria-label', 'Close feature preview');
  closeBtn.addEventListener('click', () => {
    petalDetail.hidden = true;
    activePetal = -1;
    syncPetalSelection();
    dirty = true;
  });

  actions.append(jumpBtn, closeBtn);
  petalDetail.append(badge, title, text, actions);
  petalDetail.hidden = false;
}

function openStartPanel() {
  petalDetail.hidden = true;
  startPanel.innerHTML = '';

  const kicker = document.createElement('span');
  kicker.className = 'start-kicker';
  kicker.textContent = 'FIRST HOP · RELAY LAUNCH';

  const heading = document.createElement('h3');
  heading.id = 'start-panel-title';
  heading.className = 'script';
  heading.textContent = "Begin someone's first hop.";

  const desc = document.createElement('p');
  desc.className = 'start-desc';
  desc.textContent =
    'Explore the 3-hop path architecture below, inspect protocol specifications, or go directly to relay participation.';

  const actions = document.createElement('div');
  actions.className = 'start-actions';

  const runBtn = document.createElement('a');
  runBtn.className = 'start-primary';
  runBtn.href = '#join';
  runBtn.textContent = 'Start / Run a Relay →';
  runBtn.addEventListener('click', closeStartPanel);

  const exploreBtn = document.createElement('a');
  exploreBtn.className = 'start-secondary';
  exploreBtn.href = '#hops';
  exploreBtn.textContent = 'Explore Features ↓';
  exploreBtn.addEventListener('click', closeStartPanel);

  const pulseBtn = document.createElement('button');
  pulseBtn.type = 'button';
  pulseBtn.className = 'start-secondary';
  pulseBtn.textContent = 'Pulse Hops';
  pulseBtn.addEventListener('click', () => {
    pulseStart = performance.now() * 0.001;
    dirty = true;
  });

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'start-close';
  closeBtn.textContent = '×';
  closeBtn.setAttribute('aria-label', 'Close start options');
  closeBtn.addEventListener('click', closeStartPanel);

  actions.append(runBtn, exploreBtn, pulseBtn);
  startPanel.append(closeBtn, kicker, heading, desc, actions);
  startPanel.hidden = false;
  pulseStart = performance.now() * 0.001;
  dirty = true;
}

const petalButtons = PETAL_FRAMES.map((item, idx) => {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = item.isStart ? 'petal-frame is-start' : 'petal-frame';
  btn.dataset.petalIndex = String(idx);
  btn.setAttribute('aria-pressed', 'false');

  const top = document.createElement('span');
  top.className = 'petal-head';
  const no = document.createElement('span');
  no.className = 'petal-no';
  no.textContent = item.no;
  const tag = document.createElement('span');
  tag.className = 'petal-tag';
  tag.textContent = item.tag;
  top.append(no, tag);

  const title = document.createElement('span');
  title.className = 'petal-title';
  title.textContent = item.title;

  const summary = document.createElement('span');
  summary.className = 'petal-summary';
  summary.textContent = item.summary;

  btn.append(top, title, summary);

  if (item.isStart) {
    const cta = document.createElement('span');
    cta.className = 'petal-start-cta';
    cta.textContent = item.ctaLabel || 'Start →';
    btn.append(cta);
  }

  btn.addEventListener('click', () => {
    activePetal = idx;
    syncPetalSelection();
    if (item.isStart) {
      openStartPanel();
    } else {
      startPanel.hidden = true;
      showFeatureDetail(item);
    }
    dirty = true;
  });

  petalRoot.append(btn);
  return btn;
});

function syncPetalSelection() {
  petalButtons.forEach((btn, i) => {
    const on = i === activePetal;
    btn.classList.toggle('is-active', on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

renderFeatures(document.getElementById('features'));

let L;
let progress = -1;

function resize() {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = window.innerWidth;
  const h = window.innerHeight;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  L = makeLayout(w, h);
  dirty = true;
}

function readScrollState() {
  if (reduced) return { p: 0.68, featBlend: 0 };
  const total = journey.offsetHeight - window.innerHeight;
  const rect = journey.getBoundingClientRect();
  const raw = -rect.top / total;
  const p = clamp(raw);
  // Smoothly transition background luminescence once scrolled past #journey into #features
  const featBlend = clamp((raw - 0.96) / 0.08);
  return { p, featBlend };
}

function updateCopy(p) {
  const n = blocks.length;
  const half = SPAN / n / 2;
  blocks.forEach((el, i) => {
    const center = START + (i + 0.5) * SPAN / n;
    const dist = i === 0 && p < center ? 0 : Math.abs(p - center);
    const a = reduced ? 1 : clamp(1 - dist / (half * 0.96));
    el.style.opacity = a.toFixed(3);
    el.style.transform = `translateY(${((1 - a) * 14).toFixed(1)}px)`;
    el.style.pointerEvents = a > 0.5 ? 'auto' : 'none';
  });
  const idx = Math.min(n - 1, Math.max(0, Math.floor((p - START) / SPAN * n)));
  ticks.forEach((t, i) => t.classList.toggle('on', i === idx));
  scrollCue.style.opacity = reduced ? '0' : clamp(1 - p / 0.06).toFixed(3);
}

function updatePetalFrames(p, t) {
  const narrow = L.w < 700;
  petalRoot.classList.toggle('is-narrow', narrow);

  if (narrow) {
    const fadeIn = reduced ? 1 : seg(p, 0.44, 0.58);
    const fadeOut = reduced ? 1 : 1 - seg(p, 0.88, 0.97);
    const alpha = clamp(fadeIn * fadeOut);
    petalRoot.style.opacity = alpha.toFixed(3);
    const interactive = alpha > 0.35;
    petalButtons.forEach((btn, i) => {
      const tilt = (i % 2 === 0 ? -1.1 : 1.1) * fadeIn;
      const scale = 0.85 + 0.15 * fadeIn;
      btn.style.left = '';
      btn.style.top = '';
      btn.style.opacity = '1';
      btn.style.transform = `scale(${scale.toFixed(3)}) rotate(${tilt.toFixed(2)}deg)`;
      btn.style.pointerEvents = interactive ? 'auto' : 'none';
    });
    if (!interactive) {
      petalDetail.hidden = true;
      startPanel.hidden = true;
    }
    return;
  }

  petalRoot.style.opacity = '1';
  const scattered = getScatteredPetals(L, reduced ? 0.68 : p, t);
  let anyInteractive = false;

  scattered.forEach((pt, i) => {
    const btn = petalButtons[i];
    const glassAlpha = reduced ? 1 : clamp(pt.morph * (1 - seg(p, 0.88, 0.97)));
    const scale = reduced ? 1 : 0.16 + 0.84 * pt.morph;
    const tilt = pt.spec.tilt * pt.morph;
    const interactive = glassAlpha > 0.45;
    if (interactive) anyInteractive = true;

    btn.style.left = `${pt.x.toFixed(1)}px`;
    btn.style.top = `${pt.y.toFixed(1)}px`;
    btn.style.opacity = glassAlpha.toFixed(3);
    btn.style.transform = `translate(-50%, -50%) scale(${scale.toFixed(3)}) rotate(${tilt.toFixed(2)}deg)`;
    btn.style.pointerEvents = interactive ? 'auto' : 'none';
  });

  if (!anyInteractive) {
    petalDetail.hidden = true;
    startPanel.hidden = true;
  }
}

function frame(now = 0) {
  const { p, featBlend } = readScrollState();
  const timeSec = now * 0.001;
  const pulseAge = pulseStart >= 0 ? timeSec - pulseStart : -1;
  if (pulseAge > 2.2) pulseStart = -1;

  const animateIdle = !reduced;
  if (p !== progress || animateIdle) {
    progress = p;
    dirty = true;
  }
  if (dirty && !document.hidden) {
    renderScene(ctx, L, progress, timeSec, { activePetal, pulseAge, featBlend });
    updateCopy(progress);
    updatePetalFrames(progress, timeSec);
    dirty = false;
  }
  requestAnimationFrame(frame);
}

window.addEventListener('resize', resize);
resize();
frame();
