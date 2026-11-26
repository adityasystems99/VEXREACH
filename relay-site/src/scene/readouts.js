import { seg, easeOut, headPos, rng } from './util.js';

// Decorative tokens only. These are not telemetry and show no measured values.
const LABELS = ['hop 1', 'encrypted', 'relay', 'hop 2', 'unlinkable', 'hop 3', 'encrypted', 'relay'];
const rand = rng(21);
const items = LABELS.map((text, i) => ({
  text,
  a: (i / LABELS.length) * Math.PI * 2 - Math.PI / 2 + rand() * 0.4,
  start: 0.5 + (i / LABELS.length) * 0.2,
  dist: 0.18 + rand() * 0.12,
}));

// Labels detach from the petals and float off in arcs (50% to 80% scroll)
export function drawReadouts(ctx, L, p) {
  const { x, y } = headPos(L, p);
  ctx.save();
  ctx.font = '500 11px Inter, system-ui, sans-serif';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = 'rgba(200,220,255,1)';
  for (const it of items) {
    const q = seg(p, it.start, it.start + 0.3);
    if (q <= 0 || q >= 1) continue;
    const d = easeOut(q) * it.dist * L.unit;
    const px = x + Math.cos(it.a) * d;
    const py = y + Math.sin(it.a) * d - q * L.unit * 0.04;
    ctx.globalAlpha = Math.sin(q * Math.PI) * 0.45;
    ctx.fillText(it.text.toUpperCase(), px, py);
  }
  ctx.restore();
}
