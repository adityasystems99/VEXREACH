import { seg, easeInOut, clamp, headPos } from './util.js';

// Segmented futuristic iris rings contracting around the core after scatter (62% to 92% scroll)
export function drawIris(ctx, L, p, t = 0) {
  const k = seg(p, 0.62, 0.74);
  const fade = (1 - seg(p, 0.82, 0.94)) * 0.55;
  if (k <= 0 || fade <= 0) return;

  const { x, y } = headPos(L, p);
  const R = L.unit * 0.16;

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';
  ctx.translate(x, y);
  ctx.lineWidth = 1.1;

  for (let j = 0; j < 5; j++) {
    const e = easeInOut(clamp(k - j * 0.05));
    const r = R * (1 - e * 0.88);
    if (r < 2) continue;
    const rot = (j % 2 === 0 ? 1 : -1) * t * (0.25 + j * 0.08);
    ctx.strokeStyle = j % 2 === 0 ? 'rgba(165, 215, 255, 1)' : 'rgba(255, 200, 130, 0.9)';
    ctx.globalAlpha = 0.55 * fade * (1 - j * 0.14);
    ctx.beginPath();
    ctx.arc(0, 0, r, rot, rot + Math.PI * 1.55);
    ctx.stroke();
  }

  const g = ctx.createRadialGradient(0, 0, 0, 0, 0, L.unit * 0.035);
  g.addColorStop(0, 'rgba(245, 250, 255, 1)');
  g.addColorStop(0.5, 'rgba(155, 215, 255, 0.45)');
  g.addColorStop(1, 'rgba(155, 215, 255, 0)');
  ctx.globalAlpha = k * fade;
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(0, 0, L.unit * 0.035, 0, Math.PI * 2);
  ctx.fill();
  ctx.restore();
}
