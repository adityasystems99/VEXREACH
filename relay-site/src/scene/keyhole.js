import { seg, easeInOut } from './util.js';

// Optical bioluminescent aperture mask centered on the dandelion head (0 to 10% scroll)
export function drawKeyhole(ctx, L, p, t = 0) {
  const k = easeInOut(seg(p, 0, 0.1));
  if (k >= 1) return;

  const maxR = Math.hypot(L.w, L.h);
  const r = L.unit * 0.16 + k * maxR;
  const cx = L.headX;
  const cy = L.headY;

  ctx.save();
  // Deep cosmic-obsidian vignette mask rather than flat black
  const maskGrad = ctx.createRadialGradient(cx, cy, r * 0.9, cx, cy, maxR * 0.75);
  maskGrad.addColorStop(0, '#050816');
  maskGrad.addColorStop(0.45, '#040610');
  maskGrad.addColorStop(1, '#020308');
  ctx.fillStyle = maskGrad;
  ctx.beginPath();
  ctx.rect(0, 0, L.w, L.h);
  ctx.moveTo(cx + r, cy);
  ctx.arc(cx, cy, r, 0, Math.PI * 2, true);
  ctx.fill('evenodd');

  // Dual photonic aperture rim (warm amber inner ring + ice-cyan diffraction halo)
  const rimAlpha = 1 - k;
  if (rimAlpha > 0.01) {
    ctx.globalCompositeOperation = 'lighter';

    ctx.strokeStyle = `rgba(120, 195, 255, ${(0.35 * rimAlpha).toFixed(3)})`;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.arc(cx, cy, r + 6, 0, Math.PI * 2);
    ctx.stroke();

    ctx.strokeStyle = `rgba(255, 192, 118, ${(0.68 * rimAlpha).toFixed(3)})`;
    ctx.lineWidth = 1.6;
    ctx.shadowColor = 'rgba(255, 184, 107, 0.8)';
    ctx.shadowBlur = 18;
    ctx.beginPath();
    ctx.arc(cx, cy, r, 0, Math.PI * 2);
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Subtle futuristic cardinal tick marks rotating gently on outer ring
    ctx.strokeStyle = `rgba(214, 235, 255, ${(0.45 * rimAlpha).toFixed(3)})`;
    ctx.lineWidth = 1;
    for (let i = 0; i < 12; i++) {
      const a = (i / 12) * Math.PI * 2 + t * 0.08;
      const len = i % 3 === 0 ? 10 : 5;
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(a) * (r + 3), cy + Math.sin(a) * (r + 3));
      ctx.lineTo(cx + Math.cos(a) * (r + 3 + len), cy + Math.sin(a) * (r + 3 + len));
      ctx.stroke();
    }
  }
  ctx.restore();
}
