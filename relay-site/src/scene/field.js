import { seg, rng } from './util.js';

const rand = rng(3);
const blades = Array.from({ length: 130 }, () => ({
  x: rand(),
  h: 0.06 + rand() * 0.14,
  lean: (rand() - 0.5) * 0.45,
  w: 1 + rand() * 2,
  glow: rand(),
}));
const embers = Array.from({ length: 56 }, () => ({
  x: rand(),
  speed: 0.35 + rand() * 0.65,
  off: rand(),
  r: 0.9 + rand() * 1.6,
}));
const spores = Array.from({ length: 80 }, () => ({
  x: rand(),
  y: rand(),
  r: 0.6 + rand() * 1.5,
  phase: rand() * Math.PI * 2,
  speed: 0.3 + rand() * 0.7,
  warm: rand() > 0.72,
}));

// Luminescent cosmic night field, photonic arcs, grass silhouettes & advancing fire front
export function drawField(ctx, L, p, t = 0, featBlend = 0) {
  // Deep luminous midnight-sapphire sky gradient
  const sky = ctx.createLinearGradient(0, 0, L.w * 0.3, L.h);
  sky.addColorStop(0, '#040614');
  sky.addColorStop(0.45, '#070f28');
  sky.addColorStop(0.82, '#0b1838');
  sky.addColorStop(1, '#080e1f');
  ctx.fillStyle = sky;
  ctx.fillRect(0, 0, L.w, L.h);

  // Soft bioluminescent nebula blooms (cobalt-cyan + warm amber horizon aura)
  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  const neb1 = ctx.createRadialGradient(
    L.headX, L.headY, 0,
    L.headX, L.headY, L.unit * (0.65 + featBlend * 0.15),
  );
  neb1.addColorStop(0, 'rgba(95, 165, 255, 0.22)');
  neb1.addColorStop(0.45, 'rgba(65, 115, 235, 0.09)');
  neb1.addColorStop(1, 'rgba(15, 30, 80, 0)');
  ctx.fillStyle = neb1;
  ctx.fillRect(0, 0, L.w, L.h);

  const neb2X = L.w * (0.2 + Math.sin(t * 0.15) * 0.03);
  const neb2Y = L.h * (0.78 - featBlend * 0.25);
  const neb2 = ctx.createRadialGradient(neb2X, neb2Y, 0, neb2X, neb2Y, L.unit * 0.55);
  neb2.addColorStop(0, 'rgba(255, 175, 95, 0.10)');
  neb2.addColorStop(0.55, 'rgba(110, 145, 255, 0.05)');
  neb2.addColorStop(1, 'rgba(10, 15, 35, 0)');
  ctx.fillStyle = neb2;
  ctx.fillRect(0, 0, L.w, L.h);

  // Futuristic subtle concentric optical reticle rings centered around the dandelion core
  const arcFade = (1 - seg(p, 0.85, 0.98)) * 0.9 + featBlend * 0.35;
  if (arcFade > 0.02) {
    ctx.strokeStyle = `rgba(135, 195, 255, ${(0.07 * arcFade).toFixed(3)})`;
    ctx.lineWidth = 1;
    [0.22, 0.36, 0.52].forEach((mul, idx) => {
      const r = L.unit * mul;
      ctx.beginPath();
      ctx.arc(L.headX, L.headY, r, idx * 0.7 + t * 0.05, idx * 0.7 + Math.PI * 1.45 + t * 0.05);
      ctx.stroke();
    });
  }

  // Drifting starlight spores across the whole canvas & behind #features
  for (const s of spores) {
    const sx = ((s.x + t * 0.008 * s.speed) % 1) * L.w;
    const sy = ((s.y - t * 0.012 * s.speed + 10) % 1) * L.h;
    const twinkle = 0.35 + 0.65 * (0.5 + 0.5 * Math.sin(t * 2.1 * s.speed + s.phase));
    const alpha = twinkle * (0.45 + featBlend * 0.35);
    ctx.fillStyle = s.warm
      ? `rgba(255, 200, 130, ${(alpha * 0.85).toFixed(3)})`
      : `rgba(175, 220, 255, ${alpha.toFixed(3)})`;
    ctx.beginPath();
    ctx.arc(sx, sy, s.r, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();

  // Foreground field grass + creeping fire front (fades softly as we leave into #features)
  const fieldVis = 1 - featBlend;
  if (fieldVis <= 0.01) return;

  const groundY = L.h * 0.92;
  const front = seg(p, 0.06, 0.3);
  const fx = front * L.w;
  const fireAlpha = (1 - seg(p, 0.3, 0.44)) * (p > 0.05 ? 1 : 0) * fieldVis;

  if (fireAlpha > 0) {
    // Luminous amber-gold fire wave
    const glow = ctx.createRadialGradient(fx, groundY, 0, fx, groundY, L.unit * 0.46);
    glow.addColorStop(0, `rgba(255, 168, 72, ${(0.62 * fireAlpha).toFixed(3)})`);
    glow.addColorStop(0.5, `rgba(255, 118, 45, ${(0.22 * fireAlpha).toFixed(3)})`);
    glow.addColorStop(1, 'rgba(255, 100, 35, 0)');
    ctx.fillStyle = glow;
    ctx.fillRect(0, groundY - L.unit * 0.46, L.w, L.unit * 0.92);

    ctx.fillStyle = `rgba(255, 220, 145, ${(0.95 * fireAlpha).toFixed(3)})`;
    ctx.fillRect(fx - 1.5, groundY - 5, 3, 10);
  }

  // Silhouetted grass blades with faint luminescent rim catch
  ctx.save();
  ctx.globalAlpha = fieldVis;
  for (const b of blades) {
    const bx = b.x * L.w;
    const by = groundY;
    const tipY = by - b.h * L.h;
    ctx.fillStyle = '#090d1b';
    ctx.beginPath();
    ctx.moveTo(bx - b.w, by);
    ctx.quadraticCurveTo(bx + b.lean * 10, by - (by - tipY) * 0.5, bx + b.lean * 20, tipY);
    ctx.quadraticCurveTo(bx + b.w, by - (by - tipY) * 0.5, bx + b.w, by);
    ctx.fill();

    if (b.glow > 0.55) {
      ctx.strokeStyle = fireAlpha > 0 && bx < fx
        ? 'rgba(255, 185, 110, 0.25)'
        : 'rgba(130, 185, 255, 0.18)';
      ctx.lineWidth = 0.7;
      ctx.beginPath();
      ctx.moveTo(bx, by);
      ctx.quadraticCurveTo(bx + b.lean * 10, by - (by - tipY) * 0.5, bx + b.lean * 20, tipY);
      ctx.stroke();
    }
  }
  ctx.restore();

  if (fireAlpha > 0) {
    ctx.save();
    ctx.globalCompositeOperation = 'lighter';
    for (const e of embers) {
      const k = (p * e.speed * 3 + t * 0.08 * e.speed + e.off) % 1;
      const ex = e.x * L.w + Math.sin(k * 6 + e.off * 10) * 14;
      const ey = groundY - k * L.h * 0.74;
      ctx.globalAlpha = (1 - k) * fireAlpha * 0.9;
      ctx.fillStyle = 'rgba(255, 190, 105, 1)';
      ctx.beginPath();
      ctx.arc(ex, ey, e.r, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }
}
