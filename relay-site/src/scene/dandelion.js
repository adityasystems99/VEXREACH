import { seg, easeOut, rng, headPos } from './util.js';

const SPOKES = 96;
const SEED_COUNT = 120;
const rand = rng(7);

const spokes = Array.from({ length: SPOKES }, (_, i) => ({
  a: (i / SPOKES) * Math.PI * 2,
  lenMul: 0.9 + rand() * 0.16,
  curve: (rand() - 0.5) * 0.14,
}));

const seeds = Array.from({ length: SEED_COUNT }, (_, i) => ({
  a: (i / SEED_COUNT) * Math.PI * 2 + rand() * 0.15,
  start: 0.3 + rand() * 0.16,
  speed: 0.65 + rand() * 0.85,
  fall: 0.04 + rand() * 0.04,
  warm: i % 5 === 0,
}));

// Radiant bioluminescent dandelion with layered photonic stem, feathered pappus crown & glowing core
export function drawDandelion(ctx, L, p, t = 0) {
  const idleDrift = p < 0.2 ? Math.sin(t * 1.4) * 0.004 * L.unit : 0;
  const pos = headPos(L, p);
  const hx = pos.x + idleDrift;
  const hy = pos.y;

  const stemAlpha = 1 - seg(p, 0.48, 0.58);
  const headAlpha = 1 - seg(p, 0.46, 0.54);
  const turn = seg(p, 0.3, 0.45);
  const squash = 1 - turn * 0.55;
  const R = L.unit * 0.105;

  // Dual-layer photonic stem + rising light pulses along stem fiber
  if (stemAlpha > 0) {
    ctx.save();
    ctx.globalAlpha = stemAlpha;
    ctx.globalCompositeOperation = 'lighter';

    const ctrlX = L.baseX + (hx - L.baseX) * 0.32;
    const ctrlY = L.h * 0.7;

    // Outer luminous cyan aura
    ctx.strokeStyle = 'rgba(110, 185, 255, 0.32)';
    ctx.lineWidth = 6;
    ctx.beginPath();
    ctx.moveTo(L.baseX, L.baseY);
    ctx.quadraticCurveTo(ctrlX, ctrlY, hx, hy);
    ctx.stroke();

    // Crisp bright optical-fiber core stem
    const stemGrad = ctx.createLinearGradient(L.baseX, L.baseY, hx, hy);
    stemGrad.addColorStop(0, 'rgba(130, 195, 255, 0.65)');
    stemGrad.addColorStop(0.6, 'rgba(220, 240, 255, 0.95)');
    stemGrad.addColorStop(1, 'rgba(255, 232, 185, 0.98)');
    ctx.strokeStyle = stemGrad;
    ctx.shadowColor = 'rgba(155, 215, 255, 0.95)';
    ctx.shadowBlur = 14;
    ctx.lineWidth = 1.9;
    ctx.beginPath();
    ctx.moveTo(L.baseX, L.baseY);
    ctx.quadraticCurveTo(ctrlX, ctrlY, hx, hy);
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Traveling light energy pulses rising up the stem toward the dandelion head
    for (let k = 0; k < 3; k++) {
      const u = (t * 0.28 + k / 3) % 1;
      const iu = 1 - u;
      const px = iu * iu * L.baseX + 2 * iu * u * ctrlX + u * u * hx;
      const py = iu * iu * L.baseY + 2 * iu * u * ctrlY + u * u * hy;
      const pg = ctx.createRadialGradient(px, py, 0, px, py, 9);
      pg.addColorStop(0, 'rgba(255, 242, 200, 0.95)');
      pg.addColorStop(1, 'rgba(140, 205, 255, 0)');
      ctx.fillStyle = pg;
      ctx.beginPath();
      ctx.arc(px, py, 9, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
  }

  // Futuristic luminescent dandelion crown
  if (headAlpha > 0) {
    ctx.save();
    ctx.globalAlpha = headAlpha;
    ctx.globalCompositeOperation = 'lighter';

    // Outer gossamer sphere halo
    const aura = ctx.createRadialGradient(hx, hy, R * 0.15, hx, hy, R * 1.45);
    aura.addColorStop(0, 'rgba(255, 244, 215, 0.55)');
    aura.addColorStop(0.42, 'rgba(135, 200, 255, 0.22)');
    aura.addColorStop(0.78, 'rgba(175, 145, 255, 0.09)');
    aura.addColorStop(1, 'rgba(90, 145, 255, 0)');
    ctx.fillStyle = aura;
    ctx.beginPath();
    ctx.arc(hx, hy, R * 1.45, 0, Math.PI * 2);
    ctx.fill();

    // Subtle holographic outer ring framing the dandelion orb
    ctx.strokeStyle = 'rgba(170, 218, 255, 0.22)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    ctx.ellipse(hx, hy, R * 1.12 * squash, R * 1.12, 0, 0, Math.PI * 2);
    ctx.stroke();

    // Gently curved luminous filaments + radial feathered pappus tufts
    for (let i = 0; i < spokes.length; i++) {
      const sp = spokes[i];
      const rad = R * sp.lenMul;
      const c = Math.cos(sp.a);
      const s = Math.sin(sp.a);
      const x1 = hx + c * R * 0.2 * squash;
      const y1 = hy + s * R * 0.2;
      const x2 = hx + c * rad * squash;
      const y2 = hy + s * rad;
      const mx = hx + Math.cos(sp.a + sp.curve) * rad * 0.55 * squash;
      const my = hy + Math.sin(sp.a + sp.curve) * rad * 0.55;

      ctx.strokeStyle = i % 3 === 0
        ? 'rgba(255, 224, 170, 0.78)'
        : 'rgba(195, 230, 255, 0.86)';
      ctx.lineWidth = 0.95;
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.quadraticCurveTo(mx, my, x2, y2);
      ctx.stroke();

      // Delicate feathered crown at outer tip of alternate filaments
      if (i % 2 === 0) {
        ctx.strokeStyle = 'rgba(235, 246, 255, 0.75)';
        ctx.lineWidth = 0.55;
        ctx.beginPath();
        for (let f = -1; f <= 1; f++) {
          const fa = sp.a + f * 0.42;
          ctx.moveTo(x2, y2);
          ctx.lineTo(x2 + Math.cos(fa) * 5.5 * squash, y2 + Math.sin(fa) * 5.5);
        }
        ctx.stroke();

        ctx.fillStyle = i % 4 === 0
          ? 'rgba(255, 215, 145, 0.95)'
          : 'rgba(220, 242, 255, 0.95)';
        ctx.beginPath();
        ctx.arc(x2, y2, 1.35, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    // Bright photonic nucleus + subtle geometric Fibonacci inner ring
    const core = ctx.createRadialGradient(hx, hy, 0, hx, hy, R * 0.26);
    core.addColorStop(0, 'rgba(255, 252, 240, 1)');
    core.addColorStop(0.45, 'rgba(255, 212, 145, 0.7)');
    core.addColorStop(1, 'rgba(150, 210, 255, 0)');
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.arc(hx, hy, R * 0.26, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = 'rgba(255, 244, 210, 0.7)';
    ctx.lineWidth = 0.8;
    ctx.beginPath();
    ctx.ellipse(hx, hy, R * 0.16 * squash, R * 0.16, 0, 0, Math.PI * 2);
    ctx.stroke();

    ctx.restore();
  }

  // Luminous scattering seeds with glowing wakes & feathered parachutes
  ctx.save();
  ctx.globalCompositeOperation = 'lighter';
  for (const s of seeds) {
    const q = seg(p, s.start, s.start + 0.22);
    if (q <= 0) continue;
    const c = Math.cos(s.a);
    const sn = Math.sin(s.a);
    const x0 = hx + c * R * squash;
    const y0 = hy + sn * R;
    const d = easeOut(q) * s.speed * L.unit * 0.24;
    const x = x0 + c * d;
    const y = y0 + sn * d + q * q * L.unit * s.fall;

    const fade = (1 - seg(q, 0.84, 1)) * 0.95;
    ctx.globalAlpha = fade;

    // Glowing trail
    ctx.strokeStyle = s.warm ? 'rgba(255, 200, 130, 0.85)' : 'rgba(195, 232, 255, 0.85)';
    ctx.lineWidth = 0.9;
    ctx.beginPath();
    ctx.moveTo(x - c * 11, y - sn * 11);
    ctx.lineTo(x, y);
    ctx.stroke();

    // Feathered parachute
    ctx.strokeStyle = 'rgba(240, 248, 255, 0.9)';
    ctx.lineWidth = 0.65;
    ctx.beginPath();
    for (let j = 0; j < 6; j++) {
      const th = (j / 6) * Math.PI * 2;
      ctx.moveTo(x, y);
      ctx.lineTo(x + Math.cos(th) * 4.5, y + Math.sin(th) * 4.5 - 2);
    }
    ctx.stroke();

    // Seed spore dot
    ctx.fillStyle = s.warm ? '#ffd399' : '#dff1ff';
    ctx.beginPath();
    ctx.arc(x, y, 1.2, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.restore();
}
