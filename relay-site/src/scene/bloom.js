import { seg, easeOut, easeInOut, headPos } from './util.js';
import { PETAL_FRAMES } from '../content.js';

// Evaluates curved quadratic Bezier point at t in [0, 1]
function quadPoint(p0, p1, p2, t) {
  const u = 1 - t;
  return {
    x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
    y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
  };
}

// Computes exact position, scale, morph factor, and trail curve for each scattered petal frame
export function getScatteredPetals(L, p, t = 0) {
  const { x: hx, y: hy } = headPos(L, p);
  const fadeOut = 1 - seg(p, 0.88, 0.97);

  return PETAL_FRAMES.map((spec, i) => {
    const start = spec.detach;
    const fly = easeOut(seg(p, start, start + 0.16));
    const morph = easeInOut(seg(p, start + 0.08, start + 0.22));

    const target = {
      x: L.w * spec.tx,
      y: L.h * spec.ty,
    };
    const ctrl = {
      x: (hx + target.x) * 0.5 + L.unit * spec.arc * 0.5,
      y: Math.min(hx > target.x ? hy : target.y, (hy + target.y) * 0.5) - Math.abs(spec.arc) * L.h,
    };

    const pos = quadPoint({ x: hx, y: hy }, ctrl, target, fly);
    // Gentle buoyancy float once settled
    const floatX = morph * Math.sin(t * 0.9 + i * 1.1) * 4;
    const floatY = morph * Math.cos(t * 1.1 + i * 0.8) * 5 - seg(p, 0.88, 0.97) * 45;

    return {
      index: i,
      spec,
      startPos: { x: hx, y: hy },
      ctrl,
      target,
      x: pos.x + floatX,
      y: pos.y + floatY,
      fly,
      morph,
      alpha: Math.min(seg(p, start, start + 0.03), fadeOut),
    };
  });
}

// Renders the scattering dandelion petals/filaments turning into glassy frames
export function drawBloom(ctx, L, p, t = 0, activeIdx = -1, pulseAge = -1) {
  if (p < 0.29 || p > 0.98) return;

  const { x: hx, y: hy } = headPos(L, p);
  const petals = getScatteredPetals(L, p, t);
  const coreFade = (1 - seg(p, 0.72, 0.88)) * seg(p, 0.3, 0.42);

  ctx.save();
  ctx.globalCompositeOperation = 'lighter';

  // Soft residual glow at dandelion core during scatter
  if (coreFade > 0.01) {
    const cg = ctx.createRadialGradient(hx, hy, 0, hx, hy, L.unit * 0.045);
    cg.addColorStop(0, `rgba(255,246,220,${(0.55 * coreFade).toFixed(3)})`);
    cg.addColorStop(1, 'rgba(255,200,120,0)');
    ctx.fillStyle = cg;
    ctx.beginPath();
    ctx.arc(hx, hy, L.unit * 0.045, 0, Math.PI * 2);
    ctx.fill();
  }

  for (const pt of petals) {
    if (pt.alpha <= 0.01 || pt.fly <= 0) continue;

    const isStart = Boolean(pt.spec.isStart);
    const isActive = pt.index === activeIdx;
    const trailFade = 1 - seg(pt.morph, 0.35, 1) * 0.72;

    // Luminous wind-scatter trajectory filament from dandelion head toward scattered petal
    ctx.save();
    ctx.globalAlpha = pt.alpha * trailFade * (isActive || isStart ? 0.65 : 0.34);
    ctx.strokeStyle = isStart ? 'rgba(255, 184, 107, 0.95)' : 'rgba(205, 226, 255, 0.85)';
    ctx.lineWidth = isActive || isStart ? 1.3 : 0.85;
    ctx.setLineDash([4, 5]);
    ctx.beginPath();
    ctx.moveTo(pt.startPos.x, pt.startPos.y);
    ctx.quadraticCurveTo(pt.ctrl.x, pt.ctrl.y, pt.x, pt.y);
    ctx.stroke();
    ctx.restore();

    // Glowing flying seed/petal head BEFORE it finishes opening into a glassy frame
    const seedPhase = 1 - pt.morph * 0.85;
    if (seedPhase > 0.05) {
      ctx.save();
      ctx.globalAlpha = pt.alpha * seedPhase;
      ctx.translate(pt.x, pt.y);

      const glow = ctx.createRadialGradient(0, 0, 0, 0, 0, 18 * seedPhase);
      glow.addColorStop(0, isStart ? 'rgba(255,205,130,0.95)' : 'rgba(235,244,255,0.95)');
      glow.addColorStop(1, 'rgba(214,230,255,0)');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(0, 0, 18 * seedPhase, 0, Math.PI * 2);
      ctx.fill();

      // Delicate parachute spokes on the scattering petal
      ctx.strokeStyle = isStart ? 'rgba(255,210,150,0.9)' : 'rgba(240,246,255,0.9)';
      ctx.lineWidth = 0.9;
      ctx.beginPath();
      for (let j = 0; j < 7; j++) {
        const a = -Math.PI * 0.85 + (j / 6) * Math.PI * 0.7;
        ctx.moveTo(0, 0);
        ctx.lineTo(Math.cos(a) * 10, Math.sin(a) * 10);
      }
      ctx.stroke();
      ctx.restore();
    }

    // Signal pulse traveling along the wind path when Start / Pulse Hops is triggered
    if (pulseAge >= 0 && pulseAge < 2.2) {
      const wave = (pulseAge - pt.index * 0.12) % 1;
      if (wave > 0 && wave < 1) {
        const wp = quadPoint(pt.startPos, pt.ctrl, { x: pt.x, y: pt.y }, wave);
        ctx.fillStyle = 'rgba(255, 224, 165, 0.96)';
        ctx.beginPath();
        ctx.arc(wp.x, wp.y, 3.2, 0, Math.PI * 2);
        ctx.fill();
      }
    }
  }

  ctx.restore();
}
