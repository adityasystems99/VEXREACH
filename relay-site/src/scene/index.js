import { drawKeyhole } from './keyhole.js';
import { drawField } from './field.js';
import { drawDandelion } from './dandelion.js';
import { drawBloom } from './bloom.js';
import { drawIris } from './iris.js';
import { drawReadouts } from './readouts.js';

export function makeLayout(w, h) {
  const narrow = w < 700;
  const headX = narrow ? w * 0.5 : w * 0.68;
  const headY = narrow ? h * 0.30 : h * 0.45;
  return {
    w, h,
    unit: Math.min(w, h),
    headX, headY,
    baseX: headX,
    baseY: h * 1.02,
  };
}

export function renderScene(ctx, L, p, t = 0, state = {}) {
  ctx.clearRect(0, 0, L.w, L.h);
  const featBlend = state.featBlend ?? 0;
  drawField(ctx, L, p, t, featBlend);
  if (featBlend < 0.99) {
    drawDandelion(ctx, L, p, t);
    drawBloom(ctx, L, p, t, state.activePetal ?? -1, state.pulseAge ?? -1);
    drawIris(ctx, L, p, t);
    drawReadouts(ctx, L, p);
    drawKeyhole(ctx, L, p, t);
  }
}
