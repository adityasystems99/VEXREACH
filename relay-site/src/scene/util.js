export const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
export const seg = (p, a, b) => clamp((p - a) / (b - a));
export const easeOut = (t) => 1 - Math.pow(1 - t, 3);
export const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);

// Deterministic PRNG so the scene is identical on every scroll position
export function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

// One damped oscillation while the fire passes behind the stem
export function swayOffset(L, p) {
  const s = seg(p, 0.2, 0.3);
  return Math.sin(s * Math.PI * 2) * (1 - s) * 0.08 * L.unit;
}

export function headPos(L, p) {
  return { x: L.headX + swayOffset(L, p), y: L.headY };
}
