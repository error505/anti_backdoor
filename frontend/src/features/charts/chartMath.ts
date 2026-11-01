/** Pure helpers for the SVG charts, kept apart from React so they are easy to test. */

export interface Box {
  width: number;
  height: number;
  padLeft: number;
  padRight: number;
  padTop: number;
  padBottom: number;
}

/** Round a maximum up to 1, 2, 5 x 10^n so the axis labels are tidy. */
export function niceMax(value: number): number {
  if (value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const fraction = value / magnitude;
  const step = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10;
  return step * magnitude;
}

export function xAt(index: number, count: number, box: Box): number {
  const span = box.width - box.padLeft - box.padRight;
  return box.padLeft + (count <= 1 ? span : (index / (count - 1)) * span);
}

export function yAt(value: number, max: number, box: Box): number {
  const span = box.height - box.padTop - box.padBottom;
  return box.padTop + span - (Math.min(value, max) / max) * span;
}

/** Smooth line through the points (monotone-looking Catmull-Rom converted to cubic Beziers). */
export function linePath(values: number[], max: number, box: Box): string {
  const points = values.map((v, i) => [xAt(i, values.length, box), yAt(v, max, box)] as const);
  if (points.length === 0) return "";
  let path = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 1; i < points.length; i += 1) {
    const [x0, y0] = points[Math.max(i - 2, 0)];
    const [x1, y1] = points[i - 1];
    const [x2, y2] = points[i];
    const [x3, y3] = points[Math.min(i + 1, points.length - 1)];
    const c1x = x1 + (x2 - x0) / 6;
    const c1y = Math.min(Math.max(y1 + (y2 - y0) / 6, box.padTop), box.height - box.padBottom);
    const c2x = x2 - (x3 - x1) / 6;
    const c2y = Math.min(Math.max(y2 - (y3 - y1) / 6, box.padTop), box.height - box.padBottom);
    path += `C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`;
  }
  return path;
}

export function areaPath(values: number[], max: number, box: Box): string {
  if (values.length === 0) return "";
  const baseline = box.height - box.padBottom;
  const lastX = xAt(values.length - 1, values.length, box).toFixed(1);
  return `${linePath(values, max, box)}L${lastX},${baseline}L${box.padLeft},${baseline}Z`;
}

/** Keeps every n-th value so a long history fits a narrow chart; the newest value is always kept. */
export function thin<T>(items: T[], target: number): T[] {
  if (items.length <= target) return items;
  const step = items.length / target;
  const kept = Array.from({ length: target }, (_, i) => items[Math.floor(i * step)]);
  kept[kept.length - 1] = items[items.length - 1];
  return kept;
}

/** Nearest sample index for a pointer position, for the hover read-out. */
export function indexAt(x: number, count: number, box: Box): number {
  const span = box.width - box.padLeft - box.padRight;
  const ratio = Math.min(Math.max((x - box.padLeft) / span, 0), 1);
  return Math.round(ratio * (count - 1));
}

export interface Bin {
  start: number;
  counts: Record<string, number>;
}

/** Groups timestamps (seconds) into equal time bins ending now, counting per category. */
export function binByTime(items: { t: number; category: string }[], now: number, binSeconds: number, binCount: number): Bin[] {
  const first = now - binSeconds * binCount;
  const bins: Bin[] = Array.from({ length: binCount }, (_, i) => ({ start: first + i * binSeconds, counts: {} }));
  for (const item of items) {
    const index = Math.floor((item.t - first) / binSeconds);
    if (index >= 0 && index < binCount) bins[index].counts[item.category] = (bins[index].counts[item.category] ?? 0) + 1;
  }
  return bins;
}
