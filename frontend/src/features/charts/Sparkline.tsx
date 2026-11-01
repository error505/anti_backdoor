import { areaPath, linePath, niceMax, thin, type Box } from "./chartMath";

const BOX: Box = { width: 120, height: 32, padLeft: 2, padRight: 2, padTop: 3, padBottom: 3 };
const MAX_POINTS = 60;

/** A tiny trend line for a stat tile. Colour follows the tile through currentColor. */
export function Sparkline({ values }: { values: number[] }) {
  const points = thin(values, MAX_POINTS);
  if (points.length < 2) return null;
  const max = niceMax(Math.max(...points) * 1.2);
  return (
    <svg className="sparkline" viewBox={`0 0 ${BOX.width} ${BOX.height}`} preserveAspectRatio="none" aria-hidden="true">
      <path className="spark-area" d={areaPath(points, max, BOX)} />
      <path className="spark-line" d={linePath(points, max, BOX)} pathLength={1} />
    </svg>
  );
}
