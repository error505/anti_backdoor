import { useId, useRef, useState, type PointerEvent } from "react";
import { useElementWidth } from "../../hooks/useElementWidth";
import { areaPath, indexAt, linePath, niceMax, thin, xAt, yAt, type Box } from "./chartMath";

export interface Series {
  label: string;
  /** A CSS colour, normally a theme variable such as var(--accent). */
  color: string;
  values: number[];
}

interface Props {
  times: number[];
  series: Series[];
  format: (value: number) => string;
  height?: number;
  emptyHint?: string;
}

const BOX: Box = { width: 760, height: 220, padLeft: 86, padRight: 12, padTop: 12, padBottom: 24 };
const MAX_POINTS = 240;
const GRID_LINES = 4;

const clock = (seconds: number) => new Date(seconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });

/** Smooth animated line/area chart with a hover read-out. Lines draw in when the chart appears. */
export function TimeSeriesChart({ times, series, format, height = BOX.height, emptyHint }: Props) {
  const gradientId = useId();
  const svg = useRef<SVGSVGElement>(null);
  const [wrap, width] = useElementWidth<HTMLDivElement>(BOX.width);
  const [hover, setHover] = useState<number | null>(null);
  const box = { ...BOX, width, height };

  const keep = thin(times.map((_, i) => i), MAX_POINTS);
  const t = keep.map((i) => times[i]);
  const lines = series.map((s) => ({ ...s, values: keep.map((i) => s.values[i] ?? 0) }));
  const max = niceMax(Math.max(0, ...lines.flatMap((s) => s.values)) * 1.08);
  const hasData = t.length > 1 && lines.some((s) => s.values.some((v) => v > 0));

  const onMove = (event: PointerEvent<SVGSVGElement>) => {
    const rect = svg.current?.getBoundingClientRect();
    if (!rect || t.length === 0) return;
    setHover(indexAt(((event.clientX - rect.left) / rect.width) * box.width, t.length, box));
  };

  return (
    <div className="chart-wrap" ref={wrap}>
      <svg ref={svg} className="chart" viewBox={`0 0 ${box.width} ${box.height}`} role="img"
        aria-label={`Chart of ${series.map((s) => s.label).join(" and ")}`}
        onPointerMove={onMove} onPointerLeave={() => setHover(null)}>
        <defs>
          {lines.map((s, i) => (
            <linearGradient key={s.label} id={`${gradientId}-${i}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={s.color} stopOpacity="0.32" />
              <stop offset="1" stopColor={s.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {Array.from({ length: GRID_LINES + 1 }, (_, i) => {
          const value = (max / GRID_LINES) * i;
          const y = yAt(value, max, box);
          return (
            <g key={i} className="chart-grid">
              <line x1={box.padLeft} x2={box.width - box.padRight} y1={y} y2={y} />
              <text x={box.padLeft - 8} y={y + 4} textAnchor="end">{format(value)}</text>
            </g>
          );
        })}
        {hasData && [0, 0.5, 1].map((ratio) => {
          const index = Math.round(ratio * (t.length - 1));
          return <text key={ratio} className="chart-axis" x={xAt(index, t.length, box)} y={box.height - 6}
            textAnchor={ratio === 0 ? "start" : ratio === 1 ? "end" : "middle"}>{clock(t[index])}</text>;
        })}
        {hasData && lines.map((s, i) => (
          <g key={s.label}>
            <path className="chart-area" d={areaPath(s.values, max, box)} fill={`url(#${gradientId}-${i})`} />
            <path className="chart-line" d={linePath(s.values, max, box)} stroke={s.color} pathLength={1} />
            <circle className="chart-head" r="4" fill={s.color}
              cx={xAt(s.values.length - 1, s.values.length, box)} cy={yAt(s.values[s.values.length - 1], max, box)} />
          </g>
        ))}
        {hasData && hover !== null && (
          <g className="chart-cursor">
            <line x1={xAt(hover, t.length, box)} x2={xAt(hover, t.length, box)} y1={box.padTop} y2={box.height - box.padBottom} />
            {lines.map((s) => <circle key={s.label} r="4" fill={s.color} cx={xAt(hover, t.length, box)} cy={yAt(s.values[hover], max, box)} />)}
          </g>
        )}
      </svg>
      {!hasData && <p className="chart-empty">{emptyHint ?? "Collecting data…"}</p>}
      <ul className="chart-legend">
        {lines.map((s) => (
          <li key={s.label}>
            <span className="swatch" style={{ background: s.color }} />{s.label}
            {hasData && <b>{format(s.values[hover ?? s.values.length - 1] ?? 0)}</b>}
          </li>
        ))}
        {hasData && hover !== null && <li className="muted">{clock(t[hover])}</li>}
      </ul>
    </div>
  );
}
