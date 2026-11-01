import type { Severity } from "../../api/types";
import { useAnimatedNumber } from "../../hooks/useAnimatedNumber";

const RADIUS = 42;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const GAP = 3;
const ORDER: { severity: Severity; label: string }[] = [
  { severity: "critical", label: "Critical" },
  { severity: "high", label: "High" },
  { severity: "medium", label: "Medium" },
  { severity: "low", label: "Low" },
  { severity: "info", label: "Info" },
];

/** Findings by severity. Each arc grows into place; the total counts up in the middle. */
export function SeverityDonut({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const rows = ORDER.map((row) => ({ ...row, count: counts[row.severity] ?? 0 }));
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  const shownTotal = useAnimatedNumber(total);
  let offset = 0;
  return (
    <div className="donut">
      <svg viewBox="0 0 120 120" role="img" aria-label={`${total} findings by severity`}>
        <circle className="donut-track" cx="60" cy="60" r={RADIUS} />
        {total > 0 && rows.filter((row) => row.count > 0).map((row) => {
          const length = Math.max((row.count / total) * CIRCUMFERENCE - GAP, 1);
          const start = offset;
          offset += (row.count / total) * CIRCUMFERENCE;
          return (
            <circle key={row.severity} className="donut-arc" cx="60" cy="60" r={RADIUS} transform="rotate(-90 60 60)"
              stroke={`var(--${row.severity})`} strokeDasharray={`${length} ${CIRCUMFERENCE}`} strokeDashoffset={-start} />
          );
        })}
        <text className="donut-total" x="60" y="60" textAnchor="middle">{shownTotal}</text>
        <text className="donut-caption" x="60" y="76" textAnchor="middle">findings</text>
      </svg>
      <ul className="chart-legend donut-legend">
        {rows.map((row) => (
          <li key={row.severity}><span className="swatch" style={{ background: `var(--${row.severity})` }} />{row.label}<b>{row.count}</b></li>
        ))}
      </ul>
    </div>
  );
}
