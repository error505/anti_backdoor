import type { Severity } from "../../api/types";
import { assessThreatLevel } from "../../lib/threatLevel";

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const TICKS = Array.from({ length: 36 }, (_, i) => i * 10);

export function ThreatGauge({ counts }: { counts: Partial<Record<Severity, number>> }) {
  const threat = assessThreatLevel(counts);
  return (
    <div className={`gauge gauge-${threat.level}`} role="img" aria-label={`Threat level: ${threat.label}`}>
      <svg viewBox="0 0 120 120">
        <g className="gauge-ticks">
          {TICKS.map((angle) => <line key={angle} x1="60" y1="2" x2="60" y2={angle % 30 === 0 ? 8 : 5} transform={`rotate(${angle} 60 60)`} />)}
        </g>
        <circle className="gauge-track" cx="60" cy="60" r={RADIUS} />
        <circle className="gauge-value" cx="60" cy="60" r={RADIUS} strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={CIRCUMFERENCE * (1 - threat.score)} transform="rotate(-90 60 60)" />
        <circle className="gauge-orbit" cx="60" cy="60" r="40" />
      </svg>
      <div className="gauge-center">
        <div className="gauge-caption">Threat level</div>
        <div className="gauge-level">{threat.label}</div>
      </div>
    </div>
  );
}
