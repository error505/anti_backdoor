/** Flockion Backdoor Watch mark: a shield around a radar. Keep in sync with docs/assets/logo.svg. */
export function LogoMark({ size = 44 }: { size?: number }) {
  return (
    <svg className="logo-mark" viewBox="0 0 64 64" width={size} height={size} role="img" aria-label="Flockion Backdoor Watch">
      <defs>
        <linearGradient id="lm-shield" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#0b2a44" />
          <stop offset="1" stopColor="#03101c" />
        </linearGradient>
        <linearGradient id="lm-rim" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#00e5ff" />
          <stop offset="1" stopColor="#ff2bd6" />
        </linearGradient>
        <radialGradient id="lm-sweep" cx="32" cy="33" r="15" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#00e5ff" stopOpacity="0.85" />
          <stop offset="1" stopColor="#00e5ff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <path d="M32 3 57 12.5V32c0 14.5-10.2 24.5-25 29.5C17.2 56.5 7 46.5 7 32V12.5Z" fill="url(#lm-shield)"
        stroke="url(#lm-rim)" strokeWidth="2.5" strokeLinejoin="round" />
      <g fill="none" stroke="#00e5ff" strokeOpacity="0.55" strokeWidth="1">
        <circle cx="32" cy="33" r="15" />
        <circle cx="32" cy="33" r="8" />
        <path d="M32 18v30M17 33h30" strokeOpacity="0.3" />
      </g>
      <g className="logo-sweep">
        <path d="M32 33 32 18A15 15 0 0 1 45 25.5Z" fill="url(#lm-sweep)" />
        <path d="M32 33 32 18" stroke="#9ff6ff" strokeWidth="1.5" strokeLinecap="round" />
      </g>
      <circle className="logo-blip" cx="39" cy="40" r="2.3" fill="#ff2bd6" />
      <circle cx="39" cy="40" r="4.5" fill="none" stroke="#ff2bd6" strokeOpacity="0.5" />
      <circle cx="32" cy="33" r="1.6" fill="#eaffff" />
    </svg>
  );
}
