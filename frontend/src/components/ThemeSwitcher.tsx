import { useState } from "react";
import { applyTheme, loadTheme, saveTheme, type Theme, type ThemeMode, type ThemeStyle } from "../lib/theme";

interface Option<T extends string> {
  value: T;
  label: string;
}

const STYLES: Option<ThemeStyle>[] = [{ value: "scifi", label: "Sci-fi" }, { value: "admin", label: "Admin" }];
const MODES: Option<ThemeMode>[] = [{ value: "dark", label: "Dark" }, { value: "light", label: "Light" }];

function Segmented<T extends string>({ label, options, value, onChange }: {
  label: string; options: Option<T>[]; value: T; onChange: (value: T) => void;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((option) => (
        <button key={option.value} type="button" className={option.value === value ? "seg active" : "seg"}
          aria-pressed={option.value === value} onClick={() => onChange(option.value)}>
          {option.label}
        </button>
      ))}
    </div>
  );
}

/** Style (sci-fi or plain admin) and mode (dark or light) are independent, so all four combinations exist. */
export function ThemeSwitcher() {
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const choose = (patch: Partial<Theme>) => {
    const next = { ...theme, ...patch };
    setTheme(next);
    applyTheme(next);
    saveTheme(next);
  };
  return (
    <div className="theme-switcher">
      <Segmented label="Style" options={STYLES} value={theme.style} onChange={(style) => choose({ style })} />
      <Segmented label="Mode" options={MODES} value={theme.mode} onChange={(mode) => choose({ mode })} />
    </div>
  );
}
