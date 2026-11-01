export type ThemeStyle = "scifi" | "admin";
export type ThemeMode = "dark" | "light";

export interface Theme {
  style: ThemeStyle;
  mode: ThemeMode;
}

const STORAGE_KEY = "backdoor-watch-theme";
const DEFAULT_THEME: Theme = { style: "scifi", mode: "dark" };

function isTheme(value: unknown): value is Theme {
  const theme = value as Partial<Theme> | null;
  return (theme?.style === "scifi" || theme?.style === "admin") && (theme.mode === "dark" || theme.mode === "light");
}

/** ?theme=admin-light style links win (used for documentation screenshots), then the saved choice; a first visit
 *  follows the operating system's light or dark setting. */
export function loadTheme(): Theme {
  const [style, mode] = (new URLSearchParams(window.location.search).get("theme") ?? "").split("-");
  if (isTheme({ style, mode })) return { style, mode } as Theme;
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null");
    if (isTheme(saved)) return saved;
  } catch {
    // private window or blocked storage: fall through to the default
  }
  const prefersLight = window.matchMedia?.("(prefers-color-scheme: light)").matches ?? false;
  return { ...DEFAULT_THEME, mode: prefersLight ? "light" : "dark" };
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.style = theme.style;
  document.documentElement.dataset.mode = theme.mode;
}

export function saveTheme(theme: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(theme));
  } catch {
    // the theme still applies for this session
  }
}
