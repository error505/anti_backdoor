import { useEffect, useState } from "react";
import { prefersReducedMotion } from "../lib/motion";

const BOOT_LINES = [
  "> FLOCKION // BACKDOOR WATCH v1.0 :: secure console",
  "> binding loopback interface 127.0.0.1 ............ OK",
  "> linking kernel process telemetry ................. OK",
  "> arming TCP/UDP socket sensors .................... OK",
  "> loading IOC set: BeaverTail / InvisibleFerret / OtterCookie ... OK",
  "> scanning autostart vectors ....................... OK",
  "> ACCESS GRANTED",
];
const BOOT_DURATION_MS = 2600;
const SHOWN_KEY = "backdoor-watch-booted";

function shouldPlay(): boolean {
  if (prefersReducedMotion()) return false;
  try {
    return sessionStorage.getItem(SHOWN_KEY) !== "1";
  } catch {
    return true;
  }
}

/** One-time-per-tab intro; any key or click skips it. */
export function BootSequence() {
  const [visible, setVisible] = useState(shouldPlay);

  useEffect(() => {
    if (!visible) return;
    try {
      sessionStorage.setItem(SHOWN_KEY, "1");
    } catch {
      // Storage may be blocked; the intro then simply replays next time.
    }
    const hide = () => setVisible(false);
    const timer = setTimeout(hide, BOOT_DURATION_MS);
    window.addEventListener("keydown", hide);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("keydown", hide);
    };
  }, [visible]);

  if (!visible) return null;
  return (
    <div className="boot" aria-hidden="true" onClick={() => setVisible(false)}>
      <div className="boot-terminal">
        {BOOT_LINES.map((line, index) => (
          <div key={line} className={index === BOOT_LINES.length - 1 ? "boot-line boot-granted" : "boot-line"}
            style={{ animationDelay: `${index * 0.27}s` }}>
            {line}
          </div>
        ))}
        <div className="boot-bar"><span /></div>
      </div>
    </div>
  );
}
