import { useMutation, useQueryClient } from "@tanstack/react-query";
import { guardApi } from "../../api/endpoints";
import type { GuardConfig, GuardMode } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Panel, Toggle } from "../../components/Layout";
import { useToast } from "../../components/Toasts";

type Modes = Pick<GuardConfig, "install_watch" | "lockdown" | "sound">;

const MODE_LABEL: Record<GuardMode, string> = {
  off: "Off",
  alert: "Alert only (siren + banner)",
  contain: "Alert and stop it (freeze the process)",
};

function ModeSelect({ label, value, onChange }: { label: string; value: GuardMode; onChange: (mode: GuardMode) => void }) {
  return (
    <label className="field">{label}
      <select value={value} onChange={(e) => onChange(e.target.value as GuardMode)}>
        {(Object.keys(MODE_LABEL) as GuardMode[]).map((mode) => <option key={mode} value={mode}>{MODE_LABEL[mode]}</option>)}
      </select>
    </label>
  );
}

export function GuardModesPanel({ config }: { config: GuardConfig }) {
  const queryClient = useQueryClient();
  const notify = useToast();
  const save = useMutation({
    mutationFn: (modes: Modes) => guardApi.setModes(modes),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["guard"] }),
    onError: (e: Error) => notify("error", e.message),
  });
  const change = (patch: Partial<Modes>) =>
    save.mutate({ install_watch: config.install_watch, lockdown: config.lockdown, sound: config.sound, ...patch });

  return (
    <Panel title="Guard modes">
      <div className="stack">
        <ModeSelect label="Install watch: npm, yarn, pnpm, bun, pip" value={config.install_watch}
          onChange={(install_watch) => change({ install_watch })} />
        <p className="muted small">
          When a project you just cloned runs install scripts (<code>npm i</code>, <code>yarn</code>, <code>pip install</code>…) and one of
          them contacts a server that is not a known registry, the guard sounds the alarm and freezes the whole install,
          then blocks that server. While running <code>npm start</code> or <code>npx</code> only known attacker ports count.
        </p>
        <ModeSelect label="Lockdown: only trusted programs may send data out" value={config.lockdown}
          onChange={(lockdown) => change({ lockdown })} />
        <p className="muted small">
          Any program that is not Microsoft-signed, not from a publisher you trust and not pinned by you is stopped the
          moment it connects to the internet. Start with <em>Alert only</em>, trust what you use below, then switch to freeze.
        </p>
        <Toggle label="Play the siren on this PC's speakers" checked={config.sound} onChange={(sound) => change({ sound })} />
        <div className="action-bar">
          <ActionButton action={{ label: "Test the siren", run: guardApi.testAlarm }} />
        </div>
      </div>
    </Panel>
  );
}
