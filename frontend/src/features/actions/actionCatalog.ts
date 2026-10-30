// Single source of truth for response actions: labels, confirmation wording and API calls.
import { defenderApi, firewallApi, processApi, quarantineApi, threatApi } from "../../api/endpoints";
import type { FindingTarget, PersistenceEntry } from "../../api/types";
import type { ActionSpec } from "../../hooks/useActionRunner";

export const killProcess = (pid: number, name: string): ActionSpec => ({
  label: "Kill tree",
  tone: "danger",
  confirm: `Kill ${name} (PID ${pid}) and all of its child processes?`,
  run: () => processApi.kill(pid, true),
});

export const killSingleProcess = (pid: number, name: string): ActionSpec => ({
  label: "Kill",
  tone: "danger",
  confirm: `Kill ${name} (PID ${pid})?`,
  run: () => processApi.kill(pid, false),
});

export const suspendProcess = (pid: number): ActionSpec => ({ label: "Suspend", run: () => processApi.suspend(pid) });

export const resumeProcess = (pid: number): ActionSpec => ({ label: "Resume", run: () => processApi.resume(pid) });

export const quarantineProcess = (pid: number, name: string): ActionSpec => ({
  label: "Kill + quarantine exe",
  tone: "danger",
  confirm: `Kill ${name} (PID ${pid}) and move its executable into quarantine? (restorable)`,
  run: () => processApi.quarantineExecutable(pid),
});

export const blockProcessNetwork = (pid: number, name: string): ActionSpec => ({
  label: "Block in firewall",
  confirm: `Block all network traffic for ${name}'s executable (inbound and outbound)?`,
  run: () => processApi.blockNetwork(pid),
});

export const blockIp = (ip: string, label?: string): ActionSpec => ({
  label: "Block IP",
  tone: "danger",
  confirm: `Block all traffic to and from ${label && label !== ip ? `${label} (${ip})` : ip}?`,
  run: () => firewallApi.blockIp(ip),
});

export const quarantinePath = (path: string): ActionSpec => ({
  label: "Quarantine",
  tone: "danger",
  confirm: `Move ${path} into quarantine? Processes using it should be killed first.`,
  run: () => quarantineApi.add(path, "Quarantined from Backdoor Watch"),
});

export const removePersistence = (entryId: string, description: string): ActionSpec => ({
  label: "Remove autostart",
  tone: "danger",
  confirm: `Remove autostart entry "${description}"? Services are stopped and disabled; other entries are ` +
    "deleted. A backup is saved in backend/data/backups.",
  run: () => threatApi.removePersistence(entryId),
});

export const removePersistenceEntry = (entry: PersistenceEntry): ActionSpec =>
  removePersistence(entry.id, `${entry.kind}: ${entry.name}`);

export const enableRealtimeProtection: ActionSpec = {
  label: "Turn on real-time protection",
  run: defenderApi.enableRealtime,
};

export const openWindowsSecurity: ActionSpec = {
  label: "Open Windows Security",
  run: defenderApi.openWindowsSecurity,
};

export function actionsForTarget(target: FindingTarget): ActionSpec[] {
  switch (target.kind) {
    case "defender":
      return [enableRealtimeProtection, openWindowsSecurity];
    case "process": {
      const pid = Number(target.ref);
      return [killProcess(pid, target.label), blockProcessNetwork(pid, target.label)];
    }
    case "file":
      return [quarantinePath(target.ref)];
    case "remote_ip":
      return [blockIp(target.ref, target.label)];
    case "persistence":
      return [removePersistence(target.ref, target.label)];
  }
}
