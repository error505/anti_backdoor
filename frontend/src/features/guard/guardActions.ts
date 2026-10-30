import { guardApi } from "../../api/endpoints";
import type { GuardAlert } from "../../api/types";
import type { ActionSpec } from "../../hooks/useActionRunner";
import { blockIp, killProcess } from "../actions/actionCatalog";

/** The process the guard froze first: the package manager for installs, the program itself for lockdown. */
const rootPid = (alert: GuardAlert) => alert.contained_pids[0] ?? alert.pid;
const serverName = (alert: GuardAlert) => alert.remote_host ?? alert.remote_ip;

const resumeAlert = (alert: GuardAlert): ActionSpec => ({
  label: "Resume (false alarm)",
  confirm: `Unfreeze the processes the guard stopped? Only do this if you recognise ${serverName(alert)}.`,
  run: () => guardApi.resume(alert.id),
});

const allowServer = (alert: GuardAlert): ActionSpec => ({
  label: "Allow this server",
  confirm: `Always allow install scripts to contact ${serverName(alert)}, and unfreeze the processes?`,
  run: async () => {
    await guardApi.allowHost(serverName(alert));
    return guardApi.resume(alert.id);
  },
});

const trustAndResume = (alert: GuardAlert): ActionSpec => ({
  label: "Trust this program",
  confirm: `Allow ${alert.process_name} (${alert.exe ?? "unknown path"}) to use the internet from now on, and unfreeze it?`,
  run: async () => {
    await guardApi.trustProgram(alert.exe ?? "");
    return guardApi.resume(alert.id);
  },
});

const acknowledge = (alert: GuardAlert): ActionSpec => ({
  label: "Acknowledge", run: () => guardApi.acknowledge(alert.id),
});

export function actionsForAlert(alert: GuardAlert): ActionSpec[] {
  const stopped = alert.action === "suspended";
  const decisions = alert.kind === "install_leak" ? [allowServer(alert)] : alert.exe ? [trustAndResume(alert)] : [];
  return [
    killProcess(rootPid(alert), alert.chain[0] ?? alert.process_name),
    blockIp(alert.remote_ip, alert.remote_host ?? undefined),
    ...(stopped ? [resumeAlert(alert), ...decisions] : decisions),
    acknowledge(alert),
  ];
}
