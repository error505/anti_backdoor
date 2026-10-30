import { useQuery } from "@tanstack/react-query";
import {
  aiApi, captureApi, defenderApi, flockionApi, guardApi, intelApi, malwareApi, firewallApi, networkApi, processApi, quarantineApi, systemApi, threatApi,
} from "../api/endpoints";

const LIVE = 2000;
const SLOW = 10000;

export const useSystemStatus = () =>
  useQuery({ queryKey: ["status"], queryFn: systemApi.status, refetchInterval: LIVE });

export const useProcesses = () =>
  useQuery({ queryKey: ["processes"], queryFn: processApi.list, refetchInterval: 4000 });

export const useProcessDetail = (pid: number | null) =>
  useQuery({
    queryKey: ["process", pid],
    queryFn: () => processApi.detail(pid as number),
    enabled: pid !== null,
    refetchInterval: LIVE,
    retry: false,
  });

export const useConnections = () =>
  useQuery({ queryKey: ["connections"], queryFn: networkApi.connections, refetchInterval: LIVE });

export const useTraffic = () =>
  useQuery({ queryKey: ["traffic"], queryFn: networkApi.traffic, refetchInterval: LIVE });

export const useFindings = () =>
  useQuery({ queryKey: ["findings"], queryFn: threatApi.findings, refetchInterval: 5000 });

export const usePersistence = () =>
  useQuery({ queryKey: ["persistence"], queryFn: threatApi.persistence, refetchInterval: SLOW });

export const useActivity = (limit: number) =>
  useQuery({ queryKey: ["events", limit], queryFn: () => threatApi.events(limit), refetchInterval: 3000 });

export const useFirewallRules = () =>
  useQuery({ queryKey: ["firewall"], queryFn: firewallApi.rules, refetchInterval: SLOW });

export const useQuarantine = () =>
  useQuery({ queryKey: ["quarantine"], queryFn: quarantineApi.list, refetchInterval: SLOW });

export const useDefender = () =>
  useQuery({ queryKey: ["defender"], queryFn: defenderApi.overview, refetchInterval: 30000 });

export const useAiSettings = () => useQuery({ queryKey: ["ai-settings"], queryFn: aiApi.settings });

/** Polls fast while a scan runs (progress), slowly otherwise. */
export const useMalwareStatus = () =>
  useQuery({ queryKey: ["malware-status"], queryFn: malwareApi.status,
             refetchInterval: (query) => (query.state.data?.state === "running" ? 1500 : 15000) });

export const useIntelSettings = () => useQuery({ queryKey: ["intel-settings"], queryFn: malwareApi.settings });

export const useFlockionSettings = () => useQuery({ queryKey: ["flockion-settings"], queryFn: flockionApi.settings });

export const useAiOptions = () => useQuery({ queryKey: ["ai-options"], queryFn: aiApi.options, staleTime: Infinity });

/** Newest first; scheduled runs land here, so it is polled. */
export const useAiHistory = () => useQuery({ queryKey: ["ai-history"], queryFn: aiApi.history, refetchInterval: 30000 });

export const useAiSchedule = () => useQuery({ queryKey: ["ai-schedule"], queryFn: aiApi.schedule, refetchInterval: 15000 });

/** PIDs belonging to Backdoor Watch itself (server, launcher, helpers). */
export function useSelfPids(): Set<number> {
  const status = useSystemStatus();
  return new Set(status.data?.self_pids ?? []);
}

export const useCaptureRecords = (limit: number) =>
  useQuery({ queryKey: ["capture", limit], queryFn: () => captureApi.records(limit), refetchInterval: LIVE });

export const useIpIntelSettings = () => useQuery({ queryKey: ["ip-intel-settings"], queryFn: intelApi.settings });

/** Owner, country and network of remote servers. Cached answers come back even while lookups are switched off. */
export const useIpIntel = (ips: string[]) => {
  const wanted = [...new Set(ips)].sort().slice(0, 50);
  return useQuery({
    queryKey: ["ip-intel", wanted],
    queryFn: () => intelApi.lookup(wanted),
    enabled: wanted.length > 0,
    staleTime: 5 * 60_000,
    select: (batch) => new Map(batch.results.map((intel) => [intel.ip, intel])),
  });
};

/** Polls fast: a guard alert must reach the screen within seconds. */
export const useGuard = () => useQuery({ queryKey: ["guard"], queryFn: guardApi.status, refetchInterval: 2000 });
