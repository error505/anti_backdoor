import { useMutation, useQueryClient } from "@tanstack/react-query";
import { intelApi } from "../../api/endpoints";
import { Toggle } from "../../components/Layout";
import { useToast } from "../../components/Toasts";
import { useIpIntelSettings } from "../../hooks/queries";

/** Opt-in switch: looking an address up tells the provider that you are talking to it. */
export function IpIntelToggle() {
  const settings = useIpIntelSettings();
  const queryClient = useQueryClient();
  const notify = useToast();
  const save = useMutation({
    mutationFn: intelApi.saveSettings,
    onSuccess: (saved) => {
      queryClient.setQueryData(["ip-intel-settings"], saved);
      void queryClient.invalidateQueries({ queryKey: ["ip-intel"] });
    },
    onError: (e: Error) => notify("error", e.message),
  });
  if (!settings.data) return null;
  const { enabled, provider, cached_addresses: cached } = settings.data;
  return (
    <div className="stack">
      <Toggle label={`Identify server owners (${provider})`} checked={enabled} onChange={(value) => save.mutate(value)} />
      <p className="muted small">
        {enabled
          ? `Public IP addresses (nothing else) are sent to ${provider} over HTTPS to learn the owner, country and network. Answers are cached for 30 days (${cached} so far) and included in AI and Flockion analyses.`
          : `Off: nothing is sent. Turn on to show who owns each remote server. Only public IP addresses are sent to ${provider}, never ports, process names or file contents.`}
      </p>
    </div>
  );
}
