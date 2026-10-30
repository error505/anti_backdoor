import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { ActionResult } from "../api/types";
import { useToast } from "../components/Toasts";

export interface ActionSpec {
  label: string;
  /** Shown in a confirmation dialog before destructive actions. */
  confirm?: string;
  tone?: "danger" | "normal";
  run: () => Promise<ActionResult>;
}

export function useActionRunner() {
  const queryClient = useQueryClient();
  const notify = useToast();
  const mutation = useMutation({
    mutationFn: (spec: ActionSpec) => spec.run(),
    onSuccess: (result) => {
      notify("success", result.message);
      void queryClient.invalidateQueries();
    },
    onError: (error: Error) => notify("error", error.message),
  });

  const run = (spec: ActionSpec) => {
    if (spec.confirm && !window.confirm(spec.confirm)) return;
    mutation.mutate(spec);
  };

  return { run, isPending: mutation.isPending };
}
