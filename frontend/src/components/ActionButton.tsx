import { useActionRunner, type ActionSpec } from "../hooks/useActionRunner";

export function ActionButton({ action }: { action: ActionSpec }) {
  const { run, isPending } = useActionRunner();
  return (
    <button
      type="button"
      className={action.tone === "danger" ? "btn btn-danger" : "btn"}
      disabled={isPending}
      onClick={(event) => {
        event.stopPropagation();
        run(action);
      }}
    >
      {isPending ? "…" : action.label}
    </button>
  );
}

export function ActionBar({ actions }: { actions: ActionSpec[] }) {
  return (
    <div className="action-bar">
      {actions.map((action) => <ActionButton key={action.label} action={action} />)}
    </div>
  );
}
