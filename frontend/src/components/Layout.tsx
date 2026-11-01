import type { ReactNode } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useAnimatedNumber } from "../hooks/useAnimatedNumber";

export function Panel({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2>{title}</h2>
        {actions && <div className="panel-actions">{actions}</div>}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function AnimatedNumber({ value }: { value: number }) {
  return <>{useAnimatedNumber(value)}</>;
}

export function StatTile({ label, value, tone, spark }: { label: string; value: ReactNode; tone?: "danger" | "warn" | "ok"; spark?: ReactNode }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-value">{typeof value === "number" ? <AnimatedNumber value={value} /> : value}</div>
      <div className="stat-label">{label}</div>
      {spark}
    </div>
  );
}

export function Notice({ tone, children }: { tone: "warn" | "info" | "danger"; children: ReactNode }) {
  return <div className={`notice notice-${tone}`} role="note">{children}</div>;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/** Renders loading / error states and only calls `children` once data exists. */
export function QueryState<T>({ query, children }: { query: UseQueryResult<T>; children: (data: T) => ReactNode }) {
  if (query.isPending) return <p className="muted">Loading…</p>;
  if (query.isError) return <Notice tone="danger">Could not load: {query.error.message}</Notice>;
  return <>{children(query.data)}</>;
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <input
      className="search"
      type="search"
      aria-label={placeholder}
      placeholder={placeholder}
      value={value}
      onChange={(event) => onChange(event.target.value)}
    />
  );
}

export function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="toggle">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}
