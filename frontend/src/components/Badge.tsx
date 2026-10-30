import type { ReactNode } from "react";
import type { Severity, SignatureInfo } from "../api/types";

export type BadgeTone = Severity | "ok" | "neutral";

export function Badge({ tone, children, title }: { tone: BadgeTone; children: ReactNode; title?: string }) {
  return <span className={`badge badge-${tone}`} title={title}>{children}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={severity}>{severity.toUpperCase()}</Badge>;
}

export function SelfBadge() {
  return <Badge tone="ok" title="This process is Backdoor Watch itself (server, launcher or helper)">Backdoor Watch</Badge>;
}

export function SignatureBadge({ signature }: { signature: SignatureInfo | null }) {
  if (!signature) return <Badge tone="neutral">checking…</Badge>;
  if (signature.is_microsoft) return <Badge tone="ok" title={signature.subject ?? ""}>Microsoft</Badge>;
  if (signature.is_valid) return <Badge tone="ok" title={signature.subject ?? ""}>{signature.signer ?? "Signed"}</Badge>;
  if (signature.is_untrusted) return <Badge tone="high">{signature.status === "NotSigned" ? "UNSIGNED" : signature.status}</Badge>;
  return <Badge tone="neutral" title="Signature could not be read">{signature.status}</Badge>;
}
