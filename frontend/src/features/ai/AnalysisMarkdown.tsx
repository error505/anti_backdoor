import { Children, isValidElement, type ComponentProps, type ReactNode } from "react";
import Markdown, { type Components } from "react-markdown";
import type { AiVerdict, IpIntel } from "../../api/types";
import { useIpIntel } from "../../hooks/queries";
import { ipv4Addresses, isIpWithOptionalPort, splitVerdictLine } from "../../lib/verdictLine";
import { IpChip } from "../intel/IpChip";
import { ServersMentioned } from "../intel/ServersMentioned";
import { VerdictHero } from "./VerdictHero";

function leadingText(node: ReactNode): string {
  const first = Children.toArray(node)[0];
  if (typeof first === "string" || typeof first === "number") return String(first);
  if (isValidElement<{ children?: ReactNode }>(first)) return leadingText(first.props.children);
  return "";
}

function markdownComponents(intel: Map<string, IpIntel>): Components {
  return {
    code({ className, children }: ComponentProps<"code">) {
      const text = typeof children === "string" ? children : "";
      const ip = className ? null : isIpWithOptionalPort(text);
      return ip ? <IpChip label={text} intel={intel.get(ip)} /> : <code className={className}>{children}</code>;
    },
    li({ children }: ComponentProps<"li">) {
      const isAction = /^action\b/i.test(leadingText(children).trim());
      return <li className={isAction ? "action-line" : undefined}>{children}</li>;
    },
  };
}

/** Renders model output: verdict banner, scannable sections, and server owners next to every IP it mentions. */
export function AnalysisMarkdown({ markdown, fallbackVerdict }: { markdown: string; fallbackVerdict?: AiVerdict }) {
  const { verdict, body } = splitVerdictLine(markdown, fallbackVerdict);
  const addresses = ipv4Addresses(body);
  const intel = useIpIntel(addresses).data ?? new Map<string, IpIntel>();
  return (
    <div className="analysis-body">
      <VerdictHero verdict={verdict} />
      {/* react-markdown never renders raw HTML, so attacker strings quoted by the model stay inert. */}
      <Markdown components={markdownComponents(intel)}>{body}</Markdown>
      <ServersMentioned addresses={addresses} intel={intel} />
    </div>
  );
}
