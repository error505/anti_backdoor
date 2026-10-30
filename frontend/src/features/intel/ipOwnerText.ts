import type { IpIntel } from "../../api/types";

export function ownerLine(intel: IpIntel): string {
  return [intel.org, intel.asn].filter(Boolean).join(" · ");
}

export function placeLine(intel: IpIntel): string {
  return [intel.city, intel.region, intel.country].filter(Boolean).join(", ");
}

export function ipTooltip(intel: IpIntel): string {
  const lines = [ownerLine(intel), placeLine(intel), intel.reverse_dns ? `rDNS ${intel.reverse_dns}` : ""];
  return lines.filter(Boolean).join("\n");
}
