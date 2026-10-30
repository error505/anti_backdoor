import type { IpIntel } from "../../api/types";
import { Badge } from "../../components/Badge";
import { ownerLine, placeLine } from "./ipOwnerText";

/** Table cell content: who registered the address, and where. */
export function IpOwner({ intel }: { intel: IpIntel | undefined }) {
  if (!intel) return <span className="muted">—</span>;
  if (intel.error) return <span className="muted small" title={intel.error}>lookup failed</span>;
  return (
    <div className="ip-owner">
      <div>
        {intel.country_code && <span className="country-code">{intel.country_code}</span>}
        <span title={ownerLine(intel)}>{intel.org ?? "unknown owner"}</span>
        {intel.cloud_hosting && (
          <> <Badge tone="info" title="Rented cloud or hosting network: common for both legitimate services and attacker servers">cloud</Badge></>
        )}
      </div>
      <div className="muted small">{[placeLine(intel), intel.asn].filter(Boolean).join(" · ")}</div>
      {intel.reverse_dns && <div className="muted small mono">{intel.reverse_dns}</div>}
    </div>
  );
}
