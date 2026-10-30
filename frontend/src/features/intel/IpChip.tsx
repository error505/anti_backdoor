import type { IpIntel } from "../../api/types";
import { ipTooltip } from "./ipOwnerText";

const MAX_OWNER_CHARS = 26;

function shortOwner(intel: IpIntel): string {
  const owner = intel.org ?? "";
  return owner.length > MAX_OWNER_CHARS ? `${owner.slice(0, MAX_OWNER_CHARS - 1)}…` : owner;
}

/** An address inside AI text, annotated with who owns it when that is known. */
export function IpChip({ label, intel }: { label: string; intel: IpIntel | undefined }) {
  const known = intel && !intel.error;
  return (
    <span className={known && intel.cloud_hosting ? "ip-chip ip-chip-cloud" : "ip-chip"} title={known ? ipTooltip(intel) : undefined}>
      <code>{label}</code>
      {known && (
        <span className="ip-chip-owner">
          {intel.country_code && <b>{intel.country_code}</b>}
          {shortOwner(intel)}
        </span>
      )}
    </span>
  );
}
