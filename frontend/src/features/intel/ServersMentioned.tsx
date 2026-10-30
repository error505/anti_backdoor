import type { IpIntel } from "../../api/types";
import { IpOwner } from "./IpOwner";

/** Every server the answer names, with its registered owner. Hidden when nothing is known. */
export function ServersMentioned({ addresses, intel }: { addresses: string[]; intel: Map<string, IpIntel> }) {
  const known = addresses.filter((ip) => intel.has(ip));
  if (known.length === 0) return null;
  return (
    <details className="servers-mentioned" open>
      <summary>Servers named in this answer ({known.length})</summary>
      <div className="table-wrap">
        <table>
          <thead><tr><th>Address</th><th>Owner</th></tr></thead>
          <tbody>
            {known.map((ip) => (
              <tr key={ip}>
                <td className="mono">{ip}</td>
                <td><IpOwner intel={intel.get(ip)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Registration data shows who rents the address, not what it is used for. Treat it as context.</p>
    </details>
  );
}
