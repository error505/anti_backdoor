import { guardApi } from "../../api/endpoints";
import type { GuardStatus, SeenProgram, TrustEntry } from "../../api/types";
import { ActionBar, ActionButton } from "../../components/ActionButton";
import { Badge } from "../../components/Badge";
import { EmptyState, Panel } from "../../components/Layout";
import type { ActionSpec } from "../../hooks/useActionRunner";

const toResult = (message: string) => async (call: Promise<unknown>) => { await call; return { message }; };

const removeTrust = (entry: TrustEntry): ActionSpec => ({
  label: "Remove",
  tone: "danger",
  run: () => toResult("Trust removed")(guardApi.untrust(entry.id)),
});

function seenActions(program: SeenProgram): ActionSpec[] {
  const actions: ActionSpec[] = [];
  if (program.exe) {
    actions.push({
      label: "Trust program",
      confirm: `Allow ${program.exe} to use the internet? Its file hash is pinned, so a replaced file loses the trust.`,
      run: () => toResult("Program trusted")(guardApi.trustProgram(program.exe ?? "")),
    });
  }
  if (program.validly_signed && program.signer) {
    actions.push({
      label: "Trust publisher",
      confirm: `Trust everything validly signed by "${program.signer}"?`,
      run: () => toResult("Publisher trusted")(guardApi.trustPublisher(program.signer ?? "")),
    });
  }
  return actions;
}

function TrustedTable({ entries }: { entries: TrustEntry[] }) {
  if (entries.length === 0) return <EmptyState>Nothing trusted yet. Microsoft-signed software is always allowed.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Type</th><th>Trusted</th><th>Pinned hash</th><th /></tr></thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.id}>
              <td><Badge tone={entry.kind === "publisher" ? "info" : "ok"}>{entry.kind}</Badge></td>
              <td className="mono">{entry.value}</td>
              <td className="mono small">{entry.sha256 ? `${entry.sha256.slice(0, 16)}…` : "—"}</td>
              <td><ActionBar actions={[removeTrust(entry)]} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SeenTable({ programs }: { programs: SeenProgram[] }) {
  if (programs.length === 0) return <EmptyState>No untrusted program is using the internet right now.</EmptyState>;
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Program</th><th>Publisher</th><th>Talking to</th><th /></tr></thead>
        <tbody>
          {programs.map((program) => (
            <tr key={program.exe ?? program.name}>
              <td>{program.name}<div className="muted small mono">{program.exe}</div></td>
              <td>{program.validly_signed ? program.signer : <Badge tone="high">UNSIGNED</Badge>}</td>
              <td className="mono small">{program.remotes.join(", ")}{program.connections > program.remotes.length ? " …" : ""}</td>
              <td><ActionBar actions={seenActions(program)} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function TrustPanel({ status }: { status: GuardStatus }) {
  const signedSeen = status.seen_programs.some((p) => p.validly_signed);
  return (
    <Panel title="Trusted programs"
      actions={signedSeen && <ActionButton action={{
        label: "Trust all signed publishers below",
        confirm: "Trust every validly signed publisher in the list below? Review it first: a signature proves who made a program, not that it is safe.",
        run: guardApi.trustSignedSeen,
      }} />}>
      <p className="muted">
        The allow-list for lockdown. A trusted <strong>program</strong> is pinned by its SHA-256, so replacing the file revokes it;
        a trusted <strong>publisher</strong> covers everything validly signed by it.
      </p>
      <TrustedTable entries={status.config.trusted} />
      <h3 className="subhead">Using the internet but not trusted yet</h3>
      <SeenTable programs={status.seen_programs} />
    </Panel>
  );
}
