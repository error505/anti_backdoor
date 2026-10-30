import { Panel } from "../../components/Layout";

// Contagious Interview payloads steal browser credentials, crypto wallets and files first and install
// backdoors second, so cleaning the PC is only half the response. These steps cover the other half.
const STEPS = [
  "Change passwords from a DIFFERENT, clean device first: email, GitHub/GitLab, cloud consoles, password manager, banking.",
  "Revoke and rotate secrets on this machine: SSH keys, GitHub/npm tokens, AWS/Azure/GCP keys, .env files, API keys.",
  "Crypto wallets (MetaMask, Phantom…): move funds to a NEW wallet with a new seed created on a clean device.",
  "Sign out all sessions (Google, GitHub, Discord, Telegram…) and review OAuth apps and SSH keys on GitHub.",
  "Enable MFA everywhere; prefer passkeys or hardware keys.",
  "Check Findings, Autostart and Open ports here; quarantine anything you don't recognize.",
  "Run a Defender FULL scan and an offline scan (Windows Security → Virus & threat protection → Scan options → Microsoft Defender Offline).",
  "If anything critical turns up, the safest fix is backing up your data (not programs) and reinstalling Windows.",
  "Report the fake recruiter/repo to GitHub and LinkedIn, and keep backend/data/logs as evidence.",
];

export function IncidentChecklist() {
  return (
    <Panel title="Incident response checklist">
      <ol className="checklist">
        {STEPS.map((step) => <li key={step}>{step}</li>)}
      </ol>
    </Panel>
  );
}
