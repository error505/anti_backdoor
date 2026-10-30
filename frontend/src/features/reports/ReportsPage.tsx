import { useState } from "react";
import { reportApi } from "../../api/endpoints";
import type { ReportFormat, UploadMethod } from "../../api/types";
import { ActionButton } from "../../components/ActionButton";
import { Panel, Toggle } from "../../components/Layout";
import { FlockionPanel } from "./FlockionPanel";

const FORMATS: { value: ReportFormat; label: string }[] = [
  { value: "html", label: "HTML (printable, save as PDF)" },
  { value: "markdown", label: "Markdown" },
  { value: "json", label: "JSON (full data)" },
];

function FormatSelect({ value, onChange }: { value: ReportFormat; onChange: (f: ReportFormat) => void }) {
  return (
    <select aria-label="Report format" value={value} onChange={(e) => onChange(e.target.value as ReportFormat)}>
      {FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
    </select>
  );
}

export function ReportsPage() {
  return (
    <>
      <div className="grid-2">
        <DownloadPanel />
        <UploadPanel />
      </div>
      <FlockionPanel />
    </>
  );
}

function DownloadPanel() {
  const [format, setFormat] = useState<ReportFormat>("html");
  const [redact, setRedact] = useState(false);
  return (
    <Panel title="Download report">
      <p className="muted">
        A point-in-time report: findings, Defender status, internet connections, open ports, non-Microsoft
        processes and autostart entries, traffic, notable events and the latest AI analysis.
      </p>
      <div className="inline-form">
        <FormatSelect value={format} onChange={setFormat} />
        <Toggle label="Redact secrets, user & host names" checked={redact} onChange={setRedact} />
        <ActionButton action={{ label: "Download", run: async () => ({ message: `Saved ${await reportApi.download(format, redact)}` }) }} />
      </div>
    </Panel>
  );
}

function UploadPanel() {
  const [url, setUrl] = useState("");
  const [method, setMethod] = useState<UploadMethod>("PUT");
  const [format, setFormat] = useState<ReportFormat>("json");
  const [redact, setRedact] = useState(true);
  return (
    <Panel title="Send report to cloud storage / webhook">
      <p className="muted">
        Paste a <strong>pre-signed upload URL</strong> (no cloud credentials are stored here). Use PUT for an AWS S3
        presigned URL, an Azure Blob SAS URL or a Google Cloud Storage signed URL; use POST for a webhook (your
        SIEM, an incident-response mailbox or Slack workflow). Only https:// is allowed. The README shows how to
        create these URLs.
      </p>
      <div className="stack">
        <input aria-label="Upload URL" placeholder="https://bucket.s3.amazonaws.com/report.json?X-Amz-Signature=…" value={url} onChange={(e) => setUrl(e.target.value)} />
        <div className="inline-form">
          <select aria-label="HTTP method" value={method} onChange={(e) => setMethod(e.target.value as UploadMethod)}>
            <option value="PUT">PUT (S3 / Azure / GCS)</option>
            <option value="POST">POST (webhook)</option>
          </select>
          <FormatSelect value={format} onChange={setFormat} />
          <Toggle label="Redact" checked={redact} onChange={setRedact} />
          <ActionButton action={{
            label: "Upload",
            confirm: `Send the ${redact ? "redacted" : "UNREDACTED"} report to ${safeHost(url)}?`,
            run: () => reportApi.upload(url.trim(), method, format, redact),
          }} />
        </div>
      </div>
    </Panel>
  );
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "this URL";
  }
}
