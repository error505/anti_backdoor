const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"];

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${BYTE_UNITS[unit]}`;
}

export const formatRate = (bytesPerSecond: number) => (bytesPerSecond > 0 ? `${formatBytes(bytesPerSecond)}/s` : "—");

export const formatEpoch = (seconds: number | null | undefined) =>
  seconds ? new Date(seconds * 1000).toLocaleString() : "—";

export const formatTime = (seconds: number) => new Date(seconds * 1000).toLocaleTimeString();

export const formatIso = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "—");

export function formatEndpoint(host: string | null, ip: string | null, port: number | null): string {
  if (!ip) return "—";
  const address = ip.includes(":") ? `[${ip}]` : ip;
  return `${host ?? address}${port !== null ? `:${port}` : ""}`;
}

export function matchesQuery(query: string, ...fields: (string | number | null | undefined)[]): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return fields.some((field) => field !== null && field !== undefined && String(field).toLowerCase().includes(needle));
}
