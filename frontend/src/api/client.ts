const TOKEN_KEY = "backdoor-watch-token";

// The backend opens the UI with #token=…; keep it for this tab only and
// remove it from the address bar so it does not end up in history or screenshots.
function readSessionToken(): string {
  const match = window.location.hash.match(/token=([^&]+)/);
  try {
    if (match) {
      sessionStorage.setItem(TOKEN_KEY, match[1]);
    }
    const stored = sessionStorage.getItem(TOKEN_KEY);
    if (match) history.replaceState(null, "", window.location.pathname + window.location.search);
    return stored ?? match?.[1] ?? "";
  } catch {
    return match?.[1] ?? "";
  }
}

const sessionToken = readSessionToken();

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      "X-Auth-Token": sessionToken,
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new ApiError(payload.detail ?? response.statusText, response.status);
  }
  return response.json() as Promise<T>;
}

export const http = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body: unknown = {}) => request<T>("POST", path, body),
};

/** Downloads need the auth header, so a plain <a href> can't be used: fetch the blob and save it. */
export async function downloadFile(path: string): Promise<string> {
  const response = await fetch(path, { headers: { "X-Auth-Token": sessionToken } });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new ApiError(payload.detail ?? response.statusText, response.status);
  }
  const filename = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] ?? "report";
  const url = URL.createObjectURL(await response.blob());
  const link = Object.assign(document.createElement("a"), { href: url, download: filename });
  link.click();
  URL.revokeObjectURL(url);
  return filename;
}

export const hasSessionToken = () => sessionToken !== "";
