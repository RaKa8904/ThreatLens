export type DevStateOverride =
  | "loading"
  | "empty"
  | "filtered-empty"
  | "offline"
  | "stale"
  | "archive-error"
  | "session-expired"
  | null;

export function getDevStateOverride(): DevStateOverride {
  if (!import.meta.env.DEV || typeof window === "undefined") return null;
  const param = new URLSearchParams(window.location.search).get("state");
  if (
    param === "loading" ||
    param === "empty" ||
    param === "filtered-empty" ||
    param === "offline" ||
    param === "stale" ||
    param === "archive-error" ||
    param === "session-expired"
  ) {
    return param;
  }
  return null;
}
