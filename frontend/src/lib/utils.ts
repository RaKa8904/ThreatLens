import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merges conditional class names, resolving conflicting Tailwind utilities. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Renders a timestamp as an ISO 8601 UTC string with millisecond precision,
 * e.g. "2026-09-14T12:34:56.789Z". Returns "N/A" for unparseable input.
 */
export function formatTimestamp(value: string | number | Date | null | undefined): string {
  if (value === null || value === undefined || value === "") return "N/A";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "N/A";
  return date.toISOString();
}
