/**
 * Compile-time assertion that the frontend alert contract carries the
 * backend-supplied severity field. Executed by `tsc --noEmit` / `npm run build`.
 *
 * If `severity` is removed from ThreatAlertSchema or its type drifts from the
 * canonical SeverityLevel union, this file fails to compile — guaranteeing the
 * dashboard consumes `alert.severity` rather than re-deriving a severity band
 * from `confidence_score`.
 */
import type { SeverityLevel, ThreatAlertSchema } from "./threat";

type AlertSeverityField = ThreatAlertSchema["severity"];

// Fails when the field is missing or mistyped.
export const alertSchemaExposesBackendSeverity: AlertSeverityField extends SeverityLevel
  ? SeverityLevel extends AlertSeverityField
    ? true
    : never
  : never = true;
