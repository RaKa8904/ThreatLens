/**
 * ThreatLens Resilient WebSocket Consumer Hook
 * ============================================
 * Manages live WebSocket telemetry ingestion, exponential backoff reconnection,
 * rolling memory buffers and exponential reconnect handling.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { AlertStatusEnum, ThreatAlertSchema, getAlertIdentity } from "@/types/threat";

export type ConnectionStatus = "CONNECTING" | "CONNECTED" | "DISCONNECTED";

const MAX_ALERTS_BUFFER = 200;
const INITIAL_BACKOFF_MS = 1000;
const MAX_BACKOFF_MS = 15000;

export function useThreatSocket(url?: string) {
  const [alerts, setAlerts] = useState<ThreatAlertSchema[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("CONNECTING");
  const [sessionReceived, setSessionReceived] = useState<number>(() => {
    try {
      const stored = sessionStorage.getItem("threatlens_session_received");
      return stored ? parseInt(stored, 10) : 0;
    } catch {
      return 0;
    }
  });
  const [archiveTotal, setArchiveTotal] = useState<number>(0);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const backoffRef = useRef<number>(INITIAL_BACKOFF_MS);
  const closingRef = useRef(false);

  const defaultUrl = (() => {
    if (typeof window === "undefined") return "ws://localhost:8000/ws/threats";
    const loc = window.location;
    const protocol = loc.protocol === "https:" ? "wss:" : "ws:";
    const token = sessionStorage.getItem("threatlens_token") || localStorage.getItem("threatlens_token");
    const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : "";
    return `${protocol}//${loc.hostname}:8000/ws/threats${tokenQuery}`;
  })();

  const targetUrl = url || defaultUrl;

  const connect = useCallback(() => {
    const existing = socketRef.current;
    if (existing && (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)) {
      return;
    }

    closingRef.current = false;
    setStatus("CONNECTING");
    try {
      const ws = new WebSocket(targetUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setStatus("CONNECTED");
        backoffRef.current = INITIAL_BACKOFF_MS;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "heartbeat" || data.type === "pong") return;

          setSessionReceived((prev) => {
            const next = prev + 1;
            try { sessionStorage.setItem("threatlens_session_received", next.toString()); } catch {}
            return next;
          });
          setArchiveTotal((prev) => prev + 1);

          setAlerts((prevAlerts) => {
            const identity = getAlertIdentity(data as ThreatAlertSchema);
            if (prevAlerts.some((a) => getAlertIdentity(a) === identity)) {
              return prevAlerts;
            }
            const updated = [data as ThreatAlertSchema, ...prevAlerts];
            return updated.slice(0, MAX_ALERTS_BUFFER);
          });
        } catch {
          // Non-JSON telemetry packet or raw log
        }
      };

      ws.onerror = () => {
        ws.close();
      };

      ws.onclose = () => {
        if (socketRef.current !== ws) return;
        socketRef.current = null;
        setStatus("DISCONNECTED");
        if (closingRef.current) return;

        const timeout = Math.min(backoffRef.current, MAX_BACKOFF_MS);
        backoffRef.current = Math.floor(backoffRef.current * 1.5);
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, timeout);
      };
    } catch {
      setStatus("DISCONNECTED");
    }
  }, [targetUrl]);

  useEffect(() => {
    let active = true;

    async function hydrateInitialState() {
      try {
        const [alertsRes, metricsRes] = await Promise.all([
          fetch("/api/alerts?limit=50"),
          fetch("/api/metrics/throughput"),
        ]);

        if (active && alertsRes.ok) {
          const fetchedAlerts: ThreatAlertSchema[] = await alertsRes.json();
          setAlerts((prev) => {
            if (prev.length === 0) return fetchedAlerts;
            const existingIds = new Set(prev.map((a) => getAlertIdentity(a)));
            const deduplicatedFetched = fetchedAlerts.filter(
              (a) => !existingIds.has(getAlertIdentity(a))
            );
            return [...prev, ...deduplicatedFetched].slice(0, MAX_ALERTS_BUFFER);
          });
        }

        if (active && metricsRes.ok) {
          const metrics = await metricsRes.json();
          if (typeof metrics.total_alerts === "number") {
            setArchiveTotal(metrics.total_alerts);
          }
        }
      } catch {
        // Hydration fallback
      }
    }

    hydrateInitialState();
    connect();

    return () => {
      active = false;
      closingRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  const updateAlertStatus = useCallback((flowId: string, status: AlertStatusEnum) => {
    setAlerts((current) => current.map((alert) => alert.flow_id === flowId ? { ...alert, status } : alert));
  }, []);

  const formattedArchiveTotal = archiveTotal >= 1000
    ? `${(archiveTotal / 1000).toFixed(1)}k`
    : `${archiveTotal}`;

  return {
    alerts,
    status,
    clearAlerts,
    updateAlertStatus,
    totalReceived: sessionReceived || archiveTotal,
    sessionReceived,
    archiveTotal,
    formattedArchiveTotal,
  };
}
