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
  const [totalReceived, setTotalReceived] = useState<number>(0);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const backoffRef = useRef<number>(INITIAL_BACKOFF_MS);
  // Set while the effect cleanup is closing the socket on purpose; prevents
  // the onclose handler from scheduling a reconnect (StrictMode unmount,
  // dependency change) and racing a second connection.
  const closingRef = useRef(false);

  const defaultUrl = (() => {
    if (typeof window === "undefined") return "ws://localhost:8000/ws/threats";
    const loc = window.location;
    const protocol = loc.protocol === "https:" ? "wss:" : "ws:";
    // If running with Vite proxy or direct port
    return `${protocol}//${loc.hostname}:8000/ws/threats`;
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
          // Filter out heartbeat ping/pong messages
          if (data.type === "heartbeat" || data.type === "pong") return;

          setTotalReceived((prev) => prev + 1);

          setAlerts((prevAlerts) => {
            const identity = getAlertIdentity(data as ThreatAlertSchema);
            // Exact logical duplicate (e.g. a second live socket delivering the
            // same broadcast, or a history replay overlapping the live stream):
            // keep the existing row. Distinct alerts never share an identity.
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
        // A stale socket (already replaced by a newer connection) must not
        // clobber the live one or schedule a parallel reconnect.
        if (socketRef.current !== ws) return;
        socketRef.current = null;
        setStatus("DISCONNECTED");
        if (closingRef.current) return;

        // Schedule exponential backoff reconnect
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
    connect();

    return () => {
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

  return {
    alerts,
    status,
    clearAlerts,
    updateAlertStatus,
    totalReceived,
  };
}
