/**
 * ThreatLens Resilient WebSocket Consumer Hook
 * ============================================
 * Manages live WebSocket telemetry ingestion, exponential backoff reconnection,
 * rolling memory buffers and exponential reconnect handling.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { ThreatAlertSchema } from "@/types/threat";

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

  const defaultUrl = (() => {
    if (typeof window === "undefined") return "ws://localhost:8000/ws/threats";
    const loc = window.location;
    const protocol = loc.protocol === "https:" ? "wss:" : "ws:";
    // If running with Vite proxy or direct port
    return `${protocol}//${loc.hostname}:8000/ws/threats`;
  })();

  const targetUrl = url || defaultUrl;

  const connect = useCallback(() => {
    if (socketRef.current?.readyState === WebSocket.OPEN) return;

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
        setStatus("DISCONNECTED");
        socketRef.current = null;

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
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [connect]);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  return {
    alerts,
    status,
    clearAlerts,
    totalReceived,
  };
}
