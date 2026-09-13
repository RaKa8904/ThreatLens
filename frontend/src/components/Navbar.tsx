import { useEffect, useState } from "react";
import {
  Shield01Icon as ShieldSecurity,
  Activity01Icon as Activity01,
} from "hugeicons-react";
import { Badge } from "@/components/ui/badge";
import { ConnectionStatus } from "@/hooks/useThreatSocket";

interface NavbarProps {
  status: ConnectionStatus;
  totalAlerts: number;
}

export function Navbar({
  status,
  totalAlerts,
}: NavbarProps) {
  const [utcTime, setUtcTime] = useState<string>("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().substring(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const getStatusBadge = () => {
    switch (status) {
      case "CONNECTED":
        return (
          <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 gap-1.5 px-2.5 py-1 font-mono text-xs">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            STREAM LIVE
          </Badge>
        );
      case "CONNECTING":
        return (
          <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-400 gap-1.5 px-2.5 py-1 font-mono text-xs">
            <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
            CONNECTING...
          </Badge>
        );
      case "DISCONNECTED":
        return (
          <Badge variant="outline" className="border-rose-500/30 bg-rose-500/10 text-rose-400 gap-1.5 px-2.5 py-1 font-mono text-xs">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span>
            OFFLINE (RETRYING)
          </Badge>
        );
    }
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-zinc-800/80 bg-[#090d16]/95 backdrop-blur-xl px-4 md:px-6 py-3 select-none">
      <div className="flex items-center justify-between">
        {/* Left: Brand & Enclave Status */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center h-8.5 w-8.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shadow-sm">
            <ShieldSecurity className="h-4.5 w-4.5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold tracking-wider text-zinc-100 uppercase font-sans">
                ThreatLens
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                PASSIVE SOC
              </span>
            </div>
            <p className="text-[10px] text-zinc-400 font-mono">
              ZERO-TRANSMIT TELEMETRY PIPELINE
            </p>
          </div>
        </div>

        {/* Center: System Status Pill */}
        <div className="hidden md:flex items-center space-x-3">
          {getStatusBadge()}

          <div className="flex items-center space-x-1.5 text-xs text-zinc-400 font-mono bg-zinc-900/80 border border-zinc-800 px-3 py-1 rounded-md">
            <Activity01 className="h-3.5 w-3.5 text-zinc-400" />
            <span>INGESTED:</span>
            <span className="text-zinc-200 font-semibold">{totalAlerts}</span>
          </div>
        </div>

        {/* Right: Controls & Real-Time Clock */}
        <div className="flex items-center space-x-3">
          {/* Real-time UTC Clock */}
          <div className="hidden sm:flex items-center h-8 px-3 rounded-md bg-zinc-900/90 border border-zinc-800 text-zinc-300 font-mono text-xs tracking-wider">
            {utcTime || "00:00:00 UTC"}
          </div>
        </div>
      </div>
    </header>
  );
}
