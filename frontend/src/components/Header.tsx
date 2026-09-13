import { useState } from "react";
import { ConnectionStatus } from "@/hooks/useThreatSocket";
import {
  PlayIcon as Play,
  PauseIcon as Pause,
  Calendar01Icon as Calendar,
  UserIcon as User,
} from "hugeicons-react";

interface HeaderProps {
  status: ConnectionStatus;
  isPaused: boolean;
  onTogglePause: () => void;
  totalAlerts: number;
}

export function Header({ status, isPaused, onTogglePause }: HeaderProps) {
  const [timeframe, setTimeframe] = useState("Last 24 Hours");

  return (
    <header className="h-16 bg-[#090d16] border-b border-zinc-800/60 px-4 md:px-6 flex items-center justify-between select-none z-10 shrink-0">
      {/* Left: Passive Mode Pill */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2 bg-emerald-950/40 border border-emerald-500/30 px-3 py-1.5 rounded-full">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
          </span>
          <span className="text-xs font-mono font-bold tracking-wide text-emerald-400 uppercase">
            Passive Mode - Zero Egress ({status})
          </span>
        </div>
        <span className="hidden xl:inline text-[11px] font-mono text-zinc-400 border-l border-zinc-800 pl-3">
          Monitoring only • Read-only • No outbound connections
        </span>
      </div>

      {/* Center: Brand Title */}
      <div className="text-center">
        <h1 className="text-lg font-bold tracking-wider text-zinc-100 uppercase font-sans">
          Threat Lens
        </h1>
        <p className="text-[10px] font-mono tracking-widest text-zinc-400 uppercase">
          See Threats. Protect What Matters.
        </p>
      </div>

      {/* Right Controls: Timeframe, Stream Pause, User Profile */}
      <div className="flex items-center space-x-3">
        {/* Stream Pause / Live Controls */}
        <button
          onClick={onTogglePause}
          className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-mono border transition-all ${
            isPaused
              ? "bg-amber-500/10 border-amber-500/30 text-amber-400"
              : "bg-zinc-900 border-zinc-800 text-zinc-300 hover:border-zinc-700"
          }`}
        >
          {isPaused ? <Play className="h-3.5 w-3.5 text-amber-400" /> : <Pause className="h-3.5 w-3.5 text-zinc-400" />}
          <span>{isPaused ? "RESUMED" : "LIVE"}</span>
        </button>

        {/* Timeframe Dropdown */}
        <div className="relative hidden sm:flex items-center space-x-1.5 bg-zinc-900/80 border border-zinc-800 px-3 py-1.5 rounded-md text-xs font-mono text-zinc-300">
          <Calendar className="h-3.5 w-3.5 text-zinc-400" />
          <select
            value={timeframe}
            onChange={(e) => setTimeframe(e.target.value)}
            className="bg-transparent focus:outline-none cursor-pointer pr-1 text-zinc-200"
          >
            <option value="Last 24 Hours" className="bg-zinc-900">Last 24 Hours</option>
            <option value="Last 1 Hour" className="bg-zinc-900">Last 1 Hour</option>
            <option value="Live Stream" className="bg-zinc-900">Live Stream</option>
          </select>
        </div>

        {/* Analyst Profile */}
        <div className="flex items-center space-x-2.5 bg-zinc-900/80 border border-zinc-800 px-2.5 py-1 rounded-md">
          <div className="h-6 w-6 rounded-full bg-zinc-800 flex items-center justify-center text-zinc-300">
            <User className="h-3.5 w-3.5" />
          </div>
          <div className="hidden lg:block text-left">
            <p className="text-xs font-medium text-zinc-200 leading-tight">Analyst</p>
            <p className="text-[9px] font-mono text-zinc-400 leading-none">SOC Viewer</p>
          </div>
        </div>
      </div>
    </header>
  );
}
