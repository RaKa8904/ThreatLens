import { useEffect, useRef, useState } from "react";
import {
  Shield01Icon as ShieldSecurity,
  Activity01Icon as Activity01,
  Settings01Icon as Settings01,
  PlayIcon as Play01,
  User02Icon as UserIcon,
  ArrowDown01Icon as ChevronDown,
  Logout01Icon as LogoutIcon,
} from "hugeicons-react";
import { Badge } from "@/components/ui/badge";
import { ConnectionStatus } from "@/hooks/useThreatSocket";
import { UserProfile } from "@/components/LoginPage";

interface NavbarProps {
  status: ConnectionStatus;
  totalAlerts: number;
  sessionReceived?: number;
  formattedArchiveTotal?: string;
  user?: UserProfile | null;
  onLogout?: () => void;
  onOpenConfig?: () => void;
  onOpenReplay?: () => void;
}

export function Navbar({
  status,
  totalAlerts,
  sessionReceived = 0,
  formattedArchiveTotal,
  user,
  onLogout,
  onOpenConfig,
  onOpenReplay,
}: NavbarProps) {
  const [utcTime, setUtcTime] = useState<string>("");
  const [menuOpen, setMenuOpen] = useState<boolean>(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().substring(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Close menu on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const getStatusBadge = () => {
    switch (status) {
      case "CONNECTED":
        return (
          <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 gap-1.5 px-2.5 py-1 font-mono text-xs select-none">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            STREAM LIVE
          </Badge>
        );
      case "CONNECTING":
        return (
          <Badge variant="outline" className="border-amber-500/30 bg-amber-500/10 text-amber-400 gap-1.5 px-2.5 py-1 font-mono text-xs select-none">
            <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
            CONNECTING...
          </Badge>
        );
      case "DISCONNECTED":
        return (
          <Badge variant="outline" className="border-rose-500/30 bg-rose-500/10 text-rose-400 gap-1.5 px-2.5 py-1 font-mono text-xs select-none">
            <span className="h-2 w-2 rounded-full bg-rose-500"></span>
            OFFLINE (RETRYING)
          </Badge>
        );
    }
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-zinc-800/80 bg-[#090d16]/95 backdrop-blur-xl px-4 md:px-6 py-2.5 select-none">
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

          <div
            title={`ClickHouse Total DB Archive: ${formattedArchiveTotal || totalAlerts} records`}
            className="flex items-center space-x-1.5 text-xs text-zinc-400 font-mono bg-zinc-900/80 border border-zinc-800 px-3 py-1 rounded-md cursor-help"
          >
            <Activity01 className="h-3.5 w-3.5 text-emerald-400" />
            <span>LIVE SESSION:</span>
            <span className="text-emerald-300 font-bold tabular-nums">
              {sessionReceived > 0 ? sessionReceived : totalAlerts}
            </span>
            {formattedArchiveTotal && (
              <span className="text-[10px] text-zinc-400 border-l border-zinc-700 pl-1.5 ml-1">
                DB: {formattedArchiveTotal}
              </span>
            )}
          </div>
        </div>

        {/* Right: User Dropdown Menu & Clock */}
        <div className="flex items-center space-x-3">
          {/* Compact User Profile Menu */}
          {user && (
            <div className="relative" ref={menuRef}>
              <button
                onClick={() => setMenuOpen(!menuOpen)}
                className="flex items-center space-x-2 bg-zinc-900/90 hover:bg-zinc-800/90 border border-zinc-800 hover:border-zinc-700 px-3 py-1.5 rounded-lg text-xs font-mono transition-all"
              >
                <UserIcon className="h-3.5 w-3.5 text-emerald-400" />
                <span className="text-zinc-200 font-medium">{user.username}</span>
                <Badge
                  variant="outline"
                  className={
                    user.role === "SOC_ADMIN"
                      ? "border-rose-500/30 bg-rose-500/10 text-rose-300 text-[9px] px-1.5 py-0"
                      : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300 text-[9px] px-1.5 py-0"
                  }
                >
                  {user.role}
                </Badge>
                <ChevronDown className="h-3.5 w-3.5 text-zinc-400" />
              </button>

              {/* Dropdown Menu Box */}
              {menuOpen && (
                <div className="absolute right-0 mt-2 w-52 rounded-xl border border-zinc-800 bg-[#0c101c] p-1.5 shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100 font-mono">
                  <div className="px-3 py-2 border-b border-zinc-800/80">
                    <p className="text-[10px] text-zinc-400 font-semibold uppercase">Logged in as</p>
                    <p className="text-xs font-bold text-zinc-100">{user.username}</p>
                  </div>

                  <div className="py-1 space-y-1">
                    {onOpenReplay && (
                      <button
                        onClick={() => {
                          setMenuOpen(false);
                          onOpenReplay();
                        }}
                        className="w-full flex items-center space-x-2 px-3 py-2 text-xs text-zinc-300 hover:text-emerald-300 hover:bg-emerald-500/10 rounded-md transition-colors text-left"
                      >
                        <Play01 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>Replay PCAP Capture</span>
                      </button>
                    )}

                    {onOpenConfig && (
                      <button
                        onClick={() => {
                          setMenuOpen(false);
                          onOpenConfig();
                        }}
                        className="w-full flex items-center space-x-2 px-3 py-2 text-xs text-zinc-300 hover:text-emerald-300 hover:bg-emerald-500/10 rounded-md transition-colors text-left"
                      >
                        <Settings01 className="h-3.5 w-3.5 text-zinc-400" />
                        <span>Rules &amp; Suppressions</span>
                      </button>
                    )}
                  </div>

                  {onLogout && (
                    <div className="pt-1 border-t border-zinc-800/80">
                      <button
                        onClick={() => {
                          setMenuOpen(false);
                          onLogout();
                        }}
                        className="w-full flex items-center space-x-2 px-3 py-2 text-xs text-rose-300 hover:bg-rose-500/15 rounded-md transition-colors text-left font-bold"
                      >
                        <LogoutIcon className="h-3.5 w-3.5 text-rose-400" />
                        <span>Sign Out of SOC</span>
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Real-time UTC Clock */}
          <div className="hidden sm:flex items-center h-8 px-3 rounded-md bg-zinc-900/90 border border-zinc-800 text-zinc-300 font-mono text-xs tracking-wider">
            {utcTime || "00:00:00 UTC"}
          </div>
        </div>
      </div>
    </header>
  );
}
