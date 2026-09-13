import {
  Database01Icon as Server,
  Shield01Icon as Diode,
  Activity01Icon as Monitor,
} from "hugeicons-react";

export function NetworkTopology() {
  return (
    <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-4 flex flex-col justify-between h-full">
      {/* Title Header */}
      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2.5 mb-3">
        <div>
          <h3 className="text-sm font-semibold text-zinc-100 font-sans flex items-center space-x-2">
            <span>Network Topology</span>
            <span className="text-xs font-mono text-zinc-400 font-normal">(Passive Monitoring)</span>
          </h3>
          <p className="text-[10px] font-mono text-zinc-400 mt-0.5">
            One-way, isolated network • Passive monitoring
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="h-2 w-2 rounded-full bg-emerald-500"></span>
          <span className="text-[10px] font-mono text-emerald-400">Zero Transmit Active</span>
        </div>
      </div>

      {/* Visual Diode Diagram */}
      <div className="relative py-4 my-auto">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
          {/* Protected Zone */}
          <div className="border border-emerald-500/30 bg-emerald-950/20 rounded-lg p-3 text-center relative overflow-hidden group hover:border-emerald-500/50 transition-colors">
            <div className="absolute top-0 right-0 bg-emerald-500/10 px-2 py-0.5 rounded-bl text-[9px] font-mono text-emerald-400 border-l border-b border-emerald-500/20">
              Protected Zone
            </div>
            <div className="my-2 flex justify-center text-emerald-400">
              <Server className="h-8 w-8" />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 font-mono">Internal Network</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-0.5">(OT / IT / Sensitive)</p>
            <div className="mt-2 flex justify-center space-x-1.5 text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
            </div>
          </div>

          {/* One-Way Data Diode */}
          <div className="border border-zinc-800 bg-zinc-900/60 rounded-lg p-3 text-center relative flex flex-col items-center justify-center">
            <div className="mb-1 text-zinc-400">
              <Diode className="h-7 w-7 text-zinc-300" />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 font-mono">One-Way Data Diode</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-0.5">Data out only (no egress)</p>

            {/* Animated Data Arrow */}
            <div className="w-full flex items-center justify-center space-x-1 mt-2 text-emerald-400 font-mono text-xs">
              <span>➔</span>
              <span className="h-1 w-12 bg-gradient-to-r from-emerald-500/80 to-emerald-400 rounded-full animate-pulse"></span>
              <span>➔</span>
            </div>
          </div>

          {/* Monitoring Zone */}
          <div className="border border-zinc-800 bg-zinc-900/40 rounded-lg p-3 text-center relative overflow-hidden group hover:border-zinc-700 transition-colors">
            <div className="absolute top-0 right-0 bg-zinc-800 px-2 py-0.5 rounded-bl text-[9px] font-mono text-zinc-300">
              Monitoring Zone
            </div>
            <div className="my-2 flex justify-center text-zinc-300">
              <Monitor className="h-8 w-8" />
            </div>
            <h4 className="text-xs font-bold text-zinc-200 font-mono">ThreatLens Sensor</h4>
            <p className="text-[10px] text-zinc-400 font-mono mt-0.5">(Analysis Only)</p>
            <div className="mt-2 flex justify-center space-x-1.5 text-zinc-400">
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-500"></span>
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-500"></span>
              <span className="h-1.5 w-1.5 rounded-full bg-zinc-500"></span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Pipeline Trail */}
      <div className="border-t border-zinc-800/60 pt-2.5 flex items-center justify-between text-[10px] font-mono text-zinc-400">
        <span>Network TAP ➔ Diode ➔ Monitoring</span>
        <span className="text-emerald-400">No Return Path Possible</span>
      </div>
    </div>
  );
}
