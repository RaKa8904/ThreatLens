import { useState } from "react";
import {
  Home01Icon as Home,
  Analytics01Icon as Activity,
  Shield01Icon as Shield,
  Share01Icon as Network,
  Database01Icon as Database,
  File01Icon as FileText,
  Settings01Icon as Settings,
  InformationCircleIcon as Info,
} from "hugeicons-react";

export function Sidebar() {
  const [activeTab, setActiveTab] = useState("dashboard");

  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: Home },
    { id: "analytics", label: "Analytics", icon: Activity },
    { id: "alerts", label: "Alerts", icon: Shield },
    { id: "topology", label: "Topology", icon: Network },
    { id: "database", label: "Database", icon: Database },
    { id: "reports", label: "Reports", icon: FileText },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside className="w-14 bg-[#090d16] border-r border-zinc-800/60 flex flex-col items-center py-3 select-none shrink-0 z-20">
      {/* Brand Icon */}
      <div className="mb-6 h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
        <Shield className="h-5 w-5" />
      </div>

      {/* Main Nav Items */}
      <nav className="flex-1 space-y-2.5 w-full px-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              title={item.label}
              className={`w-full h-9 rounded-md flex items-center justify-center transition-all ${
                isActive
                  ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 shadow-sm"
                  : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
              }`}
            >
              <Icon className="h-4.5 w-4.5" />
            </button>
          );
        })}
      </nav>

      {/* Info Icon at Bottom */}
      <div className="w-full px-2 pt-2 border-t border-zinc-800/60">
        <button
          title="System Info"
          className="w-full h-9 rounded-md flex items-center justify-center text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors"
        >
          <Info className="h-4.5 w-4.5" />
        </button>
      </div>
    </aside>
  );
}
