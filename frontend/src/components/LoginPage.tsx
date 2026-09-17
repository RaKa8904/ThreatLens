import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield01Icon as ShieldSecurity,
  LockKeyIcon as LockKey,
  User02Icon as UserIcon,
  CheckmarkCircle02Icon as CheckCircle,
} from "hugeicons-react";

export interface UserProfile {
  username: string;
  role: "SOC_ADMIN" | "SOC_ANALYST";
  disabled?: boolean;
}

interface LoginPageProps {
  onLoginSuccess: (token: string, user: UserProfile) => void;
}

export function LoginPage({ onLoginSuccess }: LoginPageProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("AdminSecretPass123!");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || "Authentication failed. Invalid SOC credentials.");
      }

      const data = await res.json();
      localStorage.setItem("threatlens_token", data.access_token);
      localStorage.setItem("threatlens_user", JSON.stringify(data.user));

      onLoginSuccess(data.access_token, data.user);
    } catch (err: any) {
      setError(err.message || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  const fillCredentials = (userRole: "admin" | "analyst") => {
    if (userRole === "admin") {
      setUsername("admin");
      setPassword("AdminSecretPass123!");
    } else {
      setUsername("analyst");
      setPassword("AnalystPass123!");
    }
  };

  return (
    <div className="min-h-screen w-full bg-[#050811] text-zinc-100 flex flex-col justify-between font-sans selection:bg-emerald-500/20 selection:text-emerald-300 relative overflow-hidden select-none">
      {/* Background Cyber Grid Glow & Ambient Lighting */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_20%,rgba(16,185,129,0.07)_0%,transparent_50%)] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_80%_80%,rgba(244,63,94,0.04)_0%,transparent_50%)] pointer-events-none" />

      {/* Header Bar */}
      <header className="w-full border-b border-zinc-800/60 bg-[#070b16]/80 backdrop-blur-md px-6 py-4 flex items-center justify-between z-10">
        <div className="flex items-center space-x-3">
          <div className="flex items-center justify-center h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shadow-sm">
            <ShieldSecurity className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-sm font-bold tracking-wider text-zinc-100 uppercase font-sans">
                ThreatLens
              </span>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                SOC ENCLAVE
              </span>
            </div>
            <p className="text-[10px] text-zinc-400 font-mono">
              ZERO-TRANSMIT PASSIVE NETWORK FORENSICS
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>ENCLAVE STATUS: PROTECTED</span>
        </div>
      </header>

      {/* Main Login Viewport */}
      <main className="flex-1 flex items-center justify-center p-4 z-10">
        <div className="w-full max-w-md space-y-6">
          {/* Card Container */}
          <div className="rounded-2xl border border-zinc-800/90 bg-[#090e1a]/90 backdrop-blur-2xl p-8 shadow-2xl space-y-6">
            {/* Title & Badge Header */}
            <div className="text-center space-y-2">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 shadow-inner">
                <LockKey className="h-6 w-6" />
              </div>
              <h1 className="text-lg font-bold uppercase tracking-wider text-zinc-100 font-sans">
                Authentication Required
              </h1>
              <p className="text-xs font-mono text-zinc-400">
                Sign in to access the SOC telemetry dashboard &amp; forensic tools
              </p>
            </div>

            {/* Quick Fill RBAC Role Selector */}
            <div className="space-y-2 bg-zinc-900/60 p-3.5 rounded-xl border border-zinc-800/80">
              <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 font-semibold uppercase">
                <span>Select Role Credential Preset:</span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => fillCredentials("admin")}
                  className={`flex flex-col items-center justify-center p-2.5 rounded-lg border font-mono transition-all text-xs ${
                    username === "admin"
                      ? "border-rose-500/50 bg-rose-500/15 text-rose-300 shadow-sm"
                      : "border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
                  }`}
                >
                  <span className="font-bold flex items-center gap-1">
                    {username === "admin" && <CheckCircle className="h-3 w-3 text-rose-400" />}
                    SOC Admin
                  </span>
                  <span className="text-[10px] text-zinc-500">Full Control Access</span>
                </button>

                <button
                  type="button"
                  onClick={() => fillCredentials("analyst")}
                  className={`flex flex-col items-center justify-center p-2.5 rounded-lg border font-mono transition-all text-xs ${
                    username === "analyst"
                      ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-300 shadow-sm"
                      : "border-zinc-800 bg-zinc-900/40 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200"
                  }`}
                >
                  <span className="font-bold flex items-center gap-1">
                    {username === "analyst" && <CheckCircle className="h-3 w-3 text-emerald-400" />}
                    SOC Analyst
                  </span>
                  <span className="text-[10px] text-zinc-500">Monitoring &amp; Notes</span>
                </button>
              </div>
            </div>

            {/* Error Notification */}
            {error && (
              <div className="p-3 rounded-lg border border-rose-500/40 bg-rose-500/10 text-rose-300 text-xs font-mono animate-in fade-in">
                ⚠️ {error}
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4 font-mono">
              <div>
                <label className="block text-xs font-semibold text-zinc-300 mb-1.5 uppercase">
                  Username
                </label>
                <div className="relative">
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full rounded-lg border border-zinc-700/80 bg-zinc-900/90 pl-9 pr-3 py-2.5 text-xs text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none transition-colors"
                    placeholder="Enter username"
                  />
                  <UserIcon className="absolute left-3 top-3 h-3.5 w-3.5 text-zinc-500" />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-zinc-300 mb-1.5 uppercase">
                  Password
                </label>
                <div className="relative">
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full rounded-lg border border-zinc-700/80 bg-zinc-900/90 pl-9 pr-3 py-2.5 text-xs text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none transition-colors"
                    placeholder="••••••••••••"
                  />
                  <LockKey className="absolute left-3 top-3 h-3.5 w-3.5 text-zinc-500" />
                </div>
              </div>

              {/* Active Role Capabilities Indicator */}
              <div className="flex items-center justify-between text-[11px] text-zinc-400 pt-1">
                <span>Active Role Permissions:</span>
                <Badge
                  variant="outline"
                  className={
                    username === "admin"
                      ? "border-rose-500/30 bg-rose-500/10 text-rose-400 font-mono text-[10px]"
                      : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-mono text-[10px]"
                  }
                >
                  {username === "admin" ? "SOC_ADMIN (Full Admin)" : "SOC_ANALYST (Read-Only)"}
                </Badge>
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                disabled={loading}
                className="w-full font-mono text-xs h-10 bg-emerald-500 text-zinc-950 font-bold hover:bg-emerald-400 shadow-md transition-all uppercase tracking-wider"
              >
                {loading ? "AUTHENTICATING ENCLAVE..." : "SIGN IN TO DASHBOARD →"}
              </Button>
            </form>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="w-full border-t border-zinc-800/60 bg-[#070b16]/80 px-6 py-3 text-center text-[10px] font-mono text-zinc-400 z-10">
        THREATLENS SOC ENCLAVE v1.0.0 — SECURE ZERO-TRANSMIT PASSIVE NETWORK DETECTOR
      </footer>
    </div>
  );
}
