import { useState, type FormEvent } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export interface UserProfile {
  username: string;
  role: "SOC_ADMIN" | "SOC_ANALYST";
  disabled?: boolean;
}

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (token: string, user: UserProfile) => void;
}

export function LoginModal({ isOpen, onClose, onLoginSuccess }: LoginModalProps) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("AdminSecretPass123!");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

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
        throw new Error(errData.detail || "Authentication failed. Invalid credentials.");
      }

      const data = await res.json();
      sessionStorage.setItem("threatlens_token", data.access_token);
      sessionStorage.setItem("threatlens_user", JSON.stringify(data.user));
      localStorage.setItem("threatlens_token", data.access_token);
      localStorage.setItem("threatlens_user", JSON.stringify(data.user));

      onLoginSuccess(data.access_token, data.user);
      onClose();
    } catch (err: any) {
      setError(err.message || "Login failed");
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-md rounded-xl border border-zinc-800 bg-[#0c101c] p-6 shadow-2xl space-y-5">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
          <div className="flex items-center space-x-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              🛡️
            </div>
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-zinc-100 font-sans">
                SOC Enclave Authentication
              </h2>
              <p className="text-[11px] font-mono text-zinc-400">
                Authenticate for RBAC Permissions
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-zinc-200 text-sm font-mono px-2 py-1"
          >
            ✕
          </button>
        </div>

        {/* Quick Fill Presets */}
        <div className="space-y-1.5 bg-zinc-900/60 p-3 rounded-lg border border-zinc-800/80">
          <p className="text-[10px] font-mono uppercase text-zinc-400 font-semibold">
            Quick-Fill Credentials (RBAC Presets):
          </p>
          <div className="flex space-x-2">
            <Button
              type="button"
              variant="subtle"
              size="sm"
              onClick={() => fillCredentials("admin")}
              className="text-[11px] font-mono bg-rose-500/10 border-rose-500/30 text-rose-300 hover:bg-rose-500/20 flex-1"
            >
              SOC Admin (admin)
            </Button>
            <Button
              type="button"
              variant="subtle"
              size="sm"
              onClick={() => fillCredentials("analyst")}
              className="text-[11px] font-mono bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20 flex-1"
            >
              SOC Analyst (analyst)
            </Button>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="p-3 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs font-mono">
            ⚠️ {error}
          </div>
        )}

        {/* Form Inputs */}
        <form onSubmit={handleSubmit} className="space-y-4 font-mono">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              USERNAME
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900/90 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
              placeholder="e.g. admin or analyst"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              PASSWORD
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900/90 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-500 focus:border-emerald-500 focus:outline-none"
              placeholder="••••••••••••"
            />
          </div>

          {/* User Role Capabilities Preview */}
          <div className="flex items-center justify-between text-[11px] text-zinc-400 border-t border-zinc-800/80 pt-3">
            <span>Target Role:</span>
            <Badge
              variant="outline"
              className={
                username === "admin"
                  ? "border-rose-500/30 bg-rose-500/10 text-rose-400 font-mono"
                  : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-mono"
              }
            >
              {username === "admin" ? "SOC_ADMIN (Full Access)" : "SOC_ANALYST (Monitoring)"}
            </Badge>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end space-x-2 pt-2">
            <Button
              type="button"
              variant="subtle"
              size="sm"
              onClick={onClose}
              className="font-mono text-xs"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={loading}
              className="font-mono text-xs bg-emerald-500 text-zinc-950 font-bold hover:bg-emerald-400 px-4"
            >
              {loading ? "AUTHENTICATING..." : "SIGN IN TO SOC"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
