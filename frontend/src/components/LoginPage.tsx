import { useState, useEffect, type FormEvent, type KeyboardEvent } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useMotionEnabled, motionTokens } from "@/lib/motion";
import { Button } from "@/components/ui/button";
import {
  Shield01Icon as ShieldSecurity,
  LockKeyIcon as LockKey,
  User02Icon as UserIcon,
  CheckmarkCircle02Icon as CheckCircle,
  ArrowRight01Icon as ArrowRight,
  ViewIcon,
  ViewOffSlashIcon,
  AlertCircleIcon as AlertCircle,
} from "hugeicons-react";

export interface UserProfile {
  username: string;
  role: "SOC_ADMIN" | "SOC_ANALYST";
  disabled?: boolean;
}

interface LoginPageProps {
  onLoginSuccess: (token: string, user: UserProfile) => void;
}

interface LogItem {
  id: number;
  text: string;
}

const mockLogTemplates = [
  "[eth0] IN 45.33.22.11:443 -> 192.168.1.100:54321 TCP FIN,ACK",
  "[eth0] IN 185.199.108.153:80 -> 192.168.1.101:49152 TCP SYN",
  "[core] BUFFER_SYNC 0x00A8F1 complete (t=12ms)",
  "[eth1] OUT 192.168.1.102:443 -> 8.8.8.8:53 UDP",
  "[eth0] IN 92.168.1.103:22 -> 104.21.44.31:443 TCP PSH,ACK",
  "[eth0] IN 172.16.0.5:443 -> 192.168.1.105:54321 TCP FIN",
  "[core] STREAM_ACTIVE: 45 flows/sec detected",
  "[eth0] IN 23.45.67.89:80 -> 192.168.1.101:49152 TCP SYN",
  "[eth1] OUT 192.168.1.102:443 -> 1.1.1.1:53 UDP",
  "[core] MEM_ALLOC 0x0A9922 (t=8ms)",
];

function CyberTopologyHero({ motionEnabled }: { motionEnabled: boolean }) {
  return (
    <div className="absolute inset-0 pointer-events-none overflow-hidden bg-[#07090e]">
      {/* Ambient background glows */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-emerald-500/[0.07] blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/3 right-1/4 w-80 h-80 rounded-full bg-sky-500/[0.05] blur-3xl pointer-events-none" />

      {/* SVG Canvas */}
      <svg className="w-full h-full opacity-70" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <pattern id="soc-grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255, 255, 255, 0.04)" strokeWidth="1" />
            <circle cx="40" cy="40" r="1" fill="rgba(16, 185, 129, 0.15)" />
          </pattern>
          <linearGradient id="streamGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#10b981" stopOpacity="0.8" />
            <stop offset="50%" stopColor="#38bdf8" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#6366f1" stopOpacity="0.2" />
          </linearGradient>
          <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(16, 185, 129, 0.15)" />
            <stop offset="100%" stopColor="rgba(16, 185, 129, 0)" />
          </radialGradient>
        </defs>

        <rect width="100%" height="100%" fill="url(#soc-grid)" />

        {/* Concentric Radar Rings */}
        <g transform="translate(320, 260)">
          <circle r="180" fill="none" stroke="rgba(16, 185, 129, 0.12)" strokeWidth="1" strokeDasharray="4 4" />
          <circle r="130" fill="url(#radarGlow)" stroke="rgba(16, 185, 129, 0.2)" strokeWidth="1" />
          <circle r="75" fill="none" stroke="rgba(56, 189, 248, 0.25)" strokeWidth="1" />
          <circle r="25" fill="none" stroke="rgba(16, 185, 129, 0.4)" strokeWidth="1.5" />
          <line x1="-190" y1="0" x2="190" y2="0" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />
          <line x1="0" y1="-190" x2="0" y2="190" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="1" />
        </g>

        {/* Network Pipeline Paths */}
        <g fill="none" strokeWidth="1.5">
          <path d="M 80 180 C 180 180, 220 260, 320 260" stroke="url(#streamGrad)" strokeDasharray="6 4" />
          <path d="M 320 260 C 400 260, 460 160, 560 160" stroke="rgba(56, 189, 248, 0.4)" strokeDasharray="4 4" />
          <path d="M 320 260 C 390 320, 480 380, 580 380" stroke="rgba(16, 185, 129, 0.4)" strokeDasharray="4 4" />
          <path d="M 120 360 C 200 360, 250 290, 320 260" stroke="rgba(244, 63, 94, 0.3)" strokeDasharray="5 5" />
        </g>

        {/* Pipeline Nodes */}
        <g className="font-mono text-[9px] fill-zinc-400 select-none">
          {/* Node 1: TAP */}
          <g transform="translate(80, 180)">
            <circle r="6" fill="#09090b" stroke="#10b981" strokeWidth="2" />
            <circle r="2.5" fill="#10b981" />
            <text x="12" y="3" fill="#34d399" fontWeight="bold">TAP MIRROR</text>
            <text x="12" y="14" fill="#71717a">eth0: promiscuous</text>
          </g>

          {/* Node 2: Ingress Hub */}
          <g transform="translate(120, 360)">
            <circle r="5" fill="#09090b" stroke="#f43f5e" strokeWidth="1.5" />
            <circle r="2" fill="#f43f5e" />
            <text x="12" y="3" fill="#fb7185">PCAP REPLAY DROP</text>
            <text x="12" y="14" fill="#71717a">/pcaps/live.pcap</text>
          </g>

          {/* Node 3: Core Sensor Engine */}
          <g transform="translate(320, 260)">
            <circle r="8" fill="#09090b" stroke="#38bdf8" strokeWidth="2" />
            <circle r="4" fill="#38bdf8" />
            <text x="-50" y="-16" fill="#38bdf8" fontWeight="bold" textAnchor="middle">ZEEK SENSOR CORE</text>
            <text x="-50" y="-5" fill="#71717a" textAnchor="middle">JA3 / TLS / Flow Extraction</text>
          </g>

          {/* Node 4: Stream Bus */}
          <g transform="translate(560, 160)">
            <circle r="6" fill="#09090b" stroke="#a78bfa" strokeWidth="2" />
            <circle r="2.5" fill="#a78bfa" />
            <text x="12" y="3" fill="#c084fc" fontWeight="bold">REDPANDA STREAM</text>
            <text x="12" y="14" fill="#71717a">traffic-flows: 9092</text>
          </g>

          {/* Node 5: Threat Classifier */}
          <g transform="translate(580, 380)">
            <circle r="6" fill="#09090b" stroke="#10b981" strokeWidth="2" />
            <circle r="2.5" fill="#10b981" />
            <text x="12" y="3" fill="#34d399" fontWeight="bold">ML ANOMALY ENGINES</text>
            <text x="12" y="14" fill="#71717a">6-Vector Detection Bus</text>
          </g>
        </g>
      </svg>

      {/* Radar sweeping line */}
      {motionEnabled && (
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 16, repeat: Infinity, ease: "linear" }}
          className="absolute w-[360px] h-[360px] top-[80px] left-[140px] pointer-events-none origin-center"
        >
          <div className="w-1/2 h-1/2 bg-gradient-to-br from-emerald-500/15 via-emerald-500/5 to-transparent rounded-tl-full" />
        </motion.div>
      )}
    </div>
  );
}

export function LoginPage({ onLoginSuccess }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [capsLockActive, setCapsLockActive] = useState(false);
  const [usernameTouched, setUsernameTouched] = useState(false);
  const [passwordTouched, setPasswordTouched] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessionExpiredNotice, setSessionExpiredNotice] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedRole, setSelectedRole] = useState<"admin" | "analyst" | null>(null);
  const [success, setSuccess] = useState(false);
  const [isExiting, setIsExiting] = useState(false);
  const [shake, setShake] = useState(0);
  const motionEnabled = useMotionEnabled();

  const [visibleLogs, setVisibleLogs] = useState<LogItem[]>(() =>
    mockLogTemplates.slice(0, 5).map((text, id) => ({ id, text }))
  );

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("state") === "session-expired" || sessionStorage.getItem("threatlens_session_expired") === "true") {
        setSessionExpiredNotice(true);
        sessionStorage.removeItem("threatlens_session_expired");
      }
    }
  }, []);

  // Continuous live network flow log stream
  useEffect(() => {
    let logCounter = 5;
    let timer: ReturnType<typeof setInterval> | null = null;

    const startTimer = () => {
      if (timer) return;
      timer = setInterval(() => {
        if (typeof document !== "undefined" && document.hidden) return;
        const template = mockLogTemplates[logCounter % mockLogTemplates.length];
        const newId = logCounter++;
        setVisibleLogs((prev) => {
          const next = [...prev, { id: newId, text: template }];
          if (next.length > 5) next.shift();
          return next;
        });
      }, 1100);
    };

    const stopTimer = () => {
      if (timer) {
        clearInterval(timer);
        timer = null;
      }
    };

    const onVisibilityChange = () => {
      if (document.hidden) {
        stopTimer();
      } else {
        startTimer();
      }
    };

    startTimer();
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibilityChange);
    }

    return () => {
      stopTimer();
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibilityChange);
      }
    };
  }, []);

  const handleKeyModifierCheck = (e: KeyboardEvent<HTMLInputElement>) => {
    setCapsLockActive(e.getModifierState("CapsLock"));
  };

  const usernameError = usernameTouched && !username.trim() ? "Username is required" : null;
  const passwordError = passwordTouched && !password ? "Password is required" : null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setUsernameTouched(true);
    setPasswordTouched(true);

    if (!username.trim() || !password) {
      setError("Please fill in all required credentials.");
      if (motionEnabled) setShake(s => s + 1);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        if (res.status === 401) {
          throw new Error("Invalid username or password.");
        } else if (res.status >= 500) {
          throw new Error("SOC Authentication Gateway is unreachable. Check network status.");
        } else {
          throw new Error(errData.detail || "Authentication failed. Invalid SOC credentials.");
        }
      }

      const data = await res.json();
      sessionStorage.setItem("threatlens_token", data.access_token);
      sessionStorage.setItem("threatlens_user", JSON.stringify(data.user));
      localStorage.setItem("threatlens_token", data.access_token);
      localStorage.setItem("threatlens_user", JSON.stringify(data.user));

      if (motionEnabled) {
        setSuccess(true);
        setTimeout(() => {
          setIsExiting(true);
          setTimeout(() => {
            onLoginSuccess(data.access_token, data.user);
          }, 150);
        }, 150);
      } else {
        onLoginSuccess(data.access_token, data.user);
      }
    } catch (err: any) {
      setError(err.message || "Authentication failed");
      if (motionEnabled) setShake(s => s + 1);
      setLoading(false);
    }
  };

  const fillCredentials = (userRole: "admin" | "analyst") => {
    setSelectedRole(userRole);
    if (userRole === "admin") {
      setUsername("admin");
      setPassword("AdminSecretPass123!");
    } else {
      setUsername("analyst");
      setPassword("AnalystPass123!");
    }
    setUsernameTouched(false);
    setPasswordTouched(false);
    setError(null);
  };

  return (
    <motion.div 
      animate={isExiting ? { opacity: 0 } : { opacity: 1 }}
      transition={{ duration: motionEnabled ? 0.15 : 0.05 }}
      className="min-h-[100dvh] w-full bg-[var(--bg-base)] text-[var(--text-primary)] flex font-sans selection:bg-emerald-500/20 selection:text-emerald-300 relative overflow-hidden select-none"
    >
        {/* Left side: Brand / Image */}
        <div className="hidden lg:flex flex-1 relative flex-col justify-between p-12 border-r border-[var(--hairline)] overflow-hidden" aria-hidden="true">
          <CyberTopologyHero motionEnabled={motionEnabled} />

          {/* Left-to-right fade to #09090b at the form edge */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#09090b]/30 to-[#09090b]" />
          {/* Bottom-to-top darkening gradient for text readability */}
          <div className="absolute inset-0 bg-gradient-to-t from-[#09090b] via-[#09090b]/60 to-transparent" />

          <div className="flex items-center space-x-3 z-10">
            <div className="flex items-center justify-center h-10 w-10 rounded border border-[var(--hairline)] text-[var(--text-primary)] shadow-sm bg-[var(--bg-surface)]">
              <ShieldSecurity className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[length:var(--text-heading)] font-bold tracking-tight uppercase">
                  ThreatLens
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 inline-block" />
                  SOC ENCLAVE
                </span>
              </div>
              <p className="text-[11px] text-[var(--text-secondary)] font-mono mt-0.5 tracking-widest">
                ZERO-TRANSMIT PASSIVE NETWORK FORENSICS
              </p>
            </div>
          </div>

          <div className="z-10 max-w-md mt-auto">
            {/* Flow log texture */}
            <div className="font-mono text-[11px] mb-6 flex flex-col justify-between select-none overflow-hidden h-[150px] border-l-2 border-emerald-500/40 pl-3 bg-zinc-950/70 backdrop-blur-md py-2.5 rounded-r border border-[var(--hairline)]" aria-hidden="true">
              <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-widest mb-1.5 flex items-center justify-between border-b border-zinc-800/80 pb-1.5">
                <span className="flex items-center gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" />
                  <span className="font-semibold text-zinc-300">[TAP: eth0/eth1 PROMISCUOUS]</span>
                </span>
                <span className="text-emerald-400 font-mono text-[9px] font-bold tracking-widest flex items-center gap-1">
                  LIVE STREAM
                </span>
              </div>
              <div className="flex flex-col gap-1 overflow-hidden flex-1 justify-end">
                <AnimatePresence initial={false}>
                  {visibleLogs.map((log) => {
                    const tagMatch = log.text.match(/^(\[[a-z0-9]+\])\s*(.*)$/);
                    const tag = tagMatch ? tagMatch[1] : log.text.slice(0, 6);
                    const rest = tagMatch ? tagMatch[2] : log.text.slice(6);
                    
                    const tagColor = 
                      tag === "[eth0]" ? "text-sky-400 font-bold" :
                      tag === "[eth1]" ? "text-emerald-400 font-bold" :
                      tag === "[core]" ? "text-amber-400 font-bold" :
                      "text-[var(--text-primary)] font-semibold";

                    return (
                      <motion.div
                        key={log.id}
                        initial={motionEnabled ? { opacity: 0, y: 6 } : { opacity: 0 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={motionEnabled ? { opacity: 0, y: -6 } : { opacity: 0 }}
                        transition={{ duration: 0.22, ease: "easeOut" }}
                        className="whitespace-nowrap text-zinc-300 font-mono text-[11px] leading-tight flex items-center gap-1.5"
                      >
                        <span className={tagColor}>{tag}</span>
                        <span className="text-zinc-400 truncate">{rest}</span>
                      </motion.div>
                    );
                  })}
                </AnimatePresence>
              </div>
            </div>
            <h2 className="mb-4 text-[24px] text-[var(--text-primary)] font-semibold tracking-tight">Security without footprint.</h2>
            <p className="text-[14px] leading-relaxed text-[var(--text-secondary)]">The SOC dashboard operates in a zero-egress, passive-tap environment. Telemetry is streamed directly from in-memory ring buffers without active probing or data exfiltration.</p>
          </div>
        </div>

      {/* Right side: Login Form */}
      <div className="flex-1 flex flex-col justify-center items-center p-6 md:p-12 relative z-10 bg-[var(--bg-base)]">
        <motion.div 
          className="w-full max-w-[400px] flex flex-col space-y-6"
          initial={motionEnabled ? "hidden" : "visible"}
          animate="visible"
          variants={{
            hidden: { opacity: 0 },
            visible: { opacity: 1, transition: { staggerChildren: 0.04 } }
          }}
        >
          
          <motion.div variants={{ hidden: { opacity: 0, y: 8 }, visible: { opacity: 1, y: 0 } }} className="space-y-1 mb-2">
            <h1 className="text-[24px] tracking-tight font-semibold text-[var(--text-primary)]">
              Sign in
            </h1>
            <p className="text-[14px] text-[var(--text-secondary)]">
              Authenticate to access the SOC telemetry dashboard.
            </p>
          </motion.div>

          {sessionExpiredNotice && (
            <div className="p-3 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300 text-[length:var(--text-body)] font-mono flex items-center gap-2" aria-live="polite">
              <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
              Your session expired. Sign in again.
            </div>
          )}

          <motion.div variants={{ hidden: { opacity: 0, y: 8 }, visible: { opacity: 1, y: 0 } }} className="bg-[var(--bg-surface)] p-1.5 rounded-lg border border-[var(--hairline)]">
            <div className="flex items-center space-x-1.5 relative">
              <button
                type="button"
                onClick={() => fillCredentials("admin")}
                className={`flex-1 flex flex-col items-center justify-center py-2.5 px-3 rounded text-center transition-colors border border-transparent relative z-10 ${
                  selectedRole === "admin"
                    ? "text-rose-300"
                    : "text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--bg-surface-hover)]"
                }`}
              >
                {selectedRole === "admin" && motionEnabled && (
                  <motion.div layoutId="roleSelect" transition={motionTokens.spring.press} className="absolute inset-0 bg-rose-500/10 border border-rose-500/20 rounded shadow-sm -z-10" />
                )}
                {!motionEnabled && selectedRole === "admin" && (
                  <div className="absolute inset-0 bg-rose-500/10 border border-rose-500/20 rounded shadow-sm -z-10" />
                )}
                <span className="text-[length:var(--text-body)] font-semibold mb-0.5 flex items-center gap-1.5">
                  {selectedRole === "admin" && <CheckCircle className="h-3.5 w-3.5" />}
                  SOC Admin
                </span>
                <span className={`text-[10px] font-mono tracking-wider uppercase ${selectedRole === "admin" ? "text-rose-400/80" : "text-[var(--text-muted)]"}`}>FULL CONTROL</span>
              </button>
              
              <button
                type="button"
                onClick={() => fillCredentials("analyst")}
                className={`flex-1 flex flex-col items-center justify-center py-2.5 px-3 rounded text-center transition-colors border border-transparent relative z-10 ${
                  selectedRole === "analyst"
                    ? "text-sky-300"
                    : "text-[var(--text-muted)] hover:text-[var(--text-secondary)] hover:bg-[var(--bg-surface-hover)]"
                }`}
              >
                {selectedRole === "analyst" && motionEnabled && (
                  <motion.div layoutId="roleSelect" transition={motionTokens.spring.press} className="absolute inset-0 bg-sky-500/10 border border-sky-500/20 rounded shadow-sm -z-10" />
                )}
                {!motionEnabled && selectedRole === "analyst" && (
                  <div className="absolute inset-0 bg-sky-500/10 border border-sky-500/20 rounded shadow-sm -z-10" />
                )}
                <span className="text-[length:var(--text-body)] font-semibold mb-0.5 flex items-center gap-1.5">
                  {selectedRole === "analyst" && <CheckCircle className="h-3.5 w-3.5" />}
                  SOC Analyst
                </span>
                <span className={`text-[10px] font-mono tracking-wider uppercase ${selectedRole === "analyst" ? "text-sky-400/80" : "text-[var(--text-muted)]"}`}>MONITORING & NOTES</span>
              </button>
            </div>
          </motion.div>

          {error && (
            <motion.div initial={motionEnabled ? { opacity: 0 } : {}} animate={motionEnabled ? { opacity: 1 } : {}} className="p-3 rounded border border-rose-500/20 bg-rose-500/10 text-rose-400 text-[length:var(--text-body)] font-mono" aria-live="polite">
              {error}
            </motion.div>
          )}

          <motion.form 
            variants={{ hidden: { opacity: 0, y: 8 }, visible: { opacity: 1, y: 0 } }} 
            onSubmit={handleSubmit} 
            className="flex flex-col space-y-5"
            animate={motionEnabled && shake > 0 ? { x: [-6, 6, -6, 6, -6, 6, 0] } : "visible"}
            transition={{ duration: 0.3 }}
          >
            <div className="space-y-1.5">
              <label htmlFor="login-username" className="block text-[length:var(--text-label)] font-medium text-[var(--text-secondary)] uppercase tracking-wider">
                Username
              </label>
              <div className="relative">
                <input
                  id="login-username"
                  type="text"
                  required
                  disabled={loading}
                  autoComplete="username"
                  value={username}
                  onChange={(e) => {
                    setUsername(e.target.value);
                    if (usernameTouched) setError(null);
                  }}
                  onBlur={() => setUsernameTouched(true)}
                  aria-invalid={Boolean(usernameError)}
                  aria-describedby={usernameError ? "username-error" : undefined}
                  className="w-full rounded-md border border-[var(--hairline)] bg-[var(--bg-base)] pl-9 pr-3 py-2.5 text-[length:var(--text-body)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 focus:outline-none transition-colors disabled:opacity-50"
                  placeholder="Enter username"
                />
                <UserIcon className="absolute left-3 top-2.5 h-4 w-4 text-[var(--text-muted)]" />
              </div>
              {usernameError && (
                <p id="username-error" className="text-[11px] text-rose-400 font-mono mt-1" role="alert">
                  {usernameError}
                </p>
              )}
            </div>

            <div className="space-y-1.5">
              <label htmlFor="login-password" className="block text-[length:var(--text-label)] font-medium text-[var(--text-secondary)] uppercase tracking-wider">
                Password
              </label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? "text" : "password"}
                  required
                  disabled={loading}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    if (passwordTouched) setError(null);
                  }}
                  onBlur={() => setPasswordTouched(true)}
                  onKeyDown={handleKeyModifierCheck}
                  onKeyUp={handleKeyModifierCheck}
                  aria-invalid={Boolean(passwordError)}
                  aria-describedby={passwordError ? "password-error" : capsLockActive ? "caps-hint" : undefined}
                  className="w-full rounded-md border border-[var(--hairline)] bg-[var(--bg-base)] pl-9 pr-10 py-2.5 text-[length:var(--text-body)] text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/50 focus:outline-none transition-colors disabled:opacity-50"
                  placeholder="Enter password"
                />
                <LockKey className="absolute left-3 top-2.5 h-4 w-4 text-[var(--text-muted)]" />
                <button
                  type="button"
                  tabIndex={-1}
                  onClick={() => setShowPassword((prev) => !prev)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  aria-pressed={showPassword}
                  className="absolute right-3 top-2.5 text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors focus:outline-none"
                >
                  {showPassword ? <ViewOffSlashIcon className="h-4 w-4" /> : <ViewIcon className="h-4 w-4" />}
                </button>
              </div>
              {capsLockActive && (
                <p id="caps-hint" className="text-[10px] text-amber-400 font-mono mt-1">
                  CAPS LOCK is ON
                </p>
              )}
              {passwordError && (
                <p id="password-error" className="text-[11px] text-rose-400 font-mono mt-1" role="alert">
                  {passwordError}
                </p>
              )}
            </div>

            <motion.div whileTap={motionEnabled && !loading ? { scale: 0.97 } : {}} transition={motionTokens.spring.press}>
              <Button
                type="submit"
                disabled={loading || success}
                className="w-full h-11 mt-2 bg-emerald-600 text-zinc-50 font-bold hover:bg-emerald-500 shadow-md transition-all uppercase tracking-wider text-[length:var(--text-body)] flex items-center justify-center gap-2 disabled:opacity-80"
              >
                {success ? (
                  <>
                    <CheckCircle className="h-4 w-4" />
                    ACCESS GRANTED
                  </>
                ) : loading ? (
                  <>
                    <svg className="animate-spin h-[14px] w-[14px] text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
                    AUTHENTICATING
                  </>
                ) : (
                  <>
                    Sign in to Dashboard
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Button>
            </motion.div>
          </motion.form>

        </motion.div>
      </div>
    </motion.div>
  );
}
