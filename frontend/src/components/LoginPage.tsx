import { useState, useEffect, type FormEvent, type KeyboardEvent } from "react";
import { motion, AnimatePresence } from "motion/react";
import { useMotionEnabled, motionTokens } from "@/lib/motion";
import { Button } from "@/components/ui/button";
import { HERO_IMAGE_DATA_URI } from "@/assets/heroImage";
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
        {/* Left side: Brand & Centered Fiber Neural Background */}
        <div className="hidden lg:flex flex-1 relative flex-col justify-between p-12 border-r border-[var(--hairline)] overflow-hidden" aria-hidden="true">
          {/* Centered Organic Fiber Network Visual */}
          <div className="absolute inset-0 overflow-hidden pointer-events-none select-none bg-[#05070c]">
            <motion.div
              initial={{ opacity: 0, scale: 1 }}
              animate={{ opacity: 1, scale: motionEnabled ? 1.03 : 1 }}
              transition={{
                opacity: { duration: motionEnabled ? 0.7 : 0.1 },
                scale: { duration: 24, ease: "easeInOut", repeat: Infinity, repeatType: "reverse" },
              }}
              className="absolute inset-0 flex items-center justify-center"
            >
              <img
                src={HERO_IMAGE_DATA_URI}
                alt=""
                className="w-full h-full object-cover object-center pointer-events-none select-none opacity-65"
              />
            </motion.div>

            {/* Subtle radial ambient vignette centered on screen */}
            <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_35%,#09090b_95%)] pointer-events-none" />

            {/* Left-to-right fade into #09090b at the form edge */}
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-[#09090b]/40 to-[#09090b]" />
            {/* Bottom-to-top darkening gradient for text readability */}
            <div className="absolute inset-0 bg-gradient-to-t from-[#09090b] via-[#09090b]/70 to-transparent" />
          </div>

          {/* Top Brand Header */}
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

          {/* Center Technical Specifications Enclave Badges */}
          <div className="z-10 my-auto max-w-md">
            <div className="grid grid-cols-2 gap-2.5 font-mono text-[10px]">
              <div className="p-3 rounded border border-[var(--hairline)] bg-[var(--bg-surface)]/80 backdrop-blur-md">
                <div className="text-[var(--text-secondary)] text-[9px] uppercase tracking-wider mb-1">Architecture</div>
                <div className="font-semibold text-[var(--text-primary)]">Passive Optical TAP</div>
                <div className="text-emerald-400 text-[9px] mt-0.5">TX Physically Disabled</div>
              </div>
              <div className="p-3 rounded border border-[var(--hairline)] bg-[var(--bg-surface)]/80 backdrop-blur-md">
                <div className="text-[var(--text-secondary)] text-[9px] uppercase tracking-wider mb-1">Sensor Ingestion</div>
                <div className="font-semibold text-[var(--text-primary)]">Zeek 6.0 Core</div>
                <div className="text-sky-400 text-[9px] mt-0.5">Line-Rate JSON Pipeline</div>
              </div>
              <div className="p-3 rounded border border-[var(--hairline)] bg-[var(--bg-surface)]/80 backdrop-blur-md">
                <div className="text-[var(--text-secondary)] text-[9px] uppercase tracking-wider mb-1">Cryptanalysis</div>
                <div className="font-semibold text-[var(--text-primary)]">TLS JA3 / JA4</div>
                <div className="text-purple-400 text-[9px] mt-0.5">Zero-Decryption Profiling</div>
              </div>
              <div className="p-3 rounded border border-[var(--hairline)] bg-[var(--bg-surface)]/80 backdrop-blur-md">
                <div className="text-[var(--text-secondary)] text-[9px] uppercase tracking-wider mb-1">Defense Matrix</div>
                <div className="font-semibold text-[var(--text-primary)]">6 Threat Vectors</div>
                <div className="text-emerald-400 text-[9px] mt-0.5">Sliding-Window Scoring</div>
              </div>
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
