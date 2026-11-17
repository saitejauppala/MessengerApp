import { useEffect, useRef, useState } from "react";
import { Eye, EyeOff, Lock, Loader2 } from "lucide-react";

type IdleTimeout = "immediate" | "1m" | "5m" | "30m";

const IDLE_MS: Record<IdleTimeout, number> = {
  immediate: 0,
  "1m": 60_000,
  "5m": 300_000,
  "30m": 1_800_000,
};

const PIN_STORAGE_KEY = "MESSENGER_APP_LOCK_PIN";
const SALT_STORAGE_KEY = "MESSENGER_APP_LOCK_SALT";
const IDLE_STORAGE_KEY = "MESSENGER_APP_LOCK_IDLE";

async function sha256(str: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function getStoredIdle(): IdleTimeout {
  if (typeof localStorage === "undefined") return "5m";
  const v = localStorage.getItem(IDLE_STORAGE_KEY) as IdleTimeout | null;
  return v && v in IDLE_MS ? v : "5m";
}

function hasPin(): boolean {
  return typeof localStorage !== "undefined" && !!localStorage.getItem(PIN_STORAGE_KEY);
}

export function AppLockGuard({
  children,
  blurOnUnfocus = true,
  idleTimeout: propIdleTimeout,
}: {
  children: React.ReactNode;
  blurOnUnfocus?: boolean;
  idleTimeout?: IdleTimeout;
}) {
  const [isLocked, setIsLocked] = useState(true);
  const [isSettingUp, setIsSettingUp] = useState(false);
  const [pin, setPin] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const idleTimeoutRef = useRef<IdleTimeout>(
    propIdleTimeout ?? getStoredIdle(),
  );
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  async function pinHash(pinValue: string): Promise<string> {
    const salt =
      typeof localStorage !== "undefined"
        ? localStorage.getItem(SALT_STORAGE_KEY)
        : null;
    return sha256(pinValue + (salt ?? ""));
  }

  function resetIdleTimer() {
    if (timerRef.current) clearTimeout(timerRef.current);
    const ms = IDLE_MS[idleTimeoutRef.current];
    if (ms === 0) return; // "immediate" locks on blur/tab switch, not while active
    timerRef.current = setTimeout(() => setIsLocked(true), ms);
  }

  useEffect(() => {
    idleTimeoutRef.current = propIdleTimeout ?? getStoredIdle();

    const initialized = hasPin();
    setIsSettingUp(!initialized);
    setIsLocked(true); // always start blocked until PIN is set or entered

    const handleActivity = () => resetIdleTimer();
    const handleBlur = () => {
      if (blurOnUnfocus) setIsLocked(true);
    };
    const handleVisibility = () => {
      if (document.hidden) {
        if (blurOnUnfocus) setIsLocked(true);
      } else if (!isLocked) {
        resetIdleTimer();
      }
    };

    window.addEventListener("mousemove", handleActivity);
    window.addEventListener("keydown", handleActivity);
    window.addEventListener("click", handleActivity);
    window.addEventListener("scroll", handleActivity);
    window.addEventListener("blur", handleBlur);
    window.addEventListener("focus", handleVisibility);
    document.addEventListener("visibilitychange", handleVisibility);

    resetIdleTimer();

    return () => {
      window.removeEventListener("mousemove", handleActivity);
      window.removeEventListener("keydown", handleActivity);
      window.removeEventListener("click", handleActivity);
      window.removeEventListener("scroll", handleActivity);
      window.removeEventListener("blur", handleBlur);
      window.removeEventListener("focus", handleVisibility);
      document.removeEventListener("visibilitychange", handleVisibility);
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [blurOnUnfocus, propIdleTimeout, isLocked]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      if (isSettingUp) {
        const salt = crypto.randomUUID();
        const hash = await sha256(pin + salt);
        localStorage.setItem(SALT_STORAGE_KEY, salt);
        localStorage.setItem(PIN_STORAGE_KEY, hash);
        setIsSettingUp(false);
        setIsLocked(false);
        setPin("");
        resetIdleTimer();
      } else {
        const storedHash = localStorage.getItem(PIN_STORAGE_KEY);
        const inputHash = await pinHash(pin);
        if (storedHash && inputHash === storedHash) {
          setUnlockError("");
          setIsLocked(false);
          setPin("");
          resetIdleTimer();
        } else {
          setUnlockError("Incorrect PIN");
        }
      }
    } finally {
      setSubmitting(false);
    }
  }

  const overlay = (
    <div className="fixed inset-0 z-50 bg-[#0f172a]/90 backdrop-blur-xl flex items-center justify-center">
      <div className="w-full max-w-md p-6 rounded-2xl bg-white dark:bg-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700">
        <div className="flex items-center gap-2 mb-4">
          <Lock className="h-5 w-5 text-indigo-600" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            {isSettingUp ? "Create App Lock PIN" : "Unlock App"}
          </h2>
        </div>
        <p className="text-sm text-slate-500 mb-6">
          {isSettingUp
            ? "Set a PIN to lock this app locally."
            : "Enter your PIN to continue."}
        </p>
        {unlockError && (
          <p className="text-sm text-red-600 mb-4">{unlockError}</p>
        )}
        <form onSubmit={handleSubmit} className="space-y-3">
          <div className="relative group">
            <input
              id="pin"
              type="password"
              value={pin}
              onChange={(e) => {
                setPin(e.target.value.replace(/\D/g, "").slice(0, 6));
                setUnlockError("");
              }}
              maxLength={6}
              autoComplete="off"
              className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
              placeholder="••••••"
            />
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
              {pin.length > 0 ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </div>
          </div>
          <button
            type="submit"
            disabled={submitting || pin.length < 4}
            className="w-full py-3 rounded-xl bg-indigo-600 text-white font-semibold disabled:opacity-50 transition flex items-center justify-center gap-2"
          >
            {submitting ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : isSettingUp ? (
              "Create PIN"
            ) : (
              "Unlock"
            )}
          </button>
        </form>
      </div>
    </div>
  );

  return (
    <div className="relative min-h-[inherit]">
      {!isLocked && <div className="relative z-10">{children}</div>}
      {isLocked && overlay}
    </div>
  );
}
