"use client";

import { useState } from "react";
import { Lock } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

export function AuthScreen() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const { signIn, signUp } = useAuth();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      if (mode === "signin") {
        const { error: err } = await signIn(email, password);
        if (err) setError(err);
      } else {
        const { error: err } = await signUp(email, password, {
          username: username.trim() || undefined,
          display_name: displayName.trim() || undefined,
        });
        if (err) setError(err);
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-md">
        <div className="mx-auto mb-8">
          <Lock className="h-8 w-8 text-indigo-600" />
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="border border-slate-200 rounded-xl bg-white p-6 shadow-sm">
            <h2 className="text-center text-xl font-bold text-slate-900 mb-6">
              {mode === "signin" ? "Welcome back" : "Create account"}
            </h2>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  autoComplete={mode === "signin" ? "email" : "new-email"}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 text-sm text-slate-900 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  required
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">
                  Password
                </label>
                <input
                  type="password"
                  autoComplete={mode === "signin" ? "current-password" : "new-password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full rounded-lg border border-slate-200 bg-slate-50 text-sm text-slate-900 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  required
                />
              </div>

              {mode === "signup" && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      autoComplete="new-username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      className="w-full rounded-lg border border-slate-200 bg-slate-50 text-sm text-slate-900 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-600 mb-1">
                      Display Name
                    </label>
                    <input
                      type="text"
                      autoComplete="name"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      className="w-full rounded-lg border border-slate-200 bg-slate-50 text-sm text-slate-900 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    />
                  </div>
                </>
              )}
            </div>

            {error && (
              <div className="rounded-lg bg-red-50 p-3 text-xs text-red-700">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl bg-indigo-600 text-white font-semibold disabled:opacity-60 transition"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Signing in...
                </span>
              ) : mode === "signin" ? (
                "Sign in"
              ) : (
                "Create account"
              )}
            </button>
          </div>

          <p className="text-center text-sm text-slate-600">
            {mode === "signin"
              ? "Don't have an account? "
              : "Already have an account? "}
            <button
              onClick={() => {
                setMode(mode === "signin" ? "signup" : "signin");
                setError("");
              }}
              className="text-indigo-600 font-semibold hover:underline"
            >
              {mode === "signin" ? "Sign up" : "Sign in"}
            </button>
          </p>
        </form>

        <p className="text-center text-xs text-slate-400 mt-6">
          End-to-end encrypted. Your private keys stay on your device.
        </p>
      </div>
    </div>
  );
}
