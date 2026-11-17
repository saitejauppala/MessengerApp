import { Lock, Shield, MessageCircle } from "lucide-react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { AppLockGuard } from "./components/privacy/AppLockGuard";
import { AuthScreen } from "./components/auth/AuthScreen";

function AppShell() {
  const { user, signOut, profile } = useAuth();

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/80 backdrop-blur-lg supports-[backdrop-filter]:bg-white/60">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center gap-3">
            <Shield className="h-6 w-6 text-indigo-600" />
            <span className="font-semibold text-slate-900 tracking-tight">MessengerApp</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex flex-col items-end">
              <span className="text-sm text-slate-900">{user?.email}</span>
              {profile?.username && (
                <span className="text-xs text-slate-500">@{profile.username}</span>
              )}
            </div>
            <button
              onClick={signOut}
              className="text-sm text-red-600 hover:text-red-800 font-medium"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto py-8 px-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="flex-shrink-0 h-9 w-9 rounded-xl bg-indigo-100 dark:bg-indigo-900 flex items-center justify-center">
            <MessageCircle className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900">Conversations</h1>
            <p className="text-sm text-slate-500">End-to-end encrypted messages</p>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 min-h-[60vh] flex flex-col">
          <div className="p-6 border-b border-slate-200 dark:border-slate-700">
            <h2 className="text-base font-semibold text-slate-900 dark:text-white">
              Secure Messaging
            </h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Your identity keys are generated and stored locally. Messages are
              encrypted before they leave your device.
            </p>
          </div>
          <div className="flex-1 flex items-center justify-center p-8">
            <div className="flex flex-col items-center gap-3 text-slate-400">
              <Lock className="h-6 w-6" />
              <p className="text-sm">Start a conversation to begin</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  const { user, loading } = useAuth();

  return (
    <AuthProvider>
      <AppLockGuard idleTimeout="5m" blurOnUnfocus>
        {loading ? (
          <div className="min-h-screen flex items-center justify-center">
            <p className="text-slate-600">Loading…</p>
          </div>
        ) : user ? (
          <AppShell />
        ) : (
          <AuthScreen />
        )}
      </AppLockGuard>
    </AuthProvider>
  );
}
