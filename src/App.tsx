import { AuthProvider, useAuth } from "./context/AuthContext";
import { AppLockGuard } from "./components/privacy/AppLockGuard";
import { AuthScreen } from "./components/auth/AuthScreen";
import { ChatWorkspace } from "./components/chat/ChatWorkspace";

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
          <ChatWorkspace />
        ) : (
          <AuthScreen />
        )}
      </AppLockGuard>
    </AuthProvider>
  );
}
