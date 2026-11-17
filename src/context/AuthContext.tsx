"use client";

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import { Session, User } from "@supabase/supabase-js";
import { supabase } from "../lib/supabase";
import type { Database, Json } from "../types/database.types";
import {
  generateIdentityKeys,
  type IdentityKeyPair,
} from "../crypto/e2ee";
import {
  getKeyPair,
  initKeystore,
  setMemoryOnly,
  storeKeyPair,
} from "../crypto/keystore";

type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];
type PrivacySettingsRow =
  Database["public"]["Tables"]["user_privacy_settings"]["Row"];

type AuthContextType = {
  user: User | null;
  session: Session | null;
  loading: boolean;
  profile: ProfileRow | null;
  privacySettings: PrivacySettingsRow | null;
  identityKeys: IdentityKeyPair | null;
  signUp: (
    email: string,
    password: string,
    opts?: { username?: string; display_name?: string },
  ) => Promise<{ error: string | null }>;
  signIn: (email: string, password: string) => Promise<{ error: string | null }>;
  signOut: () => Promise<void>;
  updatePrivacySettings: (
    updates: Partial<PrivacySettingsRow>,
  ) => Promise<{ error: string | null }>;
  setMemoryOnly: (enabled: boolean) => void;
  refreshProfile: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}

const DEVICE_ID_KEY = "MESSENGER_DEVICE_ID";

function getDeviceId(): string {
  if (typeof localStorage === "undefined") return "";
  let id = localStorage.getItem(DEVICE_ID_KEY);
  if (!id) {
    id = crypto.randomUUID();
    try {
      localStorage.setItem(DEVICE_ID_KEY, id);
    } catch {}
  }
  return id;
}

async function exportPrivateJwk(key: CryptoKey) {
  return crypto.subtle.exportKey("jwk", key);
}

async function importPrivateJwk(
  jwk: JsonWebKey,
  kind: "ecdh" | "ecdsa",
): Promise<CryptoKey> {
  if (kind === "ecdh") {
    return crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"],
    );
  }
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
}

export function AuthProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState<ProfileRow | null>(null);
  const [privacySettings, setPrivacySettings] =
    useState<PrivacySettingsRow | null>(null);
  const [identityKeys, setIdentityKeys] = useState<IdentityKeyPair | null>(null);

  const deviceId = useRef(getDeviceId());

  useEffect(() => {
    let mounted = true;
    initKeystore();

    const { data: authSub } = supabase.auth.onAuthStateChange(
      async (_event, sess) => {
        if (!mounted) return;
        setSession(sess ?? null);
        const u = sess?.user ?? null;
        setUser(u);
        if (u) {
          await loadProfile(u.id);
          await loadPrivacySettings(u.id);
          await ensureIdentityKeys(u.id);
        } else {
          setProfile(null);
          setPrivacySettings(null);
          setIdentityKeys(null);
        }
        setLoading(false);
      },
    );

    return () => {
      mounted = false;
      authSub?.subscription.unsubscribe();
    };
  }, []);

  async function loadProfile(userId: string) {
    const { data, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", userId)
      .single();
    setProfile(error || !data ? null : (data as ProfileRow));
  }

  async function loadPrivacySettings(userId: string) {
    const { data, error } = await supabase
      .from("user_privacy_settings")
      .select("*")
      .eq("user_id", userId)
      .single();
    setPrivacySettings(error || !data ? null : (data as PrivacySettingsRow));
  }

  async function ensureIdentityKeys(userId: string) {
    const stored = await getKeyPair(userId);
    let keys: IdentityKeyPair;
    if (stored) {
      keys = {
        ecdhPrivateKey: await importPrivateJwk(
          stored.ecdhPrivateKey,
          "ecdh",
        ),
        ecdsaPrivateKey: await importPrivateJwk(
          stored.ecdsaPrivateKey,
          "ecdsa",
        ),
        ecdhPublicKey: stored.ecdhPublicKey,
        ecdsaPublicKey: stored.ecdsaPublicKey,
      };
    } else {
      keys = await generateIdentityKeys();
      const [ecdhPrivateJwk, ecdsaPrivateJwk] = await Promise.all([
        exportPrivateJwk(keys.ecdhPrivateKey),
        exportPrivateJwk(keys.ecdsaPrivateKey),
      ]);
      await storeKeyPair(userId, {
        userId,
        deviceId: deviceId.current,
        ecdhPrivateKey: ecdhPrivateJwk,
        ecdsaPrivateKey: ecdsaPrivateJwk,
        ecdhPublicKey: keys.ecdhPublicKey,
        ecdsaPublicKey: keys.ecdsaPublicKey,
      });
    }
    setIdentityKeys(keys);
    await upsertUserKeys(userId, keys);
  }

  async function upsertUserKeys(userId: string, keys: IdentityKeyPair) {
    await supabase.from("user_keys").upsert({
      user_id: userId,
      device_id: deviceId.current,
      ecdh_public_jwk: keys.ecdhPublicKey as unknown as Json,
      ecdsa_public_jwk: keys.ecdsaPublicKey as unknown as Json,
      updated_at: new Date().toISOString(),
    });
  }

  async function signUp(
    email: string,
    password: string,
    opts?: { username?: string; display_name?: string },
  ) {
    const { error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          username: opts?.username ?? null,
          full_name: opts?.display_name ?? null,
        },
      },
    });
    if (error) return { error: error.message };

    const { data } = await supabase.auth.getUser();
    if (data.user && (opts?.username || opts?.display_name)) {
      await supabase.from("profiles").upsert({
        id: data.user.id,
        username: opts.username ?? null,
        display_name: opts.display_name ?? null,
      });
    }
    return { error: null };
  }

  async function signIn(email: string, password: string) {
    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) return { error: error.message };
    return { error: null };
  }

  async function signOut() {
    await supabase.auth.signOut();
    setIdentityKeys(null);
    setProfile(null);
    setPrivacySettings(null);
  }

  async function updatePrivacySettings(
    updates: Partial<PrivacySettingsRow>,
  ) {
    if (!user) return { error: "Not authenticated" };
    const { error } = await supabase
      .from("user_privacy_settings")
      .upsert({ user_id: user.id, ...updates });
    if (error) return { error: error.message };
    await loadPrivacySettings(user.id);
    return { error: null };
  }

  async function refreshProfile() {
    if (!user) return;
    await loadProfile(user.id);
  }

  const value: AuthContextType = {
    user,
    session,
    loading,
    profile,
    privacySettings,
    identityKeys,
    signUp,
    signIn,
    signOut,
    updatePrivacySettings,
    setMemoryOnly,
    refreshProfile,
  };

  return (
    <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
  );
}
