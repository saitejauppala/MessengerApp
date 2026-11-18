"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  ChevronLeft,
  Eye,
  Image,
  Lock,
  LockOpen,
  Menu,
  MessageCircle,
  Paperclip,
  Search,
  Shield,
  Trash2,
  User,
  UserPlus,
  Zap,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { useEncryptedChat } from "../../hooks/useEncryptedChat";
import { PrivacySettingsDrawer } from "../privacy/PrivacySettingsDrawer";
import { SafetyNumberModal } from "./SafetyNumberModal";
import { ViewOnceViewer } from "./ViewOnceViewer";
import { supabase } from "../../lib/supabase";
import type { Database } from "../../types/database.types";

type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];
type MemberRow = Database["public"]["Tables"]["conversation_members"]["Row"];

interface PeerKeys {
  ecdh: JsonWebKey;
  ecdsa: JsonWebKey;
}

interface ListedConversation {
  id: string;
  type: string;
  name: string | null;
  peerUserId: string | null;
  peer: ProfileRow | null;
  isLocked: boolean;
  disappearingSeconds: number | null;
  lastPreview: string;
  lastAt: string | null;
  unreadCount: number;
}

const VAULT_PIN_KEY = "MESSENGER_VAULT_PIN";
const VAULT_SALT_KEY = "MESSENGER_VAULT_SALT";
const LOCKED_CHATS_KEY = "MESSENGER_LOCKED_CHATS";

export function ChatWorkspace() {
  const { user, signOut } = useAuth();
  const [active, setActive] = useState<ListedConversation | null>(null);
  const [activePeerKeys, setActivePeerKeys] = useState<PeerKeys | null>(null);
  const [conversations, setConversations] = useState<ListedConversation[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<ProfileRow[]>([]);
  const [searching, setSearching] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [privacyDrawer, setPrivacyDrawer] = useState(false);
  const [createChat, setCreateChat] = useState(false);
  const [createChatError, setCreateChatError] = useState("");

  // Locked chats vault
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [vaultPin, setVaultPin] = useState("");
  const [vaultMode, setVaultMode] = useState<"unlock" | "set">("unlock");
  const [vaultError, setVaultError] = useState("");

  const [viewOnceMessage, setViewOnceMessage] = useState<{
    id: string;
    card: any;
    mimeType: string;
  } | null>(null);
  const [safetyPeer, setSafetyPeer] = useState<{
    userId: string;
    ourKey: JsonWebKey;
    theirKey: JsonWebKey;
  } | null>(null);

  const disappearingSecondsRef = useRef<number | null>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, []);

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  async function sha256(str: string): Promise<string> {
    const buf = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(str),
    );
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function getLockedChatIds(): string[] {
    if (typeof localStorage === "undefined") return [];
    try {
      const raw = localStorage.getItem(LOCKED_CHATS_KEY);
      return raw ? (JSON.parse(raw) as string[]) : [];
    } catch {
      return [];
    }
  }

  function setLockedChatIds(ids: string[]) {
    if (typeof localStorage === "undefined") return;
    localStorage.setItem(LOCKED_CHATS_KEY, JSON.stringify(ids));
  }

  function hasVaultPin(): boolean {
    return (
      typeof localStorage !== "undefined" &&
      !!localStorage.getItem(VAULT_PIN_KEY)
    );
  }

  async function verifyVaultPin(pin: string): Promise<boolean> {
    const salt = localStorage.getItem(VAULT_SALT_KEY);
    const stored = localStorage.getItem(VAULT_PIN_KEY);
    if (!stored || !salt) return false;
    const hash = await sha256(pin + salt);
    return hash === stored;
  }

  async function setVaultPinValue(pin: string) {
    const salt = crypto.randomUUID();
    const hash = await sha256(pin + salt);
    localStorage.setItem(VAULT_SALT_KEY, salt);
    localStorage.setItem(VAULT_PIN_KEY, hash);
  }

  // ------------------------------------------------------------------
  // Data loading
  // ------------------------------------------------------------------

  async function loadConversations() {
    if (!user) return;
    try {
      const { data: memberships } = await supabase
        .from("conversation_members")
        .select("*")
        .eq("user_id", user.id);

      const ids = (memberships ?? []).map((m) => m.conversation_id);
      if (!ids.length) {
        setConversations([]);
        return;
      }

      const memberByConv = new Map<string, MemberRow[]>();
      for (const m of memberships ?? []) {
        const arr = memberByConv.get(m.conversation_id) ?? [];
        arr.push(m);
        memberByConv.set(m.conversation_id, arr);
      }

      const { data: convs } = await supabase
        .from("conversations")
        .select("*")
        .in("id", ids)
        .order("updated_at", { ascending: false });

      const { data: allMembers } = await supabase
        .from("conversation_members")
        .select("*")
        .in("conversation_id", ids);

      const memberIds = [
        ...new Set((allMembers ?? []).map((m) => m.user_id)),
      ];
      const { data: profiles } = await supabase
        .from("profiles")
        .select("*")
        .in("id", memberIds);
      const profilesById = Object.fromEntries(
        (profiles ?? []).map((p) => [p.id, p]),
      );

      const locked = getLockedChatIds();

      const listed: ListedConversation[] = (convs ?? []).map((c) => {
        const members = memberByConv.get(c.id) ?? [];
        const peerMember =
          members.find((m) => m.user_id !== user.id) ?? null;
        const peer = peerMember
          ? (profilesById[peerMember.user_id] as ProfileRow | null)
          : null;
        const isLocked = c.is_locked || locked.includes(c.id);
        return {
          id: c.id,
          type: c.type,
          name: c.name,
          peerUserId: peerMember?.user_id ?? null,
          peer,
          isLocked,
          disappearingSeconds:
            members.find((m) => m.user_id === user.id)
              ?.disappearing_seconds ?? null,
          lastPreview: "Encrypted message",
          lastAt: c.updated_at,
          unreadCount: 0,
        };
      });

      setConversations(listed.filter((c) => !c.isLocked));
    } catch {
      setConversations([]);
    }
  }

  async function loadPeerKeys(targetUserId: string): Promise<PeerKeys | null> {
    const { data } = await supabase
      .from("user_keys")
      .select("*")
      .eq("user_id", targetUserId)
      .order("updated_at", { ascending: false })
      .limit(1);
    const row = data?.[0];
    if (!row) return null;
    return {
      ecdh: row.ecdh_public_jwk as JsonWebKey,
      ecdsa: row.ecdsa_public_jwk as JsonWebKey,
    };
  }

  async function loadMyEcdhKey(): Promise<JsonWebKey | null> {
    if (!user) return null;
    const { data } = await supabase
      .from("user_keys")
      .select("ecdh_public_jwk")
      .eq("user_id", user.id)
      .order("updated_at", { ascending: false })
      .limit(1);
    return data?.[0]?.ecdh_public_jwk as JsonWebKey | null;
  }

  // ------------------------------------------------------------------
  // Conversation actions
  // ------------------------------------------------------------------

  async function openConversation(conv: ListedConversation) {
    setActive(conv);
    setActivePeerKeys(null);
    setShowSidebar(false);
    disappearingSecondsRef.current = conv.disappearingSeconds ?? null;
    if (conv.peerUserId && user) {
      const their = await loadPeerKeys(conv.peerUserId);
      const ourEcdh = await loadMyEcdhKey();
      if (their && ourEcdh) {
        setActivePeerKeys({ ecdh: ourEcdh, ecdsa: their.ecdsa });
      }
    }
  }

  async function startDirectChat(peer: ProfileRow) {
    if (!user || !peer.id) return;
    setCreateChatError("");
    const { data: peerMemberships } = await supabase
      .from("conversation_members")
      .select("conversation_id")
      .eq("user_id", peer.id);
    const { data: myMemberships } = await supabase
      .from("conversation_members")
      .select("conversation_id")
      .eq("user_id", user.id);
    const peerIds = new Set(
      (peerMemberships ?? []).map((m) => m.conversation_id),
    );
    const common = (myMemberships ?? []).find((m) => peerIds.has(m.conversation_id));

    let conversationId: string;
    if (common) {
      conversationId = common.conversation_id;
    } else {
      const { data: conv, error: cErr } = await supabase
        .from("conversations")
        .insert({ type: "direct", created_by: user.id })
        .select("id")
        .single();
      if (cErr) {
        setCreateChatError(cErr.message);
        return;
      }
      conversationId = conv.id;
      await supabase.from("conversation_members").insert([
        { conversation_id: conversationId, user_id: user.id },
        { conversation_id: conversationId, user_id: peer.id },
      ]);
    }

    const { data: updated } = await supabase
      .from("conversation_members")
      .select("*")
      .eq("conversation_id", conversationId)
      .eq("user_id", user.id)
      .single();
    setCreateChat(false);
    const conv: ListedConversation = {
      id: conversationId,
      type: "direct",
      name: null,
      peerUserId: peer.id,
      peer,
      isLocked: false,
      disappearingSeconds: updated?.disappearing_seconds ?? null,
      lastPreview: "Encrypted message",
      lastAt: new Date().toISOString(),
      unreadCount: 0,
    };
    setConversations((curr) => [
      conv,
      ...curr.filter((c) => c.id !== conversationId),
    ]);
    await openConversation(conv);
  }

  // ------------------------------------------------------------------
  // Vault
  // ------------------------------------------------------------------

  async function handleVaultSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!vaultPin.trim()) return;
    setVaultError("");
    if (vaultMode === "set") {
      await setVaultPinValue(vaultPin);
      setVaultMode("unlock");
      setVaultPin("");
      setVaultUnlocked(true);
      return;
    }
    const ok = await verifyVaultPin(vaultPin);
    if (ok) {
      setVaultUnlocked(true);
      setVaultPin("");
    } else {
      setVaultError("Incorrect PIN");
    }
  }

  function lockChat(convId: string) {
    const ids = getLockedChatIds();
    if (!ids.includes(convId)) setLockedChatIds([...ids, convId]);
    setConversations((curr) => curr.filter((c) => c.id !== convId));
  }

  function unlockChat(convId: string) {
    const ids = getLockedChatIds().filter((id) => id !== convId);
    setLockedChatIds(ids);
    loadConversations();
  }

  // ------------------------------------------------------------------
  // View-once
  // ------------------------------------------------------------------

  async function handleViewed(messageId: string) {
    await supabase
      .from("messages")
      .update({ viewed_at: new Date().toISOString() })
      .eq("id", messageId);
    setViewOnceMessage(null);
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  const isMobile = useMemo(() => {
    if (typeof window === "undefined") return false;
    return window.innerWidth < 768;
  }, []);

  useEffect(() => {
    loadConversations();
    // eslint-disable-next-line no-empty
  }, []);

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      {/* Top bar (mobile) */}
      <div className="lg:hidden flex-shrink-0 border-b border-slate-200 bg-white px-4 py-3 flex items-center justify-between z-20">
        <button
          onClick={() => setShowSidebar(true)}
          className="text-slate-600 hover:text-slate-900"
        >
          <Menu className="h-5 w-5" />
        </button>
        <div className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-indigo-600" />
          <span className="font-semibold text-slate-900 tracking-tight">
            MessengerApp
          </span>
        </div>
        <button
          onClick={signOut}
          className="text-xs text-red-600 hover:text-red-800 font-medium px-2 py-1 rounded"
        >
          Sign out
        </button>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* ================= SIDEBAR ================= */}
        <aside
          className={`hidden lg:flex w-80 flex-col border-r border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900`}
        >
          <div className="p-4 border-b border-slate-200 dark:border-slate-700">
            <div className="flex items-center gap-3">
              <Shield className="h-5 w-5 text-indigo-600" />
              <span className="font-semibold text-slate-900 dark:text-white tracking-tight">
                Messenger
              </span>
            </div>
          </div>

          <div className="p-3 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search users…"
                className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white pl-9 pr-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>
            {searching && <p className="text-xs text-slate-500">Searching…</p>}
            {searchResults.length > 0 && (
              <ul className="max-h-48 overflow-y-auto space-y-1">
                {searchResults.map((p) => (
                  <li
                    key={p.id}
                    onClick={() => {
                      setSearchQuery("");
                      setSearchResults([]);
                      startDirectChat(p);
                    }}
                    className="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                  >
                    {p.avatar_url && (
                      <img
                        src={p.avatar_url}
                        alt=""
                        className="h-8 w-8 rounded-full object-cover"
                      />
                    )}
                    <div>
                      <p className="text-sm text-slate-900 dark:text-white truncate">
                        {p.username}
                      </p>
                      {p.display_name && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                          {p.display_name}
                        </p>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <button
              onClick={() => setCreateChat(true)}
              className="w-full py-2 rounded-lg text-sm text-indigo-600 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 transition"
            >
              <UserPlus className="h-4 w-4 mr-2" /> Start new chat
            </button>
          </div>

          <div className="p-3 border-t border-slate-200 dark:border-slate-700 space-y-2">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Conversations
            </p>
            <div className="space-y-1">
              {conversations.map((c) => (
                <div
                  key={c.id}
                  onClick={() => openConversation(c)}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 transition group"
                >
                  {c.peer?.avatar_url && (
                    <img
                      src={c.peer.avatar_url}
                      alt=""
                      className="h-8 w-8 rounded-full object-cover border border-slate-200 dark:border-slate-700"
                    />
                  )}
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-slate-900 dark:text-white truncate font-medium">
                      {c.name ?? c.peer?.username ?? "Unknown"}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                      {c.lastPreview}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        lockChat(c.id);
                      }}
                      className="p-1.5 text-slate-400 hover:text-red-600 dark:hover:text-red-400 rounded"
                      title="Lock chat"
                    >
                      <Lock className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              ))}
              {conversations.length === 0 && (
                <p className="text-xs text-slate-500 dark:text-slate-400 text-center px-3 py-2">
                  No conversations yet
                </p>
              )}
            </div>

            {/* Locked Chats Vault */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-700">
              <button
                onClick={() => {
                  if (hasVaultPin()) {
                    setVaultMode("unlock");
                    setVaultUnlocked(false);
                  } else {
                    setVaultMode("set");
                    setVaultUnlocked(false);
                  }
                }}
                className="w-full py-2 rounded-lg text-sm text-indigo-600 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 transition flex items-center justify-center gap-2"
              >
                {vaultUnlocked ? (
                  <LockOpen className="h-4 w-4" />
                ) : (
                  <Lock className="h-4 w-4" />
                )}
                <span>{vaultUnlocked ? "Hide Vault" : "Locked Chats Vault"}</span>
              </button>

              {!hasVaultPin() && vaultMode === "set" && !vaultUnlocked && (
                <div className="mt-2 p-3 rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-900/20">
                  <p className="text-xs text-indigo-700 dark:text-indigo-300 mb-2">
                    Set a PIN to protect locked chats
                  </p>
                  <form onSubmit={handleVaultSubmit} className="flex gap-2">
                    <input
                      type="password"
                      value={vaultPin}
                      onChange={(e) => setVaultPin(e.target.value)}
                      placeholder="New PIN"
                      className="flex-1 rounded border border-indigo-300 dark:border-indigo-600 bg-white dark:bg-indigo-900/30 text-indigo-900 dark:text-white px-2 py-1.5 text-sm focus:ring-2 focus:ring-indigo-500"
                    />
                    <button
                      type="submit"
                      className="rounded bg-indigo-600 text-white px-3 py-1.5 text-sm hover:bg-indigo-700 disabled:opacity-50"
                      disabled={!vaultPin.trim()}
                    >
                      Set
                    </button>
                  </form>
                </div>
              )}

              {hasVaultPin() && vaultMode === "unlock" && !vaultUnlocked && (
                <div className="mt-2 p-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-2">
                    Enter vault PIN
                  </p>
                  <form onSubmit={handleVaultSubmit} className="flex gap-2">
                    <input
                      type="password"
                      value={vaultPin}
                      onChange={(e) => setVaultPin(e.target.value)}
                      placeholder="PIN"
                      className="flex-1 rounded border border-slate-300 dark:border-slate-600 bg-white dark:bg-slate-900 text-slate-900 dark:text-white px-2 py-1.5 text-sm focus:ring-2 focus:ring-indigo-500"
                    />
                    <button
                      type="submit"
                      className="rounded bg-indigo-600 text-white px-3 py-1.5 text-sm hover:bg-indigo-700 disabled:opacity-50"
                      disabled={!vaultPin.trim()}
                    >
                      Unlock
                    </button>
                  </form>
                  {vaultError && (
                    <p className="mt-1 text-xs text-red-600 dark:text-red-400">
                      {vaultError}
                    </p>
                  )}
                </div>
              )}
            </div>

            <button
              onClick={() => setPrivacyDrawer(true)}
              className="w-full py-2 rounded-lg text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition flex items-center justify-center gap-2"
            >
              <Zap className="h-4 w-4 mr-2" /> Privacy & Security
            </button>
          </div>
        </aside>

        {/* Mobile sidebar overlay */}
        {showSidebar && isMobile && (
          <div
            className="lg:hidden fixed inset-0 z-30 bg-black/40 backdrop-blur-sm"
            onClick={() => setShowSidebar(false)}
          />
        )}
        {showSidebar && isMobile && (
          <aside className="lg:hidden fixed left-0 top-0 z-40 w-80 h-full bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-700 flex flex-col">
            <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
              <button
                onClick={() => setShowSidebar(false)}
                className="text-slate-600 hover:text-slate-900"
              >
                <ChevronLeft className="h-5 w-5" />
              </button>
              <span className="font-semibold text-slate-900 dark:text-white">
                Conversations
              </span>
            </div>
            <div className="flex-1 overflow-y-auto p-3">
              {conversations.map((c) => (
                <div
                  key={c.id}
                  onClick={() => {
                    openConversation(c);
                    setShowSidebar(false);
                  }}
                  className="flex items-center gap-3 px-3 py-2.5 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                >
                  <div className="h-8 w-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center">
                    <User className="h-5 w-5 text-slate-600 dark:text-slate-300" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-slate-900 dark:text-white truncate font-medium">
                      {c.name ?? c.peer?.username ?? "Unknown"}
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                      {c.lastPreview}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </aside>
        )}

        {/* ================= MAIN PANEL ================= */}
        <main className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
          {active && activePeerKeys ? (
            <ActiveThread
              conversation={active}
              peerPublicKeys={activePeerKeys}
              onLockChat={() => lockChat(active.id)}
              onUnlockChat={() => unlockChat(active.id)}
              onViewOnce={(msg) => setViewOnceMessage(msg)}
              onSafetyPeer={() => {
                if (!active.peerUserId || !user) return;
                setSafetyPeer({
                  userId: active.peerUserId,
                  ourKey: activePeerKeys.ecdh,
                  theirKey: activePeerKeys.ecdsa,
                });
              }}
            />
          ) : (
            <EmptyState />
          )}
        </main>
      </div>

      {privacyDrawer && (
        <PrivacySettingsDrawer open={privacyDrawer} onClose={() => setPrivacyDrawer(false)} />
      )}
      {safetyPeer && (
        <SafetyNumberModal
          open={!!safetyPeer}
          onClose={() => setSafetyPeer(null)}
          peerUserId={safetyPeer.userId}
          ourPublicKey={safetyPeer.ourKey}
          theirPublicKey={safetyPeer.theirKey}
        />
      )}
      {viewOnceMessage && (
        <ViewOnceViewer
          open={!!viewOnceMessage}
          onClose={() => setViewOnceMessage(null)}
          card={viewOnceMessage.card}
          messageId={viewOnceMessage.id}
          onViewed={handleViewed}
        />
      )}
      {createChat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="fixed inset-0 bg-black/40 backdrop-blur-sm"
            onClick={() => setCreateChat(false)}
          />
          <div className="relative z-10 w-full max-w-md p-6 rounded-2xl bg-white dark:bg-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col gap-4">
            <h3 className="text-base font-semibold text-slate-900 dark:text-white">
              Start a chat
            </h3>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  if (e.target.value.trim()) {
                    setSearching(true);
                    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
                    searchTimerRef.current = setTimeout(async () => {
                      const { data } = await supabase
                        .from("profiles")
                        .select("*")
                        .ilike("username", `%${e.target.value}%`)
                        .neq("id", user?.id ?? "")
                        .limit(10);
                      setSearchResults(data ?? []);
                      setSearching(false);
                    }, 300);
                  } else {
                    setSearchResults([]);
                    setSearching(false);
                  }
                }}
                placeholder="Search username…"
                className="w-full rounded-lg border border-slate-200 dark:border-slate-600 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white pl-9 pr-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
              />
            </div>
            {searching && <p className="text-xs text-slate-500">Searching users…</p>}
            {searchResults.length > 0 && (
              <ul className="max-h-60 overflow-y-auto space-y-1">
                {searchResults.map((p) => (
                  <li
                    key={p.id}
                    onClick={() => startDirectChat(p)}
                    className="flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                  >
                    <div className="h-8 w-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center">
                      <User className="h-5 w-5 text-slate-600 dark:text-slate-300" />
                    </div>
                    <div>
                      <p className="text-sm text-slate-900 dark:text-white truncate">
                        {p.username}
                      </p>
                      {p.display_name && (
                        <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
                          {p.display_name}
                        </p>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {createChatError && (
              <p className="text-xs text-red-600 dark:text-red-400">
                {createChatError}
              </p>
            )}
            <button
              onClick={() => setCreateChat(false)}
              className="w-full py-2 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-white text-sm"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// Active thread (right panel / mobile full view)
// -----------------------------------------------------------------------------

interface ActiveThreadProps {
  conversation: ListedConversation;
  peerPublicKeys: PeerKeys;
  onLockChat: () => void;
  onUnlockChat: () => void;
  onViewOnce: (msg: { id: string; card: any; mimeType: string }) => void;
  onSafetyPeer: () => void;
}

function ActiveThread({
  conversation,
  peerPublicKeys,
  onLockChat,
  onUnlockChat,
  onViewOnce,
  onSafetyPeer,
}: ActiveThreadProps) {
  const { user } = useAuth();
  const [input, setInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [sending, setSending] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [disappearing, setDisappearing] = useState<"off" | "15s" | "1h" | "24h" | "7d">("off");

  const {
    messages,
    loading,
    error,
    onlineUsers,
    typingUsers,
    sendText,
    sendFile: hookSendFile,
    sendTyping,
    deleteForEveryone,
  } = useEncryptedChat({
    conversationId: conversation.id,
    peerUserId: conversation.peerUserId ?? "",
    peerPublicKeys,
  });

  const peerUserId = conversation.peerUserId;
  const isLocked = conversation.isLocked;

  const DISAPPEARING_MAP: Record<string, number | null> = {
    off: null,
    "15s": 15,
    "1h": 3_600,
    "24h": 86_400,
    "7d": 604_800,
  };

  useEffect(() => {
    setDisappearing(
      (conversation.disappearingSeconds ?? null) === null ? "off" : "24h",
    );
  }, [conversation.disappearingSeconds]);

  const expiresAt = useMemo(() => {
    const secs = DISAPPEARING_MAP[disappearing];
    if (!secs) return null;
    return new Date(Date.now() + secs * 1000).toISOString();
  }, [disappearing]);

  useEffect(() => {
    const el = messagesEndRef.current;
    if (el) el.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    setSending(true);
    await sendText(input.trim(), expiresAt);
    setInput("");
    setSending(false);
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setFile(f);
    setSending(true);
    await hookSendFile(f);
    setFile(null);
    setSending(false);
    e.target.value = "";
  };

  return (
    <div className="flex flex-col h-full border-l border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
      {/* Header */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700 bg-white/80 dark:bg-slate-900/80 backdrop-blur supports-[backdrop-filter]:bg-white/60 z-10">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-xl bg-indigo-100 dark:bg-indigo-900 flex items-center justify-center">
            <MessageCircle className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">
              {conversation.name ?? conversation.peer?.username ?? "Conversation"}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 truncate flex items-center gap-1">
              {onlineUsers.has(peerUserId ?? "") ? (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-green-500" />{" "}
                  Online
                </>
              ) : (
                <span>Offline</span>
              )}
              {typingUsers.has(peerUserId ?? "") && (
                <span className="ml-2 text-italic text-indigo-600 dark:text-indigo-400">typing…</span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onSafetyPeer}
            className="p-2 rounded-lg text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition"
            title="Verify safety number"
          >
            <Shield className="h-4 w-4" />
          </button>
          <select
            value={disappearing}
            onChange={(e) => setDisappearing(e.target.value as any)}
            className="text-xs bg-transparent text-slate-600 dark:text-slate-400 border-none focus:ring-0"
          >
            <option value="off">Disappearing: Off</option>
            <option value="15s">15s</option>
            <option value="1h">1h</option>
            <option value="24h">24h</option>
            <option value="7d">7d</option>
          </select>
          <button
            onClick={isLocked ? onUnlockChat : onLockChat}
            className="p-2 rounded-lg text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition"
            title={isLocked ? "Unlock chat" : "Lock chat"}
          >
            {isLocked ? <LockOpen className="h-4 w-4" /> : <Lock className="h-4 w-4" />}
          </button>
        </div>
      </header>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 space-y-4">
        {loading && <p className="text-center text-slate-500">Loading…</p>}
        {error && <p className="text-center text-xs text-red-600 dark:text-red-400">{error}</p>}
        {messages.map((msg) => {
          const isMine = msg.sender_id === user?.id;
          const status = isMine
            ? msg.raw.viewed_at
              ? "read"
              : "delivered"
            : null;
          return (
            <div
              key={msg.id}
              className={`flex ${
                isMine ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`max-w-[80%] rounded-xl p-3 break-words ${
                  isMine
                    ? "bg-indigo-600 text-white"
                    : "bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-white"
                }`}
              >
                {msg.is_view_once && msg.fileCard && (
                  <div className="mb-2 flex items-center gap-2 text-xs text-opacity-75">
                    <Eye className="h-3 w-3" /> View once media
                  </div>
                )}
                {msg.message_type === "file" && msg.fileCard ? (
                  <button
                    onClick={() => {
                      const card = msg.fileCard!;
                      onViewOnce({
                        id: msg.id,
                        card,
                        mimeType: card.mimeType,
                      });
                    }}
                    className="flex items-center gap-2"
                  >
                    <Image className="h-4 w-4" />
                    <div>
                      <div className="text-sm font-medium">
                        {msg.fileCard.name}
                      </div>
                      <div className="text-xs opacity-80">
                        {(msg.fileCard.size / 1024).toFixed(1)} KB
                      </div>
                    </div>
                  </button>
                ) : (
                  msg.decryptedText ??
                  (msg.signatureValid === false
                    ? "[Message could not be verified]"
                    : "[Encrypted]")
                )}
                <div className="text-[10px] text-opacity-60 mt-1 text-right">
                  {msg.created_at
                    ? new Date(msg.created_at).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })
                    : "--:--"}
                  {status === "read" ? (
                    <span className="ml-1 text-indigo-400">✓✓</span>
                  ) : status === "delivered" ? (
                    <span className="ml-1">✓</span>
                  ) : null}
                </div>
                {msg.deleted_for_everyone && (
                  <p className="text-[10px] text-slate-400 mt-1">
                    This message was deleted
                  </p>
                )}
              </div>
              {isMine && (
                <div className="ml-2 flex items-center gap-1">
                  <button
                    onClick={() => deleteForEveryone(msg.id)}
                    className="p-1 text-red-500 hover:bg-red-500/20 rounded transition"
                    title="Delete for everyone"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              )}
            </div>
          );
        })}
        <div ref={messagesEndRef} />
      </div>

      {/* Composer */}
      <footer className="border-t border-slate-200 dark:border-slate-700 bg-white/80 dark:bg-slate-900/80 backdrop-blur supports-[backdrop-filter]:bg-white/60 p-3">
        <div className="flex items-center gap-2">
          <label className="cursor-pointer">
            <Paperclip className="h-4 w-4 text-slate-500 hover:text-indigo-600 dark:hover:text-indigo-400" />
            <input type="file" onChange={handleFileChange} className="hidden" />
          </label>
          <form onSubmit={handleSend} className="flex-1">
            <div className="relative">
              <input
                value={input}
                onChange={(e) => {
                  setInput(e.target.value);
                  sendTyping(true);
                }}
                placeholder="Type a message…"
                className="w-full rounded-full border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white pl-4 pr-10 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent disabled:opacity-60"
                disabled={sending}
              />
              <button
                type="submit"
                disabled={sending || !input.trim()}
                className="absolute right-2 top-1/2 -translate-y-1/2 rounded-full bg-indigo-600 text-white p-1.5 disabled:opacity-50 transition"
              >
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </form>
          {file && (
            <div className="bg-slate-100 dark:bg-slate-800 rounded-lg px-2 py-1 text-xs text-slate-600 dark:text-slate-400 flex items-center gap-2">
              {file.name} — sending…
            </div>
          )}
        </div>
      </footer>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-slate-500 dark:text-slate-400">
      <MessageCircle className="h-12 w-12 mx-2 mb-3 opacity-50" />
      <h3 className="text-sm font-medium text-slate-900 dark:text-white">
        Select a conversation
      </h3>
      <p className="text-xs">Start an end-to-end encrypted chat from the sidebar</p>
    </div>
  );
}
