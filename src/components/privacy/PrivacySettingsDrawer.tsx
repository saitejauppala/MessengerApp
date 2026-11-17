"use client";

import { useEffect, useState } from "react";
import { Lock, ShieldAlert, Trash2, UserX, Zap } from "lucide-react";
import { supabase } from "../../lib/supabase";
import { useAuth } from "../../context/AuthContext";
import type { Database } from "../../types/database.types";
import {
  exportEncryptedVault,
  importEncryptedVault,
  type KeyBundle,
} from "../../crypto/e2ee";
import { getKeyPair, storeKeyPair } from "../../crypto/keystore";

type PrivacySettingsRow =
  Database["public"]["Tables"]["user_privacy_settings"]["Row"];
type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];

type BlockedUser = {
  blocked_id: string;
  created_at: string | null;
  profile: ProfileRow | null;
};

const VISIBILITY_OPTIONS = [
  { value: "everyone", label: "Everyone" },
  { value: "contacts", label: "Contacts Only" },
  { value: "nobody", label: "Nobody" },
] as const;

const DISAPPEARING_OPTIONS = [
  { value: null, label: "Off" },
  { value: 15, label: "15 seconds" },
  { value: 3_600, label: "1 hour" },
  { value: 86_400, label: "24 hours" },
  { value: 604_800, label: "7 days" },
] as const;

export interface PrivacySettingsDrawerProps {
  open: boolean;
  onClose: () => void;
}

export function PrivacySettingsDrawer({
  open,
  onClose,
}: PrivacySettingsDrawerProps) {
  const {
    user,
    privacySettings,
    updatePrivacySettings,
    identityKeys,
    setMemoryOnly,
  } = useAuth();

  const [saving, setSaving] = useState(false);
  const [saveOk, setSaveOk] = useState(false);
  const [blocked, setBlocked] = useState<BlockedUser[]>([]);
  const [blockLoading, setBlockLoading] = useState(false);
  const [blockSearch, setBlockSearch] = useState("");
  const [blockUsername, setBlockUsername] = useState("");
  const [blockError, setBlockError] = useState("");

  const [backupModal, setBackupModal] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [backupVault, setBackupVault] = useState("");
  const [backupImportJson, setBackupImportJson] = useState("");
  const [backupImportPass, setBackupImportPass] = useState("");

  const [noLocalCache, setNoLocalCache] = useState(false);

  const filteredBlocked = blocked.filter(
    (b) =>
      b.profile?.username?.toLowerCase().includes(blockSearch.toLowerCase()) ||
      b.profile?.display_name?.toLowerCase().includes(blockSearch.toLowerCase()),
  );

  useEffect(() => {
    if (!open) return;
    loadBlocked();
  }, [open]);

  async function loadBlocked() {
    if (!user) return;
    setBlockLoading(true);
    try {
      const { data: rows } = await supabase
        .from("blocked_users")
        .select("blocked_id, created_at")
        .eq("blocker_id", user.id)
        .order("created_at", { ascending: false });

      const ids = (rows ?? []).map((r) => r.blocked_id);
      let profiles: Record<string, ProfileRow> = {};
      if (ids.length) {
        const { data: profs } = await supabase
          .from("profiles")
          .select("id, username, display_name, avatar_url")
          .in("id", ids);
        profiles = Object.fromEntries(
          (profs ?? []).map((p) => [p.id, p]),
        ) as Record<string, ProfileRow>;
      }

      setBlocked(
        (rows ?? []).map((r) => ({
          blocked_id: r.blocked_id,
          created_at: r.created_at,
          profile: profiles[r.blocked_id] ?? null,
        })),
      );
    } finally {
      setBlockLoading(false);
    }
  }

  async function handleBlock() {
    if (!user) return;
    setBlockError("");
    const { data: target } = await supabase
      .from("profiles")
      .select("id")
      .eq("username", blockUsername.trim())
      .single();
    if (!target) {
      setBlockError("Username not found");
      return;
    }
    if (target.id === user.id) {
      setBlockError("You cannot block yourself");
      return;
    }
    const { error } = await supabase.from("blocked_users").insert({
      blocker_id: user.id,
      blocked_id: target.id,
    });
    if (error) {
      setBlockError(error.message);
      return;
    }
    setBlockUsername("");
    await loadBlocked();
  }

  async function handleUnblock(blockedId: string) {
    if (!user) return;
    const { error } = await supabase
      .from("blocked_users")
      .delete()
      .eq("blocker_id", user.id)
      .eq("blocked_id", blockedId);
    if (error) return;
    await loadBlocked();
  }

  async function updateSetting(
    field: keyof PrivacySettingsRow,
    value: PrivacySettingsRow[keyof PrivacySettingsRow],
  ) {
    if (!user) return;
    setSaving(true);
    setSaveOk(false);
    const { error } = await updatePrivacySettings({ [field]: value });
    setSaving(false);
    if (!error) {
      setSaveOk(true);
      setTimeout(() => setSaveOk(false), 1500);
    }
  }

  async function buildKeyBundle(): Promise<KeyBundle | null> {
    if (!user || !identityKeys) return null;
    const stored = await getKeyPair(user.id);
    if (stored) {
      return {
        userId: stored.userId,
        deviceId: stored.deviceId,
        ecdhPrivateKey: stored.ecdhPrivateKey,
        ecdsaPrivateKey: stored.ecdsaPrivateKey,
        ecdhPublicKey: stored.ecdhPublicKey,
        ecdsaPublicKey: stored.ecdsaPublicKey,
      };
    }
    const [ecdhPrivateJwk, ecdsaPrivateJwk] = await Promise.all([
      crypto.subtle.exportKey("jwk", identityKeys.ecdhPrivateKey),
      crypto.subtle.exportKey("jwk", identityKeys.ecdsaPrivateKey),
    ]);
    return {
      userId: user.id,
      deviceId: crypto.randomUUID(),
      ecdhPrivateKey: ecdhPrivateJwk as unknown as JsonWebKey,
      ecdsaPrivateKey: ecdsaPrivateJwk as unknown as JsonWebKey,
      ecdhPublicKey: identityKeys.ecdhPublicKey,
      ecdsaPublicKey: identityKeys.ecdsaPublicKey,
    };
  }

  async function handleExportBackup() {
    if (!backupPassphrase) return;
    const bundle = await buildKeyBundle();
    if (!bundle) return;
    try {
      const vault = await exportEncryptedVault(bundle, backupPassphrase);
      setBackupVault(vault);
    } catch {
      // invalid state; ignore
    }
  }

  async function handleImportBackup() {
    if (!user) return;
    try {
      const bundle = await importEncryptedVault(
        backupImportJson,
        backupImportPass,
      );
      await storeKeyPair(user.id, {
        userId: user.id,
        deviceId: crypto.randomUUID(),
        ecdhPrivateKey: bundle.ecdhPrivateKey,
        ecdsaPrivateKey: bundle.ecdsaPrivateKey,
        ecdhPublicKey: bundle.ecdhPublicKey,
        ecdsaPublicKey: bundle.ecdsaPublicKey,
      });
      setBackupImportJson("");
      setBackupImportPass("");
      setBackupModal(false);
    } catch {
      // invalid passphrase or corrupted vault
    }
  }

  const toggle = (
    key: keyof PrivacySettingsRow,
    label: string,
    hint: string,
    checked: boolean,
  ) => (
    <div className="flex items-center justify-between" key={key}>
      <div>
        <p className="text-sm text-slate-900 dark:text-white">{label}</p>
        <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>
      </div>
      <button
        onClick={() => updateSetting(key, !checked)}
        className="relative inline-flex w-11 h-6 shrink-0 rounded-full border border-slate-200 dark:border-slate-600 bg-slate-200 dark:bg-slate-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
        aria-checked={checked}
      >
        <span
          className={`block h-4 w-4 rounded-full bg-white transition-transform ${
            checked ? "bg-indigo-600 translate-x-6" : "translate-x-1"
          }`}
        />
      </button>
    </div>
  );

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative z-10 w-full max-w-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between p-6 border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
          <h2 className="text-lg font-semibold text-slate-900 dark:text-white">
            Privacy & Security
          </h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
          >
            <Lock className="h-5 w-5" />
          </button>
        </div>
        <div className="overflow-y-auto p-6 max-h-[70vh]">
          <div className="space-y-6">
            {/* Visibility section */}
            <section>
              <h3 className="text-sm font-medium text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <Zap className="h-4 w-4 text-indigo-600" />
                Visibility
              </h3>
              <div className="space-y-4">
                {[
                  {
                    key: "last_seen_visibility",
                    label: "Last Seen & Online Status",
                  },
                  { key: "avatar_visibility", label: "Profile Photo" },
                  { key: "bio_visibility", label: "Bio" },
                ].map(({ key, label }) => {
                  const value = (
                    privacySettings?.[key as keyof PrivacySettingsRow] ??
                    "contacts"
                  ) as PrivacySettingsRow["last_seen_visibility"];
                  return (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-sm text-slate-600 dark:text-slate-300">
                        {label}
                      </span>
                      <select
                        value={value}
                        onChange={(e) =>
                          updateSetting(
                            key as keyof PrivacySettingsRow,
                            e.target.value as PrivacySettingsRow["last_seen_visibility"],
                          )}
                        className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      >
                        {VISIBILITY_OPTIONS.map((o) => (
                          <option key={o.value} value={o.value}>
                            {o.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* Receipts & typing section */}
            <section className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <h3 className="text-sm font-medium text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <Zap className="h-4 w-4 text-indigo-600" />
                Receipts & Typing
              </h3>
              <div className="space-y-4">
                {[
                  {
                    key: "read_receipts",
                    label: "Read Receipts",
                    hint: "Others see when you read messages",
                  },
                  {
                    key: "typing_indicators",
                    label: "Typing Indicators",
                    hint: "Others see when you are typing",
                  },
                ].map(({ key, label, hint }) => {
                  const checked = !!(
                    privacySettings?.[key as keyof PrivacySettingsRow] ?? true
                  );
                  return toggle(
                    key as keyof PrivacySettingsRow,
                    label,
                    hint,
                    checked,
                  );
                })}
              </div>
            </section>

            {/* Privacy protections section */}
            <section className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <h3 className="text-sm font-medium text-slate-900 dark:text-white mb-4 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-indigo-600" />
                Privacy Protections
              </h3>
              <div className="space-y-4">
                {[
                  {
                    key: "hide_notification_content",
                    label: "Private Notification Previews",
                    hint: 'Shows "New encrypted message" instead of content',
                  },
                  {
                    key: "blur_on_unfocus",
                    label: "Blur on Tab Switch",
                    hint: "Blurs the screen when the tab loses focus",
                  },
                  {
                    key: "disable_link_previews",
                    label: "Disable Link Previews",
                    hint: "Prevents recipient IP leaks from link fetching",
                  },
                ].map(({ key, label, hint }) => {
                  const checked = !!(
                    privacySettings?.[key as keyof PrivacySettingsRow] ?? false
                  );
                  return toggle(
                    key as keyof PrivacySettingsRow,
                    label,
                    hint,
                    checked,
                  );
                })}

                {/* No Local Cache Mode (client-only) */}
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-slate-900 dark:text-white">
                      No Local Cache Mode
                    </p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Keys live only in memory (volatile)
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      const next = !noLocalCache;
                      setNoLocalCache(next);
                      setMemoryOnly(next);
                    }}
                    className="relative inline-flex w-11 h-6 shrink-0 rounded-full border border-slate-200 dark:border-slate-600 bg-slate-200 dark:bg-slate-700 transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <span
                      className={`block h-4 w-4 rounded-full bg-white transition-transform ${
                        noLocalCache ? "bg-indigo-600 translate-x-6" : "translate-x-1"
                      }`}
                    />
                  </button>
                </div>

                <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
                  <p className="text-sm text-slate-900 dark:text-white mb-3">
                    Default Disappearing Messages
                  </p>
                  <select
                    value={String(
                      privacySettings?.default_disappearing_seconds ?? "null",
                    )}
                    onChange={(e) => {
                      const v = e.target.value;
                      updateSetting(
                        "default_disappearing_seconds",
                        v === "null" ? null : Number(v),
                      );
                    }}
                    className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent w-48"
                  >
                    {DISAPPEARING_OPTIONS.map((o) => (
                      <option key={String(o.value)} value={String(o.value ?? "null")}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </section>

            {/* Blocked users section */}
            <section className="pt-4 border-t border-slate-100 dark:border-slate-800">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-medium text-slate-900 dark:text-white flex items-center gap-2">
                  <UserX className="h-4 w-4 text-indigo-600" />
                  Blocked Users
                </h3>
                {blocked.length === 0 && (
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    No blocked users
                  </p>
                )}
              </div>
              <div className="space-y-3">
                <div className="flex gap-2">
                  <input
                    value={blockUsername}
                    onChange={(e) => setBlockUsername(e.target.value)}
                    placeholder="Username to block"
                    className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  />
                  <button
                    onClick={handleBlock}
                    disabled={!blockUsername.trim()}
                    className="rounded-lg px-3 py-2 text-sm font-semibold bg-indigo-600 text-white disabled:opacity-50 transition"
                  >
                    Block
                  </button>
                </div>
                {blockError && (
                  <p className="text-xs text-red-600 dark:text-red-400">{blockError}</p>
                )}
                {blockLoading ? (
                  <p className="text-xs text-slate-500">Loading...</p>
                ) : (
                  <div>
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">
                      Search blocked users
                    </label>
                    <input
                      value={blockSearch}
                      onChange={(e) => setBlockSearch(e.target.value)}
                      placeholder="Search..."
                      className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent mb-3"
                    />
                    {filteredBlocked.length === 0 ? (
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        No matches
                      </p>
                    ) : (
                      <ul className="space-y-2">
                        {filteredBlocked.map((b) => (
                          <li
                            key={b.blocked_id}
                            className="flex items-center justify-between px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800"
                          >
                            <div className="flex items-center gap-3">
                              {b.profile?.avatar_url && (
                                <img
                                  src={b.profile.avatar_url}
                                  alt=""
                                  className="h-8 w-8 rounded-full object-cover"
                                />
                              )}
                              <div>
                                <p className="text-sm text-slate-900 dark:text-white">
                                  {b.profile?.username ?? b.blocked_id}
                                </p>
                                {b.profile?.display_name && (
                                  <p className="text-xs text-slate-500 dark:text-slate-400">
                                    {b.profile.display_name}
                                  </p>
                                )}
                              </div>
                            </div>
                            <button
                              onClick={() => handleUnblock(b.blocked_id)}
                              className="text-slate-400 hover:text-red-500 dark:hover:text-red-400"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}
              </div>
            </section>
          </div>
        </div>

        <div className="p-4 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            {saveOk && (
              <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
                <Zap className="h-3 w-3" /> Saved
              </span>
            )}
            {saving && <span>Saving...</span>}
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setBackupModal(true)}
              className="text-sm text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400 flex items-center gap-1"
            >
              <Lock className="h-3 w-3" /> Key Backup
            </button>
            <button
              onClick={onClose}
              className="rounded-lg px-4 py-2 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            >
              Done
            </button>
          </div>
        </div>

        {/* Key backup export / restore modal */}
        {backupModal && (
          <div className="fixed inset-0 z-60 flex items-center justify-center">
            <div
              className="fixed inset-0 bg-black/60 backdrop-blur-sm"
              onClick={() => setBackupModal(false)}
            />
            <div className="relative z-61 w-full max-w-md p-6 rounded-2xl bg-white dark:bg-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold text-slate-900 dark:text-white">
                  Encrypted Key Backup
                </h3>
                <button
                  onClick={() => setBackupModal(false)}
                  className="text-slate-400 hover:text-white"
                >
                  &times;
                </button>
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                Protect your identity keys with a passphrase. They never leave your device.
              </p>
              <div className="space-y-3 mb-4">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400">
                  Passphrase
                </label>
                <input
                  type="password"
                  value={backupPassphrase}
                  onChange={(e) => setBackupPassphrase(e.target.value)}
                  placeholder="Enter a strong passphrase"
                  className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
              <div className="flex gap-3">
                <button
                  onClick={handleExportBackup}
                  disabled={!backupPassphrase}
                  className="flex-1 py-2 rounded-lg bg-indigo-600 text-white text-sm font-semibold disabled:opacity-50 transition"
                >
                  Export Vault
                </button>
                <button
                  onClick={handleImportBackup}
                  className="px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white transition"
                >
                  Restore
                </button>
              </div>
              <div className="mt-4">
                <label className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 block">
                  Vault JSON (to restore, paste below)
                </label>
                <textarea
                  value={backupImportJson}
                  onChange={(e) => setBackupImportJson(e.target.value)}
                  placeholder="Paste exported vault JSON here"
                  rows={3}
                  className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-xs text-slate-600 dark:text-slate-300 font-mono p-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
                <input
                  type="password"
                  value={backupImportPass}
                  onChange={(e) => setBackupImportPass(e.target.value)}
                  placeholder="Restore passphrase"
                  className="mt-2 w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-sm text-slate-900 dark:text-white px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
              {backupVault && (
                <div className="mt-4 border border-slate-200 dark:border-slate-700 rounded-lg bg-slate-50 dark:bg-slate-900/50 p-3">
                  <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">
                    Exported vault JSON
                  </p>
                  <textarea
                    value={backupVault}
                    readOnly
                    rows={3}
                    className="w-full text-xs text-slate-600 dark:text-slate-300 bg-transparent font-mono"
                  />
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
