"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { Database } from "../types/database.types";
import { supabase } from "../lib/supabase";
import { useAuth } from "../context/AuthContext";
import {
  decryptFile,
  decryptMessage,
  deriveSharedKey,
  encryptFile,
  encryptMessage,
  type EncryptedMessagePayload,
} from "../crypto/e2ee";

type ProfileRow = Database["public"]["Tables"]["profiles"]["Row"];
type MessageRow = Database["public"]["Tables"]["messages"]["Row"];
type ReceiptRow = Database["public"]["Tables"]["message_receipts"]["Row"];
type ConversationRow =
  Database["public"]["Tables"]["conversations"]["Row"];
type MemberRow = Database["public"]["Tables"]["conversation_members"]["Row"];

const FILES_BUCKET = "e2ee-files";
const VERIFIED_KEY_PREFIX = "MESSENGER_VERIFIED_KEY_";
const EXPIRY_POLL_MS = 30_000;

interface FileCard {
  path: string;
  wrappedKeyB64: string;
  wrappedIvB64: string;
  fileIvB64: string;
  name: string;
  mimeType: string;
  size: number;
}

interface ChatMessage {
  id: string;
  conversation_id: string;
  sender_id: string;
  message_type: string;
  is_view_once: boolean;
  viewed_at: string | null;
  expires_at: string | null;
  deleted_for_everyone: boolean;
  created_at: string | null;
  sender: ProfileRow | null;
  raw: MessageRow;
  decryptedText: string | null;
  fileCard: FileCard | null;
  signatureValid: boolean | null;
  senderKeyChanged: boolean;
}

interface UseEncryptedChatProps {
  conversationId: string;
  peerUserId: string;
  peerPublicKeys: { ecdh: JsonWebKey; ecdsa: JsonWebKey } | null;
}

interface UseEncryptedChatReturn {
  messages: ChatMessage[];
  loading: boolean;
  error: string | null;
  onlineUsers: Set<string>;
  typingUsers: Set<string>;
  keyChangeAlert: boolean;
  conversation: ConversationRow | null;
  members: MemberRow[];
  sendText: (text: string, expiresAt?: string | null) => Promise<void>;
  sendFile: (file: File) => Promise<void>;
  markRead: (messageId: string) => Promise<void>;
  sendTyping: (typing: boolean) => void;
  deleteForEveryone: (messageId: string) => Promise<void>;
  toggleLock: () => Promise<void>;
  downloadFile: (message: ChatMessage) => Promise<void>;
  openViewOnce: (message: ChatMessage) => Promise<string | null>;
}

export function useEncryptedChat({
  conversationId,
  peerUserId,
  peerPublicKeys,
}: UseEncryptedChatProps): UseEncryptedChatReturn {
  const { user, identityKeys, privacySettings } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [conversation, setConversation] = useState<ConversationRow | null>(
    null,
  );
  const [members, setMembers] = useState<MemberRow[]>([]);
  const [onlineUsers, setOnlineUsers] = useState<Set<string>>(new Set());
  const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
  const [keyChangeAlert, setKeyChangeAlert] = useState(false);

  const channelRef = useRef<ReturnType<typeof supabase.channel> | null>(null);
  const typingTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const expiryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);
  const sharedKeyRef = useRef<CryptoKey | null>(null);

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------

  const peerEcdh = useMemo(() => peerPublicKeys?.ecdh ?? null, [
    peerPublicKeys,
  ]);
  const peerEcdsa = useMemo(() => peerPublicKeys?.ecdsa ?? null, [
    peerPublicKeys,
  ]);

  const typingEnabled = useMemo(
    () => privacySettings?.typing_indicators !== false,
    [privacySettings?.typing_indicators],
  );
  const receiptsEnabled = useMemo(
    () => privacySettings?.read_receipts !== false,
    [privacySettings?.read_receipts],
  );

  async function ensureSharedKey(): Promise<CryptoKey | null> {
    if (sharedKeyRef.current) return sharedKeyRef.current;
    if (!identityKeys?.ecdhPrivateKey || !peerEcdh) return null;
    try {
      const key = await deriveSharedKey(identityKeys.ecdhPrivateKey, peerEcdh);
      sharedKeyRef.current = key;
      return key;
    } catch {
      return null;
    }
  }

  async function wrapKey(
    key: CryptoKey,
    plaintextB64: string,
  ): Promise<{ ciphertextB64: string; ivB64: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plaintextB64),
    );
    return {
      ciphertextB64: btoa(
        String.fromCharCode(...new Uint8Array(ciphertext)),
      ),
      ivB64: btoa(String.fromCharCode(...iv)),
    };
  }

  async function unwrapKey(
    key: CryptoKey,
    ciphertextB64: string,
    ivB64: string,
  ): Promise<string> {
    const iv = new Uint8Array(
      atob(ivB64).split("").map((c) => c.charCodeAt(0)),
    );
    const ciphertext = new Uint8Array(
      atob(ciphertextB64).split("").map((c) => c.charCodeAt(0)),
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext,
    );
    return new TextDecoder().decode(plain);
  }

  function isExpired(message: ChatMessage): boolean {
    if (!message.expires_at) return false;
    return new Date(message.expires_at) < new Date();
  }

  function verifiedKeyStorageKey() {
    return `${VERIFIED_KEY_PREFIX}${peerUserId}`;
  }

  function isPeerKeyVerified(): boolean {
    if (typeof localStorage === "undefined") return false;
    const stored = localStorage.getItem(verifiedKeyStorageKey());
    if (!stored || !peerEcdsa) return false;
    try {
      return stored === JSON.stringify(peerEcdsa);
    } catch {
      return false;
    }
  }

  async function loadMessages() {
    const { data, error: err } = await supabase
      .from("messages")
      .select("*")
      .eq("conversation_id", conversationId)
      .order("created_at", { ascending: true });

    if (err) {
      setError(err.message);
      setLoading(false);
      return;
    }

    const sharedKey = await ensureSharedKey();
    const decrypted = await Promise.all(
      (data ?? []).map(async (row) => decryptRow(row, sharedKey)),
    );

    setMessages(decrypted.filter(Boolean) as ChatMessage[]);
    setLoading(false);
    scheduleExpiryCleanup();
  }

  async function decryptRow(
    row: MessageRow,
    sharedKey: CryptoKey | null,
  ): Promise<ChatMessage | null> {
    if (row.deleted_for_everyone) return null;

    let decryptedText: string | null = null;
    let fileCard: FileCard | null = null;
    let signatureValid: boolean | null = null;

    // Verify signature + decrypt for text messages.
    if (
      row.message_type === "text" &&
      sharedKey &&
      identityKeys &&
      peerEcdsa
    ) {
      const payload: EncryptedMessagePayload = {
        ciphertext_b64: row.ciphertext,
        iv_b64: row.iv,
        signature_b64: row.signature ?? "",
        timestamp: Date.parse(row.created_at ?? "0"),
      };
      try {
        decryptedText = await decryptMessage(
          payload,
          sharedKey,
          peerEcdsa,
        );
        signatureValid = true;
      } catch {
        signatureValid = false;
        decryptedText = null;
      }
    } else if (row.message_type === "file" && sharedKey) {
      try {
        const card = JSON.parse(row.ciphertext) as FileCard;
        const wrappedKey = await unwrapKey(
          sharedKey,
          card.wrappedKeyB64,
          card.wrappedIvB64,
        );
        fileCard = { ...card, wrappedKeyB64: wrappedKey };
        signatureValid = row.signature
          ? await verifyFileSignature(card, row.signature)
          : null;
      } catch {
        fileCard = null;
        signatureValid = false;
      }
    }

    return {
      id: row.id,
      conversation_id: row.conversation_id,
      sender_id: row.sender_id,
      message_type: row.message_type,
      is_view_once: row.is_view_once,
      viewed_at: row.viewed_at,
      expires_at: row.expires_at,
      deleted_for_everyone: row.deleted_for_everyone,
      created_at: row.created_at,
      sender: null, // populated below
      raw: row,
      decryptedText,
      fileCard,
      signatureValid,
      senderKeyChanged: false,
    };
  }

  async function verifyFileSignature(
    card: FileCard,
    signatureB64: string,
  ): Promise<boolean> {
    if (!peerEcdsa || !identityKeys?.ecdsaPrivateKey) return false;
    try {
      const senderKey = await crypto.subtle.importKey(
        "jwk",
        peerEcdsa,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );
      const data = new TextEncoder().encode(JSON.stringify(card));
      const sig = new Uint8Array(
        atob(signatureB64).split("").map((c) => c.charCodeAt(0)),
      );
      return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        senderKey,
        sig,
        data,
      );
    } catch {
      return false;
    }
  }

  async function loadConversationAndMembers() {
    const { data: conv } = await supabase
      .from("conversations")
      .select("*")
      .eq("id", conversationId)
      .single();
    setConversation(conv ?? null);

    const { data: mems } = await supabase
      .from("conversation_members")
      .select("*")
      .eq("conversation_id", conversationId);
    setMembers(mems ?? []);
  }

  async function loadSenderProfiles() {
    const senderIds = [
      ...new Set(messages.map((m) => m.sender_id)),
    ];
    if (!senderIds.length) return;
    const { data: profiles } = await supabase
      .from("profiles")
      .select("*")
      .in("id", senderIds);
    const byId = Object.fromEntries(
      (profiles ?? []).map((p) => [p.id, p]),
    );
    setMessages((curr) =>
      curr.map((m) => ({ ...m, sender: byId[m.sender_id] ?? null })),
    );
  }

  // ------------------------------------------------------------------
  // Realtime subscription
  // ------------------------------------------------------------------

  useEffect(() => {
    mountedRef.current = true;
    loadConversationAndMembers();
    loadMessages();

    const channel = supabase.channel(`conv:${conversationId}`);

    // New messages
    channel.on(
      "postgres_changes",
      {
        event: "INSERT",
        schema: "public",
        table: "messages",
        filter: `conversation_id=eq.${conversationId}`,
      },
      async (payload) => {
        const row = payload.new as MessageRow;
        if (row.sender_id === user?.id) {
          // Echo of our own sent message already handled optimistically.
          return;
        }
        const sharedKey = await ensureSharedKey();
        const decrypted = await decryptRow(row, sharedKey);
        if (!decrypted) return;
        setMessages((curr) => {
          if (curr.some((m) => m.id === row.id)) return curr;
          return [...curr, { ...decrypted, sender: null }];
        });
        loadSenderProfiles();
        scheduleExpiryCleanup();
      },
    );

    // Message receipts (delivery / read)
    channel.on(
      "postgres_changes",
      {
        event: "INSERT",
        schema: "public",
        table: "message_receipts",
      },
      async (payload) => {
        const receipt = payload.new as ReceiptRow;
        const msg = messages.find((m) => m.id === receipt.message_id);
        if (!msg || msg.conversation_id !== conversationId) return;
        setMessages((curr) =>
          curr.map((m) =>
            m.id === receipt.message_id
              ? {
                  ...m,
                  raw: {
                    ...m.raw,
                    viewed_at:
                      receipt.read_at && receiptsEnabled
                        ? receipt.read_at
                        : m.raw.viewed_at,
                  },
                }
              : m,
          ),
        );
      },
    );

    // Typing indicators via broadcast
    channel.on(
      "broadcast",
      { event: "typing" },
      (payload: { payload: { user_id: string; typing: boolean } }) => {
        if (!typingEnabled) return;
        const { user_id, typing } = payload.payload;
        if (!user_id || user_id === user?.id) return;
        setTypingUsers((curr) => {
          const next = new Set(curr);
          if (typing) next.add(user_id);
          else next.delete(user_id);
          return next;
        });
      },
    );

    // Online status via presence
    channel.on(
      "presence",
      { event: "sync" },
      () => {
        const state = channel.presenceState();
        const now = Date.now();
        const online = new Set<string>();
        for (const [, presences] of Object.entries(state)) {
          for (const p of presences as any[]) {
            if (p.user_id && p.online_at && now - p.online_at < 120_000) {
              online.add(p.user_id);
            }
          }
        }
        setOnlineUsers(online);
      },
    );

    channel.subscribe();
    channelRef.current = channel;

    // Track presence
    if (user) {
      channel.track({
        user_id: user.id,
        online_at: Date.now(),
        conversation_id: conversationId,
      });
    }

    // Key-change alert: compare peer ECDSA key against locally verified key.
    if (peerEcdsa) {
      const verified = isPeerKeyVerified();
      const storedRaw = localStorage.getItem(
        `${VERIFIED_KEY_PREFIX}RAW_${peerUserId}`,
      );
      if (!verified && storedRaw) {
        try {
          const prev = JSON.parse(storedRaw) as JsonWebKey;
          const prevStr = JSON.stringify(prev);
          const curStr = JSON.stringify(peerEcdsa);
          if (prevStr !== curStr) {
            setKeyChangeAlert(true);
          }
        } catch {}
      } else if (!storedRaw) {
        localStorage.setItem(
          `${VERIFIED_KEY_PREFIX}RAW_${peerUserId}`,
          JSON.stringify(peerEcdsa),
        );
      }
    }

    // Periodic expired-message cleanup
    expiryTimerRef.current = setInterval(() => {
      cleanupExpiredMessages();
    }, EXPIRY_POLL_MS);

    return () => {
      mountedRef.current = false;
      if (user) {
        channel.untrack().catch(() => {});
      }
      channelRef.current = null;
      if (expiryTimerRef.current) clearInterval(expiryTimerRef.current);
      if (typingTimerRef.current) clearTimeout(typingTimerRef.current);
      supabase.removeChannel(channel);
    };
  }, [conversationId, user, typingEnabled, receiptsEnabled, peerEcdsa]);

  // ------------------------------------------------------------------
  // Actions
  // ------------------------------------------------------------------

  async function sendText(
    text: string,
    expiresAt?: string | null,
  ) {
    if (!user || !identityKeys || !sharedKeyRef.current || !peerEcdsa)
      return;
    try {
      const payload: EncryptedMessagePayload = await encryptMessage(
        text,
        sharedKeyRef.current,
        identityKeys.ecdsaPrivateKey,
      );
      const { error: err } = await supabase.from("messages").insert({
        conversation_id: conversationId,
        sender_id: user.id,
        ciphertext: payload.ciphertext_b64,
        iv: payload.iv_b64,
        signature: payload.signature_b64,
        message_type: "text",
        expires_at: expiresAt ?? null,
        created_at: new Date(payload.timestamp).toISOString(),
      });
      if (err) throw err;
      await markMessageDeliveredLocally();
    } catch (err: any) {
      setError(err?.message || "Failed to send message");
    }
  }

  async function sendFile(file: File) {
    if (!user || !identityKeys || !peerPublicKeys) return;
    const sharedKey = await ensureSharedKey();
    if (!sharedKey) {
      setError("Cannot establish shared key");
      return;
    }
    try {
      setError(null);
      const arrayBuffer = await file.arrayBuffer();
      const enc = await encryptFile(arrayBuffer);

      // Upload the .enc blob to Supabase Storage.
      const fileId = crypto.randomUUID();
      const path = `${conversationId}/${fileId}.enc`;
      const { error: upErr } = await supabase.storage
        .from(FILES_BUCKET)
        .upload(path, enc.encrypted, {
          contentType: "application/octet-stream",
          upsert: false,
        });
      if (upErr) throw upErr;

      // Wrap the file key with the shared key so only conversation members can unwrap.
      const wrapped = await wrapKey(sharedKey, enc.keyB64);

      // Sign the file card for integrity.
      const card: FileCard = {
        path,
        wrappedKeyB64: wrapped.ciphertextB64,
        wrappedIvB64: wrapped.ivB64,
        fileIvB64: enc.ivB64,
        name: file.name,
        mimeType: file.type,
        size: file.size,
      };
      const cardJson = JSON.stringify(card);
      const sig = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        identityKeys.ecdsaPrivateKey,
        new TextEncoder().encode(cardJson),
      );
      const signatureB64 = btoa(
        String.fromCharCode(...new Uint8Array(sig)),
      );

      const { error: insErr } = await supabase.from("messages").insert({
        conversation_id: conversationId,
        sender_id: user.id,
        ciphertext: cardJson,
        iv: enc.ivB64,
        signature: signatureB64,
        message_type: "file",
        created_at: new Date().toISOString(),
      });
      if (insErr) throw insErr;
    } catch (err: any) {
      setError(err?.message || "Failed to send file");
    }
  }

  async function markRead(messageId: string) {
    if (!user || !receiptsEnabled) return;
    await supabase.from("message_receipts").upsert(
      {
        message_id: messageId,
        user_id: user.id,
        read_at: new Date().toISOString(),
      },
      { onConflict: "message_id,user_id" },
    );
  }

  async function markMessageDeliveredLocally() {
    if (!user) return;
    // Best-effort delivery receipt for our own latest messages is handled
    // by recipients; we do not write delivered receipts for our own messages.
  }

  async function sendTyping(typing: boolean) {
    if (!typingEnabled || !user) return;
    if (typingTimerRef.current) clearTimeout(typingTimerRef.current);
    const channel = channelRef.current;
    if (!channel) return;
        channel.send({
          type: "broadcast",
          event: "typing",
          payload: { user_id: user.id, conversation_id: conversationId, typing },
        });
    if (typing) {
      typingTimerRef.current = setTimeout(() => {
        channel.send({
          type: "broadcast",
          event: "typing",
          payload: { user_id: user.id, conversation_id: conversationId, typing: false },
        });
      }, 2_000);
    }
  }

  async function deleteForEveryone(messageId: string) {
    if (!user) return;
    const { error: err } = await supabase
      .from("messages")
      .update({ deleted_for_everyone: true })
      .eq("id", messageId)
      .eq("sender_id", user.id);
    if (err) setError(err.message);
    else {
      setMessages((curr) =>
        curr.map((m) =>
          m.id === messageId ? { ...m, raw: { ...m.raw, deleted_for_everyone: true } } : m,
        ),
      );
    }
  }

  async function toggleLock() {
    if (!conversation) return;
    const { error: err } = await supabase
      .from("conversations")
      .update({ is_locked: !conversation.is_locked })
      .eq("id", conversationId);
    if (err) setError(err.message);
    else setConversation((c) => (c ? { ...c, is_locked: !c.is_locked } : c));
  }

  async function downloadFile(message: ChatMessage) {
    if (!message.fileCard) return;
    const { data, error } = await supabase.storage
      .from(FILES_BUCKET)
      .download(message.fileCard.path);
    if (error || !data) {
      setError(error?.message || "Failed to download file");
      return;
    }
    const arrayBuffer = await data.arrayBuffer();
    const decrypted = await decryptFile(
      arrayBuffer,
      message.fileCard.wrappedKeyB64,
      message.fileCard.fileIvB64,
    );
    const blob = new Blob([decrypted], { type: message.fileCard.mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = message.fileCard.name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  async function openViewOnce(message: ChatMessage): Promise<string | null> {
    if (!message.fileCard) return null;
    const { data, error } = await supabase.storage
      .from(FILES_BUCKET)
      .download(message.fileCard.path);
    if (error || !data) {
      setError(error?.message || "Failed to load view-once media");
      return null;
    }
    const arrayBuffer = await data.arrayBuffer();
    const decrypted = await decryptFile(
      arrayBuffer,
      message.fileCard.wrappedKeyB64,
      message.fileCard.fileIvB64,
    );
    const blob = new Blob([decrypted], { type: message.fileCard.mimeType });
    const url = URL.createObjectURL(blob);
    // Mark viewed_at
    await supabase
      .from("messages")
      .update({ viewed_at: new Date().toISOString() })
      .eq("id", message.id);
    return url;
  }

  async function cleanupExpiredMessages() {
    try {
      await supabase.rpc("cleanup_expired_messages");
      // Remove locally any now-expired messages
      setMessages((curr) => curr.filter((m) => !isExpired(m)));
    } catch {
      // Ignore cleanup failures
    }
  }

  function scheduleExpiryCleanup() {
    // Already running via interval; no-op here
  }

  // ------------------------------------------------------------------
  // Memoized return
  // ------------------------------------------------------------------

  const value: UseEncryptedChatReturn = useMemo(
    () => ({
      messages,
      loading,
      error,
      onlineUsers,
      typingUsers,
      keyChangeAlert,
      conversation,
      members,
      sendText,
      sendFile,
      markRead,
      sendTyping,
      deleteForEveryone,
      toggleLock,
      downloadFile,
      openViewOnce,
    }),
    [
      messages,
      loading,
      error,
      onlineUsers,
      typingUsers,
      keyChangeAlert,
      conversation,
      members,
      sendText,
      sendFile,
      markRead,
      sendTyping,
      deleteForEveryone,
      toggleLock,
      downloadFile,
      openViewOnce,
    ],
  );

  return value;
}
