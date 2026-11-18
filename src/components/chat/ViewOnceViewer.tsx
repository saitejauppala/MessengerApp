"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import { supabase } from "../../lib/supabase";
import { decryptFile } from "../../crypto/e2ee";

// FileCard is defined in the hook; we re-declare a minimal structural type here
// to keep this component independent of the hook's internal types.
export interface ViewOnceFileCard {
  path: string;
  wrappedKeyB64: string;
  fileIvB64: string;
  name: string;
  mimeType: string;
  size: number;
}

interface ViewOnceViewerProps {
  open: boolean;
  onClose: () => void;
  card: ViewOnceFileCard;
  onViewed: (messageId: string) => void;
  messageId: string;
}

export function ViewOnceViewer({
  open,
  onClose,
  card,
  onViewed,
  messageId,
}: ViewOnceViewerProps) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [viewed, setViewed] = useState(false);
  const urlRef = useRef<string | null>(null);

  const revoke = useCallback(() => {
    if (urlRef.current) {
      URL.revokeObjectURL(urlRef.current);
      urlRef.current = null;
    }
    setObjectUrl(null);
  }, []);

  // Revoke the ObjectURL whenever the modal closes or unmounts.
  useEffect(() => {
    if (!open) {
      revoke();
      setViewed(false);
    }
    return () => {
      revoke();
    };
  }, [open, revoke]);

  const isImage = card.mimeType.startsWith("image/");
  const isVideo = card.mimeType.startsWith("video/");

  const loadMedia = useCallback(async () => {
    if (!open || urlRef.current) return;
    setLoading(true);
    setError("");
    try {
      const { data, error } = await supabase.storage
        .from("e2ee-files")
        .download(card.path);
      if (error || !data) throw new Error(error?.message ?? "Download failed");

      const arrayBuffer = await data.arrayBuffer();
      const decrypted = await decryptFile(
        arrayBuffer,
        card.wrappedKeyB64,
        card.fileIvB64,
      );
      const blob = new Blob([decrypted], { type: card.mimeType });
      const url = URL.createObjectURL(blob);
      urlRef.current = url;
      setObjectUrl(url);

      if (!viewed) {
        setViewed(true);
        onViewed(messageId);
      }
    } catch (err: any) {
      setError(err?.message ?? "Failed to load media");
    } finally {
      setLoading(false);
    }
  }, [open, card, messageId, viewed, onViewed, revoke]);

  useEffect(() => {
    loadMedia();
  }, [loadMedia]);

  // Block right-click / context menu and dragging within the viewer.
  const handleContextMenu = (e: React.MouseEvent) => e.preventDefault();
  const handleDragStart = (e: React.DragEvent) => e.preventDefault();

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="fixed inset-0 bg-black/80 backdrop-blur-sm"
        onClick={onClose}
      />
      <div
        className="relative z-10 w-full max-w-2xl max-h-[90vh] rounded-2xl bg-white dark:bg-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden flex flex-col"
        onContextMenu={handleContextMenu}
        onDragStart={handleDragStart}
      >
        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white">
            View Once
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 flex items-center justify-center p-4 bg-slate-900/50">
          {loading && (
            <div className="text-slate-400">Loading media…</div>
          )}
          {error && (
            <div className="p-4 rounded-lg text-center">
              <p className="text-xs text-red-600 dark:text-red-400">{error}</p>
              <button
                onClick={loadMedia}
                className="mt-2 text-xs text-indigo-600 hover:underline"
              >
                Retry
              </button>
            </div>
          )}
          {objectUrl && (
            <>
              {isImage && (
                <img
                  src={objectUrl}
                  alt={card.name}
                  className="max-w-full max-h-[60vh] object-contain"
                  draggable={false}
                />
              )}
              {isVideo && (
                <video
                  src={objectUrl}
                  controls
                  className="max-w-full max-h-[60vh] object-contain"
                  draggable={false}
                />
              )}
              {!isImage && !isVideo && (
                <div className="flex flex-col items-center gap-2 text-slate-400">
                  <p className="text-sm">{card.name}</p>
                  <p className="text-xs">{card.mimeType}</p>
                  <button
                    onClick={() => {
                      const a = document.createElement("a");
                      a.href = objectUrl!;
                      a.download = card.name;
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                    }}
                    className="text-xs text-indigo-600 hover:underline disabled:opacity-50"
                    disabled={true}
                  >
                    Save blocked (view-once)
                  </button>
                </div>
              )}
            </>
          )}
        </div>

        <div className="p-3 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            {card.name} &bull; {(card.size / 1024).toFixed(1)} KB
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Media is decrypted in-memory only and is revoked when you close
            this view. Right-click and saving are disabled.
          </p>
        </div>
      </div>
    </div>
  );
}
