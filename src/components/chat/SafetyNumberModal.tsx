"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldCheck, ShieldOff, X } from "lucide-react";
import { computeSafetyNumber } from "../../crypto/e2ee";

interface SafetyNumberModalProps {
  open: boolean;
  onClose: () => void;
  peerUserId: string;
  ourPublicKey: JsonWebKey;
  theirPublicKey: JsonWebKey;
}

function storageKey(peerUserId: string) {
  return `MESSENGER_VERIFIED_KEY_${peerUserId}`;
}

function digitColor(digit: number): string {
  const hues = [
    "#2563eb", "#7c3aed", "#db2777", "#be185d", "#dc2626",
    "#d97706", "#ca8a04", "#15803d", "#0f766e", "#0ea5e9",
  ];
  return hues[digit % hues.length];
}

export function SafetyNumberModal({
  open,
  onClose,
  peerUserId,
  ourPublicKey,
  theirPublicKey,
}: SafetyNumberModalProps) {
  const [fingerprint, setFingerprint] = useState("");
  const [computing, setComputing] = useState(true);
  const [verified, setVerified] = useState(false);
  const [error, setError] = useState("");

  const storage = useMemo(() => storageKey(peerUserId), [peerUserId]);

  useEffect(() => {
    if (!open) return;
    setComputing(true);
    setError("");
    computeSafetyNumber(ourPublicKey, theirPublicKey)
      .then((fp) => {
        setFingerprint(fp);
        setComputing(false);
        try {
          const stored = localStorage.getItem(storage);
          setVerified(stored === JSON.stringify(theirPublicKey));
        } catch {
          setVerified(false);
        }
      })
      .catch(() => {
        setError("Unable to compute safety number");
        setComputing(false);
      });
  }, [open, ourPublicKey, theirPublicKey, storage]);

  const groups = useMemo(() => {
    const g: string[] = [];
    for (let i = 0; i < fingerprint.length; i += 10) {
      g.push(fingerprint.slice(i, i + 10));
    }
    return g;
  }, [fingerprint]);

  const cells = useMemo(() => {
    return fingerprint.split("").map((d, i) => ({
      index: i,
      digit: d,
      color: digitColor(Number(d)),
    }));
  }, [fingerprint]);

  const handleToggleVerified = useCallback(() => {
    try {
      if (verified) {
        localStorage.removeItem(storage);
        setVerified(false);
      } else {
        localStorage.setItem(storage, JSON.stringify(theirPublicKey));
        setVerified(true);
      }
    } catch {
      // localStorage unavailable
    }
  }, [verified, storage, theirPublicKey]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative z-10 w-full max-w-md p-6 rounded-2xl bg-white dark:bg-slate-900 shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col gap-5">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-semibold text-slate-900 dark:text-white">
            Safety Number
          </h3>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 dark:hover:text-white"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="text-sm text-slate-500 dark:text-slate-400">
          Verify this safety number with your contact through a trusted
          channel. A match means your E2EE keys have not been intercepted.
        </p>

        {computing ? (
          <div className="flex items-center justify-center py-8 text-slate-500">
            Computing fingerprint…
          </div>
        ) : error ? (
          <div className="p-3 rounded-lg bg-red-50 text-xs text-red-700">
            {error}
          </div>
        ) : (
          <>
            <div className="flex flex-col items-center gap-3">
              <p className="text-xs font-medium text-slate-500 uppercase tracking-wider">
                60-digit fingerprint
              </p>
              <div className="text-xs font-mono text-slate-700 dark:text-slate-300 break-all text-center">
                {groups.join(" ")}
              </div>
              <div className="grid grid-cols-6 gap-1 w-full max-w-xs">
                {cells.map((cell) => (
                  <div
                    key={cell.index}
                    className="h-8 rounded-sm"
                    style={{ backgroundColor: cell.color }}
                    title={`Digit ${cell.index + 1}: ${cell.digit}`}
                  />
                ))}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Compare every digit with your contact.
              </p>
            </div>

            <div className="border-t border-slate-200 dark:border-slate-700 pt-4 flex items-center justify-between">
              <button
                onClick={handleToggleVerified}
                className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300 hover:text-indigo-600 dark:hover:text-indigo-400"
              >
                {verified ? (
                  <>
                    <ShieldCheck className="h-4 w-4 text-green-500" />
                    Mark as verified
                  </>
                ) : (
                  <>
                    <ShieldOff className="h-4 w-4" />
                    Mark as verified
                  </>
                )}
              </button>
              {verified && (
                <span className="text-xs text-green-600 dark:text-green-400 font-medium">
                  Verified
                </span>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
