/**
 * src/crypto/keystore.ts
 *
 * Local key storage for E2EE identity private keys.
 *
 * Design notes:
 *  - Private keys never leave the client device. They are persisted to
 *    IndexedDB under the database "e2ee_keystore" in JWK form (the client
 *    exports them from extractable CryptoKey objects only for local backup).
 *  - A volatile, in-memory-only mode is available for "No Local Cache Mode":
 *    nothing is written to disk; keys live only in RAM for the session.
 *  - All IndexedDB access is promise-based and guarded so a missing/blocked
 *    IndexedDB (e.g. private browsing, older browsers) degrades gracefully.
 */

const DB_NAME = "e2ee_keystore";
const STORE_NAME = "identity_keys";
const DB_VERSION = 1;

export interface StoredKeyPair {
  userId: string;
  deviceId: string;
  ecdhPrivateKey: JsonWebKey;
  ecdsaPrivateKey: JsonWebKey;
  ecdhPublicKey: JsonWebKey;
  ecdsaPublicKey: JsonWebKey;
}

let dbPromise: Promise<IDBDatabase> | null = null;
let memoryOnly = false;
const memoryStore = new Map<string, StoredKeyPair>();

/**
 * Enable volatile in-memory-only storage ("No Local Cache Mode"). Nothing is
 * written to IndexedDB; keys exist only for the lifetime of the page.
 */
export function setMemoryOnly(flag: boolean): void {
  memoryOnly = flag;
}

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this environment");
  }
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("Failed to open keystore"));
    req.onblocked = () => {
      // Non-fatal; another tab holds an upgrade lock.
    };
  });
  return dbPromise;
}

function txComplete<T>(tx: IDBTransaction, result: T): Promise<T> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(result);
    tx.onerror = () => reject(tx.error ?? new Error("Keystore transaction failed"));
    tx.onabort = () => reject(new Error("Keystore transaction aborted"));
  });
}

/**
 * Initialise the keystore. Call once at app startup.
 */
export async function initKeystore(opts?: { memoryOnly?: boolean }): Promise<void> {
  if (opts?.memoryOnly) {
    memoryOnly = true;
    return;
  }
  memoryOnly = false;
  await openDb();
}

/**
 * Persist an identity key pair for a user/device. Overwrites any existing
 * entry for the same userId.
 */
export async function storeKeyPair(userId: string, keys: StoredKeyPair): Promise<void> {
  if (memoryOnly) {
    memoryStore.set(userId, keys);
    return;
  }
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).put(keys);
  await txComplete(tx, undefined);
}

/**
 * Load a stored identity key pair by userId. Returns null if not found.
 */
export async function getKeyPair(userId: string): Promise<StoredKeyPair | null> {
  if (memoryOnly) {
    return memoryStore.get(userId) ?? null;
  }
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readonly");
  const req = tx.objectStore(STORE_NAME).get(userId);
  return new Promise<StoredKeyPair | null>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error ?? new Error("Failed to read keystore"));
  });
}

/**
 * Remove a stored identity key pair by userId.
 */
export async function removeKeyPair(userId: string): Promise<void> {
  if (memoryOnly) {
    memoryStore.delete(userId);
    return;
  }
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).delete(userId);
  await txComplete(tx, undefined);
}

/**
 * List all stored key pairs (e.g. for multi-account / device list).
 */
export async function listKeyPairs(): Promise<StoredKeyPair[]> {
  if (memoryOnly) {
    return Array.from(memoryStore.values());
  }
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readonly");
  const req = tx.objectStore(STORE_NAME).getAll();
  return new Promise<StoredKeyPair[]>((resolve, reject) => {
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror = () => reject(req.error ?? new Error("Failed to list keystore"));
  });
}

/**
 * Clear all stored keys (e.g. logout / wipe).
 */
export async function clearKeystore(): Promise<void> {
  if (memoryOnly) {
    memoryStore.clear();
    return;
  }
  const db = await openDb();
  const tx = db.transaction(STORE_NAME, "readwrite");
  tx.objectStore(STORE_NAME).clear();
  await txComplete(tx, undefined);
}
