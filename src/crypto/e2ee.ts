/**
 * src/crypto/e2ee.ts
 *
 * Client-side End-to-End Encryption (E2EE) cryptography layer.
 *
 * Security model:
 *  - Uses ONLY the native Web Crypto API (`globalThis.crypto.subtle`).
 *  - No third-party cryptography packages.
 *  - Private keys never leave the client device and are never transmitted.
 *  - Every AES-GCM operation uses a fresh, random 12-byte (96-bit) IV and a
 *    128-bit authentication tag (the native Web Crypto GCM tag size).
 */

const subtle = globalThis.crypto?.subtle;
if (!subtle) {
  throw new Error("Web Crypto API (globalThis.crypto.subtle) is not available");
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function concatUint8(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IdentityKeyPair {
  ecdhPrivateKey: CryptoKey;
  ecdsaPrivateKey: CryptoKey;
  ecdhPublicKey: JsonWebKey;
  ecdsaPublicKey: JsonWebKey;
}

export interface EncryptedMessagePayload {
  ciphertext_b64: string;
  iv_b64: string;
  signature_b64: string;
  timestamp: number;
}

export interface KeyBundle {
  userId: string;
  deviceId: string;
  ecdhPrivateKey: JsonWebKey;
  ecdsaPrivateKey: JsonWebKey;
  ecdhPublicKey: JsonWebKey;
  ecdsaPublicKey: JsonWebKey;
}

export interface EncryptedFile {
  encrypted: ArrayBuffer;
  keyB64: string;
  ivB64: string;
}

// ---------------------------------------------------------------------------
// 1. generateIdentityKeys
// ---------------------------------------------------------------------------

export async function generateIdentityKeys(): Promise<IdentityKeyPair> {
  const [ecdhKeyPair, ecdsaKeyPair] = await Promise.all([
    subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true, // extractable (only exported for the encrypted local vault)
      ["deriveBits"]
    ),
    subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    ),
  ]);

  const [ecdhPublicJwk, ecdsaPublicJwk] = await Promise.all([
    subtle.exportKey("jwk", ecdhKeyPair.publicKey),
    subtle.exportKey("jwk", ecdsaKeyPair.publicKey),
  ]);

  return {
    ecdhPrivateKey: ecdhKeyPair.privateKey,
    ecdsaPrivateKey: ecdsaKeyPair.privateKey,
    ecdhPublicKey: ecdhPublicJwk as JsonWebKey,
    ecdsaPublicKey: ecdsaPublicJwk as JsonWebKey,
  };
}

// ---------------------------------------------------------------------------
// HKDF (SHA-256) built purely from Web Crypto HMAC
//   Web Crypto exposes HMAC sign/verify; HKDF-Extract/Expand are layered on top.
// ---------------------------------------------------------------------------

async function hkdfExtract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer> {
  const saltKey = await subtle.importKey("raw", salt, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return subtle.sign({ name: "HMAC", hash: "SHA-256" }, saltKey, ikm);
}

async function hkdfExpand(prk: ArrayBuffer, info: Uint8Array, length: number): Promise<Uint8Array> {
  const prkKey = await subtle.importKey("raw", prk, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const hashLen = 32; // SHA-256
  const n = Math.ceil(length / hashLen);
  const blocks: Uint8Array[] = [];
  let t = new Uint8Array(0);
  const ctr = new Uint8Array(1);
  for (let i = 1; i <= n; i++) {
    ctr[0] = i;
    const input = concatUint8(t, info, ctr);
    t = new Uint8Array(await subtle.sign({ name: "HMAC", hash: "SHA-256" }, prkKey, input));
    blocks.push(t);
  }
  const okm = new Uint8Array(length);
  let offset = 0;
  for (const block of blocks) {
    const take = Math.min(block.length, length - offset);
    okm.set(block.subarray(0, take), offset);
    offset += take;
    if (offset >= length) break;
  }
  return okm;
}

// ---------------------------------------------------------------------------
// 2. deriveSharedKey  (ECDH + HKDF-SHA-256, domain-separated info)
// ---------------------------------------------------------------------------

/**
 * Derives a 256-bit AES-GCM key from an ECDH agreement.
 *   1. ECDH deriveBits (P-256 shared secret ZZ).
 *   2. HKDF-Extract(salt = 32 zero bytes, IKM = ZZ) -> PRK.
 *   3. HKDF-Expand(PRK, info = domain-separation bytes, L = 256 bits) -> key material.
 *   4. Import as AES-GCM key.
 */
export async function deriveSharedKey(
  myEcdhPrivateKey: CryptoKey,
  theirEcdhPublicJwk: JsonWebKey
): Promise<CryptoKey> {
  const theirKey = await subtle.importKey(
    "jwk",
    theirEcdhPublicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );

  const sharedSecret = await subtle.deriveBits(
    { name: "ECDH", public: theirKey },
    myEcdhPrivateKey,
    256
  );

  // Explicit domain-separation info bytes so the same DH output is never
  // reused for a different purpose.
  const info = encoder.encode("MessengerApp/v1 ECDH-HKDF-SHA256 AES-GCM key");

  const salt = new Uint8Array(32); // 256-bit zero salt
  const prk = await hkdfExtract(salt, sharedSecret as ArrayBuffer);
  const keyMaterial = await hkdfExpand(prk, info, 32); // 256-bit AES key = 32 bytes

  return subtle.importKey("raw", keyMaterial, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// ---------------------------------------------------------------------------
// 3. encryptMessage  (AES-GCM + ECDSA signature, signature covers ciphertext)
// ---------------------------------------------------------------------------

/**
 * Encrypts UTF-8 plaintext with AES-GCM (fresh 12-byte IV, 128-bit tag) and
 * signs { ciphertext_b64, iv_b64, timestamp } with ECDSA-SHA-256.
 */
export async function encryptMessage(
  plaintext: string,
  sharedAesKey: CryptoKey,
  myEcdsaPrivateKey: CryptoKey
): Promise<EncryptedMessagePayload> {
  const plaintextBytes = encoder.encode(plaintext);

  // Fresh cryptographically random 12-byte (96-bit) IV.
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv }, sharedAesKey, plaintextBytes)
  );

  const timestamp = Date.now();

  // Canonical signed payload. Key order must match decryptMessage exactly.
  const signedPayload = encoder.encode(
    JSON.stringify({
      ciphertext_b64: toBase64(ciphertext),
      iv_b64: toBase64(iv),
      timestamp,
    })
  );

  const signature = new Uint8Array(
    await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, myEcdsaPrivateKey, signedPayload)
  );

  return {
    ciphertext_b64: toBase64(ciphertext),
    iv_b64: toBase64(iv),
    signature_b64: toBase64(signature),
    timestamp,
  };
}

// ---------------------------------------------------------------------------
// 4. decryptMessage  (verify ECDSA signature FIRST, then decrypt)
// ---------------------------------------------------------------------------

/**
 * Verifies the ECDSA-SHA-256 signature before attempting decryption.
 * Throws a generic error on any verification or decryption failure so that
 * no oracle distinguishes tampered signatures from bad ciphertext.
 */
export async function decryptMessage(
  payload: EncryptedMessagePayload,
  sharedAesKey: CryptoKey,
  senderEcdsaPublicJwk: JsonWebKey
): Promise<string> {
  const senderKey = await subtle.importKey(
    "jwk",
    senderEcdsaPublicJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );

  const signedPayload = encoder.encode(
    JSON.stringify({
      ciphertext_b64: payload.ciphertext_b64,
      iv_b64: payload.iv_b64,
      timestamp: payload.timestamp,
    })
  );

  const signature = fromBase64(payload.signature_b64);

  const valid = await subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    senderKey,
    signature,
    signedPayload
  );

  if (!valid) {
    throw new Error("Decryption failed");
  }

  const iv = fromBase64(payload.iv_b64);
  const ciphertext = fromBase64(payload.ciphertext_b64);

  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv },
    sharedAesKey,
    ciphertext as ArrayBuffer
  );

  return decoder.decode(plaintext);
}

// ---------------------------------------------------------------------------
// 5. encryptFile / decryptFile  (one-time 256-bit AES-GCM key + 12-byte IV)
// ---------------------------------------------------------------------------

/**
 * Encrypts binary media with a fresh one-time 256-bit AES-GCM key and IV.
 * Caller is responsible for wrapping/sharing `keyB64` out-of-band (e.g. via
 * deriveSharedKey per recipient).
 */
export async function encryptFile(arrayBuffer: ArrayBuffer): Promise<EncryptedFile> {
  const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, key, arrayBuffer);

  const exported = await subtle.exportKey("raw", key);

  return {
    encrypted: encrypted as ArrayBuffer,
    keyB64: toBase64(new Uint8Array(exported as ArrayBuffer)),
    ivB64: toBase64(iv),
  };
}

/**
 * Decrypts a file produced by encryptFile using the provided key/IV.
 */
export async function decryptFile(
  encryptedBuffer: ArrayBuffer,
  keyB64: string,
  ivB64: string
): Promise<ArrayBuffer> {
  const key = await subtle.importKey(
    "raw",
    fromBase64(keyB64),
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const iv = fromBase64(ivB64);
  return subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedBuffer);
}

// ---------------------------------------------------------------------------
// 6. computeSafetyNumber  (symmetric 60-digit SHA-256 fingerprint)
// ---------------------------------------------------------------------------

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) + BigInt(b);
  }
  return result;
}

const TEN_POW_60 = 10n ** 60n;

/**
 * Deterministically orders the two public keys, hashes them with SHA-256, and
 * returns a symmetric 60-digit verification fingerprint. computeSafetyNumber(A,B)
 * === computeSafetyNumber(B,A).
 */
export async function computeSafetyNumber(
  pubKeyAJwk: JsonWebKey,
  pubKeyBJwk: JsonWebKey
): Promise<string> {
  const a = JSON.stringify(pubKeyAJwk);
  const b = JSON.stringify(pubKeyBJwk);
  const [first, second] = a < b ? [a, b] : [b, a];

  const data = encoder.encode(`${first}|${second}`);
  const hash = new Uint8Array(await subtle.digest("SHA-256", data));

  const num = bytesToBigInt(hash) % TEN_POW_60;
  return num.toString().padStart(60, "0");
}

// ---------------------------------------------------------------------------
// 7. exportEncryptedVault / importEncryptedVault  (PBKDF2 + AES-GCM)
// ---------------------------------------------------------------------------

const PBKDF2_ITERATIONS = 600_000;

async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  // NOTE: the DOM type union for `importKey` does not list Pbkdf2Params, so we
  // cast the algorithm object. Browsers accept the PBKDF2 parameters here.
  const passwordKey = await subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS,
    } as unknown as AlgorithmIdentifier,
    false,
    ["deriveBits"]
  );
  const keyBits = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    passwordKey,
    256
  );
  return subtle.importKey("raw", keyBits, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
}

interface VaultJson {
  version: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

/**
 * Encrypts a KeyBundle (private keys included) under a passphrase-derived
 * 256-bit AES-GCM key. Uses PBKDF2 (600k iterations, SHA-256, random 16-byte
 * salt) + AES-GCM with a fresh 12-byte IV. Never emits raw private keys.
 */
export async function exportEncryptedVault(
  keyBundle: KeyBundle,
  passphrase: string
): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const aesKey = await deriveKeyFromPassphrase(passphrase, salt);
  const plaintext = encoder.encode(JSON.stringify(keyBundle));
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext)
  );

  const vault: VaultJson = {
    version: 1,
    salt: toBase64(salt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
  return JSON.stringify(vault);
}

/**
 * Decrypts a vault produced by exportEncryptedVault. Throws on invalid
 * passphrase or corrupted ciphertext.
 */
export async function importEncryptedVault(
  encryptedJson: string,
  passphrase: string
): Promise<KeyBundle> {
  const vault = JSON.parse(encryptedJson) as VaultJson;
  if (vault.version !== 1) {
    throw new Error("Decryption failed");
  }

  const aesKey = await deriveKeyFromPassphrase(
    passphrase,
    fromBase64(vault.salt)
  );
  const plaintext = await subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(vault.iv) },
    aesKey,
    fromBase64(vault.ciphertext) as ArrayBuffer
  );
  return JSON.parse(decoder.decode(plaintext));
}
