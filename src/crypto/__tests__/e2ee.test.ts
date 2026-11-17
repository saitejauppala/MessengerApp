/**
 * src/crypto/__tests__/e2ee.test.ts
 *
 * Vitest suite for the client-side E2EE cryptography layer.
 *
 * Covers:
 *   - Round-trip encryption / decryption
 *   - Tampered ciphertext rejection
 *   - Tampered signature rejection (signature verified before decryption)
 *   - Wrong sender key rejection
 *   - Fresh IV per encryption (same plaintext -> different ciphertext)
 *   - Binary file encrypt / decrypt
 *   - Symmetric safety numbers (A,B === B,A), determinism, 60 digits
 *   - PBKDF2 key backup / restore (valid + invalid passphrases)
 *   - Shared key derivation agreement (both sides derive the same key)
 */

import { describe, it, expect } from "vitest";
import {
  generateIdentityKeys,
  type IdentityKeyPair,
  deriveSharedKey,
  encryptMessage,
  decryptMessage,
  EncryptedMessagePayload,
  encryptFile,
  decryptFile,
  computeSafetyNumber,
  exportEncryptedVault,
  importEncryptedVault,
} from "../e2ee";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compares two AES-GCM keys without exporting them (they are non-extractable).
 * Encrypts the same plaintext with the same fixed IV under both keys and
 * compares the resulting ciphertexts. Equal keys produce equal ciphertext.
 */
async function symmetricKeysEqual(a: CryptoKey, b: CryptoKey): Promise<boolean> {
  const iv = new Uint8Array(12); // fixed IV, used for comparison only
  const plaintext = new TextEncoder().encode("key-comparison");
  const ca = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a, plaintext)
  );
  const cb = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, b, plaintext)
  );
  return ca.length === cb.length && ca.every((v, i) => v === cb[i]);
}

async function makeAliceAndBob() {
  const alice = await generateIdentityKeys();
  const bob = await generateIdentityKeys();
  const shared = await deriveSharedKey(alice.ecdhPrivateKey, bob.ecdhPublicKey);
  return { alice, bob, shared };
}

async function makeBundle(keys?: IdentityKeyPair) {
  keys = keys ?? (await generateIdentityKeys());
  return {
    userId: "user-vault",
    deviceId: "device-vault",
    ecdhPrivateKey: await crypto.subtle.exportKey("jwk", keys.ecdhPrivateKey),
    ecdsaPrivateKey: await crypto.subtle.exportKey("jwk", keys.ecdsaPrivateKey),
    ecdhPublicKey: keys.ecdhPublicKey,
    ecdsaPublicKey: keys.ecdsaPublicKey,
  };
}

// ---------------------------------------------------------------------------
// generateIdentityKeys
// ---------------------------------------------------------------------------

describe("generateIdentityKeys", () => {
  it("generates ECDH (P-256) and ECDSA (P-256) keypairs with JWK public keys", async () => {
    const keys = await generateIdentityKeys();

    expect(keys.ecdhPrivateKey).toBeInstanceOf(CryptoKey);
    expect(keys.ecdsaPrivateKey).toBeInstanceOf(CryptoKey);
    expect(keys.ecdhPublicKey.kty).toBe("EC");
    expect(keys.ecdhPublicKey.crv).toBe("P-256");
    expect(keys.ecdsaPublicKey.kty).toBe("EC");
    expect(keys.ecdsaPublicKey.crv).toBe("P-256");
    expect(typeof keys.ecdhPublicKey.x).toBe("string");
    expect(typeof keys.ecdsaPublicKey.x).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// deriveSharedKey
// ---------------------------------------------------------------------------

describe("deriveSharedKey", () => {
  it("both parties derive the identical shared AES-GCM key", async () => {
    const { alice, bob } = await makeAliceAndBob();

    const aliceDerived = await deriveSharedKey(alice.ecdhPrivateKey, bob.ecdhPublicKey);
    const bobDerived = await deriveSharedKey(bob.ecdhPrivateKey, alice.ecdhPublicKey);

    expect(await symmetricKeysEqual(aliceDerived, bobDerived)).toBe(true);
  });

  it("produces different keys for different peer public keys", async () => {
    const alice = await generateIdentityKeys();
    const bob = await generateIdentityKeys();
    const carol = await generateIdentityKeys();

    const k1 = await deriveSharedKey(alice.ecdhPrivateKey, bob.ecdhPublicKey);
    const k2 = await deriveSharedKey(alice.ecdhPrivateKey, carol.ecdhPublicKey);

    expect(await symmetricKeysEqual(k1, k2)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// encryptMessage / decryptMessage
// ---------------------------------------------------------------------------

describe("encryptMessage / decryptMessage", () => {
  it("round-trips plaintext through encrypt then decrypt", async () => {
    const { alice, shared } = await makeAliceAndBob();
    const plaintext = "Hello, this is a secret message! 🔐";

    const payload = await encryptMessage(plaintext, shared, alice.ecdsaPrivateKey);

    expect(payload).toHaveProperty("ciphertext_b64");
    expect(payload).toHaveProperty("iv_b64");
    expect(payload).toHaveProperty("signature_b64");
    expect(payload).toHaveProperty("timestamp");
    expect(typeof payload.timestamp).toBe("number");

    const decrypted = await decryptMessage(payload, shared, alice.ecdsaPublicKey);
    expect(decrypted).toBe(plaintext);
  });

  it("rejects tampered ciphertext", async () => {
    const { alice, shared } = await makeAliceAndBob();
    const payload = await encryptMessage("secret", shared, alice.ecdsaPrivateKey);

    const tampered: EncryptedMessagePayload = {
      ...payload,
      ciphertext_b64: payload.ciphertext_b64 === "AAAA" ? "BBBB" : "AAAA",
    };

    await expect(
      decryptMessage(tampered, shared, alice.ecdsaPublicKey)
    ).rejects.toThrow("Decryption failed");
  });

  it("rejects tampered signature (signature verified before decryption)", async () => {
    const { alice, shared } = await makeAliceAndBob();
    const payload = await encryptMessage("secret", shared, alice.ecdsaPrivateKey);

    const tampered: EncryptedMessagePayload = {
      ...payload,
      signature_b64: payload.signature_b64 === "AAAA" ? "BBBB" : "AAAA",
    };

    await expect(
      decryptMessage(tampered, shared, alice.ecdsaPublicKey)
    ).rejects.toThrow("Decryption failed");
  });

  it("rejects messages signed by a different sender key", async () => {
    const alice = await generateIdentityKeys();
    const bob = await generateIdentityKeys();
    const shared = await deriveSharedKey(alice.ecdhPrivateKey, bob.ecdhPublicKey);

    const payload = await encryptMessage("secret", shared, alice.ecdsaPrivateKey);

    // Decrypt with Bob's own ECDSA key as the supposed sender -> invalid signature.
    await expect(
      decryptMessage(payload, shared, bob.ecdsaPublicKey)
    ).rejects.toThrow("Decryption failed");
  });

  it("generates a fresh IV per encryption (same plaintext -> different ciphertext)", async () => {
    const { alice, shared } = await makeAliceAndBob();
    const plaintext = "repeat me";

    const p1 = await encryptMessage(plaintext, shared, alice.ecdsaPrivateKey);
    const p2 = await encryptMessage(plaintext, shared, alice.ecdsaPrivateKey);

    expect(p1.iv_b64).not.toBe(p2.iv_b64);
    expect(p1.ciphertext_b64).not.toBe(p2.ciphertext_b64);

    expect(await decryptMessage(p1, shared, alice.ecdsaPublicKey)).toBe(plaintext);
    expect(await decryptMessage(p2, shared, alice.ecdsaPublicKey)).toBe(plaintext);
  });

  it("produces a 12-byte IV (96-bit)", async () => {
    const { alice, shared } = await makeAliceAndBob();
    const payload = await encryptMessage("x", shared, alice.ecdsaPrivateKey);

    const ivBytes = new Uint8Array(
      atob(payload.iv_b64).split("").map((c) => c.charCodeAt(0))
    );
    expect(ivBytes.length).toBe(12);
  });
});

// ---------------------------------------------------------------------------
// encryptFile / decryptFile
// ---------------------------------------------------------------------------

describe("encryptFile / decryptFile", () => {
  it("round-trips binary media", async () => {
    const original = new Uint8Array([0, 1, 2, 3, 255, 254, 253, 42, 0, 0, 0]).buffer;

    const encrypted = await encryptFile(original as ArrayBuffer);
    expect(encrypted.encrypted).toBeInstanceOf(ArrayBuffer);
    expect(typeof encrypted.keyB64).toBe("string");
    expect(typeof encrypted.ivB64).toBe("string");

    const decrypted = await decryptFile(
      encrypted.encrypted as ArrayBuffer,
      encrypted.keyB64,
      encrypted.ivB64
    );
    expect(new Uint8Array(decrypted)).toEqual(new Uint8Array(original as ArrayBuffer));
  });

  it("rejects decryption with a wrong key", async () => {
    const original = new Uint8Array([1, 2, 3]).buffer as ArrayBuffer;
    const encrypted = await encryptFile(original);

    const wrongKey = crypto.getRandomValues(new Uint8Array(32));
    const wrongKeyB64 = btoa(String.fromCharCode(...wrongKey));

    await expect(
      decryptFile(encrypted.encrypted as ArrayBuffer, wrongKeyB64, encrypted.ivB64)
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// computeSafetyNumber
// ---------------------------------------------------------------------------

describe("computeSafetyNumber", () => {
  it("is symmetric: computeSafetyNumber(A, B) === computeSafetyNumber(B, A)", async () => {
    const { alice, bob } = await makeAliceAndBob();

    const ab = await computeSafetyNumber(alice.ecdhPublicKey, bob.ecdhPublicKey);
    const ba = await computeSafetyNumber(bob.ecdhPublicKey, alice.ecdhPublicKey);

    expect(ab).toBe(ba);
  });

  it("is deterministic (same inputs -> same fingerprint)", async () => {
    const { alice, bob } = await makeAliceAndBob();

    const f1 = await computeSafetyNumber(alice.ecdhPublicKey, bob.ecdhPublicKey);
    const f2 = await computeSafetyNumber(alice.ecdhPublicKey, bob.ecdhPublicKey);

    expect(f1).toBe(f2);
  });

  it("returns exactly 60 digits", async () => {
    const { alice, bob } = await makeAliceAndBob();

    const fp = await computeSafetyNumber(alice.ecdhPublicKey, bob.ecdhPublicKey);
    expect(/^\d{60}$/.test(fp)).toBe(true);
  });

  it("changes when the key pair changes", async () => {
    const alice = await generateIdentityKeys();
    const bob = await generateIdentityKeys();
    const carol = await generateIdentityKeys();

    const ab = await computeSafetyNumber(alice.ecdhPublicKey, bob.ecdhPublicKey);
    const ac = await computeSafetyNumber(alice.ecdhPublicKey, carol.ecdhPublicKey);

    expect(ab).not.toBe(ac);
  });
});

// ---------------------------------------------------------------------------
// exportEncryptedVault / importEncryptedVault
// ---------------------------------------------------------------------------

describe("exportEncryptedVault / importEncryptedVault", () => {
  it("round-trips a key bundle with a valid passphrase", async () => {
    const bundle = await makeBundle();
    const passphrase = "correct-passphrase-123";

    const encrypted = await exportEncryptedVault(bundle, passphrase);
    const vault = JSON.parse(encrypted);
    expect(vault).toHaveProperty("version", 1);
    expect(vault).toHaveProperty("salt");
    expect(vault).toHaveProperty("iv");
    expect(vault).toHaveProperty("ciphertext");

    const restored = await importEncryptedVault(encrypted, passphrase);
    expect(restored.userId).toBe("user-vault");
    expect(restored.deviceId).toBe("device-vault");
    expect(restored.ecdhPrivateKey).toBeDefined();
    expect(restored.ecdsaPrivateKey).toBeDefined();
  });

  it("rejects an invalid passphrase", async () => {
    const bundle = await makeBundle();
    const encrypted = await exportEncryptedVault(bundle, "correct-passphrase-123");

    await expect(
      importEncryptedVault(encrypted, "wrong-passphrase")
    ).rejects.toThrow();
  });

  it("rejects corrupted ciphertext", async () => {
    const bundle = await makeBundle();
    const encrypted = await exportEncryptedVault(bundle, "correct-passphrase-123");
    const vault = JSON.parse(encrypted);
    vault.ciphertext = vault.ciphertext === "AAAA" ? "BBBB" : "AAAA";

    await expect(
      importEncryptedVault(JSON.stringify(vault), "correct-passphrase-123")
    ).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// E2EE integration
// ---------------------------------------------------------------------------

describe("E2EE integration", () => {
  it("Alice can encrypt for Bob and Bob can decrypt; a wrong key cannot", async () => {
    const { alice, bob, shared } = await makeAliceAndBob();
    const mallory = await generateIdentityKeys();
    const malloryKey = await deriveSharedKey(mallory.ecdhPrivateKey, bob.ecdhPublicKey);

    // Same derived secret both directions (Alice->Bob and Bob->Alice agree).
    const bobToAlice = await deriveSharedKey(bob.ecdhPrivateKey, alice.ecdhPublicKey);
    expect(await symmetricKeysEqual(shared, bobToAlice)).toBe(true);

    const plaintext = "meet me at midnight";
    const payload = await encryptMessage(plaintext, shared, alice.ecdsaPrivateKey);

    // Bob decrypts with his copy of the shared key and Alice's public key.
    const decrypted = await decryptMessage(payload, bobToAlice, alice.ecdsaPublicKey);
    expect(decrypted).toBe(plaintext);

    // Mallory, who derives a different shared key, cannot decrypt.
    await expect(
      decryptMessage(payload, malloryKey, alice.ecdsaPublicKey)
    ).rejects.toThrow();
  });
});
