/* WebCrypto helpers — AES-GCM + PBKDF2-SHA256 (matches site/build_pages.py) */
const VERIFY_PLAIN = "CHEATSHEETS-OK-v1";

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(password, saltB64, iterations) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64ToBytes(saltB64),
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

async function decryptBytes(key, ivB64, ctB64) {
  const iv = b64ToBytes(ivB64);
  const ct = b64ToBytes(ctB64);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

async function decryptText(key, ivB64, ctB64) {
  const bytes = await decryptBytes(key, ivB64, ctB64);
  return new TextDecoder().decode(bytes);
}

async function verifyPassword(vault, password) {
  if (!vault || !vault.salt || !vault.verify || !vault.iter) {
    throw new Error("Invalid vault");
  }
  const key = await deriveKey(password, vault.salt, vault.iter);
  try {
    const plain = await decryptText(key, vault.verify.iv, vault.verify.ct);
    if (plain !== VERIFY_PLAIN) throw new Error("bad verify");
    return key;
  } catch {
    throw new Error("Wrong password");
  }
}

async function decryptDoc(key, docMeta) {
  const json = await decryptText(key, docMeta.iv, docMeta.ct);
  return JSON.parse(json);
}

window.FMCrypto = { deriveKey, decryptText, decryptDoc, verifyPassword, VERIFY_PLAIN };
