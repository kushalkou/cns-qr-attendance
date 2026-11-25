// Device binding with WebCrypto.
// The phone generates an ECDSA P-256 key pair with extractable=false: the private key can be USED
// to sign, but no script (not even ours) can read it out. It lives in this browser's IndexedDB.
// The server stores only the public key and checks every scan is signed by it.

const DB_NAME = "secureattend";
const STORE = "keys";

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const r = db.transaction(STORE).objectStore(STORE).get(key);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idbPut(key, val) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(val, key);
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

async function sha256hex(buf) {
  const h = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const Device = {
  supported() {
    return !!(window.crypto && crypto.subtle && window.indexedDB);
  },

  async getKey(userId) {
    return idbGet(`device-key-${userId}`);
  },

  async create(userId) {
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // private key NOT extractable
      ["sign", "verify"]
    );
    await idbPut(`device-key-${userId}`, pair);
    return pair;
  },

  async publicKeyB64(pair) {
    return b64(await crypto.subtle.exportKey("spki", pair.publicKey));
  },

  async fingerprint(pair) {
    const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
    return (await sha256hex(spki)).slice(0, 16);
  },

  // Must match crypto_core.scan_message: "<token>|<userId>|<ts>|<nonce>"
  async signScan(pair, token, userId) {
    const ts = Math.floor(Date.now() / 1000);
    const nonceBytes = crypto.getRandomValues(new Uint8Array(18));
    const nonce = b64(nonceBytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const msg = new TextEncoder().encode(`${token}|${userId}|${ts}|${nonce}`);
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, msg);
    return { token, ts, nonce, sig: b64(sig) };
  },
};
