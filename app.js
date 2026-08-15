/* CipherRelay — AES-256-GCM message encryption + RSA-OAEP-2048 key wrapping
   Everything runs client-side via the Web Crypto API (crypto.subtle).
   No backend, no network calls — safe to host as a static Firebase site. */

const $ = (id) => document.getElementById(id);

let rsaKeyPair = null; // { publicKey, privateKey } as CryptoKey objects

/* ---------------- base64 helpers ---------------- */
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBuf(b64) {
  const bin = atob(b64.trim());
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/* ---------------- key generation / persistence ---------------- */
async function generateRsaKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"]
  );
  const pub = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const priv = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  localStorage.setItem("cr_pub", bufToB64(pub));
  localStorage.setItem("cr_priv", bufToB64(priv));
  return keyPair;
}

async function importRsaKeyPairFromStorage() {
  const pubB64 = localStorage.getItem("cr_pub");
  const privB64 = localStorage.getItem("cr_priv");
  if (!pubB64 || !privB64) return null;
  const publicKey = await crypto.subtle.importKey(
    "spki", b64ToBuf(pubB64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
  );
  const privateKey = await crypto.subtle.importKey(
    "pkcs8", b64ToBuf(privB64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]
  );
  return { publicKey, privateKey };
}

async function ensureKeyPair(forceNew = false) {
  $("keyStatus").textContent = "Generating keypair…";
  $("keyStatus").classList.remove("error");
  if (!forceNew) {
    const existing = await importRsaKeyPairFromStorage().catch(() => null);
    if (existing) {
      rsaKeyPair = existing;
      renderKeyDisplays();
      $("keyStatus").textContent = "Keypair loaded from this browser's storage.";
      return;
    }
  }
  rsaKeyPair = await generateRsaKeyPair();
  renderKeyDisplays();
  $("keyStatus").textContent = "New 2048-bit RSA keypair generated.";
}

function renderKeyDisplays() {
  $("pubKeyOut").value = localStorage.getItem("cr_pub") || "";
  $("privKeyOut").value = localStorage.getItem("cr_priv") || "";
}

/* ---------------- AES-GCM message encryption ---------------- */
async function encryptMessage(plaintext) {
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);

  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const encryptedKeyBuf = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" }, rsaKeyPair.publicKey, rawAesKey
  );

  return {
    ciphertext: bufToB64(ciphertextBuf),
    iv: bufToB64(iv.buffer),
    encryptedKey: bufToB64(encryptedKeyBuf),
  };
}

async function decryptMessage(ciphertextB64, ivB64, encryptedKeyB64) {
  const encryptedKeyBuf = b64ToBuf(encryptedKeyB64);
  const rawAesKey = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, rsaKeyPair.privateKey, encryptedKeyBuf);
  const aesKey = await crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);

  const iv = new Uint8Array(b64ToBuf(ivB64));
  const ciphertextBuf = b64ToBuf(ciphertextB64);
  const plaintextBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ciphertextBuf);
  return new TextDecoder().decode(plaintextBuf);
}

/* ---------------- UI wiring ---------------- */
function setActiveTab(name) {
  document.querySelectorAll(".tab").forEach((t) => {
    const active = t.dataset.tab === name;
    t.classList.toggle("active", active);
    t.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `panel-${name}`);
  });
}

function highlightPipeline(step) {
  document.querySelectorAll(".pipe-step").forEach((el) => {
    el.classList.toggle("active", Number(el.dataset.step) <= step);
  });
}

function scrambleReveal(el, finalText, duration = 900) {
  const chars = "ABCDEF0123456789#%&$*/\\";
  const start = performance.now();
  function frame(now) {
    const t = Math.min(1, (now - start) / duration);
    let out = "";
    for (let i = 0; i < finalText.length; i++) {
      if (finalText[i] === " ") { out += " "; continue; }
      const revealAt = (i / finalText.length);
      out += t > revealAt + (1 - t) * 0.15 ? finalText[i] : chars[Math.floor(Math.random() * chars.length)];
    }
    el.textContent = out;
    if (t < 1) requestAnimationFrame(frame);
    else el.textContent = finalText;
  }
  requestAnimationFrame(frame);
}

async function init() {
  scrambleReveal($("scramble"), "AES + RSA READY");
  await ensureKeyPair(false);

  $("regenKeys").addEventListener("click", async () => {
    await ensureKeyPair(true);
    scrambleReveal($("scramble"), "KEYPAIR ROTATED");
  });

  $("togglePriv").addEventListener("click", () => {
    const box = $("privKeyOut");
    const hidden = box.classList.toggle("masked");
    $("togglePriv").textContent = hidden ? "show" : "hide";
  });

  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => setActiveTab(t.dataset.tab));
  });

  $("encryptBtn").addEventListener("click", async () => {
    const text = $("plaintextIn").value;
    if (!text.trim()) return;
    if (!rsaKeyPair) { await ensureKeyPair(false); }

    highlightPipeline(1);
    $("encryptBtn").disabled = true;
    $("encryptBtn").textContent = "Encrypting…";
    try {
      await new Promise((r) => setTimeout(r, 150));
      highlightPipeline(2);
      const result = await encryptMessage(text);
      highlightPipeline(3);
      await new Promise((r) => setTimeout(r, 150));
      highlightPipeline(4);

      $("outCiphertext").value = result.ciphertext;
      $("outIv").value = result.iv;
      $("outEncKey").value = result.encryptedKey;
      $("encryptOutput").hidden = false;
      $("encryptHint").hidden = false;

      // auto-fill the decrypt panel so the round trip "just works"
      $("inCiphertext").value = result.ciphertext;
      $("inIv").value = result.iv;
      $("inEncKey").value = result.encryptedKey;
    } finally {
      $("encryptBtn").disabled = false;
      $("encryptBtn").textContent = "Encrypt message";
      setTimeout(() => highlightPipeline(0), 1200);
    }
  });

  $("decryptBtn").addEventListener("click", async () => {
    $("decryptError").hidden = true;
    const ct = $("inCiphertext").value, iv = $("inIv").value, ek = $("inEncKey").value;
    if (!ct.trim() || !iv.trim() || !ek.trim()) {
      $("decryptError").textContent = "Fill in ciphertext, IV, and encrypted key first.";
      $("decryptError").hidden = false;
      return;
    }
    $("decryptBtn").disabled = true;
    $("decryptBtn").textContent = "Decrypting…";
    try {
      const plaintext = await decryptMessage(ct, iv, ek);
      $("outPlaintext").value = plaintext;
      $("decryptOutput").hidden = false;
    } catch (e) {
      $("decryptError").textContent = "Decryption failed — check the values match a message encrypted with the current keypair.";
      $("decryptError").hidden = false;
      $("decryptOutput").hidden = true;
    } finally {
      $("decryptBtn").disabled = false;
      $("decryptBtn").textContent = "Decrypt message";
    }
  });
}

init();
