(function () {
  var SESSION = "fm.wrap.v1";
  var form = document.getElementById("f");
  var pwEl = document.getElementById("pw");
  var errEl = document.getElementById("err");
  var goBtn = document.getElementById("go");

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function saveSession(password) {
    try {
      sessionStorage.setItem(SESSION, JSON.stringify({ password: password, ts: Date.now() }));
    } catch (e) {}
  }

  function loadSession() {
    try {
      return JSON.parse(sessionStorage.getItem(SESSION) || "null");
    } catch (e) {
      return null;
    }
  }

  async function deriveKey(password, saltB64, iterations) {
    var baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: b64ToBytes(saltB64),
        iterations: iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
  }

  async function unlock(password) {
    var res = await fetch("data/site.vault.json", { cache: "no-store" });
    if (!res.ok) throw new Error("Failed to load site (" + res.status + ")");
    var vault = await res.json();
    var key = await deriveKey(password, vault.salt, vault.iter);
    var pt;
    try {
      pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: b64ToBytes(vault.iv) },
        key,
        b64ToBytes(vault.ct)
      );
    } catch (e) {
      throw new Error("Wrong password");
    }
    var html = new TextDecoder().decode(pt);
    saveSession(password);
    document.open();
    document.write(html);
    document.close();
  }

  async function submit(e) {
    if (e) e.preventDefault();
    errEl.textContent = "";
    goBtn.disabled = true;
    goBtn.textContent = "Opening…";
    try {
      await unlock(pwEl.value || "");
    } catch (err) {
      errEl.textContent = err.message || "Unlock failed";
      goBtn.disabled = false;
      goBtn.textContent = "Unlock";
      pwEl.focus();
      pwEl.select();
    }
  }

  form.addEventListener("submit", submit);

  var session = loadSession();
  if (session && session.password) {
    goBtn.disabled = true;
    goBtn.textContent = "Opening…";
    unlock(session.password).catch(function () {
      try {
        sessionStorage.removeItem(SESSION);
      } catch (e) {}
      goBtn.disabled = false;
      goBtn.textContent = "Unlock";
      pwEl.focus();
    });
  } else {
    pwEl.focus();
  }
})();
