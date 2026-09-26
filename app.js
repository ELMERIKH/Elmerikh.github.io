/* Field Manual — site-wide gate + encrypted reader */
const SESSION_KEY = "fm.session.v1";

const FieldManual = (() => {
  let catalog = null;
  let vault = null;
  let cryptoKey = null;
  let decrypted = new Map(); // id -> {title, md}
  let docsMeta = [];

  function qs(sel, root = document) {
    return root.querySelector(sel);
  }

  function saveSession(password) {
    // Password only in sessionStorage for this tab (not localStorage).
    sessionStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ password, ts: Date.now() })
    );
  }

  function loadSession() {
    try {
      return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    } catch {
      return null;
    }
  }

  function clearSession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  function isUnlocked() {
    const s = loadSession();
    return !!(s && s.password);
  }

  async function fetchJson(url) {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to load ${url} (${res.status})`);
    return res.json();
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function setBusy(btn, busy, labelIdle) {
    if (!btn) return;
    btn.disabled = !!busy;
    btn.textContent = busy ? "Decrypting…" : labelIdle;
  }

  /** Probe first available vault to verify password (same KDF/salt for all domains in a build). */
  async function unlockSite(password) {
    if (!password) throw new Error("Enter the password");
    catalog = catalog || (await fetchJson("data/catalog.json"));
    if (!catalog.domains || !catalog.domains.length) {
      throw new Error("No domains in catalog");
    }
    const first = catalog.domains[0];
    const v = await fetchJson(first.vault);
    await FMCrypto.verifyPassword(v, password);
    saveSession(password);
    return password;
  }

  async function renderDomainGrid() {
    catalog = catalog || (await fetchJson("data/catalog.json"));
    const grid = qs("#domain-grid");
    if (!grid) return;
    grid.innerHTML = "";
    for (const d of catalog.domains) {
      const a = document.createElement("a");
      a.href = `reader.html?domain=${encodeURIComponent(d.id)}`;
      a.className = "card";
      a.style.setProperty("--card-accent", d.accent);
      a.innerHTML = `
        <div class="kicker">${escapeHtml(d.id)}</div>
        <h3>${escapeHtml(d.title)}</h3>
        <p>${escapeHtml(d.blurb)}</p>
        <div class="foot"><span>${d.count} modules</span><span class="go">open →</span></div>
      `;
      grid.appendChild(a);
    }
  }

  function showShell() {
    const gate = qs("#site-gate");
    const shell = qs("#site-shell");
    if (gate) gate.hidden = true;
    if (shell) shell.hidden = false;
    document.body.classList.add("unlocked");
  }

  function showGate() {
    const gate = qs("#site-gate");
    const shell = qs("#site-shell");
    if (gate) gate.hidden = false;
    if (shell) shell.hidden = true;
    document.body.classList.remove("unlocked");
  }

  async function initLanding() {
    const params = new URLSearchParams(location.search);
    const next = params.get("next");
    const errEl = qs("#gate-err");
    const pwEl = qs("#pw");
    const goBtn = qs("#gate-go");
    const form = qs("#gate-form");

    async function tryResume() {
      const session = loadSession();
      if (!session || !session.password) return false;
      try {
        await unlockSite(session.password);
        return true;
      } catch {
        clearSession();
        return false;
      }
    }

    async function afterUnlock() {
      if (next && next.startsWith("reader.html")) {
        location.replace(next);
        return;
      }
      showShell();
      await renderDomainGrid();
      const boot = qs("#boot-line");
      if (boot) {
        boot.textContent = "session ok · vaults mounted";
        boot.classList.add("ok");
      }
    }

    if (await tryResume()) {
      await afterUnlock();
      return;
    }

    showGate();
    if (pwEl) pwEl.focus();

    async function submit(e) {
      if (e) e.preventDefault();
      if (errEl) errEl.textContent = "";
      const password = (pwEl && pwEl.value) || "";
      setBusy(goBtn, true, "Unlock");
      try {
        await unlockSite(password);
        await afterUnlock();
      } catch (err) {
        if (errEl) errEl.textContent = err.message || "Unlock failed";
        if (pwEl) {
          pwEl.select();
          pwEl.focus();
        }
      } finally {
        setBusy(goBtn, false, "Unlock");
      }
    }

    if (form) form.addEventListener("submit", submit);
    else if (goBtn) goBtn.addEventListener("click", submit);
  }

  async function initReader() {
    const params = new URLSearchParams(location.search);
    const domainId = params.get("domain");
    const wantDoc = params.get("doc");
    const lock = qs("#lock");
    const reader = qs("#reader");
    const errEl = qs("#lock-err");
    const pwEl = qs("#pw2");
    const goBtn = qs("#lock-go");
    const form = qs("#lock-form");

    if (!domainId) {
      location.replace("./");
      return;
    }

    async function unlockWith(password) {
      if (!password) throw new Error("Enter the password");
      vault = await fetchJson(`data/${encodeURIComponent(domainId)}.vault.json`);
      cryptoKey = await FMCrypto.verifyPassword(vault, password);
      saveSession(password);
      docsMeta = (vault.domain && vault.domain.docs) || [];
      const side = qs("#side-title");
      if (side) side.textContent = vault.domain.title;
      document.documentElement.style.setProperty(
        "--accent",
        (vault.domain && vault.domain.accent) || "#3dd6c6"
      );
      if (lock) {
        lock.hidden = true;
        lock.setAttribute("aria-hidden", "true");
        // Remove from DOM so CSS/a11y cannot resurrect the lock overlay.
        lock.remove();
      }
      if (reader) reader.hidden = false;
      document.body.classList.add("unlocked");
      renderNav();
      const search = qs("#search");
      if (search && !search.dataset.bound) {
        search.dataset.bound = "1";
        search.addEventListener("input", renderNav);
      }
      const target =
        (wantDoc && docsMeta.find((d) => d.id === wantDoc)) || docsMeta[0];
      if (target) await openDoc(target.id);
    }

    const session = loadSession();
    if (session && session.password) {
      try {
        // Keep lock hidden while PBKDF2 runs (can take ~1–2s).
        if (lock) lock.hidden = true;
        if (reader) reader.hidden = true;
        await unlockWith(session.password);
        return;
      } catch (err) {
        clearSession();
        console.warn("session unlock failed", err);
      }
    }

    // Prefer redirect to site gate so nothing is exposed without unlock.
    const next = `reader.html?${params.toString()}`;
    location.replace(`./?next=${encodeURIComponent(next)}`);
    // Fallback UI if redirect is blocked (should not run in normal browsers).
    if (lock) lock.hidden = false;
    if (reader) reader.hidden = true;

    async function submit(e) {
      if (e) e.preventDefault();
      if (errEl) errEl.textContent = "";
      setBusy(goBtn, true, "Unlock");
      try {
        await unlockWith((pwEl && pwEl.value) || "");
      } catch (err) {
        if (errEl) errEl.textContent = err.message || "Unlock failed";
        if (pwEl) {
          pwEl.select();
          pwEl.focus();
        }
      } finally {
        setBusy(goBtn, false, "Unlock");
      }
    }

    if (form) form.addEventListener("submit", submit);
    else if (goBtn) goBtn.addEventListener("click", submit);
  }

  function renderNav() {
    const search = qs("#search");
    const q = ((search && search.value) || "").trim().toLowerCase();
    const nav = qs("#nav");
    if (!nav) return;
    nav.innerHTML = "";
    const groups = [];
    const map = new Map();
    for (const d of docsMeta) {
      if (
        q &&
        !d.title.toLowerCase().includes(q) &&
        !d.path.toLowerCase().includes(q)
      ) {
        continue;
      }
      if (!map.has(d.group)) {
        map.set(d.group, []);
        groups.push(d.group);
      }
      map.get(d.group).push(d);
    }
    for (const g of groups) {
      const box = document.createElement("div");
      box.className = "nav-group";
      box.innerHTML = `<h4>${escapeHtml(g)}</h4>`;
      for (const d of map.get(g)) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "nav-item";
        b.dataset.id = d.id;
        b.textContent = d.title;
        b.addEventListener("click", () => openDoc(d.id));
        box.appendChild(b);
      }
      nav.appendChild(box);
    }
  }

  async function openDoc(id) {
    const meta = docsMeta.find((d) => d.id === id);
    if (!meta) return;
    let body = decrypted.get(id);
    if (!body) {
      try {
        body = await FMCrypto.decryptDoc(cryptoKey, meta);
        decrypted.set(id, body);
      } catch {
        throw new Error("Decrypt failed — wrong password or corrupt vault");
      }
    }
    qs("#doc-title").textContent = body.title;
    qs("#doc-sub").textContent = meta.path;
    const article = qs("#article");
    article.classList.remove("reveal");
    void article.offsetWidth;
    const html =
      typeof marked !== "undefined"
        ? marked.parse(body.md, { mangle: false, headerIds: true })
        : `<pre>${escapeHtml(body.md)}</pre>`;
    article.innerHTML = html;
    article.classList.add("reveal");
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle("active", el.dataset.id === id);
    });
    history.replaceState(
      null,
      "",
      `reader.html?domain=${encodeURIComponent(vault.domain.id)}&doc=${encodeURIComponent(id)}`
    );
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function lockNow() {
    clearSession();
    location.href = "./";
  }

  return { initLanding, initReader, lockNow, isUnlocked };
})();

window.FieldManual = FieldManual;
