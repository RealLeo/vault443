/* Small, GSAP-independent platform selection. Runs before CSS to avoid a wrong-OS flash. */
(() => {
  "use strict";
  const validPlatform = value => value === "windows" || value === "linux" ? value : null;
  function detectPlatform(nav = {}) {
    const ua = nav.userAgent || "";
    if (nav.userAgentData?.mobile || /Android|iPhone|iPad|iPod|Mobile|CrOS/i.test(ua)) return null;
    const platform = nav.userAgentData?.platform || nav.platform || "";
    if (/Windows|Win32|Win64/i.test(platform) || /Windows NT/i.test(ua)) return "windows";
    if (/Linux/i.test(platform) || /X11.*Linux/i.test(ua)) return "linux";
    return null;
  }
  function resolvePlatform(search, stored, nav) {
    return validPlatform(new URLSearchParams(search).get("platform")) || validPlatform(stored) || detectPlatform(nav) || "all";
  }
  if (typeof document === "undefined") {
    if (typeof module !== "undefined") module.exports = { validPlatform, detectPlatform, resolvePlatform };
    return;
  }
  const root = document.documentElement;
  const key = "vault443.platform";
  const read = () => { try { return window.localStorage.getItem(key); } catch { return null; } };
  const write = value => { try { window.localStorage.setItem(key, value); } catch {} };
  const resolve = () => resolvePlatform(window.location.search, read(), window.navigator);
  root.dataset.platform = resolve();

  function initialize() {
    const choices = [...document.querySelectorAll("[data-platform-select]")];
    const languages = [...document.querySelectorAll(".language-link")];
    const saveHistory = (method, platform) => {
      try {
        const url = new URL(window.location.href);
        if (method === "pushState") {
          url.searchParams.set("platform", platform);
          if (/^#download-(?:windows|linux)$/.test(url.hash)) url.hash = "#download";
        }
        window.history[method]({ ...window.history.state, vaultPlatform: platform }, "", url);
      } catch {} // Selection still works if history is unavailable.
    };
    const languageURL = link => {
      const url = new URL(link.href, window.location.href);
      const platform = validPlatform(root.dataset.platform);
      if (platform) url.searchParams.set("platform", platform); else url.searchParams.delete("platform");
      url.hash = window.location.hash;
      link.href = url.href;
    };
    function apply(platform) {
      const focusedPanel = document.activeElement?.closest("[data-platform-panel]");
      root.dataset.platform = platform;
      for (const choice of choices) {
        if (choice.dataset.platformSelect === platform) choice.setAttribute("aria-current", "true");
        else choice.removeAttribute("aria-current");
      }
      languages.forEach(languageURL);
      if (focusedPanel && platform !== "all" && focusedPanel.dataset.platformPanel !== platform) {
        choices.find(choice => choice.dataset.platformSelect === platform)?.focus({ preventScroll: true });
      }
      window.dispatchEvent(new Event("platformchange"));
    }
    apply(root.dataset.platform);
    saveHistory("replaceState", root.dataset.platform);
    for (const choice of choices) choice.addEventListener("click", event => {
      if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      event.preventDefault();
      const platform = choice.dataset.platformSelect;
      write(platform);
      if (root.dataset.platform !== platform || new URLSearchParams(window.location.search).get("platform") !== platform) saveHistory("pushState", platform);
      apply(platform);
    });
    languages.forEach(link => link.addEventListener("click", () => languageURL(link)));
    const restore = state => {
      const explicit = validPlatform(new URLSearchParams(window.location.search).get("platform"));
      apply(explicit || (state?.vaultPlatform === "all" ? "all" : validPlatform(state?.vaultPlatform)) || resolve());
    };
    window.addEventListener("popstate", event => restore(event.state));
    window.addEventListener("pageshow", event => { if (event.persisted) restore(window.history.state); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", initialize, { once: true });
  else initialize();
})();
