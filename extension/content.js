// content.js
// - Detects real user activity (input + submit) and notifies background service worker.
// - Listens for background messages to show a lightweight in-page toast popup.

(() => {
  // Time (ms) of last user interaction on this page
  let lastUserActivity = 0;

  // Notify background service worker about user activity
  function bumpActivity() {
    lastUserActivity = Date.now();
    try {
      chrome.runtime.sendMessage({ cmd: "user-activity", time: lastUserActivity });
    } catch (e) {
      // service worker may be temporarily unavailable
    }
  }

  // Register events that indicate real user intention:
  // - input events (typing / selecting)
  // - form submit (explicit submit)
  // - change events
  document.addEventListener("input", () => bumpActivity(), { passive: true });
  document.addEventListener("submit", () => bumpActivity(), {
    passive: true,
    capture: true,
  });
  document.addEventListener("change", () => bumpActivity(), { passive: true });

  // Optional: also bump activity on focus in form controls
  document.addEventListener(
    "focusin",
    (ev) => {
      const t = ev.target;
      if (
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.isContentEditable)
      ) {
        bumpActivity();
      }
    },
    true
  );

  // ---- In-page toast UI for alerts (display minimal information) ----
  // The background will send messages { cmd: "psw-alert", category, title, message }
  function createToastContainer() {
    let existing = document.getElementById("psw-toast-container");
    if (existing) return existing;

    const container = document.createElement("div");
    container.id = "psw-toast-container";
    container.style.position = "fixed";
    container.style.zIndex = 2147483647;
    container.style.right = "12px";
    container.style.bottom = "12px";
    container.style.display = "flex";
    container.style.flexDirection = "column";
    container.style.gap = "8px";
    container.style.maxWidth = "320px";
    document.documentElement.appendChild(container);
    return container;
  }

  function showToast(title, text, lifetime = 5000) {
    const container = createToastContainer();
    if (!container) return;

    const card = document.createElement("div");
    card.style.background = "rgba(32,33,36,0.95)";
    card.style.color = "#fff";
    card.style.padding = "10px 12px";
    card.style.borderRadius = "8px";
    card.style.boxShadow = "0 6px 18px rgba(0,0,0,0.35)";
    card.style.fontFamily =
      "system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif";
    card.style.fontSize = "13px";
    card.style.lineHeight = "1.2";
    card.style.opacity = "0";
    card.style.transition = "opacity .18s ease, transform .18s ease";

    // If text is empty, just show the title line
    if (text) {
      card.innerHTML = `<strong style="display:block;margin-bottom:4px">${escapeHtml(
        title
      )}</strong><span>${escapeHtml(text)}</span>`;
    } else {
      card.innerHTML = `<strong style="display:block;">${escapeHtml(
        title
      )}</strong>`;
    }

    container.appendChild(card);

    // entrance
    requestAnimationFrame(() => {
      card.style.opacity = "1";
      card.style.transform = "translateY(0)";
    });

    // remove after lifetime
    setTimeout(() => {
      card.style.opacity = "0";
      setTimeout(() => card.remove(), 220);
    }, lifetime);
  }

  function escapeHtml(s = "") {
    return String(s).replace(/[&<>"']/g, (m) => {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
      }[m];
    });
  }

  // handle messages from background
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (!msg || !msg.cmd) return;

    if (msg.cmd === "psw-alert") {
      // ❗ Override any category/title from background –
      // always show the same generic toast text.
      const title = "Network leak detected";
      const message = ""; // no second line
      showToast(title, message, 6000);
    }
  });
})();
