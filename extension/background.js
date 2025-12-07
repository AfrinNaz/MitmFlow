// background.js (MV3 service worker)
let sse = null;
const SSE_URL = "https://127.0.0.1:5000/sse"; // adjust if needed

// How long to keep Chrome notification visible (ms)
const NOTIFY_TTL_MS = 12000;

// Simple in-memory de-dup on the frontend (optional but helpful)
const frontSeen = new Map(); // key -> expiresAt

function frontShouldShow(key) {
  const now = Date.now();
  // purge
  for (const [k, exp] of frontSeen.entries()) {
    if (exp < now) frontSeen.delete(k);
  }
  const exp = frontSeen.get(key);
  if (exp && exp > now) return false;
  frontSeen.set(key, now + NOTIFY_TTL_MS);
  return true;
}

function showNotification(title, message) {
  chrome.notifications.create(
    {
      type: "basic",
      iconUrl: "icons/icon48.png",
      title,
      message,
      priority: 2,
    },
    (id) => {
      if (id && NOTIFY_TTL_MS > 0) {
        setTimeout(() => chrome.notifications.clear(id, () => {}), NOTIFY_TTL_MS);
      }
    }
  );
}

function setBadge(text) {
  try {
    chrome.action.setBadgeText({ text: text ? String(text) : "" });
    chrome.action.setBadgeBackgroundColor({ color: "#d93025" });
  } catch (e) {
    // ignore if not supported
  }
}

function saveLastAlert(alert) {
  chrome.storage.local.set({ lastAlert: alert });
}

// --- helper: hostname normalization & noise filtering ---

function normalizeHost(host) {
  if (!host) return "";
  host = host.toLowerCase();
  if (host.startsWith("www.")) host = host.slice(4);
  return host;
}

// You can keep some high-noise infra out if you want
const NOISE_HOSTS = new Set([
  "frog.wix.com",
  "ssl.google-analytics.com",
  "www.google-analytics.com",
  "play.google.com",
  "android.clients.google.com",
  "maps.googleapis.com",
  "update.googleapis.com",
  "google.com",
  "facebook.com",
  "canada.tt.omtrdc.net",
  "canada.sc.omtrdc.net"
]);

function isNoiseHost(host) {
  host = normalizeHost(host);
  return NOISE_HOSTS.has(host);
}

// Broadcast to all tabs (for content.js toast)
function broadcastLeak(category) {
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs) {
      if (tab.id && tab.url && /^https?:\/\//.test(tab.url)) {
        chrome.tabs.sendMessage(tab.id, {
          cmd: "psw-alert",
          category,
        });
      }
    }
  });
}

function connectSSE() {
  try {
    sse = new EventSource(SSE_URL);
  } catch (err) {
    console.error("SSE new EventSource failed:", err);
    setTimeout(connectSSE, 2000);
    return;
  }

  sse.onopen = () => {
    console.log("SSE open");
    setBadge("1");
  };

  sse.onmessage = (e) => {
    try {
      const alert = JSON.parse(e.data);

      const cat = alert.leak_category || alert.type || "unknown"; // "email" / "phone" / "address"
      const host = alert.host || "";
      const masked = alert.value_masked || "[masked]";

      // Ignore some noisy infrastructure if you like
      if (isNoiseHost(host)) {
        return;
      }

      // Build generic label for title (no (ON)/(BC) etc.)
      let label;
      if (cat === "email") label = "Email";
      else if (cat === "phone") label = "Phone";
      else if (cat === "address") label = "Address";
      else label = cat;

      const title = `Network leak detected: ${label}`;
      const msgHost = host ? ` • ${host}` : "";
      const message = `${masked}${msgHost}`;

      // Front-end de-dup (title + message)
      const frontKey = `${label}|${masked}|${normalizeHost(host)}`;
      if (!frontShouldShow(frontKey)) {
        return;
      }

      // Show OS-level notification
      showNotification(title, message);

      // Save to storage
      saveLastAlert({ title, message, raw: alert });

      // Badge indicator
      let badgeChar = "!";
      if (cat === "email") badgeChar = "E";
      else if (cat === "phone") badgeChar = "P";
      else if (cat === "address") badgeChar = "A";
      setBadge(badgeChar);

      // Trigger in-page popup toast on active tabs
      broadcastLeak(cat);
    } catch (err) {
      console.error("Failed to parse SSE data", err, e.data);
    }
  };

  sse.onerror = (e) => {
    console.warn("SSE error, reconnecting...", e);
    try {
      sse.close();
    } catch (x) {}
    setTimeout(connectSSE, 1500);
  };
}

// initialize SSE connection
connectSSE();

// popup request handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.cmd === "get-last-alert") {
    chrome.storage.local.get(["lastAlert"], (res) => {
      sendResponse({ lastAlert: res.lastAlert || null });
    });
    return true; // async
  }
});
