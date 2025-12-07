// popup.js
const content = document.getElementById("content");
const refresh = document.getElementById("refresh");

function render(alert) {
  if (!alert) {
    content.innerHTML = '<div class="none">No recent alerts</div>';
    return;
  }
  const title = alert.title || "Network leak detected";
  const message = alert.message || "";
  // simple parse: type shown from title
  const typeMatch = title.match(/:?\s*(.+)$/);
  const typeText = typeMatch ? typeMatch[1] : "";
  content.innerHTML = `
    <div class="alert">
      <div class="type">${title}</div>
      <div class="masked">${message}</div>
    </div>
  `;
}

function fetchLastAlert() {
  chrome.runtime.sendMessage({ cmd: "get-last-alert" }, (res) => {
    if (res && res.lastAlert) {
      render(res.lastAlert);
    } else {
      render(null);
    }
  });
}

refresh.addEventListener("click", fetchLastAlert);

document.addEventListener("DOMContentLoaded", fetchLastAlert);
