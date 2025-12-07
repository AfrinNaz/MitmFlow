# MitmFlow

MitmFlow is a research prototype for **real-time detection of sensitive data leaks** in web traffic.
It combines:

- a `mitmproxy` Python add-on (`mitm_alerts_addon.py`) that scans outbound HTTP/HTTPS requests for
  emails, Canadian phone numbers, and Canadian postal codes; and
- a Chrome/Chromium extension that receives alerts via **Server-Sent Events (SSE)** and notifies the user.

This repository accompanies the paper:

> “Privacy Sentinel: Real-Time Detection of Sensitive Data Leaks in Web Traffic Using Network Interception and SSE Alerts”

## Project structure

```text
MitmFlow/
├─ mitmproxy-addon/
│  └─ mitm_alerts_addon.py    # mitmproxy add-on with PII detection + SSE server
├─ extension/
│  ├─ manifest.json           # MV3 manifest
│  ├─ background.js           # SSE client, notifications, badge logic
│  ├─ content.js              # in-page toast and user-activity tracking
│  ├─ popup.html              # extension popup UI
│  ├─ popup.js                # popup logic (last alert, etc.)
│  └─ icons/
│     └─ icon48.png
└─ docs/
   ├─ architecture.png        # architecture / detection diagram
   └─ screenshots/            # example alerts and SSE output 
