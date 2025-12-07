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
Requirements

Python 3

mitmproxy

Chrome or Chromium-based browser with developer mode (for loading the extension)

Usage (short)

1.Start mitmproxy with the add-on: 
mitmproxy -s mitmproxy-addon/mitm_alerts_addon.py

2. Configure your browser to use the mitmproxy proxy and trust the mitmproxy CA certificate.
3. Load the Chrome extension in developer mode from the extension/ folder.
4. Browse target sites (e.g., medical / pharmacy / municipal). When emails, Canadian phone numbers,
or postal codes are detected, alerts appear as:desktop notifications, and an in-page toast “Network leak detected

Disclaimer

MitmFlow is a research and educational tool.
Use it only on traffic you are legally allowed to inspect and in controlled environments.
The author assumes no responsibility for misuse.
