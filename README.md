# MitmFlow

**MitmFlow** is a research prototype for **real-time detection of sensitive personal data leaks in web traffic**.  
It combines a **mitmproxy-based network interceptor** with a **Chrome browser extension** to detect, analyze, and notify users when personally identifiable information (PII) is leaked to third parties via HTTP/HTTPS requests.

This project was developed as part of an academic research effort focused on **privacy-aware network monitoring and user-side alerting**.

---

## Key Features

- **Real-time PII leak detection** in outbound web traffic
- Detects:
  - Email addresses
  - Canadian phone numbers (with province mapping)
  - Canadian postal codes (FSA-based province inference)
- **Sensitive data masking** before sending alerts to the client
- **Server-Sent Events (SSE)** for low-latency browser notifications
- **De-duplication logic** to prevent alert spam
- **In-page visual warning** when a leak is detected
- **Browser notifications + popup history**
- Noise suppression for common tracking and analytics domains

---

## System Architecture

MitmFlow uses a hybrid architecture:

1. **mitmproxy add-on (Python)**  
   - Intercepts HTTP/HTTPS requests
   - Inspects URLs, headers, and body content
   - Identifies PII via regex-based detection
   - Masks sensitive values
   - Streams alerts via an embedded SSE server

2. **Chrome Extension**
   - Listens to SSE alerts
   - Displays system notifications
   - Shows alerts in an extension popup
   - Injects in-page warning banners

![Architecture Diagram](docs/architecture.png)

---

## Repository Structure

```text
MitmFlow/
├── mitmproxy-addon/
│   └── mitm_alerts_addon.py     # mitmproxy add-on + SSE server
├── extension/
│   ├── manifest.json
│   ├── background.js            # SSE client + notification logic
│   ├── content.js               # In-page visual alerts
│   ├── popup.html
│   ├── popup.js
│   └── icons/
├── docs/
│   ├── architecture.png
│   └── screenshots/
├── README.md
├── LICENSE
└── .gitignore

#Disclaimer

Requirements

Python 3.8+

mitmproxy

Chrome or any Chromium-based browser

Basic knowledge of HTTP/HTTPS proxy configuration
