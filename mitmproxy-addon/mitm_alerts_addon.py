#!/usr/bin/env python3
"""
mitm_alerts_addon.py — PII watcher with Canadian phone & postal code tags

Emits only these leak_category values:
  - "email"
  - "phone"   (Canadian area-code mapped only, others ignored)
  - "address" (Canadian postal codes only)


"""

import os
import re
import json
import ssl
import time
import hashlib
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import unquote_plus, urlparse
from mitmproxy import ctx, http

# --------------------------- Config ---------------------------

HOST = "127.0.0.1"
PORT = int(os.getenv("MITM_ALERTS_PORT", "5000"))

CERTFILE = os.getenv(
    "MITM_ALERTS_CERT",
    os.path.expanduser("~/mitm_local_certs/cert.pem")
)
KEYFILE = os.getenv(
    "MITM_ALERTS_KEY",
    os.path.expanduser("~/mitm_local_certs/key.pem")
)

MAX_ALERTS = 300
DEDUP_TTL_SECONDS = 20  # 20s de-dup per (kind, masked, host)

# --------------------------- Patterns ---------------------------

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)

# North American Numbering Plan (captures area code as group(1))
NANP_RE = re.compile(
    r'(?:\+1[\s\-]?)?(?:\(?([2-9]\d{2})\)?[\s\.\-]?)(\d{3})[\s\.\-]?(\d{4})'
)

# Canadian postal code:
# Letter Digit Letter [space/hyphen optional] Digit Letter Digit
# Valid FSA letters: A,B,C,E,G,H,J,K,L,M,N,P,R,S,T,V,X,Y
POSTAL_CA_RE = re.compile(
    r'\b([ABCEGHJ-NPRSTVXY])\d[ABCEGHJ-NPRSTVWXYZ][ -]?\d[ABCEGHJ-NPRSTVWXYZ]\d\b',
    re.I,
)

# --------------------------- Province maps ---------------------------

# First letter of FSA -> Province/Territory
FSA_LETTER_TO_PROV = {
    "A": "NL",
    "B": "NS",
    "C": "PE",
    "E": "NB",
    "G": "QC",
    "H": "QC",
    "J": "QC",
    "K": "ON",
    "L": "ON",
    "M": "ON",
    "N": "ON",
    "P": "ON",
    "R": "MB",
    "S": "SK",
    "T": "AB",
    "V": "BC",
    "X": "NT/NU",
    "Y": "YT",
}

# Canadian area codes -> Province/Territory
AREA_TO_PROV = {
    # NL
    "709": "NL",
    # NS / PE
    "902": "NS/PE",
    "782": "NS/PE",
    # NB
    "506": "NB",
    "428": "NB",
    # QC
    "418": "QC",
    "581": "QC",
    "367": "QC",
    "819": "QC",
    "873": "QC",
    "514": "QC",
    "438": "QC",
    "450": "QC",
    "579": "QC",
    "354": "QC",
    # ON
    "416": "ON",
    "647": "ON",
    "437": "ON",
    "905": "ON",
    "289": "ON",
    "365": "ON",
    "742": "ON",
    "613": "ON",
    "343": "ON",
    "705": "ON",
    "249": "ON",
    "807": "ON",
    "519": "ON",
    "226": "ON",
    "548": "ON",
    # MB
    "204": "MB",
    "431": "MB",
    "584": "MB",
    # SK
    "306": "SK",
    "639": "SK",
    "474": "SK",
    # AB
    "403": "AB",
    "587": "AB",
    "780": "AB",
    "825": "AB",
    "368": "AB",
    # BC
    "604": "BC",
    "250": "BC",
    "778": "BC",
    "236": "BC",
    "672": "BC",
    # North
    "867": "YT/NT/NU",
}

# --------------------------- Storage & helpers ---------------------------

_alerts_lock = threading.RLock()
_alerts: list[dict] = []

_clients_lock = threading.RLock()
_sse_clients: list[BaseHTTPRequestHandler] = []

_seen_lock = threading.RLock()
_seen: dict[str, float] = {}  # key -> expires_at


def _now() -> float:
    return time.time()


def _purge_seen(now: float) -> None:
    for k, exp in list(_seen.items()):
        if exp < now:
            _seen.pop(k, None)


def _mk_key(kind: str, masked: str, host: str | None) -> str:
    raw = f"{kind}|{masked}|{host or ''}"
    return hashlib.sha1(raw.encode()).hexdigest()


def should_emit(kind: str, masked: str, host: str | None) -> bool:
    """
    De-dup based on (kind, masked, host) with TTL.
    """
    now = _now()
    with _seen_lock:
        _purge_seen(now)
        k = _mk_key(kind, masked, host)
        exp = _seen.get(k)
        if exp and exp > now:
            return False
        _seen[k] = now + DEDUP_TTL_SECONDS
        return True


def mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        if len(local) <= 2:
            masked_local = local[0] + "*"
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return masked_local + "@" + domain
    except Exception:
        return email


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    if not digits:
        return phone
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_postal(pc: str) -> str:
    pc = pc.upper().replace("-", " ")
    # e.g. "K1A 0B1" -> "K1A *B1"
    return pc[:3] + " *" + pc[-2:]


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def flatten_json_to_lines(obj) -> list[str]:
    out: list[str] = []

    def walk(x):
        if isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        else:
            out.append(str(x))

    walk(obj)
    return out


def extract_body_text(flow: http.HTTPFlow) -> str:
    """
    Best-effort: JSON → flatten; else URL-decode; trim to 20k.
    """
    try:
        b = flow.request.get_text(strict=False)
        if not b:
            return ""
        ctype = flow.request.headers.get("content-type", "").lower()

        if "application/json" in ctype:
            try:
                obj = json.loads(b)
                return "\n".join(flatten_json_to_lines(obj))[:20000]
            except Exception:
                pass

        # form or anything else: url-decode for readability
        return unquote_plus(b)[:20000]
    except Exception:
        return ""


# --------------------------- Alert I/O ---------------------------


def add_alert(alert: dict) -> None:
    # attach server_ts, store, push to SSE clients
    with _alerts_lock:
        alert["server_ts"] = int(time.time() * 1000)
        _alerts.append(alert)
        if len(_alerts) > MAX_ALERTS:
            del _alerts[0 : len(_alerts) - MAX_ALERTS]

    payload = json.dumps(alert, ensure_ascii=False).encode("utf-8")
    with _clients_lock:
        dead = []
        for client in list(_sse_clients):
            try:
                client.wfile.write(b"data: " + payload + b"\n\n")
                client.wfile.flush()
            except Exception:
                dead.append(client)
        for d in dead:
            try:
                _sse_clients.remove(d)
            except ValueError:
                pass


def get_alerts_copy() -> list[dict]:
    with _alerts_lock:
        return list(_alerts)


def register_sse_client(h: BaseHTTPRequestHandler) -> None:
    with _clients_lock:
        _sse_clients.append(h)


def unregister_sse_client(h: BaseHTTPRequestHandler) -> None:
    with _clients_lock:
        try:
            _sse_clients.remove(h)
        except ValueError:
            pass


# --------------------------- Admin/SSE HTTP server ---------------------------


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _cors_json(self) -> None:
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors_json()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/alerts":
            self.send_response(200)
            self._cors_json()
            self.end_headers()
            try:
                self.wfile.write(
                    json.dumps(get_alerts_copy(), ensure_ascii=False).encode("utf-8")
                )
            except Exception:
                ctx.log.info("Failed writing /alerts")
            return

        if path == "/sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            # initial comment (keeps some clients happy)
            try:
                self.wfile.write(b":ok\n\n")
                self.wfile.flush()
            except Exception:
                return
            register_sse_client(self)
            try:
                while True:
                    time.sleep(1.0)  # keep the handler alive
            except Exception:
                pass
            finally:
                unregister_sse_client(self)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        # silence default logs
        return


_server: ThreadedHTTPServer | None = None
_server_thread: threading.Thread | None = None


def start_admin_server(
    host: str = HOST,
    port: int = PORT,
    certfile: str = CERTFILE,
    keyfile: str = KEYFILE,
):
    global _server, _server_thread
    if _server is not None:
        return _server

    server = ThreadedHTTPServer((host, port), AdminHandler)
    use_https = False
    if os.path.isfile(certfile) and os.path.isfile(keyfile):
        try:
            ctx.log.info(f"Using TLS cert={certfile} key={keyfile} for admin server")
            sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sc.load_cert_chain(certfile=certfile, keyfile=keyfile)
            server.socket = sc.wrap_socket(server.socket, server_side=True)
            use_https = True
        except Exception as e:
            ctx.log.warn(
                f"Failed to enable HTTPS for admin server: {e}. Falling back to HTTP."
            )

    _server = server

    def run():
        scheme = "https" if use_https else "http"
        ctx.log.info(
            f"HTTP(S) admin server started at {scheme}://{host}:{port} (SSE /alerts)"
        )
        try:
            server.serve_forever()
        except Exception:
            pass

    t = threading.Thread(target=run, daemon=True)
    t.start()
    _server_thread = t
    return server


def stop_admin_server():
    global _server
    if _server:
        try:
            _server.shutdown()
        except Exception:
            pass
        try:
            _server.server_close()
        except Exception:
            pass
        _server = None


# --------------------------- Detection ---------------------------


def province_from_area(area: str | None) -> str | None:
    if not area:
        return None
    return AREA_TO_PROV.get(area)


def analyze_text_for_leaks(
    text: str, source_url: str | None, client_addr: str | None
) -> list[dict]:
    alerts: list[dict] = []
    h = host_of(source_url)

    # ----- Emails -----
    for email in EMAIL_RE.findall(text):
        masked = mask_email(email)
        if should_emit("email", masked, h):
            alerts.append(
                {
                    "type": "email",
                    "leak_category": "email",
                    "value": email,
                    "value_masked": masked,
                    "where": source_url,
                    "host": h,
                    "client": client_addr,
                }
            )

    # ----- Phones: only Canadian (area code maps to a province) -----
    for m in NANP_RE.finditer(text):
        full = m.group(0)
        area = m.group(1)
        masked = mask_phone(full)
        prov = province_from_area(area)

        # Skip all non-Canadian / unknown area codes
        if prov is None:
            continue

        # Generic category "phone" (you still keep province as metadata)
        if should_emit("phone", masked, h):
            alerts.append(
                {
                    "type": "phone",
                    "leak_category": "phone",
                    "province": prov,
                    "area_code": area,
                    "value": full,
                    "value_masked": masked,
                    "where": source_url,
                    "host": h,
                    "client": client_addr,
                }
            )

    # ----- Canadian postal codes → address -----
    for m in POSTAL_CA_RE.finditer(text):
        raw = m.group(0)
        fsa_letter = m.group(1).upper()
        prov = FSA_LETTER_TO_PROV.get(fsa_letter)
        masked = mask_postal(raw.upper())

        if should_emit("address", masked, h):
            alerts.append(
                {
                    "type": "address",
                    "leak_category": "address",
                    "province": prov,
                    "postal": raw.upper(),
                    "value_masked": masked,
                    "where": source_url,
                    "host": h,
                    "client": client_addr,
                }
            )

    return alerts


# --------------------------- mitmproxy addon ---------------------------


class MitmAlertsAddon:
    def __init__(self):
        self.server = None

    def load(self, loader):
        try:
            self.server = start_admin_server()
        except Exception as e:
            ctx.log.warn(f"Could not start admin server: {e}")
        ctx.log.info("MitmAlerts addon loaded - listening for leaks")

    def done(self):
        stop_admin_server()
        ctx.log.info("MitmAlerts addon stopped")

    def _record_and_push_alerts(self, alerts: list[dict]):
        for a in alerts:
            a.setdefault("detected_by", "mitm_alerts_addon")
            add_alert(a)
            ctx.log.info(
                f"[mitm_alerts] {a.get('leak_category')} "
                f"{a.get('value_masked')} host={a.get('host')}"
            )

    def request(self, flow: http.HTTPFlow):
        """
        Only inspect likely *form submissions*:
          - Methods: POST / PUT / PATCH
          - Has a body and/or looks like form/JSON content
        This avoids random GET noise from analytics.
        """
        try:
            method = flow.request.method.upper()
            if method not in ("POST", "PUT", "PATCH"):
                return  # ignore GET etc.

            ctype = flow.request.headers.get("content-type", "").lower()
            has_body = bool(flow.request.raw_content)

            looks_like_form = any(
                t in ctype
                for t in (
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                    "application/json",
                )
            )

            if not looks_like_form and not has_body:
                # No meaningful body → ignore
                return

            parts = []

            # URL (leaks can appear in query params of POSTs)
            try:
                parts.append(flow.request.pretty_url or flow.request.url)
            except Exception:
                pass

            # Headers (optional; can remove if you want to be stricter)
            try:
                parts.append(
                    "\n".join(f"{k}:{v}" for k, v in flow.request.headers.items())
                )
            except Exception:
                pass

            # Body (decoded/flattened)
            parts.append(extract_body_text(flow))

            combined = "\n".join(p for p in parts if p)

            client_addr = None
            try:
                if flow.client_conn:
                    client_addr = (
                        f"{flow.client_conn.address[0]}:{flow.client_conn.address[1]}"
                    )
            except Exception:
                pass

            alerts = analyze_text_for_leaks(
                combined,
                source_url=flow.request.pretty_url,
                client_addr=client_addr,
            )
            if alerts:
                self._record_and_push_alerts(alerts)

        except Exception as e:
            ctx.log.debug(f"mitm_alerts error: {e}")


addons = [MitmAlertsAddon()]
