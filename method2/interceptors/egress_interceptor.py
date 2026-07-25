"""
egress_interceptor.py  --  PILLAR A

Lightweight transparent HTTP proxy that intercepts ALL outbound HTTP requests
from the sandbox container and scans them for canary tokens.

The container's HTTP_PROXY and HTTPS_PROXY environment variables are set to
point here, so every outbound request (urllib, requests, curl) routes through
this proxy regardless of destination (Telegram, Discord, attacker.com, etc).

This catches exfiltration via:
  - HTTP POST webhooks to any external service
  - GET requests with canary tokens in query parameters
  - HTTP headers containing canary values

KNOWN LIMITATION -- HTTPS payload content is NOT inspected. do_CONNECT()
does not perform TLS interception (no MITM CA cert is installed in the
sandbox), so canary tokens sent inside an HTTPS request body/headers are
invisible to this interceptor -- only Pillar C's post-execution volume
scan or Pillar A's plain-HTTP scanning above would ever catch those. What
this DOES do for HTTPS: read the plaintext ClientHello that immediately
follows a CONNECT and extract its SNI (Server Name Indication) field, so
the destination HOSTNAME is visible and logged even though the payload
is not. Real content coverage for HTTPS would require a full MITM proxy
with a trusted CA cert installed in the sandbox image, which this
lightweight, dependency-free interceptor deliberately does not attempt.

Design: Pure Python stdlib (http.server + urllib). No external dependencies.
Runs as a background thread started by the orchestrator.

Usage (standalone for testing):
    python egress_interceptor.py [port]
"""

import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from method2.interceptors.intercept_hits import log_intercept_hit, scan_text_for_canaries

DEFAULT_PORT = 8080

# Bind address for the interceptor. 127.0.0.1 (not 0.0.0.0) so this port
# isn't reachable from the LAN during a test run -- verified empirically
# that a Docker Desktop container (macOS/Windows) CAN still reach a
# 127.0.0.1-bound host service through host.docker.internal, thanks to
# Docker Desktop's vpnkit networking layer forwarding it to host loopback.
# CAVEAT: this is a Docker Desktop behavior, not a Docker Engine/Linux one --
# on native Linux Docker, host.docker.internal resolves to the real bridge
# gateway IP, and a 127.0.0.1-only bind would NOT be reachable from a
# container there. If this project is ever run under Linux Docker Engine
# (not Docker Desktop), this bind address would need to change (e.g. to the
# bridge/host-gateway IP) to keep working.
BIND_HOST = "127.0.0.1"


def _extract_sni(data: bytes):
    """Best-effort parse of the SNI hostname out of a raw TLS ClientHello,
    without decrypting anything (SNI is sent in plaintext by design).
    Returns None if `data` isn't a parseable ClientHello (truncated, not
    TLS, or no SNI extension present) -- callers must treat that as
    'unknown destination', not an error."""
    try:
        if len(data) < 5 or data[0] != 0x16:  # TLS record type: Handshake
            return None
        pos = 5  # skip record header: type(1) + version(2) + length(2)
        if pos >= len(data) or data[pos] != 0x01:  # handshake type: ClientHello
            return None
        pos += 4  # skip handshake type(1) + length(3)
        pos += 2 + 32  # skip client_version(2) + random(32)
        if pos >= len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(data):
            return None
        cipher_suites_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2 + cipher_suites_len
        if pos >= len(data):
            return None
        compression_len = data[pos]
        pos += 1 + compression_len
        if pos + 2 > len(data):
            return None
        extensions_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(pos + extensions_len, len(data))
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            ext_data_start = pos + 4
            if ext_type == 0x0000:  # server_name extension
                sni_pos = ext_data_start + 2  # skip server_name_list length
                if sni_pos + 3 <= len(data):
                    name_type = data[sni_pos]
                    name_len = int.from_bytes(data[sni_pos + 1:sni_pos + 3], "big")
                    name_start = sni_pos + 3
                    if name_type == 0x00 and name_start + name_len <= len(data):
                        return data[name_start:name_start + name_len].decode(
                            "ascii", errors="ignore"
                        )
            pos = ext_data_start + ext_len
        return None
    except Exception:
        return None

# The container's HTTP_PROXY/HTTPS_PROXY env vars route ALL outbound HTTP
# through this interceptor first -- including the sandbox agent's own
# webhook POST to the port-9000 listener (listener.py), which would
# otherwise never be reached directly and canary_hits.json would stay
# permanently empty for containerized runs. Rather than leave that
# "ground truth" log silently dead, we forward exactly that one
# destination -- the listener's own callback path -- on to the real
# listener (over loopback, on THIS host, never re-entering the container's
# network). Every other destination (genuine external exfil targets) is
# still intercepted and NOT forwarded, so canary tokens never actually
# leave the test environment; those are logged here in intercept_hits.json
# only. aggregate_verdict.py already merges both files, so nothing is lost
# either way -- this forwarding just keeps the two logs consistent with
# what each is documented to record.
LISTENER_FORWARD_HOST = "127.0.0.1"
LISTENER_FORWARD_PORT = 9000
LISTENER_CALLBACK_PATH = "/canary-callback"


class EgressInterceptorHandler(BaseHTTPRequestHandler):
    """
    HTTP proxy handler that inspects all forwarded requests for canary tokens.

    This is NOT a full transparent proxy (which would require CONNECT tunneling).
    Instead, the fake_agent inside Docker uses HTTP_PROXY env var, which causes
    urllib/requests to send requests in proxy format (full URL in request line).

    We inspect the request, log any canary matches, and return a 200 OK.
    We intentionally do NOT forward the request to its real destination --
    canary tokens should never leave the test environment -- with exactly
    one exception: requests headed for the port-9000 listener's own
    /canary-callback path get forwarded there (loopback only), so
    canary_hits.json keeps working as documented instead of silently
    going dark. See LISTENER_FORWARD_HOST/PORT above.
    """

    def _scan_and_log(self, body: str = ""):
        """Scan URL, headers, query params, and body for canary tokens."""
        full_url = self.path
        parsed = urlparse(full_url)

        # Combine all scannable text
        scannable_parts = [
            full_url,
            body,
            str(self.headers),
        ]

        # Also scan query parameters
        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            scannable_parts.extend(values)

        combined_text = "\n".join(scannable_parts)
        canaries_found = scan_text_for_canaries(combined_text)

        if canaries_found:
            # Try to extract ATTACK_ID from body
            attack_id = ""
            attack_id_match = re.search(r"ATTACK_ID=(\S+)", body)
            if attack_id_match:
                attack_id = attack_id_match.group(1)

            # Try to extract credential key from body (KEY=VALUE format)
            extracted_key = ""
            key_match = re.search(r"^([A-Z_]+)=", body, re.MULTILINE)
            if key_match:
                extracted_key = key_match.group(1)

            for canary in set(canaries_found):
                log_intercept_hit(
                    channel="HTTP_WEBHOOK",
                    extracted_value=canary,
                    detail=f"Outbound HTTP to {parsed.netloc or parsed.path} "
                           f"(method={self.command})",
                    extracted_key=extracted_key,
                    attack_id=attack_id,
                )

    def _maybe_forward_to_listener(self, method: str, body: bytes = b""):
        """If this request was headed for the port-9000 listener's own
        callback endpoint, forward it there for real (loopback only) so
        canary_hits.json stays populated too. See module docstring."""
        parsed = urlparse(self.path)
        if parsed.path != LISTENER_CALLBACK_PATH:
            return
        try:
            req = urllib.request.Request(
                f"http://{LISTENER_FORWARD_HOST}:{LISTENER_FORWARD_PORT}{parsed.path}",
                data=body if method == "POST" else None,
                method=method,
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            print(f"[pillar_a] WARNING: failed to forward to listener: {e}")

    def do_GET(self):
        self._scan_and_log()
        self._maybe_forward_to_listener("GET")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"intercepted")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)
        self._scan_and_log(body_bytes.decode(errors="ignore"))
        self._maybe_forward_to_listener("POST", body_bytes)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"intercepted")

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling.

        We do NOT decrypt TLS (no MITM cert here) so the request body/headers
        inside the tunnel are invisible to us -- see the KNOWN LIMITATION
        note in the module docstring. What we CAN do without decrypting
        anything: read the plaintext ClientHello the client sends right
        after our 200, and pull the SNI hostname out of it. That gives
        visibility into WHERE an HTTPS attempt was headed even though we
        can't see WHAT was sent.
        """
        target = self.path  # "host:port"
        self.send_response(200, "Connection Established")
        self.end_headers()

        sni = None
        try:
            self.connection.settimeout(2)
            client_hello = self.connection.recv(4096)
            sni = _extract_sni(client_hello)
        except Exception:
            pass

        if sni:
            print(f"[pillar_a] HTTPS CONNECT to {target} (SNI: {sni}) -- "
                  f"payload content NOT inspected (TLS not decrypted)")
        else:
            print(f"[pillar_a] HTTPS CONNECT to {target} -- "
                  f"payload content NOT inspected (TLS not decrypted)")

    def log_message(self, format, *args):
        # Suppress default noisy logging
        pass


def start_egress_interceptor(port: int = DEFAULT_PORT) -> HTTPServer:
    """Start the egress interceptor as a background thread.
    Returns the server instance for later shutdown."""
    server = HTTPServer((BIND_HOST, port), EgressInterceptorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[pillar_a] egress interceptor started on port {port}")
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = HTTPServer((BIND_HOST, port), EgressInterceptorHandler)
    print(f"[pillar_a] egress interceptor running on http://{BIND_HOST}:{port}")
    print("[pillar_a] scanning all outbound HTTP for canary tokens...")
    server.serve_forever()
