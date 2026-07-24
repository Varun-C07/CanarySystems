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

Design: Pure Python stdlib (http.server + urllib). No external dependencies.
Runs as a background thread started by the orchestrator.

Usage (standalone for testing):
    python egress_interceptor.py [port]
"""

import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from method2.interceptors.intercept_hits import log_intercept_hit, scan_text_for_canaries

DEFAULT_PORT = 8080


class EgressInterceptorHandler(BaseHTTPRequestHandler):
    """
    HTTP proxy handler that inspects all forwarded requests for canary tokens.

    This is NOT a full transparent proxy (which would require CONNECT tunneling).
    Instead, the fake_agent inside Docker uses HTTP_PROXY env var, which causes
    urllib/requests to send requests in proxy format (full URL in request line).

    We inspect the request, log any canary matches, and return a 200 OK.
    We intentionally do NOT forward the request to the real destination --
    canary tokens should never leave the test environment.
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

    def do_GET(self):
        self._scan_and_log()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"intercepted")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode(errors="ignore")
        self._scan_and_log(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"intercepted")

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling -- intercept and sink."""
        self._scan_and_log()
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress default noisy logging
        pass


def start_egress_interceptor(port: int = DEFAULT_PORT) -> HTTPServer:
    """Start the egress interceptor as a background thread.
    Returns the server instance for later shutdown."""
    server = HTTPServer(("0.0.0.0", port), EgressInterceptorHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[pillar_a] egress interceptor started on port {port}")
    return server


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = HTTPServer(("0.0.0.0", port), EgressInterceptorHandler)
    print(f"[pillar_a] egress interceptor running on http://0.0.0.0:{port}")
    print("[pillar_a] scanning all outbound HTTP for canary tokens...")
    server.serve_forever()
