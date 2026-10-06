"""
AmneziaWG 2.0 CPS Generator — Python port of generator.ts
Ported from: https://github.com/Vadim-Khristenko/AmneziaWG-Architect
"""

import random
import os
import re
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Types / constants
# ─────────────────────────────────────────────────────────────────────────────

MIMIC_PROFILES = [
    "quic_initial", "quic_0rtt", "tls_client_hello", "wireguard_noise",
    "dtls", "http3", "sip", "tls_to_quic", "quic_burst", "dns_query", "random"
]

BROWSER_PROFILES = ["chrome", "edge", "firefox", "safari", "yandex_desktop", "yandex_mobile", ""]

CHROMIUM_PROFILES = {"chrome", "edge", "yandex_desktop", "yandex_mobile"}

PROFILE_LABELS = {
    "quic_initial": "QUIC Initial",
    "quic_0rtt": "QUIC 0-RTT",
    "tls_client_hello": "TLS 1.3",
    "wireguard_noise": "Noise_IK",
    "dtls": "DTLS 1.3",
    "http3": "HTTP/3",
    "sip": "SIP",
    "tls_to_quic": "TLS → QUIC",
    "quic_burst": "QUIC Burst",
    "dns_query": "DNS Query",
    "random": "Random",
}
