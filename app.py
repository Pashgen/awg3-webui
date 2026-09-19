#!/usr/bin/env python3
"""
AWG 3.1 Web UI — Flask backend.
Manages AmneziaWG 2.0 server: peers, config, CPS generation, QR codes.
"""

import os
import re
import io
import time
import json
import uuid
import hmac
import base64
import hashlib
import secrets
import struct
import fcntl
import subprocess
from pathlib import Path
from functools import wraps
from datetime import datetime

from flask import Flask, request, jsonify, render_template, Response, abort, session, redirect, url_for

import sys
sys.path.insert(0, os.path.dirname(__file__))
from cps_generator import gen_cfg, gen_awg31_extra, default_input, MIMIC_PROFILES, BROWSER_PROFILES, PROFILE_LABELS

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

AWG_IF        = os.environ.get("AWG_INTERFACE", "awg0")
AWG_CONF_DIR  = os.environ.get("AWG_CONF_DIR", "/etc/amnezia/amneziawg")
AWG_CONF_PATH = os.path.join(AWG_CONF_DIR, f"{AWG_IF}.conf")
AWG_PORT      = int(os.environ.get("AWG_PORT", 51820))
AWG_SUBNET    = os.environ.get("AWG_SUBNET", "10.8.0.0/24")
AWG_DNS       = os.environ.get("AWG_DNS", "1.1.1.1,8.8.8.8")
AWG_ENDPOINT  = os.environ.get("AWG_ENDPOINT", "auto")
WEB_PORT      = int(os.environ.get("WEB_PORT", 5000))
WEB_USER      = os.environ.get("WEB_USER", "admin")
WEB_PASS      = os.environ.get("WEB_PASS", "admin")

SETTINGS_PATH = os.path.join(AWG_CONF_DIR, ".webui_settings.json")


def _load_settings() -> dict:
    try:
        with open(SETTINGS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_settings(data: dict):
    existing = _load_settings()
    existing.update(data)
    Path(AWG_CONF_DIR).mkdir(parents=True, exist_ok=True)
    try:
        with open(SETTINGS_PATH, "w") as f:
            json.dump(existing, f)
    except PermissionError:
        try:
            os.unlink(SETTINGS_PATH)
        except Exception:
            pass
        with open(SETTINGS_PATH, "w") as f:
            json.dump(existing, f)


def _get_credentials() -> tuple:
    """Return (username, password) — from settings file or env defaults."""
    s = _load_settings()
    return s.get("username", WEB_USER), s.get("password", WEB_PASS)


AWG_TOOL      = "/usr/bin/awg"
AWG_QUICK     = "/usr/bin/awg-quick"
AWG_GO        = "/usr/bin/amneziawg-go"

# ─────────────────────────────────────────────────────────────────────────────
# Flask app
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates")

# ── Split WebUI access/error logging ─────────────────────────────────────────
# supervisord.conf points flask's stdout_logfile AND stderr_logfile at the
# same shared /var/log/supervisor/flask.log, and LOG_FILES used to map both
# the "WebUI Access" and "WebUI Error" tabs to that identical path - so the
# two tabs in Settings -> System Logs always showed exactly the same content,
# which is what prompted this fix. Give each its own file, split by level:
# werkzeug's per-request INFO lines go to _WEBUI_ACCESS_LOG, anything WARNING
# or above (including our own app.logger.error() calls) goes to
# _WEBUI_ERROR_LOG. flask.log itself is kept as-is (see LOG_FILES below,
# "WebUI Startup/Crash") since it's still the only place a hard crash before
# these handlers attach, or a raw print(), would land.
_WEBUI_ACCESS_LOG = "/var/log/supervisor/webui_access.log"
_WEBUI_ERROR_LOG   = "/var/log/supervisor/webui_error.log"


def _setup_split_logging():
    try:
        from logging.handlers import RotatingFileHandler

        class _MaxLevelFilter(logging.Filter):
            def __init__(self, max_level):
                super().__init__()
                self.max_level = max_level

            def filter(self, record):
                return record.levelno <= self.max_level

        fmt = logging.Formatter("%(asctime)s %(message)s", "%d/%b/%Y %H:%M:%S")

        access_handler = RotatingFileHandler(_WEBUI_ACCESS_LOG, maxBytes=5 * 1024 * 1024, backupCount=2)
        access_handler.setFormatter(fmt)
        access_handler.addFilter(_MaxLevelFilter(logging.INFO))

        error_handler = RotatingFileHandler(_WEBUI_ERROR_LOG, maxBytes=5 * 1024 * 1024, backupCount=2)
        error_handler.setFormatter(fmt)
        error_handler.setLevel(logging.WARNING)

        for logger_name in ("werkzeug", None):  # None = Flask's app.logger
            lg = logging.getLogger(logger_name) if logger_name else app.logger
            lg.handlers = []
            lg.propagate = False
            lg.setLevel(logging.INFO)
            lg.addHandler(access_handler)
            lg.addHandler(error_handler)
    except Exception as e:
        # Don't let a logging-setup problem take the whole app down - worst
        # case, Access/Error just fall back to whatever they were before.
        print(f"[AWG Web UI] Split logging setup failed: {e}")


app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

import logging
logging.basicConfig(level=logging.WARNING)
app.logger.setLevel(logging.ERROR)

# In-memory store for one-time download links: token -> {pub_key, conf, name, expires}
_otl_store: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# Security: Rate limiting + password hashing
# ─────────────────────────────────────────────────────────────────────────────

# Rate limiter: {ip: {'count': int, 'blocked_until': float}}
_login_attempts: dict = {}
_MAX_ATTEMPTS   = 5      # max failed attempts before block
_BLOCK_SECONDS  = 300    # block duration: 5 minutes


def _get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def _check_rate_limit(ip: str) -> tuple[bool, int]:
    """Returns (is_blocked, seconds_remaining). Cleans expired blocks."""
    now = time.time()
    entry = _login_attempts.get(ip, {})
    blocked_until = entry.get("blocked_until", 0)
    if blocked_until > now:
        return True, int(blocked_until - now)
    if blocked_until and blocked_until <= now:
        # Block expired — reset
        _login_attempts.pop(ip, None)
    return False, 0


def _record_failed_attempt(ip: str):
    now = time.time()
    entry = _login_attempts.setdefault(ip, {"count": 0, "blocked_until": 0})
    entry["count"] += 1
    if entry["count"] >= _MAX_ATTEMPTS:
        entry["blocked_until"] = now + _BLOCK_SECONDS
        entry["count"] = 0


def _reset_attempts(ip: str):
    _login_attempts.pop(ip, None)


def _hash_password(password: str) -> str:
    """Hash password with scrypt (stdlib, no extra deps)."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def _verify_password(password: str, stored: str) -> bool:
    """Timing-safe password verification. Supports plain (legacy) and scrypt."""
    if stored.startswith("scrypt$"):
        try:
            _, salt_b64, dk_b64 = stored.split("$")
            salt = base64.b64decode(salt_b64)
            dk_stored = base64.b64decode(dk_b64)
            dk_input = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
            return hmac.compare_digest(dk_input, dk_stored)
        except Exception:
            return False
    # Legacy plain-text — timing-safe compare
    return hmac.compare_digest(password, stored)


def require_auth(f):
    """Session-based auth: redirect to /login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            # For API calls return 401 JSON, for page calls redirect
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ─────────────────────────────────────────────────────────────────────────────

def _gen_keypair():
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        priv_bytes = priv.private_bytes_raw()
        pub_bytes  = priv.public_key().public_bytes_raw()
        return (
            base64.b64encode(priv_bytes).decode(),
            base64.b64encode(pub_bytes).decode(),
        )
    except Exception:
        try:
            priv = subprocess.check_output([AWG_TOOL, "genkey"]).strip().decode()
            pub  = subprocess.check_output(
                [AWG_TOOL, "pubkey"], input=priv.encode()
            ).strip().decode()
            return priv, pub
        except Exception:
            return None, None


def _sanitize_conf_field(s: str, maxlen: int = 96) -> str:
    """Make a free-text value safe to embed as a single `#Key=value` line in
    the raw INI-style awg0.conf.

    The conf format has no quoting/escaping: any newline in a stored value
    (peer name, expiry, ...) would inject arbitrary extra lines - including a
    fake "[Peer]" section with an attacker-chosen PublicKey/AllowedIPs (e.g.
    "0.0.0.0/0" for full-tunnel access) that _parse_peers() would then parse
    as a real, separate peer once conf is rewritten/reloaded. Stripping CR/LF
    closes that off; the length cap keeps a runaway value from bloating conf.
    """
    return s.replace("\r", " ").replace("\n", " ").strip()[:maxlen]


def _gen_psk():
    return base64.b64encode(os.urandom(32)).decode()


def _b64_key_to_hex(b64_key: str) -> str:
    """Convert a base64-encoded 32-byte key (.conf format) to hex (UAPI format)."""
    return base64.b64decode(b64_key).hex()


_AWG31_REQUEST_KEYS = (
    "enable_awg31", "random_trailers", "disable_cookies",
    "content_padding_addition", "rekey_after_time", "rekey_timeout",
    "reject_after_time", "keepalive_timeout", "max_handshake_attempts",
)


def _awg31_input_from_request(data: dict) -> dict:
    """Extract AWG 3.1 extra fields from a request JSON body into gen_awg31_extra() input shape."""
    out = {"enable_awg31": bool(data.get("enable_awg31", False))}
    out["random_trailers"] = bool(data.get("random_trailers", False))
    out["disable_cookies"] = bool(data.get("disable_cookies", False))
    for k in ("content_padding_addition", "rekey_after_time", "rekey_timeout",
              "reject_after_time", "keepalive_timeout", "max_handshake_attempts"):
        out[k] = str(data.get(k, "") or "").strip()
    return out


def _derive_pubkey(priv_b64: str) -> str:
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        raw = base64.b64decode(priv_b64)
        priv_obj = X25519PrivateKey.from_private_bytes(raw)
        return base64.b64encode(priv_obj.public_key().public_bytes_raw()).decode()
    except Exception:
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Config file helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read_conf() -> str:
    try:
        return Path(AWG_CONF_PATH).read_text()
    except FileNotFoundError:
        return ""


def _write_conf(text: str):
    Path(AWG_CONF_DIR).mkdir(parents=True, exist_ok=True)
    p = Path(AWG_CONF_PATH)
    try:
        p.write_text(text)
    except PermissionError:
        # RouterOS containers lack CAP_DAC_OVERRIDE — root can't overwrite
        # files owned by 'nobody' (written via SFTP). Fix: unlink creates a
        # whiteout in the overlayfs upper layer, then recreate owned by root.
        p.unlink()
        p.write_text(text)
    p.chmod(0o600)


def _parse_server_section(conf: str) -> dict:
    result = {}
    in_iface = False
    for line in conf.splitlines():
        line = line.strip()
        if line == "[Interface]":
            in_iface = True
            continue
        if line.startswith("[") and line != "[Interface]":
            in_iface = False
        if in_iface and "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def _parse_peers(conf: str) -> list:
    """Parse all [Peer] sections, including #ClientConf=, #Name=, #Expiry=, #Disabled= comments."""
    peers = []
    current = None
    for line in conf.splitlines():
        line_stripped = line.strip()
        if line_stripped == "[Peer]":
            current = {"_name": "", "_client_conf": "", "_expiry": "", "_disabled": False}
            peers.append(current)
        elif line_stripped.startswith("#Name=") and current is not None:
            current["_name"] = line_stripped[6:].strip()
        elif line_stripped.startswith("#ClientConf=") and current is not None:
            current["_client_conf"] = line_stripped[12:].strip()
        elif line_stripped.startswith("#Expiry=") and current is not None:
            current["_expiry"] = line_stripped[8:].strip()
        elif line_stripped == "#Disabled=true" and current is not None:
            current["_disabled"] = True
        elif line_stripped.startswith("[") and line_stripped != "[Peer]":
            current = None
        elif current is not None and "=" in line_stripped and not line_stripped.startswith("#"):
            k, _, v = line_stripped.partition("=")
            current[k.strip()] = v.strip()
    return peers


def _extract_interface_block(conf: str) -> str:
    """Return the [Interface] section text verbatim (everything before first [Peer])."""
    lines = conf.splitlines()
    result = []
    for line in lines:
        if line.strip() == "[Peer]":
            break
        result.append(line)
    # strip trailing blank lines
    while result and not result[-1].strip():
        result.pop()
    return "\n".join(result)


def _rebuild_conf(conf: str, peers: list) -> str:
    """Rebuild the full conf from the original interface block + peer list."""
    iface_block = _extract_interface_block(conf)
    parts = [iface_block]
    for p in peers:
        parts.append("")
        parts.append(_peer_to_conf(p))
    return "\n".join(parts) + "\n"


def _peer_to_conf(peer: dict) -> str:
    """Render a [Peer] section with optional stored client conf.
    Comments MUST come after [Peer] so _parse_peers can read them
    (current is only set when [Peer] is encountered)."""
    lines = ["[Peer]"]
    if peer.get("_name"):
        lines.append(f"#Name={peer['_name']}")
    if peer.get("_client_conf"):
        lines.append(f"#ClientConf={peer['_client_conf']}")
    if peer.get("_expiry"):
        lines.append(f"#Expiry={peer['_expiry']}")
    if peer.get("_disabled"):
        lines.append("#Disabled=true")
    for k in ("PublicKey", "PresharedKey", "AllowedIPs"):
        if peer.get(k):
            lines.append(f"{k} = {peer[k]}")
    if peer.get("Endpoint"):
        lines.append(f"Endpoint = {peer['Endpoint']}")
    return "\n".join(lines)


_RANGE_KEYS = {"H1", "H2", "H3", "H4"}


def _resolve_range(value: str) -> str:
    """If value is 'min-max' pick a random int in [min, max], else return as-is."""
    m = re.fullmatch(r"(\d+)-(\d+)", value.strip())
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        return str(secrets.randbelow(hi - lo + 1) + lo)
    return value


def _get_resolved_h_values() -> dict:
    """Read H1-H4 resolved (single integer) values from amneziawg-go UAPI socket.
    Returns dict like {'H1': '627191031', ...} or empty dict on failure.
    Mac Amnezia client doesn't support range syntax in client configs,
    so we must give it the exact resolved value the server is using."""
    import socket as _socket
    sock_path = f"/var/run/amneziawg/{AWG_IF}.sock"
    if not os.path.exists(sock_path):
        return {}
    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect(sock_path)
            s.sendall(b"get=1\n\n")
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\n\n" in resp:
                    break
        result = {}
        for line in resp.decode(errors="replace").splitlines():
            for key in ("h1", "h2", "h3", "h4"):
                if line.startswith(f"{key}="):
                    result[key.upper()] = line.split("=", 1)[1].strip()
        return result
    except Exception:
        return {}


def _build_runtime_conf(conf: str) -> str:
    """Build conf for awg-quick:
    - excludes disabled peer blocks
    - resolves H1-H4 range values (e.g. '100-200') to a single random integer
    """
    lines = conf.splitlines()
    result = []
    in_peer = False
    peer_buf: list = []
    is_disabled = False

    for line in lines:
        stripped = line.strip()
        if stripped == "[Peer]":
            # flush previous peer block if it was enabled
            if in_peer and not is_disabled:
                result.extend(peer_buf)
            in_peer = True
            peer_buf = [line]
            is_disabled = False
        elif stripped.startswith("[") and stripped != "[Peer]":
            # flush previous peer block
            if in_peer and not is_disabled:
                result.extend(peer_buf)
            in_peer = False
            peer_buf = []
            is_disabled = False
            result.append(line)
        elif in_peer:
            peer_buf.append(line)
            if stripped == "#Disabled=true":
                is_disabled = True
        else:
            # H1-H4 ranges are passed as-is to awg setconf.
            # awg-tools v1.0.20260223 support range syntax natively;
            # amneziawg-go validates any client value within [start,end].
            result.append(line)

    # flush last peer block
    if in_peer and not is_disabled:
        result.extend(peer_buf)

    return "\n".join(result)


# Fields accepted by `awg setconf` (Protocol-level only — no Address/DNS/PostUp etc.)
# Note: I1-I5 use our cps_generator DSL format; excluded here to avoid UAPI mismatch.
# They are AmneziaWG CPS params — if the running daemon supports them, add back.
_SETCONF_IFACE_KEYS = {
    "PrivateKey", "ListenPort",
    "H1", "H2", "H3", "H4",
    "S1", "S2", "S3", "S4",
    "Jc", "Jmin", "Jmax",
}
_SETCONF_PEER_KEYS = {
    "PublicKey", "PresharedKey", "AllowedIPs", "Endpoint",
}


def _build_setconf_input(runtime_conf: str) -> str:
    """Strip awg-quick-only fields (Address, DNS, PostUp, PreDown, etc.) from
    the config so the result can be passed directly to `awg setconf`.
    Uses the already-range-resolved runtime_conf as input.
    """
    lines = runtime_conf.splitlines()
    result = []
    in_peer = False
    allowed_keys = _SETCONF_IFACE_KEYS

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[Peer]"):
            in_peer = True
            allowed_keys = _SETCONF_PEER_KEYS
            result.append(line)
            continue
        if stripped.startswith("[") and not stripped.startswith("[Peer]"):
            in_peer = False
            allowed_keys = _SETCONF_IFACE_KEYS
            result.append(line)
            continue
        if stripped.startswith("#") or not stripped:
            continue  # skip comments and blank lines
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in allowed_keys:
                result.append(line)
        # else: skip unrecognized / awg-quick-only field

    return "\n".join(result) + "\n"


def _next_ip(conf: str) -> str:
    base = AWG_SUBNET.rsplit(".", 1)[0]
    used = set(re.findall(r"AllowedIPs\s*=\s*([\d.]+)", conf))
    iface = _parse_server_section(conf)
    server_addr = iface.get("Address", "")
    if "/" in server_addr:
        used.add(server_addr.split("/")[0])
    for i in range(2, 254):
        candidate = f"{base}.{i}"
        if candidate not in used:
            return f"{base}.{i}/32"
    raise RuntimeError("IP pool exhausted")


_public_ip_cache: dict = {"ip": "", "ts": 0.0}
_PUBLIC_IP_TTL = 600  # seconds — avoid hitting third-party IP-lookup services on every dashboard load


def _detect_public_ip() -> str:
    """Return the real public IP of this host, cached for _PUBLIC_IP_TTL seconds.

    Only curls an external service (ifconfig.me / api.ipify.org / icanhazip.com)
    when the cache is empty or stale — a public IP rarely changes within a
    session, and querying it on every /api/server/status poll unnecessarily
    exposes this host's IP to those third parties and adds request latency.
    """
    now = time.time()
    if _public_ip_cache["ip"] and now - _public_ip_cache["ts"] < _PUBLIC_IP_TTL:
        return _public_ip_cache["ip"]
    for url in ["https://ifconfig.me", "https://api.ipify.org", "https://icanhazip.com"]:
        try:
            ip = subprocess.check_output(
                ["curl", "-s", "--max-time", "5", url],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                _public_ip_cache["ip"] = ip
                _public_ip_cache["ts"] = now
                return ip
        except Exception:
            continue
    return _public_ip_cache["ip"]  # stale cache beats nothing if all lookups fail


def _get_endpoint() -> str:
    # Settings file overrides env var
    s = _load_settings()
    ep = s.get("endpoint", "").strip()
    if not ep:
        ep = AWG_ENDPOINT
    if ep and ep != "auto":
        # Append port if not present
        if ":" not in ep:
            ep = f"{ep}:{AWG_PORT}"
        return ep
    # auto-detect
    ip = _detect_public_ip()
    if ip:
        return f"{ip}:{AWG_PORT}"
    return f"YOUR_SERVER_IP:{AWG_PORT}"


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024**2:
        return f"{n/1024:.1f} KiB"
    elif n < 1024**3:
        return f"{n/1024**2:.1f} MiB"
    else:
        return f"{n/1024**3:.2f} GiB"


def _fmt_handshake(ts: int) -> str:
    if not ts:
        return "Never"
    age = int(time.time()) - ts
    if age < 60:
        return f"{age}s ago"
    elif age < 3600:
        return f"{age//60}m ago"
    elif age < 86400:
        return f"{age//3600}h ago"
    else:
        return f"{age//86400}d ago"


# ─────────────────────────────────────────────────────────────────────────────
# System metrics: uptime, version, CPU, RAM
# ─────────────────────────────────────────────────────────────────────────────

def _awg_uptime() -> int:
    """Return amneziawg-go process uptime in seconds, or 0 if not found."""
    try:
        r = subprocess.run(['pidof', 'amneziawg-go'], capture_output=True, text=True)
        pid = r.stdout.strip().split()[0]
        with open(f'/proc/{pid}/stat') as f:
            starttime = int(f.read().split()[21])
        hz = os.sysconf('SC_CLK_TCK')
        with open('/proc/uptime') as f:
            boot_uptime = float(f.read().split()[0])
        return max(0, int(boot_uptime - starttime / hz))
    except Exception:
        return 0


def _awg_version() -> str:
    """Return amneziawg-go version string."""
    try:
        r = subprocess.run([AWG_GO, '--version'], capture_output=True, text=True, timeout=2)
        out = (r.stdout or r.stderr).strip()
        return out.split('\n')[0] if out else 'unknown'
    except Exception:
        return 'unknown'


def _read_cpu_stat():
    """Read /proc/stat first line and return (user+nice+sys, total) ticks."""
    try:
        with open('/proc/stat') as f:
            parts = f.readline().split()
        vals = [int(x) for x in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        total = sum(vals)
        return total, idle
    except Exception:
        return 0, 0


def _cgroup_memory() -> tuple:
    """Return (used_bytes, limit_bytes) from THIS container's own cgroup.

    limit_bytes is 0 when the container has no memory limit configured
    (cgroup v2 memory.max == "max", or v1's unlimited sentinel value).
    Returns (0, 0) if cgroup memory files aren't readable at all (e.g. cgroups
    not namespaced in this environment) - caller falls back to /proc/meminfo.
    """
    try:  # cgroup v2 (unified) - default on modern Docker and RouterOS containers
        with open('/sys/fs/cgroup/memory.current') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory.max') as f:
            raw = f.read().strip()
            limit = 0 if raw == 'max' else int(raw)
        return used, limit
    except Exception:
        pass
    try:  # cgroup v1 fallback
        with open('/sys/fs/cgroup/memory/memory.usage_in_bytes') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory/memory.limit_in_bytes') as f:
            raw = int(f.read().strip())
        limit = 0 if raw > (1 << 62) else raw  # v1 reports a huge sentinel when unlimited
        return used, limit
    except Exception:
        pass
    return 0, 0


def _cgroup_cpu_usage() -> tuple:
    """Return (used_ns, ncpus) - this container's own cgroup CPU accounting.

    used_ns: cumulative CPU time consumed by the cgroup (all its threads,
    across all cores), in nanoseconds, since cgroup creation.
    ncpus: number of CPUs available to the cgroup - from its quota/period
    if one is set, else the host's visible CPU count (os.cpu_count()).
    Used to normalize used_ns into a 0-100% gauge the same way /proc/stat's
    idle-ratio naturally is, instead of a raw core-seconds figure that can
    exceed 100% on a multi-core box.
    Returns (0, 0) if cgroup CPU files aren't readable - caller falls back
    to host-wide /proc/stat (same reasoning as _cgroup_memory()).
    """
    try:  # cgroup v2 (unified)
        usage_usec = 0
        with open('/sys/fs/cgroup/cpu.stat') as f:
            for line in f:
                if line.startswith('usage_usec'):
                    usage_usec = int(line.split()[1])
                    break
        with open('/sys/fs/cgroup/cpu.max') as f:
            quota_raw, period_raw = f.read().split()
        ncpus = (os.cpu_count() or 1) if quota_raw == 'max' \
            else max(1.0, int(quota_raw) / int(period_raw))
        return usage_usec * 1000, ncpus
    except Exception:
        pass
    try:  # cgroup v1 fallback
        with open('/sys/fs/cgroup/cpuacct/cpuacct.usage') as f:
            used_ns = int(f.read().strip())
        quota, period = -1, 100000
        try:
            with open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us') as f:
                quota = int(f.read().strip())
            with open('/sys/fs/cgroup/cpu/cpu.cfs_period_us') as f:
                period = int(f.read().strip())
        except Exception:
            pass
        ncpus = (os.cpu_count() or 1) if quota <= 0 else max(1.0, quota / period)
        return used_ns, ncpus
    except Exception:
        pass
    return 0, 0


_cpu_cache: dict = {"ts": None, "host_total": 0, "host_idle": 0,
                    "cg_used": 0, "cg_ncpus": 0.0, "pct": 0}


def _sample_cpu_pct() -> int:
    """Return CPU% without blocking the (single-threaded) Flask dev server.

    _system_resources() used to take two /proc/stat (or cgroup) readings
    200ms apart, sleeping the whole request thread in between. That was
    fine when this only ran once per dashboard navigation, but the
    dashboard now auto-polls /api/server/status every 15s (see the
    dashboard-freeze fix) - a permanent 200ms stall every 15s would block
    every other request, including a second browser tab or admin, since
    this app isn't run with threaded=True.

    Instead, keep the last sample in a module-level cache and diff against
    it on the NEXT poll - 15s between samples gives a far less noisy delta
    than 200ms ever did anyway. Only the very first call in the process's
    lifetime does one blocking 200ms measurement, so the first-ever status
    response isn't just a meaningless 0%.
    """
    global _cpu_cache
    now_mono = time.monotonic()
    cg_used, cg_ncpus = _cgroup_cpu_usage()
    host_total, host_idle = _read_cpu_stat()
    prev = _cpu_cache

    if prev["ts"] is None:
        try:
            time.sleep(0.2)
            cg2, _ = _cgroup_cpu_usage()
            host_total2, host_idle2 = _read_cpu_stat()
            if cg_used and cg_ncpus:
                pct = int((cg2 - cg_used) / (0.2e9 * cg_ncpus) * 100)
            else:
                dt = host_total2 - host_total
                di = host_idle2 - host_idle
                pct = int((1 - di / dt) * 100) if dt > 0 else 0
            pct = max(0, min(100, pct))
            _cpu_cache = {"ts": now_mono, "host_total": host_total2, "host_idle": host_idle2,
                          "cg_used": cg2, "cg_ncpus": cg_ncpus, "pct": pct}
        except Exception:
            _cpu_cache = {"ts": now_mono, "host_total": host_total, "host_idle": host_idle,
                          "cg_used": cg_used, "cg_ncpus": cg_ncpus, "pct": 0}
        return _cpu_cache["pct"]

    elapsed = now_mono - prev["ts"]
    if elapsed < 1.0:
        # Too soon since the last sample for a meaningful delta.
        return prev["pct"]

    try:
        if cg_used and cg_ncpus:
            delta_ns = cg_used - prev["cg_used"]
            pct = int(delta_ns / (elapsed * 1e9 * cg_ncpus) * 100)
        else:
            dt = host_total - prev["host_total"]
            di = host_idle - prev["host_idle"]
            pct = int((1 - di / dt) * 100) if dt > 0 else prev["pct"]
        pct = max(0, min(100, pct))
    except Exception:
        pct = prev["pct"]

    _cpu_cache = {"ts": now_mono, "host_total": host_total, "host_idle": host_idle,
                  "cg_used": cg_used, "cg_ncpus": cg_ncpus, "pct": pct}
    return pct


def _system_resources() -> dict:
    """Return load average, CPU% and memory stats for THIS container.

    Memory prefers this container's own cgroup accounting (so it reflects
    what's actually capped by e.g. RouterOS's /container memory-max, not
    the whole host/VM) and only falls back to host-wide /proc/meminfo when
    cgroup memory files aren't available - a container's /proc/meminfo is
    NOT cgroup-namespaced by default, so it always reports the host's
    (or, under Docker Desktop, the Linux VM's) total/used memory rather
    than this process's own footprint, which is misleading for exactly
    the "how much RAM is this app actually using" question this is for.
    """
    load_avg = 0.0
    mem_total = mem_used = mem_pct = 0
    cpu_pct = 0
    try:
        with open('/proc/loadavg') as f:
            load_avg = float(f.read().split()[0])
    except Exception:
        pass
    # CPU% - see _sample_cpu_pct() for why this is a non-blocking delta
    # against the previous poll rather than a blocking 200ms measurement
    # on every single request.
    try:
        cpu_pct = _sample_cpu_pct()
    except Exception:
        pass
    host_total = 0
    try:
        mem = {}
        with open('/proc/meminfo') as f:
            for line in f:
                parts = line.split()
                if parts[0] in ('MemTotal:', 'MemAvailable:', 'MemFree:'):
                    mem[parts[0][:-1]] = int(parts[1]) * 1024
        host_total = mem.get('MemTotal', 0)
        mem_avail = mem.get('MemAvailable', mem.get('MemFree', 0))
        mem_total, mem_used = host_total, host_total - mem_avail
    except Exception:
        pass
    cg_used, cg_limit = _cgroup_memory()
    if cg_used:
        mem_used = cg_used
        # No explicit container limit set -> report against host total (still the
        # best available denominator), but the numerator is now this container's
        # own usage instead of the whole host's.
        mem_total = cg_limit if cg_limit else host_total
    mem_pct = int(mem_used / mem_total * 100) if mem_total else 0
    return {'load_avg': load_avg, 'cpu_pct': cpu_pct,
            'mem_total': mem_total, 'mem_used': mem_used, 'mem_pct': mem_pct}


def _fmt_uptime(secs: int) -> str:
    if secs <= 0:
        return '—'
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f'{d}d {h}h {m}m'
    if h:
        return f'{h}h {m}m'
    return f'{m}m {s}s'


# ─────────────────────────────────────────────────────────────────────────────
# Rolling 24h traffic history
# ─────────────────────────────────────────────────────────────────────────────

_traffic_history: list = []           # [(ts, rx_total, tx_total), ...]
_peer_traffic_history: dict = {}      # {pub_key: [(ts, rx, tx), ...]}
_TRAFFIC_WINDOW = 86400               # 24 hours


def _update_traffic(rx_total: int, tx_total: int, peer_stats: dict):
    now = time.time()
    cutoff = now - _TRAFFIC_WINDOW
    # Global
    _traffic_history.append((now, rx_total, tx_total))
    while len(_traffic_history) > 1 and _traffic_history[0][0] < cutoff:
        _traffic_history.pop(0)
    # Per-peer
    for pub, s in peer_stats.items():
        if pub not in _peer_traffic_history:
            _peer_traffic_history[pub] = []
        _peer_traffic_history[pub].append((now, s['transfer_rx'], s['transfer_tx']))
        _peer_traffic_history[pub] = [p for p in _peer_traffic_history[pub] if p[0] >= cutoff]


def _traffic_24h() -> tuple:
    if len(_traffic_history) < 2:
        return 0, 0
    oldest, newest = _traffic_history[0], _traffic_history[-1]
    return max(0, newest[1] - oldest[1]), max(0, newest[2] - oldest[2])


# ─────────────────────────────────────────────────────────────────────────────
# Geo-IP: country flag by peer endpoint IP
# ─────────────────────────────────────────────────────────────────────────────

_geo_cache: dict = {}
_GEO_TTL = 3600


def _get_geo(ip: str) -> dict:
    now = time.time()
    cached = _geo_cache.get(ip)
    if cached and now - cached['ts'] < _GEO_TTL:
        return cached
    try:
        import urllib.request
        url = f'http://ip-api.com/json/{ip}?fields=country,countryCode'
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
        cc = data.get('countryCode', '')
        # Regional Indicator Symbols start at U+1F1E6 ('A'); 'A'+offset builds
        # the two-letter flag emoji from an ISO 3166-1 alpha-2 country code.
        flag = (''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in cc.upper())
                if len(cc) == 2 and cc.isalpha() else '')
        result = {'country': data.get('country', ''), 'cc': cc, 'flag': flag, 'ts': now}
    except Exception:
        result = {'country': '', 'cc': '', 'flag': '', 'ts': now}
    _geo_cache[ip] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Ping peer via tunnel
# ─────────────────────────────────────────────────────────────────────────────

def _ping_peer(ip: str) -> float:
    """ICMP ping peer IP. Returns latency ms or -1 on failure."""
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '1', ip],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0:
            m = re.search(r'time=(\d+\.?\d*)', r.stdout)
            if m:
                return float(m.group(1))
    except Exception:
        pass
    return -1.0


# ─────────────────────────────────────────────────────────────────────────────
# CPS profile detector: detect mimic from I1 static bytes
# ─────────────────────────────────────────────────────────────────────────────

def _detect_cps_profile(i1: str) -> str:
    if not i1:
        return ''
    m = re.search(r'<b 0x([0-9a-fA-F]+)>', i1)
    if not m:
        return 'Random'
    h = m.group(1).lower()
    if h[:2] in ('c0', 'c1', 'c2', 'c3'):
        return 'QUIC Initial'
    if h[:2] in ('d0', 'd1', 'd2', 'd3'):
        return 'QUIC 0-RTT'
    if h[:6] in ('160301', '160303'):
        return 'TLS 1.3'
    if h[:6] == '16fefd':
        return 'DTLS 1.3'
    if h[:8] == '52454749':   # "REGI" = SIP REGISTER
        return 'SIP'
    if h[:8] == '01000000':   # WG type=1 Noise_IK
        return 'Noise_IK'
    if len(h) < 10:
        return 'DNS Query'
    return 'Custom'


# ─────────────────────────────────────────────────────────────────────────────
# Alerts
# ─────────────────────────────────────────────────────────────────────────────

def _check_alerts(running: bool, configured: bool, peer_stats: dict) -> list:
    alerts = []
    now = time.time()
    if not running and configured:
        alerts.append({'level': 'error', 'msg': 'AWG daemon is not running'})
    for pub, s in peer_stats.items():
        # peer_stats keys the raw handshake timestamp as "last_handshake"
        # (see _awg_peer_stats()) - "handshake_ts" was never a real key here,
        # so this alert silently never fired regardless of how stale a
        # peer's handshake actually was.
        ts = s.get('last_handshake', 0)
        if ts > 0 and (now - ts) > 7200:
            h = int((now - ts) / 3600)
            alerts.append({'level': 'warn',
                           'msg': f'Peer {pub[:8]}… no handshake for {h}h'})
    return alerts


def _build_client_conf(peer_priv: str, peer_pub: str, server_pub: str,
                       psk: str, peer_ip: str, awg_params: dict) -> str:
    endpoint = _get_endpoint()
    dns = AWG_DNS
    lines = ["[Interface]"]
    lines.append(f"PrivateKey = {peer_priv}")
    lines.append(f"Address = {peer_ip}")
    lines.append(f"DNS = {dns}")

    version = awg_params.get("version", "2.0")
    if version in ("2.0", "3.1"):
        lines += [f"H1 = {awg_params['H1']}", f"H2 = {awg_params['H2']}",
                  f"H3 = {awg_params['H3']}", f"H4 = {awg_params['H4']}"]
    else:
        lines += [f"H1 = {awg_params['H1s']}", f"H2 = {awg_params['H2s']}",
                  f"H3 = {awg_params['H3s']}", f"H4 = {awg_params['H4s']}"]

    lines += [f"S1 = {awg_params['S1']}", f"S2 = {awg_params['S2']}"]
    if version in ("2.0", "3.1"):
        lines += [f"S3 = {awg_params['S3']}", f"S4 = {awg_params['S4']}"]
    lines += [f"Jc = {awg_params['Jc']}", f"Jmin = {awg_params['Jmin']}", f"Jmax = {awg_params['Jmax']}"]
    # I1-I5: client-side CPS (independent per peer, server doesn't need to match)
    if version in ("2.0", "3.1"):
        for tag in ("I1","I2","I3","I4","I5"):
            if awg_params.get(tag):
                lines.append(f"{tag} = {awg_params[tag]}")

    # AWG 3.1 extras — mirrored VERBATIM from the server (HeaderProtectionKey is a
    # symmetric key shared between both ends; RandomTrailers/DisableCookies/timing
    # ranges must match the server's behavior, same reasoning as H1-H4/S1-S4/Jc above).
    if awg_params.get("HeaderProtectionKey"):
        lines.append(f"HeaderProtectionKey = {awg_params['HeaderProtectionKey']}")
    if "RandomTrailers" in awg_params:
        lines.append(f"RandomTrailers = {'on' if awg_params['RandomTrailers'] else 'off'}")
    if "DisableCookies" in awg_params:
        lines.append(f"DisableCookies = {'on' if awg_params['DisableCookies'] else 'off'}")
    for tag in ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
        if awg_params.get(tag):
            lines.append(f"{tag} = {awg_params[tag]}")

    lines += ["", "[Peer]", f"PublicKey = {server_pub}"]
    if psk:
        lines.append(f"PresharedKey = {psk}")
    lines += [f"Endpoint = {endpoint}", "AllowedIPs = 0.0.0.0/0, ::/0", "PersistentKeepalive = 25"]
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# AWG live stats
# ─────────────────────────────────────────────────────────────────────────────
# Transfer-change cache for online detection when handshake_ts=0
# amneziawg-go (from master) doesn't report handshake timestamps via UAPI,
# so we track transfer byte changes between polls to detect active peers.
_transfer_cache: dict = {}   # {pubkey: {'rx': int, 'tx': int, 'updated': float}}


def _awg_peer_stats() -> dict:
    """Parse `awg show <if> dump` for per-peer live stats.

    AWG 2.0 dump format (tab-separated):
      Interface line: privkey TAB pubkey TAB port TAB jc TAB jmin TAB jmax TAB
                      s1..s4 TAB h1..h4 TAB i1..i5 TAB fwmark
      Peer line:      pubkey TAB psk TAB endpoint TAB allowed_ips TAB
                      handshake_ts TAB rx TAB tx TAB keepalive

    amneziawg-go built from master reports handshake_ts=0 even after a
    successful handshake (UAPI timestamp not written). We fall back to
    detecting activity via transfer byte changes between polls.
    """
    stats = {}
    now = int(time.time())

    # Get real handshake timestamps.
    # awg show dump always returns handshake_ts=0 in amneziawg-go (UAPI bug).
    # Strategy 1: awg show latest-handshakes (tab-separated pubkey\ttimestamp)
    # Strategy 2: parse awg show <if> human-readable for "latest handshake: X ago"
    real_handshakes = {}
    try:
        hs_out = subprocess.check_output(
            [AWG_TOOL, "show", AWG_IF, "latest-handshakes"], stderr=subprocess.DEVNULL
        ).decode()
        for hs_line in hs_out.splitlines():
            hs_parts = hs_line.split('\t')
            if len(hs_parts) >= 2:
                try:
                    ts_val = int(hs_parts[1])
                    if ts_val > 0:
                        real_handshakes[hs_parts[0]] = ts_val
                except ValueError:
                    pass
    except Exception:
        pass

    # Strategy 2: parse human-readable output for "latest handshake: X ago"
    # awg show <if> prints this line only when timestamp != 0
    if not any(v > 0 for v in real_handshakes.values()):
        try:
            import re as _re
            hr_out = subprocess.check_output(
                [AWG_TOOL, "show", AWG_IF], stderr=subprocess.DEVNULL
            ).decode()
            cur_peer = None
            for hr_line in hr_out.splitlines():
                s = hr_line.strip()
                if s.startswith("peer:"):
                    cur_peer = s.split("peer:", 1)[1].strip()
                elif s.startswith("latest handshake:") and cur_peer:
                    # Parse "X seconds ago", "Y minutes, Z seconds ago", "W hours ago" etc.
                    txt = s.replace("latest handshake:", "").strip()
                    secs = 0
                    for val, unit in _re.findall(r'(\d+)\s+(second|minute|hour|day)', txt):
                        v = int(val)
                        if 'second' in unit: secs += v
                        elif 'minute' in unit: secs += v * 60
                        elif 'hour'   in unit: secs += v * 3600
                        elif 'day'    in unit: secs += v * 86400
                    if secs > 0:
                        real_handshakes[cur_peer] = now - secs
        except Exception:
            pass

    try:
        out = subprocess.check_output(
            [AWG_TOOL, "show", AWG_IF, "dump"], stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            parts = line.split('\t')
            # Detect peer line: 3rd column (index 2) is endpoint (has ':') or '(none)'.
            # Interface line has listenport at index 2 (digits only, no ':').
            if len(parts) < 8:
                continue
            if ':' not in parts[2] and parts[2] != '(none)':
                continue  # Skip interface line
            pub, psk, endpoint, allowed_ips, handshake_ts, rx, tx, ka = parts[:8]
            try:
                ts = int(handshake_ts)
            except ValueError:
                ts = 0
            # Override with real timestamp from latest-handshakes if available
            if real_handshakes.get(pub, 0) > ts:
                ts = real_handshakes[pub]
            try:
                rx_b = int(rx)
            except ValueError:
                rx_b = 0
            try:
                tx_b = int(tx)
            except ValueError:
                tx_b = 0

            age = (now - ts) if ts > 0 else None

            # Fallback online detection via transfer change between polls
            cached = _transfer_cache.get(pub, {})
            if 'rx' not in cached:
                # First time seeing this peer after restart.
                # Only rx (bytes FROM the peer) proves it's actually there and
                # talking back — use now as timestamp so UI shows activity
                # instead of "Never" right after Flask restart.
                first_updated = now if rx_b > 0 else 0
                _transfer_cache[pub] = {'rx': rx_b, 'tx': tx_b, 'updated': first_updated}
            else:
                # Only bump the freshness timestamp when RX changed. TX keeps
                # climbing even for a dead/unreachable peer (the server just
                # keeps firing outbound UDP packets, fire-and-forget, with no
                # reply needed) — using tx here made a peer that had actually
                # dropped show as "active" forever on the dashboard.
                new_updated = now if rx_b != cached['rx'] else cached['updated']
                _transfer_cache[pub] = {'rx': rx_b, 'tx': tx_b, 'updated': new_updated}
            transfer_updated = _transfer_cache.get(pub, {}).get('updated', 0)
            transfer_age = now - transfer_updated  # seconds since last real rx change

            # Active: handshake within 3 min  OR  rx bytes changed within 60s.
            # PersistentKeepalive=25s means a genuinely connected peer keeps
            # sending traffic back to us too, not just receiving from us.
            active = (age is not None and age < 180) or (transfer_age < 60 and rx_b > 0)

            # Handshake display string
            # amneziawg-go doesn't report handshake_ts via UAPI → use transfer activity time
            if ts > 0:
                hs_str = _fmt_handshake(ts)
            elif transfer_updated > 0 and (rx_b > 0 or tx_b > 0):
                hs_str = _fmt_handshake(int(transfer_updated))  # "X seconds ago" based on last transfer change
            else:
                hs_str = "Never"

            stats[pub] = {
                "endpoint":         endpoint if endpoint not in ("(none)", "") else "",
                "last_handshake":   ts,
                "handshake_str":    hs_str,
                "handshake_age":    age,
                "active":           active,
                "transfer_rx":      rx_b,
                "transfer_tx":      tx_b,
                "transfer_rx_str":  _fmt_bytes(rx_b),
                "transfer_tx_str":  _fmt_bytes(tx_b),
            }
    except Exception:
        pass
    return stats


def _awg_status() -> dict:
    try:
        out = subprocess.check_output(
            [AWG_TOOL, "show", AWG_IF], stderr=subprocess.DEVNULL
        ).decode()
        return {"running": True, "output": out}
    except Exception:
        return {"running": False, "output": ""}


def _classify_awg_error(stderr: str, stdout: str) -> str:
    """Return a human-readable error message for common AWG startup failures."""
    combined = (stderr or "") + (stdout or "")
    # Docker Desktop / macOS: amneziawg-go refuses to start in userspace because
    # it detects native WireGuard support (but not amneziawg), then awg setconf fails.
    if "first class support" in combined or (
            ("Unable to modify interface" in combined or "Invalid argument" in combined)
            and "amneziawg-go" in combined):
        return ("AWG cannot start: Docker Desktop (macOS) kernel has WireGuard but not "
                "AmneziaWG. UI is fully functional — tunnel won't work in test mode.")
    if "Missing WireGuard" in combined or "Unknown device type" in combined:
        return ("AWG kernel module not loaded. "
                "On Linux: modprobe amneziawg or install the kernel module. "
                "On macOS: AWG cannot run natively — UI-only test mode.")
    if "rosetta error" in combined or "ld-linux" in combined:
        return ("amneziawg-go binary requires glibc but container uses musl. "
                "Rebuild image with gcompat fix. On macOS this is expected in test mode.")
    if "RTNETLINK" in combined:
        return f"Network error: {combined.strip()[:200]}"
    return (combined.strip()[:300] or "Unknown error")


_TUNSETIFF   = 0x400454ca  # Linux ioctl: set TUN interface name+flags
_IFF_TUN     = 0x0001
_IFF_NO_PI   = 0x1000


def _open_tun(ifname: str):
    """Open /dev/net/tun and bind it to an interface named ifname.
    Returns the open file descriptor (int) or None on failure."""
    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)
        flags = _IFF_TUN | _IFF_NO_PI
        ifr = struct.pack("16sH14s", ifname.encode()[:15] + b"\x00", flags, b"\x00" * 14)
        fcntl.ioctl(fd, _TUNSETIFF, ifr)
        return fd
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        return None


AWG_GO = "/usr/bin/amneziawg-go"
AWG_TOOL_BIN = "/usr/bin/awg"


def _apply_direct(runtime_conf: str) -> tuple:
    """Userspace AWG startup that bypasses awg-quick.

    amneziawg-go source analysis (main.go):
    - warning() only PRINTS the "not required" message — it does NOT call os.Exit()
    - amneziawg-go creates its own TUN via tun.CreateTUN("/dev/net/tun") then daemonizes:
        parent exits rc=0, child daemon keeps running
    - WG_TUN_FD: if set, uses provided fd instead of creating TUN
    - WG_PROCESS_FOREGROUND=1: suppress warning + run in foreground (no fork)

    Root cause of previous failures:
    - Python _open_tun() created awg0 TUN fd BEFORE amneziawg-go — causing EBUSY
    - bind-mount hiding didn't help because check is via netlink socket, not sysfs

    Correct flow:
      1. Kill existing daemon and delete interface
      2. Launch amneziawg-go (it creates TUN + UAPI + forks → parent exits rc=0)
      3. Wait for parent to exit, verify rc=0
      4. Wait for daemon UAPI socket to appear
      5. Configure via awg setconf
      6. Set IP + bring interface up
      7. Run PostUp

    Returns (warn_or_None, raw_output_str).
    """
    logs = []

    # -- 1. Kill existing daemon and remove interface --------------------------
    # Kill any running amneziawg-go for this interface first
    subprocess.run(["pkill", "-f", f"amneziawg-go {AWG_IF}"],
                   check=False, capture_output=True)
    time.sleep(0.2)
    subprocess.run(["ip", "link", "del", AWG_IF], check=False, capture_output=True)
    time.sleep(0.3)

    # -- 2. Launch amneziawg-go (daemon mode) ----------------------------------
    # amneziawg-go daemonizes: parent creates TUN+UAPI, forks child, parent exits rc=0
    env = os.environ.copy()
    env["LOG_LEVEL"] = "silent"   # suppress warning() noise

    proc = subprocess.Popen(
        [AWG_GO, AWG_IF],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # -- 3. Wait for parent to daemonize (exits rc=0) or fail (rc!=0) ----------
    try:
        proc.wait(timeout=8.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        return ("amneziawg-go start timeout (8s)", "\n".join(logs))

    rc = proc.returncode
    logs.append(f"[direct] amneziawg-go parent exited rc={rc}")
    if rc != 0:
        return (f"amneziawg-go failed (rc={rc}) — check kernel/TUN support",
                "\n".join(logs))

    # -- 4. Wait for daemon UAPI socket to be ready ----------------------------
    import glob as _glob
    uapi_socket = f"/var/run/amneziawg/{AWG_IF}.sock"
    for _ in range(20):
        time.sleep(0.15)
        if os.path.exists(uapi_socket):
            break
    logs.append(f"[direct] UAPI socket ready: {os.path.exists(uapi_socket)}")

    # -- 5. setconf via standard `wg` tool ------------------------------------
    # On Docker Desktop (macOS), amneziawg-go compiled from master has a different
    # UAPI format than the older `awg` tool from ulfrasark. Use standard `wg setconf`
    # with WireGuard-only fields (PrivateKey, ListenPort, Peers).
    # This gives a working WireGuard tunnel for UI testing (no AWG obfuscation in test mode).
    import tempfile as _tmpfile

    # Build WireGuard-only config (no AWG-specific params)
    wg_only_keys_iface = {"PrivateKey", "ListenPort"}
    wg_only_keys_peer  = {"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint"}
    lines_out = []
    _in_peer = False
    _allowed = wg_only_keys_iface
    for _line in runtime_conf.splitlines():
        _s = _line.strip()
        if _s == "[Peer]":
            _in_peer = True
            _allowed = wg_only_keys_peer
            lines_out.append(_line)
            continue
        if _s.startswith("[") and _s != "[Peer]":
            _in_peer = False
            _allowed = wg_only_keys_iface
            lines_out.append(_line)
            continue
        if not _s or _s.startswith("#"):
            continue
        if "=" in _s:
            _k = _s.split("=", 1)[0].strip()
            if _k in _allowed:
                lines_out.append(_line)
    wg_conf = "\n".join(lines_out) + "\n"

    # -- 5a. Build AWG-setconf-compatible config (AWG params, no awg-quick fields) --
    # `awg setconf` accepts AWG/WG params but rejects awg-quick-only fields:
    # Address, DNS, PostUp, PreDown, MTU, Table, etc.
    # We keep all AWG 2.0 params (H1-H4 ranges, I1-I5, S1-S4, Jc, Jmin, Jmax).
    AWG_QUICK_ONLY = {"Address", "DNS", "DNS6", "PostUp", "PostDown",
                      "PreUp", "PreDown", "MTU", "Table", "FwMark",
                      "SaveConfig", "ListenPort"  # ListenPort set via daemon args
                      }
    # Actually keep ListenPort — amneziawg-go UAPI accepts it
    AWG_QUICK_ONLY = {"Address", "DNS", "DNS6", "PostUp", "PostDown",
                      "PreUp", "PreDown", "MTU", "Table", "FwMark", "SaveConfig"}
    awg_lines = []
    for _line in runtime_conf.splitlines():
        _s = _line.strip()
        if not _s or _s.startswith("#") or _s.startswith("["):
            awg_lines.append(_line)
            continue
        if "=" in _s:
            _k = _s.split("=", 1)[0].strip()
            if _k not in AWG_QUICK_ONLY:
                awg_lines.append(_line)
    awg_full_conf = "\n".join(awg_lines) + "\n"

    def _run_setconf(conf_text: str, label: str) -> tuple:
        with _tmpfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tf:
            tf.write(conf_text)
            tf_path = tf.name
        logs.append(f"[direct] setconf ({label}) {len(conf_text)}b")
        try:
            r = subprocess.run(
                [AWG_TOOL_BIN, "setconf", AWG_IF, tf_path],
                capture_output=True, text=True,
            )
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass
        logs.append(f"[direct] setconf ({label}) rc={r.returncode} {r.stderr.strip()[:150]}")
        return r

    r = _run_setconf(awg_full_conf, "awg2.0")
    if r.returncode != 0:
        # Fall back: strip AWG-specific params, apply WireGuard-only fields
        logs.append("[direct] awg2.0 setconf failed — retrying with WG-only params")
        r = _run_setconf(wg_conf, "wg-only")
        if r.returncode != 0:
            return (r.stderr.strip() or "setconf failed", "\n".join(logs))

    # -- 5b. Apply I1-I5 directly via UAPI socket --------------------------------
    # H1-H4 ranges are handled by `awg setconf` (new awg-tools v1.0.20250901+
    # passes them to amneziawg-go correctly as start/end range pairs).
    # UAPI does NOT support range syntax — only single integers.
    # We use UAPI only for I1-I5 (CPS chain strings not supported by old setconf).
    def _apply_cps_via_uapi(conf_text: str) -> str:
        """Apply I1-I5 CPS params to amneziawg-go via UAPI socket.
        H1-H4 are intentionally excluded (ranges must go through awg setconf).
        Returns error string or empty string on success."""
        import socket as _socket
        # Only I1-I5 via UAPI — H1-H4/S/Jc handled by awg setconf
        AWG_UAPI_KEYS = {"I1","I2","I3","I4","I5"}
        UAPI_KEY_MAP  = {}
        cps = {}
        for line in conf_text.splitlines():
            s = line.strip()
            if s.startswith("#") or "=" not in s:
                continue
            k, _, v = s.partition("=")
            k = k.strip().upper()
            if k in AWG_UAPI_KEYS:
                uapi_key = UAPI_KEY_MAP.get(k, k.lower())
                cps[uapi_key] = v.strip()
        if not cps:
            return ""
        sock_path = f"/var/run/amneziawg/{AWG_IF}.sock"
        if not os.path.exists(sock_path):
            return f"UAPI socket not found: {sock_path}"
        try:
            payload = "set=1\n"
            for k, v in cps.items():
                payload += f"{k}={v}\n"
            payload += "\n"
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
                sock.settimeout(5.0)
                sock.connect(sock_path)
                sock.sendall(payload.encode())
                resp = sock.recv(4096).decode(errors="replace")
            logs.append(f"[direct] uapi cps keys={list(cps.keys())} resp={resp.strip()[:80]}")
            if "errno=0" in resp or resp.strip() == "errno=0":
                return ""
            # errno=0 not present = success in some versions; check for error
            if "errno=" in resp and "errno=0" not in resp:
                return f"UAPI CPS error: {resp.strip()}"
            return ""
        except Exception as e:
            return f"UAPI CPS exception: {e}"

    cps_err = _apply_cps_via_uapi(runtime_conf)
    if cps_err:
        logs.append(f"[direct] CPS warning: {cps_err}")
    else:
        logs.append("[direct] I1-I5 applied via UAPI")

    # -- 6. IP + link up -------------------------------------------------------
    iface = _parse_server_section(runtime_conf)
    address = iface.get("Address", "")
    if address:
        subprocess.run(["ip", "addr", "flush", "dev", AWG_IF],
                       check=False, capture_output=True)
        subprocess.run(["ip", "addr", "add", address, "dev", AWG_IF],
                       check=False, capture_output=True)
    subprocess.run(["ip", "link", "set", "up", "dev", AWG_IF],
                   check=False, capture_output=True)
    logs.append(f"[direct] interface up addr={address}")

    # -- 7. PostUp -------------------------------------------------------------
    post_up = iface.get("PostUp", "")
    if post_up:
        for cmd in post_up.split(";"):
            cmd = cmd.strip().replace("%i", AWG_IF)
            if cmd:
                subprocess.run(cmd, shell=True, check=False, capture_output=True)
        logs.append("[direct] PostUp executed")

    return (None, "\n".join(logs))


def _apply_config():
    """Apply config — write runtime conf and restart AWG daemon.
    Config save ALWAYS succeeds (ok=True).
    AWG daemon start failure is returned as a warning string (not a fatal error).
    Returns: (True, None, '') on full success, (True, warn_str, raw_output) if AWG failed to start."""
    full_conf = _read_conf()
    runtime_conf = _build_runtime_conf(full_conf)
    awg_warn = None
    raw_output = ""
    try:
        _write_conf(runtime_conf)

        # Detect Docker Desktop / LinuxKit: WireGuard built-in but amneziawg missing.
        # Use direct daemon management instead of awg-quick to avoid the
        # false-positive "native support" detection in amneziawg-go v0.2.x.
        wg_loaded  = os.path.isdir("/sys/module/wireguard")
        awg_loaded = os.path.isdir("/sys/module/amneziawg")
        if wg_loaded and not awg_loaded:
            awg_warn, raw_output = _apply_direct(runtime_conf)
            return True, awg_warn, raw_output

        # Normal path: use awg-quick (production Linux with amneziawg module)
        subprocess.run([AWG_QUICK, "down", AWG_IF], check=False, capture_output=True)
        result = subprocess.run([AWG_QUICK, "up", AWG_IF],
                                capture_output=True, text=True)
        raw_output = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            awg_warn = _classify_awg_error(result.stderr, result.stdout)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else ""
        raw_output = stderr
        awg_warn = _classify_awg_error(stderr, "")
    except FileNotFoundError:
        awg_warn = "awg-quick not found (dev mode)"
        raw_output = "awg-quick binary missing"
    finally:
        # Always restore full management conf (with disabled markers)
        _write_conf(full_conf)
    return True, awg_warn, raw_output  # config always saved; awg_warn=None means AWG started OK


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        ip = _get_client_ip()
        blocked, remaining = _check_rate_limit(ip)
        if blocked:
            mins = remaining // 60
            secs = remaining % 60
            error = f"Too many failed attempts. Try again in {mins}m {secs}s."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        cur_user, cur_pass = _get_credentials()

        # Timing-safe comparison (prevents timing attacks)
        user_ok = hmac.compare_digest(username, cur_user)
        pass_ok = _verify_password(password, cur_pass)

        if user_ok and pass_ok:
            _reset_attempts(ip)
            session["logged_in"] = True
            session.permanent = True   # persist across browser restarts
            return redirect(url_for("index"))
        else:
            _record_failed_attempt(ip)
            _, remaining = _check_rate_limit(ip)
            entry = _login_attempts.get(ip, {})
            attempts_left = _MAX_ATTEMPTS - entry.get("count", 0)
            if remaining:
                error = f"Too many failed attempts. Blocked for {_BLOCK_SECONDS//60} min."
            else:
                error = f"Invalid login or password. {attempts_left} attempts left."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@require_auth
def index():
    return render_template("index.html")


# ── Server ────────────────────────────────────────────────────────────────────

@app.route("/api/server/status", methods=["GET"])
@require_auth
def server_status():
    stat = _awg_status()
    conf = _read_conf()
    iface = _parse_server_section(conf)
    peers = _parse_peers(conf)
    pub = _derive_pubkey(iface["PrivateKey"]) if iface.get("PrivateKey") else ""
    configured = bool(iface.get("PrivateKey"))

    peer_stats = _awg_peer_stats()
    active_count = sum(1 for s in peer_stats.values() if s["active"])

    total_rx = sum(s["transfer_rx"] for s in peer_stats.values())
    total_tx = sum(s["transfer_tx"] for s in peer_stats.values())

    # Update rolling traffic history
    _update_traffic(total_rx, total_tx, peer_stats)
    rx_24h, tx_24h = _traffic_24h()

    endpoint = _get_endpoint()
    public_ip = _detect_public_ip()

    # System metrics
    uptime_secs = _awg_uptime()
    version     = _awg_version()
    resources   = _system_resources()

    # Config info for dashboard
    conf_params = {
        "H1": iface.get("H1", ""), "H2": iface.get("H2", ""),
        "H3": iface.get("H3", ""), "H4": iface.get("H4", ""),
        "Jc": iface.get("Jc", ""), "Jmin": iface.get("Jmin", ""),
        "Jmax": iface.get("Jmax", ""),
        "S1": iface.get("S1", ""), "S2": iface.get("S2", ""),
        "S3": iface.get("S3", ""), "S4": iface.get("S4", ""),
        "I1": iface.get("I1", ""), "I2": iface.get("I2", ""),
        # AWG 3.1 extras (empty string = not configured)
        "HeaderProtectionKey":   "set" if iface.get("HeaderProtectionKey") else "",
        "RandomTrailers":        iface.get("RandomTrailers", ""),
        "DisableCookies":        iface.get("DisableCookies", ""),
        "ContentPaddingAddition": iface.get("ContentPaddingAddition", ""),
        "RekeyAfterTime":        iface.get("RekeyAfterTime", ""),
        "RekeyTimeout":          iface.get("RekeyTimeout", ""),
        "RejectAfterTime":       iface.get("RejectAfterTime", ""),
        "KeepaliveTimeout":      iface.get("KeepaliveTimeout", ""),
        "MaxHandshakeAttempts":  iface.get("MaxHandshakeAttempts", ""),
    }
    awg31_enabled = bool(iface.get("HeaderProtectionKey"))
    cps_profile = _detect_cps_profile(iface.get("I1", ""))

    # Alerts
    alerts = _check_alerts(stat["running"], configured, peer_stats)

    return jsonify({
        "running":       stat["running"],
        "configured":    configured,
        "interface":     AWG_IF,
        "address":       iface.get("Address", ""),
        "listen_port":   iface.get("ListenPort", AWG_PORT),
        "public_key":    pub,
        "peer_count":    len(peers),
        "active_peers":  active_count,
        "endpoint":      endpoint,
        "public_ip":     public_ip,
        # Traffic
        "total_rx":      _fmt_bytes(total_rx),
        "total_rx_raw":  total_rx,
        "total_tx":      _fmt_bytes(total_tx),
        "total_tx_raw":  total_tx,
        "rx_24h":        _fmt_bytes(rx_24h),
        "tx_24h":        _fmt_bytes(tx_24h),
        # System metrics
        "uptime_secs":   uptime_secs,
        "uptime_str":    _fmt_uptime(uptime_secs),
        "version":       version,
        "load_avg":      resources["load_avg"],
        "cpu_pct":       resources.get("cpu_pct", 0),
        "mem_total":     resources["mem_total"],
        "mem_used":      resources["mem_used"],
        "mem_pct":       resources["mem_pct"],
        "mem_used_str":  _fmt_bytes(resources["mem_used"]),
        "mem_total_str": _fmt_bytes(resources["mem_total"]),
        # Config
        "conf_params":   conf_params,
        "cps_profile":   cps_profile,
        "awg31_enabled": awg31_enabled,
        # Alerts
        "alerts":        alerts,
    })


@app.route("/api/server/init", methods=["POST"])
@require_auth
def init_server():
    data = request.get_json() or {}
    conf = _read_conf()
    iface = _parse_server_section(conf)

    priv_key = iface.get("PrivateKey")
    if not priv_key or data.get("regenerate_keys"):
        priv, pub = _gen_keypair()
        if not priv:
            return jsonify({"error": "Cannot generate keypair"}), 500
        priv_key = priv
    else:
        pub = _derive_pubkey(priv_key)

    gen_inp = default_input()
    gen_inp.update({
        "version":       data.get("version", "2.0"),
        "intensity":     data.get("intensity", "medium"),
        "profile":       data.get("profile", "quic_initial"),
        "junk_level":    int(data.get("junk_level", 4)),
        "router_mode":   bool(data.get("router_mode", False)),
        "use_extreme_max": bool(data.get("use_extreme_max", False)),
        "browser_profile": data.get("browser_profile", "chrome"),
        "use_browser_fp": True,
        "use_tag_c": False,  # <c> unsupported by amneziawg-go obfBuilders → errno=-22
        "use_tag_t": True, "use_tag_r": True,
        "use_tag_rc": True, "use_tag_rd": False,
        # So gen_cfg() applies the S1-S4 >= 12 bytes floor Header Protection
        # requires, when this same /api/server/init call is also enabling
        # AWG 3.1 extras (see awg31_inp below - same source, data.enable_awg31).
        "enable_awg31":  bool(data.get("enable_awg31", False)),
    })
    awg_params = gen_cfg(gen_inp)

    address    = data.get("address", "10.8.0.1/24")
    listen_port = int(data.get("listen_port", AWG_PORT))
    subnet = address.rsplit("/", 1)[0].rsplit(".", 1)[0] + ".0/24"  # e.g. 10.8.0.0/24
    # Auto-detect iptables binary (iptables-legacy on CHR/old kernels, iptables elsewhere)
    # Auto-detect outbound interface via default route — no hardcoded 'eth0'
    ipt = "$(command -v iptables-legacy || command -v iptables)"
    post_up    = (
        f"sysctl -w net.ipv4.ip_forward=1; "
        f"{ipt} -A FORWARD -i {AWG_IF} -j ACCEPT; "
        f"{ipt} -A FORWARD -o {AWG_IF} -j ACCEPT; "
        f"{ipt} -t nat -A POSTROUTING -s {subnet} -j MASQUERADE"
    )
    post_down  = (
        f"{ipt} -D FORWARD -i {AWG_IF} -j ACCEPT; "
        f"{ipt} -D FORWARD -o {AWG_IF} -j ACCEPT; "
        f"{ipt} -t nat -D POSTROUTING -s {subnet} -j MASQUERADE"
    )

    version = awg_params["version"]
    lines = ["[Interface]",
             f"PrivateKey = {priv_key}",
             f"Address = {address}",
             f"ListenPort = {listen_port}"]
    # DNS is client-only — server doesn't need it and awg-quick would fail
    # trying to configure resolvconf which is not available in the container

    if version in ("2.0", "3.1"):
        lines += [f"H1 = {awg_params['H1']}", f"H2 = {awg_params['H2']}",
                  f"H3 = {awg_params['H3']}", f"H4 = {awg_params['H4']}"]
    else:
        lines += [f"H1 = {awg_params['H1s']}", f"H2 = {awg_params['H2s']}",
                  f"H3 = {awg_params['H3s']}", f"H4 = {awg_params['H4s']}"]

    lines += [f"S1 = {awg_params['S1']}", f"S2 = {awg_params['S2']}"]
    if version in ("2.0", "3.1"):
        lines += [f"S3 = {awg_params['S3']}", f"S4 = {awg_params['S4']}"]
    lines += [f"Jc = {awg_params['Jc']}", f"Jmin = {awg_params['Jmin']}", f"Jmax = {awg_params['Jmax']}"]
    if version in ("2.0", "3.1"):
        for tag in ("I1","I2","I3","I4","I5"):
            if awg_params.get(tag):
                lines.append(f"{tag} = {awg_params[tag]}")

    # AWG 3.1 extras (opt-in — see project handoff "СЛЕДУЮЩИЙ ШАГ" for the plan
    # this implements). Off by default: existing 2.0-only servers/peers are
    # untouched unless the caller explicitly passes enable_awg31=true.
    awg31_inp = _awg31_input_from_request(data)
    if awg31_inp["enable_awg31"]:
        try:
            awg31_extra = gen_awg31_extra(awg31_inp)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        # Reuse the existing HeaderProtectionKey on re-init (unless the caller asks
        # to regenerate it) — same reasoning as PrivateKey above: don't silently
        # rotate a key that's already baked into existing peers' client confs.
        existing_hpk = iface.get("HeaderProtectionKey", "")
        if existing_hpk and not data.get("regenerate_header_key"):
            header_key = existing_hpk
        else:
            header_key = _gen_psk()  # 32 random bytes, base64 — same shape as a PSK
        lines.append(f"HeaderProtectionKey = {header_key}")
        lines.append(f"RandomTrailers = {'on' if awg31_extra['RandomTrailers'] else 'off'}")
        lines.append(f"DisableCookies = {'on' if awg31_extra['DisableCookies'] else 'off'}")
        for tag in ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
            if tag in awg31_extra:
                lines.append(f"{tag} = {awg31_extra[tag]}")

    lines += [f"PostUp = {post_up}", f"PreDown = {post_down}"]

    peers = _parse_peers(conf)
    for peer in peers:
        lines.append("")
        lines.append(_peer_to_conf(peer))

    _write_conf("\n".join(lines) + "\n")

    # Auto-start: bring up AWG if requested
    auto_start = bool(data.get("auto_start", True))
    warn = None
    if auto_start:
        _, warn, _ = _apply_config()

    resp = {"ok": True, "public_key": pub, "awg_params": awg_params,
            "endpoint": _get_endpoint()}
    if warn:
        resp["warn"] = f"Config saved but AWG start failed: {warn}"
    return jsonify(resp)


@app.route("/api/server/apply", methods=["POST"])
@require_auth
def apply_config():
    ok, warn, raw = _apply_config()
    return jsonify({"ok": True, "message": warn or "OK", "warn": warn, "_raw": raw})


@app.route("/api/debug/setconf_test", methods=["POST"])
@require_auth
def debug_setconf_test():
    """Test awg setconf with progressively more fields to find what causes Invalid argument."""
    import tempfile as _tf
    data = request.get_json() or {}
    conf_text = data.get("conf", "")
    if not conf_text:
        return jsonify({"error": "no conf provided"})
    with _tf.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write(conf_text)
        path = f.name
    r = subprocess.run([AWG_TOOL_BIN, "setconf", AWG_IF, path],
                       capture_output=True, text=True)
    try:
        os.unlink(path)
    except Exception:
        pass
    return jsonify({"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr})


@app.route("/api/server/rawconf", methods=["GET"])
@require_auth
def get_raw_conf():
    conf = _read_conf()
    masked = re.sub(r"(PrivateKey\s*=\s*)(\S+)", r"\1[hidden]", conf)
    masked = re.sub(r"(PresharedKey\s*=\s*)(\S+)", r"\1[hidden]", masked)
    masked = re.sub(r"(#ClientConf=)(\S+)", r"\1[hidden]", masked)
    return jsonify({"conf": masked})


# ── CPS Generator ─────────────────────────────────────────────────────────────

@app.route("/api/generate", methods=["POST"])
@require_auth
def generate_params():
    data = request.get_json() or {}
    inp = default_input()
    inp.update({
        "version":         data.get("version", "2.0"),
        "intensity":       data.get("intensity", "medium"),
        "profile":         data.get("profile", "quic_initial"),
        "custom_host":     data.get("custom_host", ""),
        "mimic_all":       bool(data.get("mimic_all", False)),
        "use_tag_c":       bool(data.get("use_tag_c", False)),  # unsupported by amneziawg-go
        "use_tag_t":       bool(data.get("use_tag_t", True)),
        "use_tag_r":       bool(data.get("use_tag_r", True)),
        "use_tag_rc":      bool(data.get("use_tag_rc", True)),
        "use_tag_rd":      bool(data.get("use_tag_rd", False)),
        "use_browser_fp":  bool(data.get("use_browser_fp", True)),
        "browser_profile": data.get("browser_profile", "chrome"),
        "mtu":             int(data.get("mtu", 1280)),
        "junk_level":      int(data.get("junk_level", 4)),
        "iter_count":      int(data.get("iter_count", 0)),
        "router_mode":     bool(data.get("router_mode", False)),
        "use_extreme_max": bool(data.get("use_extreme_max", False)),
    })
    cfg = gen_cfg(inp)
    return jsonify(cfg)


@app.route("/api/profiles", methods=["GET"])
@require_auth
def get_profiles():
    return jsonify({
        "mimic_profiles":   [{"id": p, "label": PROFILE_LABELS.get(p, p)} for p in MIMIC_PROFILES],
        "browser_profiles": BROWSER_PROFILES,
    })


# ── Peers ─────────────────────────────────────────────────────────────────────

@app.route("/api/peers", methods=["GET"])
@require_auth
def list_peers():
    conf = _read_conf()
    peers = _parse_peers(conf)
    peer_stats = _awg_peer_stats()
    result = []
    now_ts = int(time.time())
    for p in peers:
        pub = p.get("PublicKey", "")
        s = peer_stats.get(pub, {})
        expiry = p.get("_expiry", "")
        expired = False
        if expiry:
            try:
                exp_ts = int(datetime.strptime(expiry, "%Y-%m-%d").timestamp()) + 86400
                expired = now_ts > exp_ts
            except Exception:
                pass
        disabled = bool(p.get("_disabled", False))
        result.append({
            "name":             p.get("_name", ""),
            "public_key":       pub,
            "allowed_ips":      p.get("AllowedIPs", ""),
            "endpoint":         s.get("endpoint", p.get("Endpoint", "")),
            "has_psk":          bool(p.get("PresharedKey")),
            "has_conf":         bool(p.get("_client_conf")),
            "active":           s.get("active", False) and not disabled,
            "disabled":         disabled,
            "last_handshake":   s.get("handshake_str", "Never"),
            "transfer_rx":      s.get("transfer_rx_str", "0 B"),
            "transfer_tx":      s.get("transfer_tx_str", "0 B"),
            "transfer_rx_bytes": s.get("transfer_rx", 0),
            "transfer_tx_bytes": s.get("transfer_tx", 0),
            "expiry":           expiry,
            "expired":          expired,
        })
    return jsonify(result)


@app.route("/api/peers", methods=["POST"])
@require_auth
def add_peer():
    data = request.get_json() or {}
    conf = _read_conf()
    iface = _parse_server_section(conf)
    if not iface.get("PrivateKey"):
        return jsonify({"error": "Server not initialized. Run Server Setup first."}), 400

    server_pub = _derive_pubkey(iface["PrivateKey"])
    if not server_pub:
        return jsonify({"error": "Cannot derive server public key"}), 500

    peer_priv = data.get("private_key", "")
    peer_pub  = data.get("public_key", "")
    if not peer_pub:
        peer_priv, peer_pub = _gen_keypair()
        if not peer_pub:
            return jsonify({"error": "Cannot generate keypair"}), 500

    psk = data.get("psk", _gen_psk() if data.get("use_psk", True) else "")

    try:
        peer_ip = data.get("allowed_ips") or _next_ip(conf)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    name   = _sanitize_conf_field(data.get("name", f"peer-{peer_pub[:8]}"))
    expiry = _sanitize_conf_field(data.get("expiry", ""), maxlen=32)

    gen_inp = default_input()
    gen_inp.update({
        "version":         data.get("version", "2.0"),
        "intensity":       data.get("intensity", "medium"),
        "profile":         data.get("profile", "quic_initial"),
        "browser_profile": data.get("browser_profile", "chrome"),
        "use_browser_fp":  bool(data.get("use_browser_fp", True)),
        "junk_level":      int(data.get("junk_level", 4)),
        "router_mode":     bool(data.get("router_mode", False)),
        "use_extreme_max": bool(data.get("use_extreme_max", False)),
        "custom_host":     data.get("custom_host", ""),
        "mtu":             int(data.get("mtu", 1280)),
        "mimic_all":       bool(data.get("mimic_all", False)),
        "use_tag_c":       bool(data.get("use_tag_c", False)),  # unsupported by amneziawg-go
        "use_tag_t":       bool(data.get("use_tag_t", True)),
        "use_tag_r":       bool(data.get("use_tag_r", True)),
        "use_tag_rc":      bool(data.get("use_tag_rc", True)),
        "use_tag_rd":      bool(data.get("use_tag_rd", False)),
    })
    awg_params = gen_cfg(gen_inp)

    # H1-H4: pass the SAME RANGES from the server config to the client.
    # amneziawg-go (via new awg-tools setconf) stores start/end and validates
    # any client H value within [start, end]. Client picks a random value from
    # its range; server accepts it if it falls within the server's range.
    # S1-S4, Jc/Jmin/Jmax: single integers, copy from server config.
    # I1-I5: CLIENT-SIDE — each peer gets independently generated CPS.
    srv_iface = _parse_server_section(conf)

    for key in ("H1","H2","H3","H4"):
        srv_val = srv_iface.get(key, "").strip()
        if srv_val:
            awg_params[key] = srv_val          # keep as range string "min-max"
            awg_params[key + "s"] = srv_val    # alias for _build_client_conf
    for key in ("S1","S2","S3","S4","Jc","Jmin","Jmax"):
        srv_val = srv_iface.get(key, "").strip()
        if srv_val:
            awg_params[key] = int(srv_val)

    # AWG 3.1 extras: mirror server's values into the client conf verbatim (if the
    # server has them configured — see /api/server/awg31). Independent per-peer
    # generation would break the protocol here (HeaderProtectionKey especially is
    # a shared symmetric key, not something each peer can pick on its own).
    if srv_iface.get("HeaderProtectionKey"):
        awg_params["HeaderProtectionKey"] = srv_iface["HeaderProtectionKey"]
        awg_params["RandomTrailers"] = srv_iface.get("RandomTrailers", "off").strip().lower() in ("on", "1", "true")
        awg_params["DisableCookies"] = srv_iface.get("DisableCookies", "off").strip().lower() in ("on", "1", "true")
        for tag in ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
            srv_val = srv_iface.get(tag, "").strip()
            if srv_val:
                awg_params[tag] = srv_val

    # I1-I5: independently generated per peer (client-side CPS)
    client_conf = _build_client_conf(peer_priv, peer_pub, server_pub, psk, peer_ip, awg_params)

    # Encode client conf for storage in server config
    client_conf_b64 = base64.b64encode(client_conf.encode()).decode()

    peer_entry = {
        "_name":         name,
        "_client_conf":  client_conf_b64,
        "_expiry":       expiry,
        "PublicKey":     peer_pub,
        "AllowedIPs":    peer_ip,
    }
    if psk:
        peer_entry["PresharedKey"] = psk

    conf += f"\n{_peer_to_conf(peer_entry)}\n"
    _write_conf(conf)

    # Hot-add if AWG is running
    try:
        cmd = [AWG_TOOL, "set", AWG_IF, "peer", peer_pub, "allowed-ips", peer_ip]
        if psk:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as tf:
                tf.write(psk)
                tf_name = tf.name
            cmd += ["preshared-key", tf_name]
        subprocess.run(cmd, capture_output=True)
        if psk:
            os.unlink(tf_name)
    except Exception:
        pass

    return jsonify({
        "ok":          True,
        "name":        name,
        "public_key":  peer_pub,
        "private_key": peer_priv,
        "allowed_ips": peer_ip,
        "expiry":      expiry,
        "client_conf": client_conf,
        "awg_params":  awg_params,
    })


@app.route("/api/peers/<path:pub_key>", methods=["DELETE"])
@require_auth
def delete_peer(pub_key: str):
    conf = _read_conf()
    peers = _parse_peers(conf)
    if not any(p.get("PublicKey") == pub_key for p in peers):
        return jsonify({"error": "Peer not found"}), 404

    remaining = [p for p in peers if p.get("PublicKey") != pub_key]
    _write_conf(_rebuild_conf(conf, remaining))
    try:
        subprocess.run([AWG_TOOL, "set", AWG_IF, "peer", pub_key, "remove"], capture_output=True)
    except Exception:
        pass
    return jsonify({"ok": True})


@app.route("/api/peers/<path:pub_key>/suspend", methods=["POST"])
@require_auth
def suspend_peer(pub_key: str):
    """Disable a peer: mark _disabled in parsed data, rebuild conf, hot-remove from live AWG."""
    conf = _read_conf()
    peers = _parse_peers(conf)
    peer = next((p for p in peers if p.get("PublicKey") == pub_key), None)
    if peer is None:
        return jsonify({"error": "Peer not found"}), 404

    peer["_disabled"] = True
    _write_conf(_rebuild_conf(conf, peers))

    try:
        subprocess.run([AWG_TOOL, "set", AWG_IF, "peer", pub_key, "remove"],
                       capture_output=True)
    except Exception:
        pass
    return jsonify({"ok": True, "disabled": True})


@app.route("/api/peers/<path:pub_key>/resume", methods=["POST"])
@require_auth
def resume_peer(pub_key: str):
    """Re-enable a peer: clear _disabled in parsed data, rebuild conf, hot-add to live AWG."""
    conf = _read_conf()
    peers = _parse_peers(conf)
    peer = next((p for p in peers if p.get("PublicKey") == pub_key), None)
    if peer is None:
        return jsonify({"error": "Peer not found"}), 404

    peer["_disabled"] = False
    _write_conf(_rebuild_conf(conf, peers))

    # Hot-add back to live AWG interface
    allowed_ips = peer.get("AllowedIPs", "")
    psk = peer.get("PresharedKey", "")
    try:
        cmd = [AWG_TOOL, "set", AWG_IF, "peer", pub_key, "allowed-ips", allowed_ips]
        if psk:
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as tf:
                tf.write(psk)
                tf_name = tf.name
            cmd += ["preshared-key", tf_name]
        subprocess.run(cmd, capture_output=True)
        if psk:
            os.unlink(tf_name)
    except Exception:
        pass
    return jsonify({"ok": True, "disabled": False})


@app.route("/api/peers/<path:pub_key>/conf", methods=["GET"])
@require_auth
def get_peer_conf(pub_key: str):
    return _peer_conf_by_key(pub_key)


@app.route("/api/peer/conf", methods=["GET"])
@require_auth
def get_peer_conf_qs():
    """Return stored client config — pubkey via ?pub= query string."""
    pub_key = request.args.get("pub", "")
    return _peer_conf_by_key(pub_key)


def _peer_conf_by_key(pub_key: str):
    conf = _read_conf()
    peers = _parse_peers(conf)
    for p in peers:
        if p.get("PublicKey") == pub_key:
            cc_b64 = p.get("_client_conf", "")
            if not cc_b64:
                return jsonify({"error": "No stored config for this peer"}), 404
            try:
                cc = base64.b64decode(cc_b64).decode()
            except Exception:
                return jsonify({"error": "Corrupt stored config"}), 500
            name = p.get("_name", pub_key[:8])
            return jsonify({"conf": cc, "name": name})
    return jsonify({"error": "Peer not found"}), 404


@app.route("/api/peers/<path:pub_key>/qr", methods=["GET"])
@require_auth
def peer_qr(pub_key: str):
    return _peer_qr_by_key(pub_key)


@app.route("/api/peer/qr", methods=["GET"])
@require_auth
def peer_qr_qs():
    """Generate QR — pubkey via ?pub= query string."""
    pub_key = request.args.get("pub", "")
    return _peer_qr_by_key(pub_key)


def _peer_qr_by_key(pub_key: str):
    client_conf = ""
    conf = _read_conf()
    peers = _parse_peers(conf)
    for p in peers:
        if p.get("PublicKey") == pub_key:
            cc_b64 = p.get("_client_conf", "")
            if cc_b64:
                try:
                    client_conf = base64.b64decode(cc_b64).decode()
                except Exception:
                    pass
            break
    if not client_conf:
        return jsonify({"error": "No config available for QR"}), 400
    try:
        return jsonify({"qr_base64": _make_qr_png(client_conf)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/peer/delete", methods=["POST"])
@require_auth
def delete_peer_qs():
    """Delete peer — pubkey via ?pub= query string."""
    pub_key = request.args.get("pub", "")
    if not pub_key:
        return jsonify({"error": "pub parameter required"}), 400
    # Reuse delete logic
    return _delete_peer_by_key(pub_key)


def _delete_peer_by_key(pub_key: str):
    conf = _read_conf()
    peers = _parse_peers(conf)
    if not any(p.get("PublicKey") == pub_key for p in peers):
        return jsonify({"error": "Peer not found"}), 404
    remaining = [p for p in peers if p.get("PublicKey") != pub_key]
    _write_conf(_rebuild_conf(conf, remaining))
    try:
        subprocess.run([AWG_TOOL, "set", AWG_IF, "peer", pub_key, "remove"], capture_output=True)
    except Exception:
        pass
    return jsonify({"ok": True})


def _make_qr_png(text: str) -> str:
    """Generate QR PNG and return as data URI base64."""
    import qrcode
    qr = qrcode.QRCode(version=None,
                       error_correction=qrcode.constants.ERROR_CORRECT_L,
                       box_size=8, border=3)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode()
    return f"data:image/png;base64,{b64}"


@app.route("/api/peer/qr_from_conf", methods=["POST"])
@require_auth
def qr_from_conf():
    """Generate QR from raw conf text (used for newly created peers)."""
    body = request.get_json() or {}
    client_conf = body.get("conf", "").strip()
    if not client_conf:
        return jsonify({"error": "No conf provided"}), 400
    try:
        return jsonify({"qr_base64": _make_qr_png(client_conf)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Peer traffic history ──────────────────────────────────────────────────────

@app.route("/api/peers/<path:pub_key>/traffic", methods=["GET"])
@require_auth
def peer_traffic_history(pub_key):
    history = _peer_traffic_history.get(pub_key, [])
    return jsonify([{"ts": p[0], "rx": p[1], "tx": p[2]} for p in history])


# ── Peer geo + ping ───────────────────────────────────────────────────────────

@app.route("/api/peers/<path:pub_key>/geo", methods=["GET"])
@require_auth
def peer_geo(pub_key):
    peer_stats = _awg_peer_stats()
    s = peer_stats.get(pub_key, {})
    ep = s.get("endpoint", "")
    ip = ep.split(":")[0] if ep else ""
    if not ip or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return jsonify({"country": "", "cc": "", "flag": "", "ip": ip})
    geo = _get_geo(ip)
    return jsonify({**geo, "ip": ip})


@app.route("/api/peers/<path:pub_key>/ping", methods=["GET"])
@require_auth
def peer_ping(pub_key):
    conf = _read_conf()
    peers = _parse_peers(conf)
    peer = next((p for p in peers if p.get("PublicKey") == pub_key), None)
    if not peer:
        return jsonify({"latency": -1, "error": "peer not found"}), 404
    # Ping the peer's tunnel IP (AllowedIPs first address)
    allowed = peer.get("AllowedIPs", "")
    ip = allowed.split(",")[0].split("/")[0].strip() if allowed else ""
    if not ip:
        return jsonify({"latency": -1, "error": "no tunnel IP"})
    latency = _ping_peer(ip)
    return jsonify({"latency": latency, "ip": ip})


# ── Regenerate CPS ────────────────────────────────────────────────────────────

@app.route("/api/server/regen_cps", methods=["POST"])
@require_auth
def regen_cps():
    conf = _read_conf()
    iface = _parse_server_section(conf)
    settings = _load_settings()

    gen_inp = default_input()
    saved = settings.get("gen_params", {})
    for k in ("version","intensity","profile","mimic_all","use_tag_t",
              "use_tag_r","use_tag_rc","use_tag_rd","browser_profile",
              "use_browser_fp","mtu","junk_level","router_mode",
              "use_extreme_max","custom_host"):
        if k in saved:
            gen_inp[k] = saved[k]
    # Keep respecting the S1-S4 >= 12 floor on every regen if Header
    # Protection is already enabled on this server - otherwise a routine
    # "Regenerate CPS" would silently drop S1-S4 back below the floor and
    # re-break Header Protection with no error anywhere.
    gen_inp["enable_awg31"] = bool(iface.get("HeaderProtectionKey"))

    awg_params = gen_cfg(gen_inp)
    logs = []

    # Apply I1-I5 via UAPI
    i_params = {k: awg_params.get(k, "") for k in ("I1","I2","I3","I4","I5")}
    try:
        uapi_lines = []
        for tag, val in i_params.items():
            if val:
                uapi_lines.append(f"{tag.lower()}={val}")
        if uapi_lines:
            sock_path = f"/var/run/amneziawg/{AWG_IF}.sock"
            if os.path.exists(sock_path):
                import socket as _sock
                s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
                s.connect(sock_path)
                msg = "set=1\n" + "\n".join(uapi_lines) + "\n\n"
                s.sendall(msg.encode())
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    resp += chunk
                    if b"\n\n" in resp: break
                s.close()
                logs.append(resp.decode().strip())
    except Exception as e:
        logs.append(f"UAPI error: {e}")

    # Update I1-I5 in raw conf text, then rebuild
    import re as _re
    updated = conf
    for tag, val in i_params.items():
        if not val:
            continue
        if _re.search(rf'^{tag}\s*=', updated, _re.MULTILINE):
            updated = _re.sub(rf'^{tag}\s*=.*$', f'{tag} = {val}', updated, flags=_re.MULTILINE)
        else:
            # insert before first [Peer] block (or append to interface section)
            if '[Peer]' in updated:
                updated = updated.replace('[Peer]', f'{tag} = {val}\n[Peer]', 1)
            else:
                updated = updated.rstrip() + f'\n{tag} = {val}\n'
    _write_conf(_rebuild_conf(updated, _parse_peers(updated)))

    return jsonify({
        "ok": True,
        "cps_profile": _detect_cps_profile(i_params.get("I1", "")),
        "I1": i_params.get("I1", ""),
        "logs": logs,
    })


@app.route("/api/server/awg31", methods=["POST"])
@require_auth
def server_awg31():
    """Enable/update or disable the AWG 3.1 extras (HeaderProtectionKey,
    RandomTrailers, DisableCookies, ContentPaddingAddition, Rekey*/Keepalive*/
    MaxHandshakeAttempts) on the server's [Interface] WITHOUT touching
    PrivateKey/H1-H4/S1-S4/Jc/Jmin/Jmax/I1-I5 or existing peers — unlike
    /api/server/init, which regenerates the whole CPS profile.

    Existing peers are NOT retroactively updated (their stored #ClientConf
    already has the OLD HeaderProtectionKey baked in, if any) — new peers
    created after this call will pick up the current values (see add_peer()).
    Re-downloading/re-issuing existing peers' configs after enabling is the
    caller's job if they need every device on the new key.
    """
    data = request.get_json() or {}
    conf = _read_conf()
    iface = _parse_server_section(conf)
    if not iface.get("PrivateKey"):
        return jsonify({"error": "Server not initialized. Run Server Setup first."}), 400

    enable = bool(data.get("enable_awg31", False))
    logs = []

    _AWG31_KEYS = ("HeaderProtectionKey", "RandomTrailers", "DisableCookies",
                   "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                   "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts")

    # Header Protection requires S1-S4 >= 12 bytes (amnezia-vpn docs: "To use
    # Header Protection, S1-S4 values must be at least 12 bytes"). A config
    # below that floor doesn't error anywhere - the handshake just silently
    # never completes. Rather than reject enabling here (which would make
    # "turn on AWG 3.1 extras after a normal 2.0 setup" - the whole point of
    # this endpoint - fail unpredictably depending on what CPS Generator
    # happened to roll), bump only the values that are actually too low.
    # Existing peers already need reissuing after HeaderProtectionKey changes
    # (see docstring above) - bumping S1-S4 at the same time doesn't add a
    # new caveat, it rides along with one that's already there.
    s_bump = {}
    if enable:
        for tag in ("S1", "S2", "S3", "S4"):
            try:
                val = int(iface.get(tag, "0") or "0")
            except ValueError:
                val = 0
            if val < 12:
                s_bump[tag] = 12

    new_values = {}
    if enable:
        awg31_inp = _awg31_input_from_request(data)
        awg31_inp["enable_awg31"] = True
        try:
            awg31_extra = gen_awg31_extra(awg31_inp)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

        existing_hpk = iface.get("HeaderProtectionKey", "")
        if existing_hpk and not data.get("regenerate_header_key"):
            header_key = existing_hpk
        else:
            header_key = _gen_psk()
        new_values["HeaderProtectionKey"] = header_key
        new_values["RandomTrailers"] = "on" if awg31_extra["RandomTrailers"] else "off"
        new_values["DisableCookies"] = "on" if awg31_extra["DisableCookies"] else "off"
        for tag in ("ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
                    "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"):
            if tag in awg31_extra:
                new_values[tag] = awg31_extra[tag]

    # ── Rewrite persisted conf: replace/insert enabled keys, strip removed ones ──
    updated = conf
    for tag in _AWG31_KEYS:
        if tag in new_values:
            val = new_values[tag]
            if re.search(rf'^{tag}\s*=', updated, re.MULTILINE):
                updated = re.sub(rf'^{tag}\s*=.*$', f'{tag} = {val}', updated, flags=re.MULTILINE)
            elif '[Peer]' in updated:
                updated = updated.replace('[Peer]', f'{tag} = {val}\n[Peer]', 1)
            else:
                updated = updated.rstrip() + f'\n{tag} = {val}\n'
        else:
            # not enabled / not provided this time → remove if present
            updated = re.sub(rf'^{tag}\s*=.*\n?', '', updated, flags=re.MULTILINE)
    for tag, val in s_bump.items():
        # These already exist (server is initialized) - always a plain replace.
        updated = re.sub(rf'^{tag}\s*=.*$', f'{tag} = {val}', updated, flags=re.MULTILINE)
    _write_conf(_rebuild_conf(updated, _parse_peers(updated)))
    if s_bump:
        logs.append(
            f"Raised {', '.join(f'{k} to {v}' for k, v in s_bump.items())} "
            "(Header Protection requires S1-S4 >= 12 bytes) - existing peers "
            "need their configs reissued, same as for the new HeaderProtectionKey."
        )

    # ── Hot-apply via UAPI (best-effort — matches regen_cps()'s I1-I5 mechanism) ──
    hot_applied = False
    if new_values:
        try:
            import socket
            uapi_lines = []
            for tag, val in new_values.items():
                if tag == "HeaderProtectionKey":
                    uapi_lines.append(f"header_protection_key={_b64_key_to_hex(val)}")
                else:
                    uapi_key = re.sub(r'(?<!^)(?=[A-Z])', '_', tag).lower()
                    uapi_lines.append(f"{uapi_key}={val}")
            sock_path = f"/var/run/amneziawg/{AWG_IF}.sock"
            if os.path.exists(sock_path) and uapi_lines:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect(sock_path)
                msg = "set=1\n" + "\n".join(uapi_lines) + "\n\n"
                s.sendall(msg.encode())
                resp = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\n\n" in resp:
                        break
                s.close()
                resp_text = resp.decode(errors="replace").strip()
                logs.append(resp_text)
                hot_applied = "errno=0" in resp_text or resp_text == ""
        except Exception as e:
            logs.append(f"UAPI error: {e}")
    elif not enable:
        logs.append("Disabled in saved config — a full AWG restart "
                     "(Apply Config) is needed to clear it from the running daemon.")

    return jsonify({
        "ok": True,
        "enabled": enable,
        "values": new_values,
        "hot_applied": hot_applied,
        "logs": logs,
    })


# ── Settings ─────────────────────────────────────────────────────────────────

@app.route("/api/ssl/configure", methods=["POST"])
@require_auth
def configure_ssl():
    """Configure SSL from UI: self-signed or Let's Encrypt."""
    data = request.get_json() or {}
    mode   = data.get("mode", "selfsigned")   # "selfsigned" | "letsencrypt"
    domain = data.get("domain", "").strip()
    email  = data.get("email", "").strip()

    ssl_dir  = "/etc/amnezia/amneziawg/ssl"
    os.makedirs(ssl_dir, exist_ok=True)

    if mode == "letsencrypt":
        if not domain:
            return jsonify({"error": "Domain required for Let's Encrypt"}), 400
        acme_root = "/var/www/acme"
        os.makedirs(acme_root, exist_ok=True)
        cmd = [
            "certbot", "certonly", "--webroot",
            "-w", acme_root, "-d", domain,
            "--email", email or f"admin@{domain}",
            "--agree-tos", "--non-interactive", "--quiet"
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            return jsonify({"error": r.stderr or r.stdout or "certbot failed"}), 500
        cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key  = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    else:
        # Self-signed — regenerate with given CN (domain or IP)
        cn = domain or "awg2-webui"
        cert = f"{ssl_dir}/selfsigned.crt"
        key  = f"{ssl_dir}/selfsigned.key"
        r = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert,
            "-days", "3650", "-subj", f"/CN={cn}"
        ], capture_output=True, text=True)
        if r.returncode != 0:
            return jsonify({"error": r.stderr or "openssl failed"}), 500

    # Patch nginx config with new cert paths and reload
    nginx_conf = "/etc/nginx/nginx.conf"
    try:
        nc = open(nginx_conf).read()
        import re as _re
        nc = _re.sub(r'ssl_certificate\s+[^;]+;',     f'ssl_certificate {cert};',     nc)
        nc = _re.sub(r'ssl_certificate_key\s+[^;]+;', f'ssl_certificate_key {key};',  nc)
        open(nginx_conf, 'w').write(nc)
        subprocess.run(["nginx", "-s", "reload"], check=True)
    except Exception as e:
        return jsonify({"error": f"nginx reload failed: {e}"}), 500

    # Persist to settings
    s = _load_settings()
    s["ssl_domain"] = domain
    s["ssl_mode"]   = mode
    _save_settings(s)

    return jsonify({"ok": True, "mode": mode, "domain": domain,
                    "cert": cert, "key": key})


@app.route("/api/settings", methods=["GET"])
@require_auth
def get_settings():
    s = _load_settings()
    cur_user, _ = _get_credentials()
    # SSL status — check env var and settings file
    ssl_domain = os.environ.get("SSL_DOMAIN", "") or s.get("ssl_domain", "")
    ssl_mode   = s.get("ssl_mode", "selfsigned")
    if ssl_mode == "letsencrypt" and ssl_domain:
        ssl_cert   = f"/etc/letsencrypt/live/{ssl_domain}/fullchain.pem"
        ssl_active = os.path.exists(ssl_cert)
    else:
        ssl_cert   = "/etc/amnezia/amneziawg/ssl/selfsigned.crt"
        ssl_active = os.path.exists(ssl_cert)
    ssl_expiry = ""
    if ssl_active:
        try:
            out = subprocess.check_output(
                ["openssl", "x509", "-noout", "-enddate", "-in", ssl_cert],
                text=True, stderr=subprocess.DEVNULL
            ).strip()
            ssl_expiry = out.replace("notAfter=", "")
        except Exception:
            pass
    return jsonify({
        "username": cur_user,
        "has_custom_creds": bool(s.get("username") or s.get("password")),
        "endpoint": s.get("endpoint", ""),
        "ssl_domain": ssl_domain,
        "ssl_active": ssl_active,
        "ssl_expiry": ssl_expiry,
        "ip_list": os.environ.get("IP_LIST", ""),
    })


@app.route("/api/settings", methods=["POST"])
@require_auth
def update_settings():
    data = request.get_json() or {}
    cur_user, cur_pass = _get_credentials()

    # Verify old password (timing-safe)
    old_pass = data.get("old_password", "")
    if not _verify_password(old_pass, cur_pass):
        return jsonify({"error": "Текущий пароль неверный"}), 403

    new_user = data.get("username", "").strip()
    new_pass = data.get("new_password", "").strip()

    if not new_user or not new_pass:
        return jsonify({"error": "Логин и пароль не могут быть пустыми"}), 400
    if len(new_pass) < 6:
        return jsonify({"error": "Пароль минимум 6 символов"}), 400

    # Store password as scrypt hash (never plain-text)
    _save_settings({"username": new_user, "password": _hash_password(new_pass)})
    # Force re-login with new credentials
    session.clear()
    return jsonify({"ok": True, "message": "Учётные данные обновлены. Войдите заново."})


@app.route("/api/settings/endpoint", methods=["POST"])
@require_auth
def update_endpoint():
    """Save custom endpoint (host:port or empty for auto)."""
    data = request.get_json() or {}
    ep = data.get("endpoint", "").strip()
    _save_settings({"endpoint": ep})
    return jsonify({"ok": True, "endpoint": ep or "auto", "resolved": _get_endpoint()})


# ── One-Time Links ────────────────────────────────────────────────────────────

@app.route("/api/peer/otl/<path:pub_key>", methods=["POST"])
@require_auth
def create_otl(pub_key: str):
    """Create a one-time download link for a peer's client config."""
    conf = _read_conf()
    peers = _parse_peers(conf)
    for p in peers:
        if p.get("PublicKey") == pub_key:
            cc_b64 = p.get("_client_conf", "")
            if not cc_b64:
                return jsonify({"error": "No stored config for this peer"}), 404
            try:
                cc = base64.b64decode(cc_b64).decode()
            except Exception:
                return jsonify({"error": "Corrupt stored config"}), 500
            token = str(uuid.uuid4())
            _otl_store[token] = {
                "conf": cc,
                "name": p.get("_name", pub_key[:8]),
                "expires": time.time() + 3600,  # 1 hour
            }
            return jsonify({"token": token, "url": f"/dl/{token}"})
    return jsonify({"error": "Peer not found"}), 404


@app.route("/dl/<token>", methods=["GET"])
def one_time_download(token: str):
    """Serve a one-time conf download — no auth required."""
    entry = _otl_store.get(token)
    if not entry:
        abort(404)
    if time.time() > entry["expires"]:
        _otl_store.pop(token, None)
        abort(410)  # Gone
    conf_text = entry["conf"]
    name = entry["name"]
    _otl_store.pop(token, None)  # Consume the link
    return Response(
        conf_text,
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{name}.conf"'},
    )


# ── Prometheus metrics ────────────────────────────────────────────────────────

@app.route("/metrics", methods=["GET"])
@require_auth
def prometheus_metrics():
    """Expose basic peer stats in Prometheus text format."""
    conf = _read_conf()
    peers = _parse_peers(conf)
    peer_stats = _awg_peer_stats()
    now_ts = int(time.time())

    lines = [
        "# HELP awg_peer_active Is peer active (handshake < 3 min)",
        "# TYPE awg_peer_active gauge",
        "# HELP awg_peer_transfer_rx_bytes Received bytes",
        "# TYPE awg_peer_transfer_rx_bytes counter",
        "# HELP awg_peer_transfer_tx_bytes Transmitted bytes",
        "# TYPE awg_peer_transfer_tx_bytes counter",
        "# HELP awg_peer_last_handshake_seconds Last handshake Unix timestamp",
        "# TYPE awg_peer_last_handshake_seconds gauge",
    ]

    for p in peers:
        pub = p.get("PublicKey", "")
        name = p.get("_name", pub[:8]).replace('"', '_')
        s = peer_stats.get(pub, {})
        active = 1 if s.get("active") else 0
        rx = s.get("transfer_rx", 0)
        tx = s.get("transfer_tx", 0)
        hs = s.get("last_handshake", 0)
        label = f'{{peer="{name}",pubkey="{pub[:16]}"}}'
        lines += [
            f"awg_peer_active{label} {active}",
            f"awg_peer_transfer_rx_bytes{label} {rx}",
            f"awg_peer_transfer_tx_bytes{label} {tx}",
            f"awg_peer_last_handshake_seconds{label} {hs}",
        ]

    lines += [
        "# HELP awg_peers_total Total number of configured peers",
        "# TYPE awg_peers_total gauge",
        f"awg_peers_total {len(peers)}",
        "# HELP awg_peers_active Total active peers",
        "# TYPE awg_peers_active gauge",
        f"awg_peers_active {sum(1 for s in peer_stats.values() if s.get('active'))}",
    ]

    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")


# ── System logs ───────────────────────────────────────────────────────────────

LOG_FILES = {
    "Nginx Access":       "/var/log/nginx/access.log",
    "Nginx Error":        "/var/log/nginx/error.log",
    "Supervisor":         "/var/log/supervisor/supervisord.log",
    "WebUI Access":       _WEBUI_ACCESS_LOG,
    "WebUI Error":        _WEBUI_ERROR_LOG,
    # Raw supervisord-captured stdout+stderr - startup banner, auto-start
    # apply logs, and anything that crashes before _setup_split_logging()
    # attaches its own handlers (or bypasses logging entirely via print()).
    "WebUI Startup/Crash": "/var/log/supervisor/flask.log",
}


@app.route("/api/system/logs", methods=["GET"])
@require_auth
def system_logs():
    """Return list of log files with sizes."""
    result = []
    for name, path in LOG_FILES.items():
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        result.append({"name": name, "path": path, "size": size})
    return jsonify(result)


@app.route("/api/system/logs/view", methods=["GET"])
@require_auth
def system_logs_view():
    """Return last N lines of a log file by path."""
    path = request.args.get("path", "")
    # Security: only allow known log paths
    allowed = set(LOG_FILES.values())
    if path not in allowed:
        return jsonify({"error": "Not allowed"}), 403
    lines = int(request.args.get("lines", 100))
    try:
        with open(path) as f:
            content = f.readlines()
        return jsonify({"lines": content[-lines:]})
    except OSError:
        return jsonify({"lines": []})


# ── Config export ─────────────────────────────────────────────────────────────

@app.route("/api/config/export", methods=["GET"])
@require_auth
def export_config():
    """Return full server config as JSON backup."""
    conf = _read_conf()
    iface = _parse_server_section(conf)
    peers = _parse_peers(conf)
    export_peers = []
    for p in peers:
        cc_b64 = p.get("_client_conf", "")
        client_conf = None
        if cc_b64:
            try:
                client_conf = base64.b64decode(cc_b64).decode()
            except Exception:
                pass
        export_peers.append({
            "name": p.get("_name", ""),
            "public_key": p.get("PublicKey", ""),
            "allowed_ips": p.get("AllowedIPs", ""),
            "expiry": p.get("_expiry", ""),
            "disabled": bool(p.get("_disabled", False)),
            "client_conf": client_conf,
        })
    return jsonify({
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "awg_version": "3.1" if iface.get("HeaderProtectionKey") else "2.0",
        "server": {
            "interface": AWG_IF,
            "address": iface.get("Address", ""),
            "listen_port": iface.get("ListenPort", AWG_PORT),
            "endpoint": _get_endpoint(),
        },
        "raw_conf": conf,
        "peers": export_peers,
        "peer_count": len(peers),
    })


def _auto_start_awg():
    """Auto-apply AWG config on Flask startup if config exists and interface is down."""
    import threading, time as _time
    def _do():
        _time.sleep(2)  # wait for amneziawg-go to settle after container start
        conf = _read_conf()
        if not conf:
            print("[AWG auto-start] No config found, skipping")
            return
        # Check if interface is already up
        try:
            r = subprocess.run([AWG_TOOL, "show", AWG_IF],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "interface:" in r.stdout:
                print(f"[AWG auto-start] {AWG_IF} already up, skipping")
                return
        except Exception:
            pass
        print(f"[AWG auto-start] Applying config: {AWG_CONF_PATH}")
        try:
            runtime = _build_runtime_conf(conf)
            warn, log = _apply_direct(runtime)
            print(f"[AWG auto-start] detail: {log}")
            if warn:
                print(f"[AWG auto-start] WARN: {warn}")
            else:
                print(f"[AWG auto-start] OK — {AWG_IF} is up")
        except Exception as e:
            print(f"[AWG auto-start] ERROR: {e}")
    threading.Thread(target=_do, daemon=True).start()


if __name__ == "__main__":
    print(f"[AWG Web UI] Starting on port {WEB_PORT}")
    print(f"[AWG Web UI] Config: {AWG_CONF_PATH}")
    _setup_split_logging()
    _auto_start_awg()
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
