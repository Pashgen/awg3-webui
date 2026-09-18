#!/bin/sh
# AWG 3.1 Web UI — container entrypoint
# Starts AWG (if config exists) + nginx + Flask via supervisord

set -e

AWG_IF="${AWG_INTERFACE:-awg0}"
AWG_CONF="/etc/amnezia/amneziawg/${AWG_IF}.conf"
AWG_QUICK="/usr/bin/awg-quick"
NGINX_CONF="/etc/nginx/nginx.conf"
ACME_WEBROOT="/var/www/acme"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AWG 3.1 Web UI — starting"
echo "  Interface : $AWG_IF"
echo "  Config    : $AWG_CONF"
echo "  AWG port  : ${AWG_PORT:-51820}/udp"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || true

# Fix stale ip rules (RouterOS compat)
ip rule 2>/dev/null | awk '
  /lookup main/    && $1+0 < 32766 { gsub(":","", $1); print $1 }
  /lookup default/ && $1+0 < 32767 { gsub(":","", $1); print $1 }
' | while read prio; do
    ip rule del priority "$prio" 2>/dev/null || true
done
ip rule 2>/dev/null | grep -q "lookup main"    || ip rule add lookup main    priority 32766 2>/dev/null || true
ip rule 2>/dev/null | grep -q "lookup default" || ip rule add lookup default priority 32767 2>/dev/null || true

# Try to load amneziawg kernel module (needed when kernel has native AWG support)
if modprobe amneziawg 2>/dev/null; then
    echo "[AWG] kernel module amneziawg loaded"
else
    echo "[AWG] amneziawg module not available — will use amneziawg-go userspace"
    # Docker Desktop (LinuxKit) has WireGuard built-in but not AmneziaWG.
    # amneziawg-go v0.2.x wrongly detects /sys/module/wireguard as "native amneziawg support"
    # and exits without starting. Unload wireguard so amneziawg-go falls through to userspace.
    if [ -d /sys/module/wireguard ] && ! [ -d /sys/module/amneziawg ]; then
        echo "[AWG] Docker Desktop detected: unloading wireguard to allow amneziawg-go userspace mode"
        modprobe -r wireguard 2>/dev/null \
            && echo "[AWG] wireguard unloaded OK" \
            || echo "[AWG] could not unload wireguard (built-in or in use) — AWG may not start"
    fi
fi

# Ensure /dev/net/tun exists (required for userspace amneziawg-go)
if [ ! -e /dev/net/tun ]; then
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200 2>/dev/null || true
    chmod 600 /dev/net/tun 2>/dev/null || true
    [ -e /dev/net/tun ] \
        && echo "[AWG] /dev/net/tun created" \
        || echo "[AWG] WARN: cannot create /dev/net/tun (pass --device /dev/net/tun to docker run)"
fi

# Start AWG if config exists
if [ -f "$AWG_QUICK" ] && [ -f "$AWG_CONF" ]; then
    echo "[AWG] bringing up $AWG_IF..."
    "$AWG_QUICK" up "$AWG_IF" 2>&1 || echo "[AWG] WARN: awg-quick up failed"
else
    echo "[AWG] config not found at $AWG_CONF — skipping (web UI only mode)"
fi

# ── Build nginx allow/deny block from IP_LIST env var ─────────────────────────
# IP_LIST: comma-separated list of IPs/CIDRs that may access the web UI.
# If empty — no restriction (allow all).
build_ip_block() {
    if [ -z "${IP_LIST:-}" ]; then
        echo "        # IP_LIST not set — allow all"
        echo "        allow all;"
        return
    fi
    echo "        # IP_LIST whitelist"
    echo "$IP_LIST" | tr ',' '\n' | while IFS= read -r ip; do
        ip="$(echo "$ip" | tr -d ' ')"
        [ -n "$ip" ] && echo "        allow $ip;"
    done
    echo "        deny all;"
}

# ── SSL configuration (3 modes, checked in priority order) ────────────────────
#
#  Mode 1 — BYO cert:      set SSL_CERT=/path/cert.pem  SSL_KEY=/path/key.pem
#  Mode 2 — Let's Encrypt: set SSL_DOMAIN=vpn.example.com  [SSL_EMAIL=...]
#  Mode 3 — Self-signed:   default, auto-generated on first start (persisted)
#
# ─────────────────────────────────────────────────────────────────────────────

SELFSIGNED_DIR="/etc/amnezia/amneziawg/ssl"
SELFSIGNED_CERT="$SELFSIGNED_DIR/selfsigned.crt"
SELFSIGNED_KEY="$SELFSIGNED_DIR/selfsigned.key"

SSL_CERT="${SSL_CERT:-}"
SSL_KEY="${SSL_KEY:-}"

# ── Mode 1: BYO certificate ──────────────────────────────────────────────────
if [ -n "$SSL_CERT" ] && [ -f "$SSL_CERT" ] && [ -n "$SSL_KEY" ] && [ -f "$SSL_KEY" ]; then
    echo "[SSL] Mode 1 — Using provided certificate: $SSL_CERT"

# ── Mode 2: Let's Encrypt via certbot ────────────────────────────────────────
elif [ -n "${SSL_DOMAIN:-}" ]; then
    echo "[SSL] Mode 2 — Let's Encrypt for $SSL_DOMAIN"
    mkdir -p "$ACME_WEBROOT"
    cat > /tmp/nginx-acme.conf <<ACMENGINX
user nginx;
worker_processes 1;
error_log /dev/stderr warn;
pid /run/nginx/nginx.pid;
events { worker_connections 64; }
http {
    server {
        listen 80;
        server_name _;
        location /.well-known/acme-challenge/ { root $ACME_WEBROOT; }
        location / { return 444; }
    }
}
ACMENGINX
    nginx -c /tmp/nginx-acme.conf 2>/dev/null || true
    sleep 1
    if certbot certonly \
        --webroot -w "$ACME_WEBROOT" \
        -d "$SSL_DOMAIN" \
        --non-interactive --agree-tos \
        --email "${SSL_EMAIL:-admin@${SSL_DOMAIN}}" \
        --keep-until-expiring 2>&1; then
        SSL_CERT="/etc/letsencrypt/live/${SSL_DOMAIN}/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/${SSL_DOMAIN}/privkey.pem"
        echo "[SSL] Certificate obtained for $SSL_DOMAIN"
        echo "0 3 * * * certbot renew --quiet --webroot -w ${ACME_WEBROOT} && nginx -s reload" \
            > /etc/crontabs/root
    else
        echo "[SSL] certbot failed — falling back to self-signed"
        SSL_CERT=""
        SSL_KEY=""
    fi
    nginx -c /tmp/nginx-acme.conf -s stop 2>/dev/null || true
    sleep 1
fi

# ── Mode 3: Self-signed (default) ────────────────────────────────────────────
if [ -z "$SSL_CERT" ] || [ ! -f "$SSL_CERT" ]; then
    if [ ! -f "$SELFSIGNED_CERT" ] || [ ! -f "$SELFSIGNED_KEY" ]; then
        echo "[SSL] Mode 3 — Generating self-signed certificate..."
        mkdir -p "$SELFSIGNED_DIR"
        # Detect public IP for certificate CN
        PUBLIC_IP="$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || echo 'AWG-WebUI')"
        openssl req -x509 -newkey rsa:4096 \
            -keyout "$SELFSIGNED_KEY" \
            -out "$SELFSIGNED_CERT" \
            -days 3650 \
            -nodes \
            -subj "/CN=${PUBLIC_IP}/O=AWG Web UI/OU=Self-Signed" \
            -addext "subjectAltName=IP:127.0.0.1" \
            2>/dev/null \
            && echo "[SSL] Self-signed certificate generated (CN=${PUBLIC_IP}, valid 10 years)" \
            || echo "[SSL] WARNING: openssl failed — will use HTTP"
    else
        echo "[SSL] Mode 3 — Using existing self-signed certificate"
    fi
    SSL_CERT="$SELFSIGNED_CERT"
    SSL_KEY="$SELFSIGNED_KEY"
fi

# ── Generate final nginx.conf ─────────────────────────────────────────────────
IP_BLOCK="$(build_ip_block)"

# Common security headers block (reused in both HTTPS and HTTP configs)
SEC_HEADERS='        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Content-Security-Policy "default-src '"'"'self'"'"'; script-src '"'"'self'"'"' '"'"'unsafe-inline'"'"' https://cdnjs.cloudflare.com; style-src '"'"'self'"'"' '"'"'unsafe-inline'"'"'; img-src '"'"'self'"'"' data:; connect-src '"'"'self'"'"';" always;
        add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;'

if [ -n "$SSL_CERT" ] && [ -f "$SSL_CERT" ]; then
    # Determine server_name for nginx (use domain if available, else wildcard)
    NGINX_SERVER_NAME="${SSL_DOMAIN:-_}"
    echo "[nginx] HTTPS mode — cert: $SSL_CERT"
    cat > "$NGINX_CONF" <<NGINX
user nginx;
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /run/nginx/nginx.pid;
events { worker_connections 1024; }
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile off;
    aio off;
    keepalive_timeout 65;

    # HTTP → HTTPS redirect (preserves host:port from original request)
    server {
        listen 80;
        server_name _;
        location /.well-known/acme-challenge/ { root ${ACME_WEBROOT}; }
        location / { return 301 https://\$http_host\$request_uri; }
    }

    server {
        listen 443 ssl;
        server_name ${NGINX_SERVER_NAME};

        ssl_certificate     ${SSL_CERT};
        ssl_certificate_key ${SSL_KEY};
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

${SEC_HEADERS}

        location / {
${IP_BLOCK}
            proxy_pass         http://127.0.0.1:5000;
            proxy_set_header   Host              \$host;
            proxy_set_header   X-Real-IP         \$remote_addr;
            proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
            proxy_set_header   Authorization     \$http_authorization;
            proxy_set_header   Cookie            \$http_cookie;
            proxy_read_timeout 120s;
        }
    }
}
NGINX
else
    # Fallback: HTTP-only (only if SSL cert generation completely failed)
    echo "[nginx] WARNING: no SSL cert available — falling back to HTTP-only"
    cat > "$NGINX_CONF" <<NGINX
user nginx;
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /run/nginx/nginx.pid;
events { worker_connections 1024; }
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile off;
    aio off;
    keepalive_timeout 65;
    server {
        listen 80;
        server_name _;
${SEC_HEADERS}
        location / {
${IP_BLOCK}
            proxy_pass         http://127.0.0.1:5000;
            proxy_set_header   Host              \$host;
            proxy_set_header   X-Real-IP         \$remote_addr;
            proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
            proxy_set_header   Authorization     \$http_authorization;
            proxy_set_header   Cookie            \$http_cookie;
            proxy_read_timeout 120s;
        }
    }
}
NGINX
fi

echo "[nginx] Config written:"
grep -E "listen|allow|deny|ssl_cert" "$NGINX_CONF" | sed 's/^/  /'

# Start nginx + flask via supervisord
echo "[supervisor] starting services..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
