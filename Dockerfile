# =============================================================================
# AWG 3.1 Web UI — built entirely from amnezia-vpn sources
# Stage 1: amneziawg-go  (Go, multi-arch: amd64 / arm64 / arm/v7)
# Stage 2: awg-tools     (C: awg + awg-quick)
# Stage 3: Runtime Alpine + Flask Web UI
# =============================================================================

# ── Stage 1: build amneziawg-go ──────────────────────────────────────────────
FROM golang:1.25.14-alpine3.24 AS build-awg-go

RUN apk add --no-cache git

# Patch files for <c> tag support (packet counter obfuscation)
# Issue: https://github.com/amnezia-vpn/amneziawg-go/issues/120
COPY patches/obf_counter.go      /patches/obf_counter.go
COPY patches/obf_counter_test.go /patches/obf_counter_test.go

WORKDIR /build
# Was pinned to v3.0.3 (cf9d2dd20282) after an unpinned floating-HEAD clone
# caused a severe regression: the resulting binary dropped almost all
# outbound relay packets under load (confirmed on ac3 via raw NAT session
# counters: 622 packets in from a real client, only 7 replies out —
# reproduced identically on both AWG 2.0 and 3.1 configs, and with
# obfuscation stripped to Jc=0, ruling out app-level config as the cause).
#
# 2026-10-23: bumped to v3.1.20260828 (b5928efb6ca1), the latest tag, after
# finding a specific related fix upstream — commit b5928ef "disable the
# whole underload if DisableCookies is on" fixes a bug where, under load
# with DisableCookies set, handshakes failing the MAC2 check were silently
# dropped (goto skip) instead of either getting a cookie reply or falling
# through to the rate limiter. Other fixes picked up in this range:
# 08d68cd (keepalives were being ignored), 1b86b2a (panic from a wrong
# trailerLen in HandshakeCookie, itself introduced by the 1f50ad7 "AWG 3.1
# protocol" commit), da11c9f (wrong udp window for RandomPaddingAddition).
#
# IMPORTANT CAVEAT: b5928ef's fix is gated on DisableCookies, a flag that
# only exists in AWG 3.1 — it does not obviously explain why the original
# packet-drop regression above was also reproduced on plain AWG 2.0 configs.
# This bump is NOT confirmed to fully fix that regression; build success
# alone proves nothing about runtime behavior under load. Verify with the
# same method used to diagnose the original issue (raw NAT session packet
# counters on ac3 under real traffic) before trusting this in production.
# If packet loss under load reappears, revert this pin to cf9d2dd20282.
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git . && \
    git checkout b5928efb6ca1 && \
    # ── Apply <c> tag patch ───────────────────────────────────────────── \
    # 1) Copy counterObf implementation into device/ package
    cp /patches/obf_counter.go      device/obf_counter.go && \
    cp /patches/obf_counter_test.go device/obf_counter_test.go && \
    # 2) Register "c": newCounterObf in obfBuilders (after newDataSizeObf)
    awk '/newDataSizeObf/{print; print "\t\"c\":  newCounterObf,"; next}1' \
        device/obf.go > /tmp/obf_patched.go && \
    mv /tmp/obf_patched.go device/obf.go && \
    # 3) Verify patch was applied successfully
    grep -q '"c":  newCounterObf' device/obf.go && \
        echo "✓ <c> tag patch applied" || \
        (echo "✗ patch FAILED — obf.go does not contain newCounterObf" && exit 1) && \
    # ── Unit tests for <c> tag ───────────────────────────────────────── \
    go test ./device/ -run TestCounterObf -v && \
    echo "✓ <c> tag tests passed" && \
    # ── Main build ───────────────────────────────────────────────────── \
    go mod download && \
    go mod verify && \
    CGO_ENABLED=0 go build -v -o /usr/bin/amneziawg-go

# ── Stage 2: build awg-tools (awg + awg-quick) ───────────────────────────────
FROM alpine:3.24 AS build-awg-tools

RUN apk add --no-cache git build-base bash linux-headers

WORKDIR /build
RUN git clone --depth=1 \
    --branch v3.1.20260812 \
    https://github.com/amnezia-vpn/amneziawg-tools.git . && \
    cd src && \
    make WITH_WGQUICK=yes && \
    install -m 0755 wg                /usr/bin/awg && \
    install -m 0755 wg-quick/linux.bash /usr/bin/awg-quick

# ── Stage 3: runtime ─────────────────────────────────────────────────────────
# Alpine 3.19 reached end-of-life 2025-11-01 and stopped receiving security
# backports — its nginx package has been frozen at 1.24.0-r16 (built
# 2024-04-26) ever since, silently missing 17+ nginx CVEs disclosed through
# 2026, including two Critical/KEV heap overflows with public exploits
# (CVE-2026-9256, CVE-2026-42945 "Rift") and the Oct 2026 batch
# (CVE-2026-15176/93479/97205/95101/97629). Alpine 3.24 (supported until
# 2028-06-01) carries nginx 1.30.6-r0 (built 2026-10-22), which fixes all of
# the above. Do not pin the nginx package version explicitly — staying on
# apk's unpinned `nginx` within a *supported* branch is what keeps future
# security patches flowing automatically on rebuild.
FROM alpine:3.24

RUN apk add --no-cache \
    iproute2 iptables iptables-legacy bash curl \
    python3 py3-pip py3-pillow \
    nginx supervisor tini \
    openssl certbot

# Copy binaries from build stages
COPY --from=build-awg-go    /usr/bin/amneziawg-go /usr/bin/amneziawg-go
COPY --from=build-awg-tools /usr/bin/awg           /usr/bin/awg
COPY --from=build-awg-tools /usr/bin/awg-quick     /usr/bin/awg-quick

# Web UI Python deps
# Note: py3-pillow is installed via apk (pre-built for all arches incl. arm/v7)
RUN pip3 install \
    flask \
    qrcode \
    cryptography \
    --break-system-packages

# Directory structure
RUN mkdir -p \
    /app/web-ui/templates \
    /app/scripts \
    /var/log/supervisor \
    /etc/amnezia/amneziawg \
    /run/nginx \
    /var/www/acme \
    /etc/crontabs

RUN rm -f /etc/nginx/conf.d/default.conf /etc/nginx/http.d/default.conf

# ── Config / App files ────────────────────────────────────────────────────────
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY config/nginx.conf       /etc/nginx/nginx.conf

COPY app.py            /app/web-ui/app.py
COPY cps_generator.py  /app/web-ui/cps_generator.py
COPY templates/        /app/web-ui/templates/

COPY start.sh /app/scripts/start.sh
RUN chmod +x /app/scripts/start.sh

# ── Ports ─────────────────────────────────────────────────────────────────────
EXPOSE 80 443
EXPOSE 51820/udp

# ── Environment defaults ──────────────────────────────────────────────────────
ENV WEB_PORT=5000 \
    WEB_USER=admin \
    WEB_PASS=admin \
    AWG_PORT=51820 \
    AWG_INTERFACE=awg0 \
    AWG_SUBNET=10.8.0.0/24 \
    AWG_ENDPOINT=auto \
    AWG_DNS=1.1.1.1,8.8.8.8 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/sbin/tini", "--", "/app/scripts/start.sh"]
