# =============================================================================
# AWG 3.1 Web UI — built entirely from amnezia-vpn sources
# Stage 1: amneziawg-go  (Go, multi-arch: amd64 / arm64 / arm/v7)
# Stage 2: awg-tools     (C: awg + awg-quick)
# Stage 3: Runtime Alpine + Flask Web UI
# =============================================================================

# ── Stage 1: build amneziawg-go ──────────────────────────────────────────────
FROM golang:1.25.5-alpine3.21 AS build-awg-go

RUN apk add --no-cache git

# Patch files for <c> tag support (packet counter obfuscation)
# Issue: https://github.com/amnezia-vpn/amneziawg-go/issues/120
COPY patches/obf_counter.go      /patches/obf_counter.go
COPY patches/obf_counter_test.go /patches/obf_counter_test.go

WORKDIR /build
RUN git clone --depth=1 https://github.com/amnezia-vpn/amneziawg-go.git . && \
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
FROM alpine:3.19 AS build-awg-tools

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
FROM alpine:3.19

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
