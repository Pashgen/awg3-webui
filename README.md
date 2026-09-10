# AWG 2.0 Web UI

<div align="center">

![AmneziaWG](https://img.shields.io/badge/AmneziaWG-2.0%2F3.1-7C3AED?style=for-the-badge&logo=wireguard)
![Docker](https://img.shields.io/badge/Docker-Multi--arch-2496ED?style=for-the-badge&logo=docker)
![Proxmox](https://img.shields.io/badge/Proxmox-LXC-E57000?style=for-the-badge&logo=proxmox)
[![Build](https://img.shields.io/github/actions/workflow/status/Pashgen/awg2-webui/build.yml?style=for-the-badge&logo=github-actions&label=CI)](https://github.com/Pashgen/awg2-webui/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/Pashgen/awg2-webui?style=for-the-badge&logo=github)](https://github.com/Pashgen/awg2-webui/releases)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)

**Web management panel for AmneziaWG 2.0 / 3.1 VPN server — built entirely from source**

[Quick Start](#-quick-start) • [Features](#-features) • [AWG 3.1](#-amneziawg-31-support) • [Proxmox LXC](#-proxmox-lxc) • [MikroTik CHR](#-mikrotik-chr) • [Screenshots](#-screenshots) • [Troubleshooting](#-troubleshooting)

</div>

---

## 📋 Overview

A self-hosted web UI for managing [AmneziaWG 2.0](https://github.com/amnezia-vpn/amneziawg-go) — the obfuscated WireGuard fork that bypasses DPI censorship. Built from source with no pre-built binaries, runs anywhere Docker runs. As of `v1.1.0` it also supports the newer AmneziaWG 3.1 protocol extras as an opt-in — see [AmneziaWG 3.1 Support](#-amneziawg-31-support).

### Why This Solution?

- ✅ **No binary trust issues** — amneziawg-go and tools compiled from source in Docker
- ✅ **Multi-arch** — runs on VPS, Raspberry Pi, MikroTik CHR, Oracle ARM
- ✅ **Full obfuscation control** — QUIC/TLS/DTLS/SIP CPS profile generator built in
- ✅ **SSL included** — self-signed out of the box, Let's Encrypt via Web UI
- ✅ **MikroTik CHR ready** — tested on RouterOS 7.x container with CHR-specific patches

---

## 🎯 Features

- 🔒 **HTTPS** — self-signed out of the box, Let's Encrypt configurable via Web UI
- 👥 **Peer management** — add, remove, suspend peers; QR code, one-click config download
- 📊 **Dashboard** — AWG status, uptime, CPU/RAM, 24h traffic charts per peer
- 🌍 **Geo + latency** — country flag and ping per connected peer
- 🔮 **CPS generator** — QUIC / TLS / DTLS / SIP obfuscation profiles (H1–H4, S1–S4, Jc/Jmin/Jmax)
- 🔔 **Alerts** — AWG daemon down, peer no handshake > 2h
- 🌐 **i18n** — English / Russian
- 📦 **Prometheus** — `/metrics` endpoint for Grafana integration
- 🆕 **AmneziaWG 3.1 (opt-in)** — HeaderProtectionKey, RandomTrailers, DisableCookies, configurable timing/padding ranges — fully backward-compatible with 2.0

---

## 🆕 AmneziaWG 3.1 Support

`v1.1.0` adds full, **opt-in** support for the newer AmneziaWG 3.1 protocol extras, on top
of the existing 2.0 obfuscation (H1–H4 / S1–S4 / Jc·Jmin·Jmax / I1–I5). AWG 3.1 is **off by
default** — existing 2.0 servers and peers are completely unaffected until you turn it on.

**What's new:**

- 🔑 **HeaderProtectionKey** — a 32-byte symmetric key shared by the server and every peer
  that encrypts each packet's header. Generated automatically the first time you enable
  AWG 3.1, shown in the UI, and can be manually regenerated (existing peers keep the old
  key baked into their config until you re-issue it — see below).
- 🎲 **RandomTrailers** — **off by default**. There's a known, unresolved upstream bug
  ([amnezia-vpn/amneziawg-go#186](https://github.com/amnezia-vpn/amneziawg-go/issues/186)):
  combined with wide H1–H3 ranges, it can silently drop transport packets (up to ~25% in
  the reported case, with nothing showing up in the logs). The Web UI warns about this
  when you turn it on.
- 🍪 **DisableCookies** — simple on/off toggle.
- ⏱️ **Timing & padding ranges** — `ContentPaddingAddition`, `RekeyAfterTime`,
  `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`. Each
  accepts either a single value (`"120"`) or a range (`"100-140"`) — seconds, except
  `ContentPaddingAddition` which is bytes. Leave any of them empty to fall back to
  amneziawg-go's own built-in defaults instead of guessing a value.

**How it works:**

- Toggling AWG 3.1 is a separate action from Server Setup (`POST /api/server/awg31`) — it
  does **not** touch your existing PrivateKey, H1–H4/S1–S4/Jc, or peer list.
- New peers automatically inherit the server's current 3.1 settings — the header-protection
  key is shared secret material, not something each peer can generate on its own.
- Enabling/disabling/regenerating attempts a best-effort hot-apply over the AmneziaWG UAPI
  socket; if the daemon isn't reachable, changes are still persisted to the config file and
  take effect on the next full config apply/restart.
- **Existing peers are not retroactively updated** — if you enable AWG 3.1 (or regenerate
  the key) after peers already exist, re-download/re-issue their configs so every device
  ends up on the same `HeaderProtectionKey`.
- `awg_version` in `/api/config/export` reports `3.1` once a `HeaderProtectionKey` is set on
  the server, `2.0` otherwise.
- Requires the toolchain already shipped since `v1.0.3` — `amneziawg-tools ≥ v3.1.20260812`
  and an `amneziawg-go` build with 3.1 support — no Dockerfile changes needed for this
  release.

---

## 📸 Screenshots

| Dashboard | CPS Generator | Add Peer |
|:---------:|:-------------:|:--------:|
| ![Dashboard](docs/screenshots/dashboard.png) | ![CPS Generator](docs/screenshots/cps-generator.png) | ![Add Peer](docs/screenshots/add-peer.png) |

---

## 📦 Requirements

### Hardware
- Any Linux host with Docker installed
- **MikroTik CHR** — x86_64 with RouterOS 7.x Container package
- **Raspberry Pi** — Pi 3 (arm/v7) or Pi 4+ (arm64)
- Minimum **256 MB RAM**, **500 MB disk** for container

### Network
- Public IP or port forwarding for VPN traffic (`51820/udp`)
- Port `443` open for HTTPS Web UI
- Port `80` open for Let's Encrypt only (optional)

---

## 🚀 Quick Start

### Docker Run

```bash
docker run -d \
  --name awg2-webui \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  -v awg_config:/etc/amnezia/amneziawg \
  -v /lib/modules:/lib/modules:ro \
  -p 443:443 -p 80:80 -p 51820:51820/udp \
  -e WEB_USER=admin \
  -e WEB_PASS=changeme \
  -e AWG_ENDPOINT=auto \
  pashgen/awg2-webui:latest
```

Open **https://YOUR_SERVER_IP** in your browser (accept the self-signed cert warning).

**⚠️ Change the default password immediately after first login!**

### Docker Compose

```bash
curl -O https://raw.githubusercontent.com/Pashgen/awg2-webui/main/docker-compose.yml
# Edit WEB_PASS and AWG_ENDPOINT, then:
docker compose up -d
```

---

## ⚙️ Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WEB_USER` | `admin` | Web UI login username |
| `WEB_PASS` | `admin` | Web UI password — **change this!** |
| `SECRET_KEY` | auto | Flask session secret key |
| `AWG_ENDPOINT` | `auto` | Server endpoint sent to clients (`IP:PORT`) |
| `AWG_PORT` | `51820` | AmneziaWG listen port (UDP) |
| `AWG_INTERFACE` | `awg0` | AWG interface name |
| `AWG_SUBNET` | `10.8.0.0/24` | VPN subnet |
| `AWG_DNS` | `1.1.1.1,8.8.8.8` | DNS pushed to clients |
| `SSL_DOMAIN` | — | Domain for Let's Encrypt (or configure via UI) |
| `SSL_EMAIL` | — | Email for Let's Encrypt ACME |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────┐
│  Docker Container                           │
│                                             │
│  nginx  ← 443 HTTPS / 80 HTTP             │
│    └──→  Flask (5000)  Python Web UI       │
│                                             │
│  amneziawg-go  ← built from source (Go)   │
│    └──→  awg0 interface  51820/udp         │
│                                             │
│  supervisord — process manager             │
│  tini        — PID 1 / signal handling    │
└────────────────────────────────────────────┘
```

**3-stage Docker build:**
1. **Stage 1** — `amneziawg-go` from source (Go compiler)
2. **Stage 2** — `awg` + `awg-quick` CLI tools from source (C/make)
3. **Stage 3** — Alpine runtime + nginx + Flask Web UI

---

## 🔒 SSL Configuration

### Option A — Self-Signed (default, works everywhere)

Configure via **Settings → SSL → Self-signed** in the Web UI. Browser shows a one-time warning — accept it, and you're done.

### Option B — Let's Encrypt

Port 80 must be publicly reachable for ACME challenge.

```bash
-e SSL_DOMAIN=vpn.example.com \
-e SSL_EMAIL=admin@example.com
```

Or configure live via **Settings → SSL → Let's Encrypt** — no restart needed.
Certificate renews automatically every Tuesday at 03:00.

---

## 🖥️ Platforms

| Platform | Tested on |
|---|---|
| `linux/amd64` | MikroTik CHR, VPS (Hetzner, DigitalOcean) |
| `linux/arm64` | Raspberry Pi 4, Oracle ARM, Apple M1 VMs |
| `linux/arm/v7` | Raspberry Pi 3, older ARM devices |

---

## 🖥️ Proxmox LXC

One-liner install directly from your **Proxmox host shell**:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Pashgen/awg2-webui/main/ct/awg2-webui.sh)"
```

This will:
1. Create a **Debian 12 LXC** container (2 CPU, 512 MB RAM, 4 GB disk)
2. Install Docker inside the container
3. Pull and start `pashgen/awg2-webui:latest`
4. Show the access URL when done

> **Note:** The LXC must run as **privileged** (`unprivileged=0`) because AmneziaWG requires `NET_ADMIN` and kernel module access.

### Manual LXC setup

If you prefer step-by-step control:

```bash
# On Proxmox host — create LXC
pct create 200 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
  --hostname awg2-webui \
  --cores 2 --memory 512 --swap 512 \
  --rootfs local-lvm:4 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --features nesting=1 \
  --unprivileged 0 \
  --start 1

# Inside LXC — install
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Pashgen/awg2-webui/main/install/awg2-webui-install.sh)"
```

---

## 🔧 MikroTik CHR

Full deployment guide: **[docs/mikrotik-chr.md](docs/mikrotik-chr.md)**

### Key CHR Differences

| Issue | Standard | CHR Fix |
|---|---|---|
| iptables binary | `iptables` | `iptables-legacy` (RouterOS kernel) |
| nginx file I/O | `sendfile on` | `sendfile off; aio off;` (overlayfs) |
| Config writes | direct | `os.unlink()` + recreate (overlayfs whiteout) |
| Image delivery | registry pull | `docker save` → `scp` → `/container add` |

### Quick CHR Deploy

```bash
# On your local machine — pull and save amd64 image
docker pull --platform linux/amd64 pashgen/awg2-webui:latest
docker save pashgen/awg2-webui:latest -o awg2-webui-chr.tar

# Upload to CHR
scp -P 22 awg2-webui-chr.tar admin@YOUR_CHR_IP:disk1/awg2-webui.tar
```

Then on CHR via SSH/Winbox — see [full guide](docs/mikrotik-chr.md).

---

## 🛠️ Troubleshooting

### Container won't start

```bash
docker logs awg2-webui
docker inspect awg2-webui | grep -A5 State
```

### Web UI not accessible

```bash
# Check what's listening
docker exec awg2-webui supervisorctl status
curl -k https://localhost/api/status
```

### AWG not routing traffic

```bash
# Check AWG interface
docker exec awg2-webui awg show

# Check iptables rules inside container
docker exec awg2-webui iptables -t nat -L POSTROUTING -v
docker exec awg2-webui iptables -L FORWARD -v
```

### Peer can't connect

```bash
# Verify UDP port is open from outside
nc -zu YOUR_SERVER_IP 51820

# Check latest handshake
docker exec awg2-webui awg show awg0 latest-handshakes
```

---

## ⚠️ Important Notes

### iptables on different platforms

- ⛔ **Never** use `iptables-legacy` alone — it may not exist on arm64/modern kernels
- ✅ The container auto-detects: `iptables-legacy` on CHR, `iptables` elsewhere
- 🔍 Generated PostUp uses subnet-based MASQUERADE (no hardcoded `-o eth0`)

### MikroTik conntrack

- ⛔ **Don't** add `--ctstate RELATED,ESTABLISHED` FORWARD rules on RouterOS containers
- ✅ `nf_conntrack` kernel module is **not loadable** inside RouterOS container environment
- ✅ Plain `FORWARD ACCEPT` + subnet MASQUERADE is sufficient and works on all platforms

### Secrets

- 🔒 Never expose the Web UI port (443) without changing the default password
- 🔒 Set a strong `SECRET_KEY` in production: `-e SECRET_KEY=$(openssl rand -hex 32)`

---

## 🔨 Build from Source

```bash
git clone https://github.com/Pashgen/awg2-webui
cd awg2-webui

# Local build (native arch)
docker build -t awg2-webui:local .

# Multi-arch build and push
docker buildx build \
  --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t pashgen/awg2-webui:latest \
  --push .
```

---

## 🤝 Contributing

Contributions are welcome! For major changes, please open an issue first.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [amnezia-vpn/amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — AmneziaWG 2.0 userspace implementation
- [WireGuard](https://www.wireguard.com) — the protocol underneath
- [MikroTik](https://mikrotik.com) — RouterOS Container support
- Community testers and contributors

---

## 💬 Support

- 📖 Check [docs/](docs/) for detailed guides
- 🐛 [Open an Issue](https://github.com/Pashgen/awg2-webui/issues) for bugs
- 💡 [Discussions](https://github.com/Pashgen/awg2-webui/discussions) for questions and ideas
- ⭐ Star this repo if it helped you!

---

<div align="center">

**Made with ❤️ for the AmneziaWG community**

[⬆ Back to Top](#awg-20-web-ui)

</div>
