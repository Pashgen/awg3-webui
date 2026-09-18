#!/usr/bin/env bash

# Copyright (c) 2024-2026 Pashgen
# Author: Pashgen
# License: MIT | https://github.com/Pashgen/awg2-webui/raw/main/LICENSE
# Source: https://github.com/Pashgen/awg2-webui

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing Dependencies"
$STD apt-get install -y \
  curl \
  ca-certificates \
  gnupg \
  lsb-release \
  iptables
msg_ok "Installed Dependencies"

msg_info "Installing Docker"
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list
$STD apt-get update
$STD apt-get install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-compose-plugin
systemctl enable --now docker
msg_ok "Installed Docker $(docker --version | cut -d' ' -f3 | tr -d ',')"

msg_info "Loading AmneziaWG kernel module support"
$STD modprobe wireguard 2>/dev/null || true
msg_ok "Kernel modules ready"

msg_info "Pulling AWG 3.1 Web UI image"
$STD docker pull pashgen/awg2-webui:latest
msg_ok "Pulled pashgen/awg2-webui:latest"

msg_info "Starting AWG 3.1 Web UI"
docker run -d \
  --name awg2-webui \
  --cap-add NET_ADMIN \
  --cap-add SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  --restart unless-stopped \
  -v awg_config:/etc/amnezia/amneziawg \
  -v /lib/modules:/lib/modules:ro \
  -p 443:443 \
  -p 80:80 \
  -p 51820:51820/udp \
  -e WEB_USER=admin \
  -e WEB_PASS=changeme \
  -e AWG_ENDPOINT=auto \
  pashgen/awg2-webui:latest >/dev/null
msg_ok "Started AWG 3.1 Web UI"

motd_ssh
customize
