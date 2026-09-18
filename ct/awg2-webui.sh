#!/usr/bin/env bash
source <(curl -fsSL https://raw.githubusercontent.com/community-scripts/ProxmoxVE/main/misc/build.func)
# Copyright (c) 2024-2026 Pashgen
# Author: Pashgen
# License: MIT | https://github.com/Pashgen/awg2-webui/raw/main/LICENSE
# Source: https://github.com/Pashgen/awg2-webui

APP="AWG 3.1 Web UI"
var_tags="${var_tags:-vpn;wireguard;amnezia}"
var_cpu="${var_cpu:-2}"
var_ram="${var_ram:-512}"
var_disk="${var_disk:-4}"
var_os="${var_os:-debian}"
var_version="${var_version:-12}"
var_unprivileged="${var_unprivileged:-0}"

header_info "$APP"
variables
color
catch_errors

function update_script() {
  header_info
  check_container_storage
  check_container_resources

  msg_info "Updating AWG 3.1 Web UI"
  $STD docker pull pashgen/awg2-webui:latest
  $STD docker stop awg2-webui
  $STD docker rm awg2-webui
  $STD docker run -d \
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
    pashgen/awg2-webui:latest
  msg_ok "Updated AWG 3.1 Web UI"
  exit
}

start
build_container
description

msg_ok "Completed successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW} Access the Web UI at:${CL}"
echo -e "${TAB}${GATEWAY}${BGN}https://${IP}${CL}"
echo -e "${INFO}${YW} Default credentials: admin / changeme${CL}"
echo -e "${INFO}${YW} Change the password in Settings after first login!${CL}"
