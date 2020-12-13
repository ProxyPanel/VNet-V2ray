#!/bin/bash

# This file is accessible as https://install.direct/go.sh
# Original source is located at github.com/v2ray/v2ray-core/release/install-release.sh

# If not specify, default meaning of return value:
# 0: Success
# 1: System error
# 2: Application error
# 3: Network error

# CLI arguments
PROXY=''
HELP=''
[ -z "${FORCE}" ] && FORCE=''
CHECK=''
REMOVE=''
VERSION=''
[ -z "${BIN_NAME}" ] && BIN_NAME='vnet-v2ray'
[ -z "${BIN_ROOT}" ] && BIN_ROOT='/usr/bin/v2ray'
[ -z "${CONFIG_ROOT}" ] && CONFIG_ROOT='/etc/v2ray'
[ -z "${CONFIG_NAME}" ] && CONFIG_NAME='config.json'
VSRC_ROOT='/tmp/v2ray'
EXTRACT_ONLY=''
LOCAL=''
LOCAL_INSTALL=''
ERROR_IF_UPTODATE=''

CUR_VER=""
NEW_VER=""
VDIS=''
ZIPFILE="/tmp/v2ray/v2ray.zip"

CMD_INSTALL=""
CMD_UPDATE=""
SOFTWARE_UPDATED=0

SYSTEMCTL_CMD=$(command -v systemctl 2>/dev/null)
SERVICE_CMD=$(command -v service 2>/dev/null)

echo "${BIN_ROOT}"
echo "${BIN_NAME}"
echo "${CONFIG_ROOT}"
echo "${CONFIG_NAME}"

#######color code########
RED="31m"    # Error message
GREEN="32m"  # Success message
YELLOW="33m" # Warning message
BLUE="36m"   # Info message

#########################
while [[ $# > 0 ]]; do
  case "$1" in
  -p | --proxy)
    PROXY="-x ${2}"
    shift # past argument
    ;;
  -h | --help)
    HELP="1"
    ;;
  -f | --force)
    FORCE="1"
    ;;
  -c | --check)
    CHECK="1"
    ;;
  --remove)
    REMOVE="1"
    ;;
  --version)
    VERSION="$2"
    shift
    ;;
  --extract)
    VSRC_ROOT="$2"
    shift
    ;;
  --extractonly)
    EXTRACT_ONLY="1"
    ;;
  -l | --local)
    LOCAL="$2"
    LOCAL_INSTALL="1"
    shift
    ;;
  --errifuptodate)
    ERROR_IF_UPTODATE="1"
    ;;
  --service_name)
    BIN_NAME="$2"
    ;;
  *)
    # unknown option
    ;;
  esac
  shift # past argument or value
done

###############################
colorEcho() {
  echo -e "\033[${1}${@:2}\033[0m" 1>&2
}

archAffix() {
  case "${1:-"$(uname -m)"}" in
  i686 | i386)
    echo '32'
    ;;
  x86_64 | amd64)
    echo '64'
    ;;
  *armv7* | armv6l)
    echo 'arm'
    ;;
  *armv8* | aarch64)
    echo 'arm64'
    ;;
  *mips64le*)
    echo 'mips64le'
    ;;
  *mips64*)
    echo 'mips64'
    ;;
  *mipsle*)
    echo 'mipsle'
    ;;
  *mips*)
    echo 'mips'
    ;;
  *s390x*)
    echo 's390x'
    ;;
  ppc64le)
    echo 'ppc64le'
    ;;
  ppc64)
    echo 'ppc64'
    ;;
  *)
    return 1
    ;;
  esac

  return 0
}

downloadV2Ray() {
  rm -rf /tmp/v2ray
  mkdir -p /tmp/v2ray
  DOWNLOAD_LINK="https://github.com/ProxyPanel/VNet-V2ray/releases/download/${NEW_VER}/v2ray-linux-${VDIS}.zip"
  colorEcho ${BLUE} "Downloading V2Ray: ${DOWNLOAD_LINK}"
  curl ${PROXY} -L -H "Cache-Control: no-cache" -o ${ZIPFILE} ${DOWNLOAD_LINK}
  if [ $? != 0 ]; then
    colorEcho ${RED} "Failed to download! Please check your network or try again."
    return 3
  fi
  return 0
}

installSoftware() {
  COMPONENT=$1
  if [[ -n $(command -v $COMPONENT) ]]; then
    return 0
  fi

  getPMT
  if [[ $? -eq 1 ]]; then
    colorEcho ${RED} "The system package manager tool isn't APT or YUM, please install ${COMPONENT} manually."
    return 1
  fi
  if [[ $SOFTWARE_UPDATED -eq 0 ]]; then
    colorEcho ${BLUE} "Updating software repo"
    $CMD_UPDATE
    SOFTWARE_UPDATED=1
  fi

  colorEcho ${BLUE} "Installing ${COMPONENT}"
  $CMD_INSTALL $COMPONENT
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to install ${COMPONENT}. Please install it manually."
    return 1
  fi
  return 0
}

# return 1: not apt, yum, or zypper
getPMT() {
  if [[ -n $(command -v apt-get) ]]; then
    CMD_INSTALL="apt-get -y -qq install"
    CMD_UPDATE="apt-get -qq update"
  elif [[ -n $(command -v yum) ]]; then
    CMD_INSTALL="yum -y -q install"
    CMD_UPDATE="yum -q makecache"
  elif [[ -n $(command -v zypper) ]]; then
    CMD_INSTALL="zypper -y install"
    CMD_UPDATE="zypper ref"
  else
    return 1
  fi
  return 0
}

extract() {
  colorEcho ${BLUE}"Extracting V2Ray package to /tmp/v2ray."
  mkdir -p /tmp/v2ray
  unzip $1 -d ${VSRC_ROOT}
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to extract V2Ray."
    return 2
  fi
  if [[ -d "/tmp/v2ray/v2ray-${NEW_VER}-linux-${VDIS}" ]]; then
    VSRC_ROOT="/tmp/v2ray/v2ray-${NEW_VER}-linux-${VDIS}"
  fi
  return 0
}

normalizeVersion() {
  if [ -n "$1" ]; then
    case "$1" in
    v*)
      echo "$1"
      ;;
    *)
      echo "v$1"
      ;;
    esac
  else
    echo ""
  fi
}

# 1: new V2Ray. 0: no. 2: not installed. 3: check failed. 4: don't check.
getVersion() {
  if [[ -n "$VERSION" ]]; then
    NEW_VER="$(normalizeVersion "$VERSION")"
    return 4
  else
    VER="$(${BIN_ROOT}/${BIN_NAME} -version 2>/dev/null)"
    RETVAL=$?
    CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
    TAG_URL="https://raw.githubusercontent.com/ProxyPanel/VNet-V2ray/master/release_vnet/version.json"
    NEW_VER="$(normalizeVersion "$(curl ${PROXY} -s "${TAG_URL}" --connect-timeout 10 | grep 'latest' | cut -d\" -f4)")"

    if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
      colorEcho ${RED} "Failed to fetch release information. Please check your network or try again."
      return 3
    elif [[ $RETVAL -ne 0 ]]; then
      return 2
    elif [[ $NEW_VER != $CUR_VER ]]; then
      return 1
    fi
    return 0
  fi
}

stopV2ray() {
  colorEcho ${BLUE} "Shutting down VNet V2Ray service."
  if [[ -n "${SYSTEMCTL_CMD}" ]] || [[ -f "/lib/systemd/system/${BIN_NAME}.service" ]] || [[ -f "/etc/systemd/system/${BIN_NAME}.service" ]]; then
    ${SYSTEMCTL_CMD} stop ${BIN_NAME}
  elif [[ -n "${SERVICE_CMD}" ]] || [[ -f "/etc/init.d/${BIN_NAME}" ]]; then
    ${SERVICE_CMD} ${BIN_NAME} stop
  fi
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "Failed to shutdown VNet V2Ray service."
    return 2
  fi
  return 0
}

startV2ray() {
  if [ -n "${SYSTEMCTL_CMD}" ] && [[ -f "/lib/systemd/system/${BIN_NAME}.service" || -f "/etc/systemd/system/${BIN_NAME}.service" ]]; then
    ${SYSTEMCTL_CMD} start ${BIN_NAME}
  elif [ -n "${SERVICE_CMD}" ] && [ -f "/etc/init.d/${BIN_NAME}" ]; then
    ${SERVICE_CMD} ${BIN_NAME} start
  fi
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "Failed to start VNet V2Ray service."
    return 2
  fi
  return 0
}

copyFile() {
  NAME=$1
  DEST_NAME=$2
  [ -z "$DEST_NAME" ] && DEST_NAME=${NAME}
  ERROR=$(cp "${VSRC_ROOT}/${NAME}" "${BIN_ROOT}/${DEST_NAME}" 2>&1)
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "${ERROR}"
    return 1
  fi
  return 0
}

makeExecutable() {
  chmod +x "${BIN_ROOT}/$1"
}

installV2Ray() {
  # Install V2Ray binary to /usr/bin/v2ray
  mkdir -p ${BIN_ROOT}
  copyFile vnet-v2ray ${BIN_NAME}
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to copy V2Ray binary and resources."
    return 1
  fi
  makeExecutable ${BIN_NAME}
  copyFile geoip.dat geoip.dat
  copyFile geosite.dat geosite.dat

  # Install V2Ray server config to /etc/v2ray
  if [[ ! -f "${CONFIG_ROOT}/${CONFIG_NAME}" ]]; then
    mkdir -p ${CONFIG_ROOT}
    mkdir -p /var/log/v2ray
    cp "${VSRC_ROOT}/config.json" "${CONFIG_ROOT}/${CONFIG_NAME}"
    if [[ $? -ne 0 ]]; then
      colorEcho ${YELLOW} "Failed to create V2Ray configuration file. Please create it manually."
      return 1
    fi
  fi

  if [[ -n "${NODE_ID}" ]]; then
    sed -i "s|\"api_server\"\:[^,]*|\"api_server\": \"${WEB_API}\"|g" "${CONFIG_ROOT}/${CONFIG_NAME}"
    sed -i "s|\"node_id\"\:[^,]*|\"node_id\": ${NODE_ID}|g" "${CONFIG_ROOT}/${CONFIG_NAME}"
    sed -i "s|\"key\"\:[^,]*|\"key\": \"${NODE_KEY}\"|g" "${CONFIG_ROOT}/${CONFIG_NAME}"
    sed -i "s|\"log_path\"\:[^,]*|\"log_path\": \"/var/log/v2ray/${BIN_NAME}\"|g" "${CONFIG_ROOT}/${CONFIG_NAME}"

    colorEcho ${BLUE} "web_api:${WEB_API}"
    colorEcho ${BLUE} "node_id:${NODE_ID}"
    colorEcho ${BLUE} "node_key:${NODE_KEY}"
  fi

  return 0
}

installInitScript() {
  if [[ -n "${SYSTEMCTL_CMD}" ]] && [[ ! -f "/etc/systemd/system/${BIN_NAME}.service" && ! -f "/lib/systemd/system/${BIN_NAME}.service" ]]; then
    sed -i "s|ExecStart=/usr/bin/v2ray/vnet-v2ray -config /etc/v2ray/config.json|ExecStart=${BIN_ROOT}/${BIN_NAME} -config ${CONFIG_ROOT}/${CONFIG_NAME}|g" "${VSRC_ROOT}/systemd/vnet-v2ray.service"
    cp "${VSRC_ROOT}/systemd/vnet-v2ray.service" "/etc/systemd/system/${BIN_NAME}.service"
    systemctl enable ${BIN_NAME}.service
  elif [[ -n "${SERVICE_CMD}" ]] && [[ ! -f "/etc/init.d/${BIN_NAME}" ]]; then
    sed -i "s|DESC=vnet-v2ray|DESC=${BIN_NAME}|g" "${VSRC_ROOT}/systemv/vnet-v2ray"
    sed -i "s|NAME=vnet-v2ray|NAME=${BIN_NAME}|g" "${VSRC_ROOT}/systemv/vnet-v2ray"
    sed -i "s|DAEMON=/usr/bin/v2ray/vnet-v2ray|DAEMON=${BIN_ROOT}/${BIN_NAME}|g" "${VSRC_ROOT}/systemv/vnet-v2ray"
    sed -i "s|DAEMON_OPTS=\"-config /etc/v2ray/config.json\"|DAEMON_OPTS=\"-config ${CONFIG_ROOT}/${CONFIG_NAME}|g" "${VSRC_ROOT}/systemv/vnet-v2ray"

    installSoftware "daemon" || return $?
    cp "${VSRC_ROOT}/systemv/vnet-v2ray" "/etc/init.d/${BIN_NAME}"
    chmod +x "/etc/init.d/${BIN_NAME}"
    update-rc.d ${BIN_NAME} defaults
  fi
}

Help() {
  cat - 1>&2 <<EOF
./install-release.sh [-h] [-c] [--remove] [-p proxy] [-f] [--version vx.y.z] [-l file]
  -h, --help            Show help
  -p, --proxy           To download through a proxy server, use -p socks5://127.0.0.1:1080 or -p http://127.0.0.1:3128 etc
  -f, --force           Force install
      --version         Install a particular version, use --version v3.15
  -l, --local           Install from a local file
      --remove          Remove installed V2Ray
  -c, --check           Check for update
      --node_id         node_id for vnetpanel
      --node_key        node_key for vnetpanel
      --api_server      api_server for vnetpanel
EOF
}

remove() {
  if [[ -n "${SYSTEMCTL_CMD}" ]] && [[ -f "/etc/systemd/system/${BIN_NAME}.service" ]]; then
    if pgrep "${BIN_NAME}" >/dev/null; then
      stopV2ray
    fi
    systemctl disable ${BIN_NAME}.service
    rm -rf "${BIN_ROOT}" "/etc/systemd/system/${BIN_NAME}.service" "${CONFIG_ROOT}/${CONFIG_NAME}"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet V2Ray."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet V2Ray successfully."
      return 0
    fi
  elif [[ -n "${SYSTEMCTL_CMD}" ]] && [[ -f "/lib/systemd/system/${BIN_NAME}.service" ]]; then
    if pgrep "${BIN_NAME}" >/dev/null; then
      stopV2ray
    fi
    systemctl disable ${BIN_NAME}.service
    rm -rf "${BIN_ROOT}" "/lib/systemd/system/${BIN_NAME}.service" "${CONFIG_ROOT}/${CONFIG_NAME}"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet V2Ray."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet V2Ray successfully."
      return 0
    fi
  elif [[ -n "${SERVICE_CMD}" ]] && [[ -f "/etc/init.d/${BIN_NAME}" ]]; then
    if pgrep "${BIN_NAME}" >/dev/null; then
      stopV2ray
    fi
    rm -rf "${BIN_ROOT}" "/etc/init.d/${BIN_NAME}" "${CONFIG_ROOT}/${CONFIG_NAME}"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet V2Ray."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet V2Ray successfully."
      return 0
    fi
  else
    colorEcho ${YELLOW} "VNet V2Ray not found."
    return 0
  fi
}

checkUpdate() {
  echo "Checking for update."
  VERSION=""
  getVersion
  RETVAL="$?"
  if [[ $RETVAL -eq 1 ]]; then
    colorEcho ${BLUE} "Found new version ${NEW_VER} for V2Ray.(Current version:$CUR_VER)"
  elif [[ $RETVAL -eq 0 ]]; then
    colorEcho ${BLUE} "No new version. Current version is ${NEW_VER}."
  elif [[ $RETVAL -eq 2 ]]; then
    colorEcho ${YELLOW} "No V2Ray installed."
    colorEcho ${BLUE} "The newest version for V2Ray is ${NEW_VER}."
  fi
  return 0
}

main() {
  #helping information
  [[ "$HELP" == "1" ]] && Help && return
  [[ "$CHECK" == "1" ]] && checkUpdate && return
  [[ "$REMOVE" == "1" ]] && remove && return

  local ARCH=$(uname -m)
  VDIS="$(archAffix)"

  # extract local file
  if [[ $LOCAL_INSTALL -eq 1 ]]; then
    colorEcho ${YELLOW} "Installing V2Ray via local file. Please make sure the file is a valid V2Ray package, as we are not able to determine that."
    NEW_VER=local
    installSoftware unzip || return $?
    rm -rf /tmp/v2ray
    extract $LOCAL || return $?
    #FILEVDIS=`ls /tmp/v2ray |grep v2ray-v |cut -d "-" -f4`
    #SYSTEM=`ls /tmp/v2ray |grep v2ray-v |cut -d "-" -f3`
    #if [[ ${SYSTEM} != "linux" ]]; then
    #    colorEcho ${RED} "The local V2Ray can not be installed in linux."
    #    return 1
    #elif [[ ${FILEVDIS} != ${VDIS} ]]; then
    #    colorEcho ${RED} "The local V2Ray can not be installed in ${ARCH} system."
    #    return 1
    #else
    #    NEW_VER=`ls /tmp/v2ray |grep v2ray-v |cut -d "-" -f2`
    #fi
  else
    # download via network and extract
    installSoftware "curl" || return $?
    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]] && [[ "$FORCE" != "1" ]]; then
      colorEcho ${BLUE} "Latest version ${CUR_VER} is already installed."
      if [ -n "${ERROR_IF_UPTODATE}" ]; then
        return 10
      fi
      return
    elif [[ $RETVAL == 3 ]]; then
      return 3
    else
      colorEcho ${BLUE} "Installing V2Ray ${NEW_VER} on ${ARCH}"
      downloadV2Ray || return $?
      installSoftware unzip || return $?
      extract ${ZIPFILE} || return $?
    fi
  fi

  if [ -n "${EXTRACT_ONLY}" ]; then
    colorEcho ${GREEN} "V2Ray extracted to ${VSRC_ROOT}, and exiting..."
    return 0
  fi

  if pgrep "v2ray" >/dev/null; then
    stopV2ray
  fi
  remove
  installV2Ray || return $?
  installInitScript || return $?
  colorEcho ${BLUE} "Starting V2Ray service."
  startV2ray
  colorEcho ${GREEN} "V2Ray ${NEW_VER} is installed."
  rm -rf /tmp/v2ray
  return 0
}

main
