#!/bin/bash

ACME_DEBUG_MODE="--debug"
ACME_ENV_MODE=""
START_MENU_ITEM=("1.安装" "2.更新" "3.卸载" "4.退出")
DETAIL_MENU_ITEM=("1.自定义获取证书" "2.返回")
WEB_SERVER_ITEM=("1.nginx" "2.apache" "3.other")
SELECT_Y_N="Y/N"
SELECT_TIP="请选择: "
ERROR_SELECT_INPUT="请输入正确的选项!"

function usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

  --help
    帮助文档
EOF
  exit 0
}

function shell_quote_string() {
  echo "[$arg]不是当前脚本命令参数，关于执行install.sh脚本的更多信息，请运行'$0 --help'"
  exit 1
}

function parse_arguments() {
  for arg; do
    local val opt_name opt_name_subst
    val=$(echo "$arg" | sed -e 's;^--[^=]*=;;')
    opt_name=$(echo "$arg" | sed -e 's/^\(--[^=]*\)=.*$/\1/')
    opt_name_subst=$(echo "$opt_name" | sed 's/_/-/g')
    arg=$(echo "$arg" | sed "s/^$opt_name/$opt_name_subst/")
    case "$arg" in
    --help) usage ;;
    *) shell_quote_string "${arg}" ;;
    esac
  done
}

function clear_window() {
  clear
  local title="========================= 【青小云】安装配置 Let's Encrypt SSL 证书 ========================="
  echo -e "\033[34m\033[01m$title\033[0m"
}

function init_log_file_path() {
  LOG_FILE="${CURRENT_SHELL_PATH}/qlite-ssl.log"
  : >"$LOG_FILE"
  QLITE_SSL_LOG_TIP="更多关于日志的信息，请查看[${LOG_FILE}]。"
}

function init_current_shell_path() {
  CURRENT_SHELL_PATH="$(
    cd "$(dirname "$0")" || exit
    pwd
  )"
}

function init_path() {
  LINUX_HOME_PATH=$(env | grep ^HOME= | cut -c 6-)
  init_current_shell_path
  init_log_file_path
  ACME_ORIGIN_DIR_PATH="${CURRENT_SHELL_PATH}/acme.sh"
  ACME_INSTALL_PATH="${LINUX_HOME_PATH}/.acme.sh"
  ACME_INSTALL_EXEC_PATH="${LINUX_HOME_PATH}/.acme.sh/acme.sh"
}

function check_user_root() {
  if [ $UID -ne 0 ]; then
    echo "必须以root权限运行该脚本"
    exit 1
  fi
}

function log_to_log() {
  echo "[$(date)]" "$@" >>"${LOG_FILE}"
}

function log_info() {
  if [ -n "$1" ]; then
    echo -e "[$(date)]" "\033[34m\033[01m$*\033[0m"
    log_to_log "$@"
  fi
}

function log_warn() {
  if [ -n "$1" ]; then
    echo -e "[$(date)]" "\033[33m\033[01m$*\033[0m"
    log_to_log "$@"
  fi
}

function log_success() {
  if [ -n "$1" ]; then
    echo -e "[$(date)]" "\033[32m\033[01m$*\033[0m"
    log_to_log "$@"
  fi
}

function log_error() {
  if [ -n "$1" ]; then
    echo -e "[$(date)]" "\033[31m\033[01m$*\033[0m"
    log_to_log "$@"
  fi
}

function log_error_without_datetime() {
  if [ -n "$1" ]; then
    echo -e "\033[31m\033[01m$*\033[0m"
    log_to_log "$@"
  fi
}

function is_command_exists() {
  local _command="$1"
  if ! [ -x "$(command -v "$_command")" ]; then
    if [ "$2" != "no" ]; then
      log_error "$(printf "系统命令[%s]不存在，请安装后重试." "${_command}")"
    fi
    return 1
  fi
  return 0
}

function create_dir() {
  local _dir="$1"
  if [ -n "${_dir}" ]; then
    if [ ! -d "${_dir}" ]; then
      mkdir -p "${_dir}" >/dev/null 2>&1
      log_to_log "create dir ${_dir}" >>"${LOG_FILE}"
    fi
    if [ ! -d "${_dir}" ]; then
      log_error "$(printf "创建文件夹[%s]失败，请重新执行此脚本！" "${_dir}")"
      return 1
    fi
  fi
  return 0
}

function show_select_item() {
  local _array="$1"
  for item in ${_array[*]}; do
    echo "$item"
  done
  read -rep "${SELECT_TIP}" _temp_selection
  printf '\n'
}

function show_agree_tip() {
  local agree_tip="$1"
  echo "$agree_tip" "${SELECT_Y_N}"
  read -rep "${SELECT_TIP}" _temp_selection
  printf '\n'
}

function show_log_tip_exit() {
  if [ "$1" -eq 1 ]; then
    local _exit_flag=1
  else
    local _exit_flag=0
  fi
  if [ "${INSTALL_NGINX_SUCCESS}" == "0" ]; then
    uninstall_nginx
  fi
  log_error "$QLITE_SSL_LOG_TIP"
  exit ${_exit_flag}
}

function get_linux_info() {
  source /etc/os-release
  local RELEASE=$ID
  if [ "$RELEASE" == "centos" ]; then
    SYSTEM_PACKAGE="yum"
  elif [ "$RELEASE" == "debian" ]; then
    SYSTEM_PACKAGE="apt-get"
  elif [ "$RELEASE" == "ubuntu" ]; then
    SYSTEM_PACKAGE="apt-get"
  fi
}

function install_required_pkg() {
  log_info "检查并安装必要文件"
  log_to_log "$SYSTEM_PACKAGE -y install socat git wget curl unzip gawk dig"
  $SYSTEM_PACKAGE -y install "socat git wget curl unzip gawk dig" >/dev/null 2>&1
}

function check_selinux() {
  if [ -f "/etc/selinux/config" ]; then
    local check
    check=$(grep SELINUX= /etc/selinux/config | grep -v "#")
    if [ "$check" == "SELINUX=enforcing" ]; then
      log_info "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
      setenforce 0
      sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    elif [ "$check" == "SELINUX=permissive" ]; then
      log_info "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
      setenforce 0
      sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
    fi
  fi
}

function check_linux_os() {
  check_selinux
}

function check_update_system_resource() {
  log_info "更新系统环境"
  log_to_log "$SYSTEM_PACKAGE -y update"
  "$SYSTEM_PACKAGE" -y update >/dev/null 2>&1
}

function check_dns_entries() {
  local real_addr local_addr
  read -rep "请输入解析到该服务器的域名:" user_domain
  if ! is_command_exists dig; then
    exit 1
  fi
  real_addr=$(dig "${user_domain}" +short)
  local_addr=$(curl -s cip.cc | grep 'IP' | awk '{ print $3 }')
  if [[ -n $real_addr ]] && [[ -n $local_addr ]] && [[ "$real_addr" == "$local_addr" ]]; then
    clear_window
    ACME_INSTALL_DOMAIN_CERT_PATH="${ACME_INSTALL_PATH}/${user_domain}/fullchain.cer"
    QLITE_SSL_CERT_PATH="${CURRENT_SHELL_PATH}/${user_domain}"
    if ! create_dir "${QLITE_SSL_CERT_PATH}"; then
      log_error "$(printf "创建文件目录[%s]出错，请检查后重试" "${QLITE_SSL_CERT_PATH}")"
    fi
    log_success "域名解析正常"
  else
    clear_window
    log_error "$(printf "域名解析地址[%s]与本服务器IP地址[%s]不一致，请输入解析到该服务器的正确域名: " "$real_addr" "$local_addr")"
    check_dns_entries
  fi
}

function pre_install_check() {
  get_linux_info
  install_required_pkg
  check_linux_os
  check_update_system_resource
  check_dns_entries
}

function check_port() {
  for _port in "$@"; do
    local port _process
    port=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w "$_port")
    if [ -n "$port" ]; then
      _process=$(netstat -tlpn | awk -F '[: ]+' '$5=='"$_port"'{print $9}')
      log_error "$(printf "检测到[%s]端口被占用，占用进程为:[%s]。请释放[%s]端口后重试，本次安装结束" "${_port}" "${_process}" "${_port}")"
      exit 1
    fi
  done
}

function check_email_valid() {
  local _email="$1"
  if [ -z "$(echo "${_email}" | gawk '/^([a-zA-Z0-9_\-\.\+]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$/{print $0}')" ]; then
    return 1
  fi
  return 0
}

function read_contact_email() {
  if [ -z "$contact_email" ]; then
    read -rep "请输入您的电子邮箱:" contact_email
    clear_window
    if ! check_email_valid "$contact_email"; then
      log_error "$(printf "邮箱地址[%s]不合法，请重新输入" "${contact_email}")"
      unset contact_email
      read_contact_email
    fi
  fi
}

function read_web_server() {
  if [ -z "$web_server" ]; then
    echo "请选择您已安装的web server"
    show_select_item "${WEB_SERVER_ITEM[*]}"
    web_server=$_temp_selection
  fi
  case $web_server in
  1)
    clear_window
    web_server_plugin="nginx"
    if ! is_command_exists nginx no; then
      log_error "没有找到您已安装的nginx，请检查后重试"
      exit 1
    fi
    ;;
  2)
    clear_window
    web_server_plugin="apache"
    if ! is_command_exists apache no; then
      log_error "没有找到您已安装的apache，请检查后重试"
      exit 1
    fi
    ;;
  3)
    clear_window
    web_server_plugin="standalone"
    check_port 80
    check_port 443
    ;;
  *)
    clear_window
    log_error "$ERROR_SELECT_INPUT"
    read_web_server
    ;;
  esac
}

function is_acme_dir_existed() {
  if ! [ -d "${ACME_ORIGIN_DIR_PATH}" ]; then
    if [ "$1" != "no" ]; then
      log_error "没有找到acme脚本"
    fi
    return 1
  fi
  return 0
}

function is_acme_cmd_existed() {
  if ! [ -x "$(command -v "$ACME_INSTALL_EXEC_PATH")" ]; then
    if [ "$1" != "no" ]; then
      log_warn "acme脚本未安装"
    fi
    return 1
  fi
  return 0
}

function install_acme() {
  log_info "开始安装acme脚本服务"
  cd "${ACME_ORIGIN_DIR_PATH}" || exit
  ./acme.sh --install --home "${ACME_INSTALL_PATH}" "${ACME_DEBUG_MODE}" >>"${LOG_FILE}" 2>&1
  if ! is_acme_cmd_existed no; then
    log_error "安装acme脚本服务失败"
    show_log_tip_exit 1
  fi
  cd "${LINUX_HOME_PATH}" || exit
  log_success "安装acme脚本服务成功"
}

function check_command_failed_reason() {
  local _is_unknown_error=0
  local acme_error_reasons=(
    "Timeout during connect (likely firewall problem)"
    "Verify error"
    "Register account Error:"
    "Create new order error"
    "'/etc/nginx/nginx.conf' doesn't exist"
    "Can not find conf file for domain"
    "Reload error for"
    "nginx: [error]"
  )
  for error_item in "${acme_error_reasons[@]}"; do
    local _err_msg
    _err_msg=$(grep "${error_item}" "$LOG_FILE")
    if [[ -n $_err_msg ]] && [[ $_err_msg != '' ]]; then
      _is_unknown_error=1
      case $error_item in
      "${acme_error_reasons[0]}") log_error "连接超时，请检查防火墙后重试" ;;
      "${acme_error_reasons[1]}") log_error "部署域名验证失败" ;;
      "${acme_error_reasons[2]}") log_error "注册申请证书用户失败" ;;
      "${acme_error_reasons[3]}") log_error "创建申请证书订单失败" ;;
      "${acme_error_reasons[4]}") log_error "没有找到nginx配置文件[/etc/nginx/nginx.conf]，请检查后重试" ;;
      "${acme_error_reasons[5]}") log_error "在配置文件中没有找到对应的域名配置，请检查后重试" ;;
      "${acme_error_reasons[6]}") log_error "重新加载配置文件出错，请重启您的web server" ;;
      "${acme_error_reasons[7]}") log_error "nginx出错，请检查" ;;
      esac
    fi
  done
  if [[ ${_is_unknown_error} == 0 ]]; then
    log_error "发生了未知错误!"
  fi
}

function issue_cert() {
  log_info "获取证书中..."
  if [ "$web_server_plugin" == "standalone" ]; then
    if ! is_command_exists socat; then
      show_log_tip_exit 1
    fi
  fi
  "$ACME_INSTALL_EXEC_PATH" $ACME_ENV_MODE --issue -d "$user_domain" -d www."$user_domain" --"$web_server_plugin" --server "letsencrypt" -m "$contact_email" "${ACME_DEBUG_MODE}" >>"${LOG_FILE}" 2>&1
  if [ $? -eq 0 ] && test -s "$ACME_INSTALL_DOMAIN_CERT_PATH"; then
    log_success "获取证书成功"
    return 0
  else
    check_command_failed_reason
    log_error "获取证书失败"
    return 1
  fi
}

function install_cert() {
  log_info "安装证书中..."
  local install_cmd
  case $web_server in
  1)
    install_cmd="$("$ACME_INSTALL_EXEC_PATH" --install-cert -d "$user_domain" -d www."$user_domain" \
      --cert-file "$QLITE_SSL_CERT_PATH"/cert.pem \
      --key-file "$QLITE_SSL_CERT_PATH"/key.pem \
      --fullchain-file "$QLITE_SSL_CERT_PATH"/fullchain.pem \
      --reloadcmd "service nginx force-reload" \
      "${ACME_DEBUG_MODE}" >>"${LOG_FILE}" 2>&1)"
    ;;
  2)
    install_cmd="$("$ACME_INSTALL_EXEC_PATH" --install-cert -d "$user_domain" -d www."$user_domain" \
      --cert-file "$QLITE_SSL_CERT_PATH"/cert.pem \
      --key-file "$QLITE_SSL_CERT_PATH"/key.pem \
      --fullchain-file "$QLITE_SSL_CERT_PATH"/fullchain.pem \
      --reloadcmd "service apache2 force-reload" \
      "${ACME_DEBUG_MODE}" >>"${LOG_FILE}" 2>&1)"
    ;;
  *)
    install_cmd="$("$ACME_INSTALL_EXEC_PATH" --install-cert -d "$user_domain" -d www."$user_domain" \
      --cert-file "$QLITE_SSL_CERT_PATH"/cert.pem \
      --key-file "$QLITE_SSL_CERT_PATH"/key.pem \
      --fullchain-file "$QLITE_SSL_CERT_PATH"/fullchain.pem \
      "${ACME_DEBUG_MODE}" >>"${LOG_FILE}" 2>&1)"
    ;;
  esac
  if [ ! "$install_cmd" ]; then
    log_success "安装证书成功"
    return 0
  else
    check_command_failed_reason
    log_error "安装证书失败"
    return 1
  fi
}

function handle_acme_script() {
  read_contact_email
  if ! is_acme_cmd_existed; then
    if ! is_acme_dir_existed ""; then
      show_log_tip_exit 1
    fi
    install_acme
  fi
  check_acme_cert
  if [ "$cert_success" != "1" ]; then
    if ! issue_cert; then
      show_log_tip_exit 1
    fi
    cert_success="1"
  fi
  if [ "$cert_success" == "1" ]; then
    if ! install_cert; then
      show_log_tip_exit 1
    fi
  else
    show_log_tip_exit 1
  fi
}

function check_acme_cert() {
  cert_success="0"
  if [ -f "$ACME_INSTALL_DOMAIN_CERT_PATH" ]; then
    local create_time now_time minus
    create_time=$(stat -c %Y "$ACME_INSTALL_DOMAIN_CERT_PATH")
    now_time=$(date +%s)
    minus=$(("$now_time" - "$create_time"))
    if [ $minus -gt 5184000 ]; then
      log_info "您的域名证书已超过60天，请重新申请域名证书"
      cert_success="0"
    else
      log_info "您的域名证书尚未超过60天，无需重新申请新的域名证书"
      cert_success="1"
      exit 1
    fi
  fi
}

function uninstall_nginx() {
  log_info "卸载nginx..."
  rm -rf "/etc/nginx" >/dev/null 2>&1
  "$SYSTEM_PACKAGE" -y autoremove nginx >>"${LOG_FILE}" 2>&1
  if ! is_command_exists nginx no; then
    log_success "nginx卸载成功"
  else
    log_error "nginx卸载失败，请手动卸载"
  fi
}

function kill_nginx_process() {
  local _process_nginx
  _process_nginx=$(pgrep -f "nginx: master process")
  if [[ -n $_process_nginx ]] && [[ $_process_nginx != '' ]]; then
    log_to_log "_process_nginx=${_process_nginx}"
    kill "${_process_nginx}" >>"${LOG_FILE}" 2>&1
    if [ "$?" -eq 0 ]; then
      echo "kill nginx success" >>"${LOG_FILE}" 2>&1
    else
      echo "kill nginx failed" >>"${LOG_FILE}" 2>&1
    fi
  fi
}

function install_nginx() {
  log_info "安装nginx..."
  INSTALL_NGINX_SUCCESS="1"
  (sudo "$SYSTEM_PACKAGE" -y install nginx) >>"${LOG_FILE}" 2>&1
  if [ ! -d "/etc/nginx" ]; then
    log_error "nginx安装有问题"
    exit 1
  fi
  log_success "nginx安装成功"
  sleep 3
  INSTALL_NGINX_SUCCESS="0"
}

function start_detail_menu() {
  show_select_item "${DETAIL_MENU_ITEM[*]}"
  menu_item=$_temp_selection
  case $menu_item in
  1) # 安装证书
    clear_window
    read_web_server
    pre_install_check
    handle_acme_script
    ;;
  2) # 返回
    clear_window
    start_menu
    ;;
  *)
    clear_window
    log_error ${ERROR_SELECT_INPUT}
    start_detail_menu
    ;;
  esac
}

function uninstall_qlite_ssl() {
  if [ -d "$ACME_INSTALL_PATH" ]; then
    "$ACME_INSTALL_EXEC_PATH" uninstall >>"${LOG_FILE}" 2>&1
  fi
  if [ $? -eq 0 ]; then
    rm -rf "$ACME_INSTALL_PATH"
  fi
  log_success "卸载脚本成功"
}

function renew_cert() {
  check_dns_entries
  log_info "开始更新域名证书"
  "$ACME_INSTALL_EXEC_PATH" --renew $ACME_ENV_MODE -d "$user_domain" -d www."$user_domain" --force >>"${LOG_FILE}" 2>&1
  if [ $? -eq 0 ]; then
    log_success "更新域名证书成功"
    exit 0
  else
    check_command_failed_reason
    log_error "更新域名证书失败"
    show_log_tip_exit 1
  fi
}

function start_menu() {
  show_select_item "${START_MENU_ITEM[*]}"
  menu_item=${_temp_selection}
  case $menu_item in
  1)
    # 安装证书
    clear_window
    start_detail_menu
    ;;
  2) # 更新证书
    clear_window
    renew_cert
    exit 0
    ;;
  3) # 卸载脚本
    clear_window
    uninstall_qlite_ssl
    exit 0
    ;;
  4) # 退出
    clear_window
    exit 0
    ;;
  *)
    clear_window
    log_error "${ERROR_SELECT_INPUT[*]}"
    start_menu
    ;;
  esac
}

main() {
  cd "${LINUX_HOME_PATH}" || exit
  start_menu
}

clear_window
parse_arguments "${@:1}"
check_user_root
init_path
main
