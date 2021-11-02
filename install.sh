#!/bin/bash

ACME_PROJECT_GITEE_GIT="https://gitee.com/silence4allen/acme.sh.git"
ACME_PROJECT_GITEE_ZIP="https://gitee.com/silence4allen/acme.sh/repository/archive/master.zip"
ACME_PROJECT_GITHUB_GIT="https://github.com/acmesh-official/acme.sh.git"
ACME_PROJECT_GITHUB_ZIP="https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.zip"
QLITE_SSL_GITEE_GIT="https://gitee.com/silence4allen/qlite-ssl.git"
QLITE_SSL_GITEE_ZIP="https://gitee.com/silence4allen/qlite-ssl/repository/archive/master.zip"
QLITE_SSL_GITHUB_GIT="https://github.com/Silence4Allen/qlite-ssl/raw/master/www.tar.gz"
QLITE_SSL_GITHUB_ZIP="https://github.com/Silence4Allen/qlite-ssl/archive/refs/heads/master.zip"

CA_SERVER_LETSENCRYPT="letsencrypt"
CA_SERVER_BUYPASS="buypass"
CA_SERVER_ZEROSSL="zerossl"
CA_SERVER_SSLCOM="sslcom"
DEFAULT_CA_SERVER="$CA_SERVER_LETSENCRYPT"

REQUIRED_PKGS="socat git wget curl unzip"
IS_DEBUG=""

START_MENU_ITEM=("【一级菜单】" "1.安装" "2.更新" "3.卸载" "4.退出")
DETAIL_MENU_ITEM=("【二级菜单】" "1.一键部署HTTPS" "2.自定义获取证书" "3.返回")
WEB_SERVER_ITEM=("1.nginx" "2.apache" "3.other")
SELECT_Y_N=("Y/N")
SELECT_TIP="请选择: "
ERROR_SELECT_INPUT=("请输入正确的选项!")
ERROR_PARAMETES_INPUT=("参数[%s]输入错误，请输入正确的参数!")
MISSING_PARAMETES_INPUT=("缺少参数，请输入正确的参数!")
MISSING_COMMAND_ERROR=("系统命令[%s]不存在，请安装后重试.")
COMAND_CHECK_TIP=("检查安装必要文件")
PARAMETERS_SUGGEST_INFO=("./build.sh --user_domain=your_domain --contact_email=your_contact_email --cert-path=your_cert_path")
CREATE_DIR_FAILED_ERROR="创建文件夹[%s]失败！请创建文件夹后重试"
CREATE_FILE_FAILED_ERROR="创建文件[%s]失败！请创建文件后重试"

IS_ONE_CLICK_DEPLOYMENT=1
ONE_CLICK_DEPLOYMENT_AGREEMENT="一键部署HTTPS需要默认安装nginx作为你的代理web服务器，是否同意？"
ONE_CLICK_DEPLOYMENT_START="开始一键部署"
ONE_CLICK_DEPLOYMENT_QUIT="退出一键部署"
ONE_CLICK_DEPLOYMENT_SUCCESS="一键部署完成"
ONE_CLICK_DEPLOYMENT_FAILED="一键部署失败"

QLITE_SSL_NAME="qlite-ssl"
QLITE_SSL_LOG_NAME='install.log'
QLITE_SSL_INDEX_NAME="index.html"
QLITE_SSL_IMAGE_NAME="welcome.png"
QLITE_SSL_DOWNLOAD_PATH=$(dirname $(readlink -f "$0"))
QLITE_SSL_DOWNLOAD_WWW="${QLITE_SSL_DOWNLOAD_PATH}/www"
QLITE_SSL_DOWNLOAD_HTML="${QLITE_SSL_DOWNLOAD_WWW}/html"
QLITE_SSL_DOWNLOAD_INDEX_HTML="${QLITE_SSL_DOWNLOAD_HTML}/${QLITE_SSL_INDEX_NAME}"
QLITE_SSL_DOWNLOAD_IMG="${QLITE_SSL_DOWNLOAD_WWW}/img"
QLITE_SSL_DOWNLOAD_WELCOME_IMAGE="${QLITE_SSL_DOWNLOAD_IMG}/${QLITE_SSL_IMAGE_NAME}"

LINUX_HOME_PATH=$(env | grep ^HOME= | cut -c 6-)
QLITE_SSL_PATH="${LINUX_HOME_PATH}/.${QLITE_SSL_NAME}"
QLITE_SSL_LOG="${QLITE_SSL_PATH}/log"
QLITE_SSL_LOG_FILE="${QLITE_SSL_LOG}/${QLITE_SSL_LOG_NAME}"
QLITE_SSL_LOG_TIP="您可以通过文件[${QLITE_SSL_LOG_FILE}]查看更多信息。"
QLITE_SSL_WWW="${QLITE_SSL_PATH}/www"
QLITE_SSL_HTML="${QLITE_SSL_WWW}/html"
QLITE_SSL_INDEX_HTML="${QLITE_SSL_HTML}/${QLITE_SSL_INDEX_NAME}"
QLITE_SSL_IMG="${QLITE_SSL_WWW}/img"
QLITE_SSL_WELCOME_IMAGE="${QLITE_SSL_IMG}/${QLITE_SSL_IMAGE_NAME}"
QLITE_SSL_DOMAIN_PATH="${QLITE_SSL_PATH}/%s"
QLITE_SSL_DOMAIN_BACKUP_NGINX="${QLITE_SSL_DOMAIN_PATH}/backup/nginx/"
QLITE_SSL_CERT_FILE_NAME="fullchain.pem"
QLITE_SSL_DOMAIN_CERT_PATH="${QLITE_SSL_DOMAIN_PATH}/${QLITE_SSL_CERT_FILE_NAME}"
QLITE_SSL_UNINSTALL_TIP="您可以自行删除[%s]文件"

NGINX_ROOT_PATH="/etc/nginx"
NGINX_CONF_FILE="/etc/nginx/nginx.conf"
NGINX_RESOURCE_PATH="/var/www"
NGINX_QLITE_RESOURCE="${NGINX_RESOURCE_PATH}/${QLITE_SSL_NAME}"
NGINX_QLITE_RESOURCE_HTML="${NGINX_QLITE_RESOURCE}/html"
NGINX_QLITE_RESOURCE_HTML_INDEX_HTML="/html/${QLITE_SSL_INDEX_NAME}"
NGINX_QLITE_RESOURCE_INDEX_HTML="${NGINX_QLITE_RESOURCE_HTML}/${QLITE_SSL_INDEX_NAME}"
NGINX_QLITE_RESOURCE_IMG="${NGINX_QLITE_RESOURCE}/img"
NGINX_QLITE_RESOURCE_IMG_WELCOME_IMG="/img/${QLITE_SSL_IMAGE_NAME}"
NGINX_QLITE_RESOURCE_WELCOME_IMG="${NGINX_QLITE_RESOURCE_IMG}/${QLITE_SSL_IMAGE_NAME}"
NGINX_INSTALL_TIP="安装nginx..."
NGINX_INSTALL_SUCCESS="nginx安装成功"
NGINX_INSTALL_ERROR="nginx安装有问题"
NGINX_UNINSTALL_TIP="卸载nginx..."
NGINX_UNINSTALL_SUCCESS="nginx卸载成功"
NGINX_UNINSTALL_ERROR="nginx卸载失败，请自行卸载"
NGINX_GET_CONF_SUCCESS="获取nginx配置成功"
NGINX_GET_CONF_FAILED="获取nginx配置失败"
NGINX_ALREADY_EXISTED_ERROR="检测到已安装nginx，请卸载后重试。"
WEB_SERVER_SELECTED_TIP="请选择您已安装的web server"
WEB_SERVER_NOT_FOUND_ERROR="未找到您已安装的web server，请检查"

PORT_OCCUPATION_ERROR="检测到[%s]端口被占用，占用进程为:[%s]，本次安装结束"
DOMAIN_NAME_SYSTEM_TIP="域名解析正常，开始安装"
DOMAIN_NAME_SYSTEM_ERROR="域名解析地址与本主机IP地址不一致，请输入解析到该主机的正确域名: "

CERT_SAVE_PATH_PARSE_ERROR="证书存储路径不存在或未正确解析！"
CERT_SAVE_ABS_PATH_TIP="您的证书保存在[%s]，请牢记。"
CERT_APPLICATION_SUCCESS="证书申请成功"
CERT_APPLICATION_FAILED="证书申请失败"
CERT_NO_NEED_RENEW_INFO="检测到域名证书存在且未超过60天，无需重新申请"
CERT_NEED_RENEW_INFO="检测到域名证书已超过60天，需要重新申请"
CERT_RENEW_TIP="开始更新域名证书"
CERT_RENEW_SUCCESS="更新域名证书成功"
CERT_RENEW_FAILED="更新域名证书失败"

ACME_SHELL_PROJECT_ENTRY="acme.sh"
CERT_FILE_NAME="fullchain.cer"
ACME_SHELL_DOWNLOAD_PATH="${LINUX_HOME_PATH}/acme.sh"
ACME_SHELL_DOWNLOAD_ENTRY_PATH="${ACME_SHELL_DOWNLOAD_PATH}/acme.sh"
ACME_SHELL_INSTALL_PATH="${LINUX_HOME_PATH}/.acme.sh"
ACME_SHELL_CERT_DOMAIN_PATH="${ACME_SHELL_INSTALL_PATH}/%s"
ACME_SHELL_CERT_DOMAIN_CERT_PATH="${ACME_SHELL_INSTALL_PATH}/%s/${CERT_FILE_NAME}"
ACME_SHELL_PATH="${LINUX_HOME_PATH}/.acme.sh/acme.sh"
ACME_SHELL_UNDOWNLOAD_ERROR="acme脚本未下载"
ACME_SHELL_UNINSTALL_ERROR="acme脚本未安装"
ACME_SHELL_DOWNLOAD_TIP="开始下载acme脚本"
ACME_SHELL_DOWNLOAD_SUCCESS="下载acme脚本完成"
ACME_SHELL_DOWNLOAD_FAILED="下载acme脚本失败"
ACME_SHELL_INSTALL_TIP="开始安装acme脚本服务"
ACME_SHELL_INSTALL_SUCCESS="安装acme脚本服务成功"
ACME_SHELL_INSTALL_FAILED="安装acme脚本服务失败"
ACME_SHELL_REMOVE_TIP="开始卸载acme脚本服务"
ACME_SHELL_REMOVE_SUCCESS="卸载脚本成功"
ACME_SHELL_REMOVE_FAILED="卸载脚本失败"
ACME_SHELL_CERT_ISSUE_TIP="获取证书中..."
ACME_SHELL_CERT_ISSUE_SUCCESS="获取证书成功"
ACME_SHELL_CERT_ISSUE_FAILED="获取证书失败"
ACME_SHELL_CERT_INSTALL_TIP="安装证书中..."
ACME_SHELL_CERT_INSTALL_SUCCESS="安装证书成功"
ACME_SHELL_CERT_INSTALL_FAILED="安装证书失败"
ACME_ERROR_REASON=("Verify error" "Register account Error:" "Create new order error")
ACME_CERT_VERIFY_ERROR=("部署域名验证失败!")
ACME_CERT_REGISTER_ACCOUNT_ERROR=("注册申请证书用户失败!")
ACME_CERT_CREATE_NEW_ORDER_ERROR=("创建申请证书订单失败!")
ACME_CERT_UNKNOWN_ERROR=("发生了未知错误!")

function usage () {
    cat <<EOF
Usage: $0 [OPTIONS]
  --domain=your_domain             [required] Specify the domain which you want to get ssl
  --email=your_contact_email       [required] The email which you can get the information about ssl information
  --cert-path=save_your_cert_path             The path where you want to save your own cert(you should input absolute path)
  --debug                                     Show the log of debugger
EOF
    exit 0
}

function shell_quote_string() {
    local _err_msg=$(printf ${ERROR_PARAMETES_INPUT} ${arg})
    echo "$_err_msg"
    usage
}

function parse_arguments() {
    for arg do
        val=`echo "$arg" | sed -e 's;^--[^=]*=;;'`
        optname=`echo "$arg" | sed -e 's/^\(--[^=]*\)=.*$/\1/'`
        optname_subst=`echo "$optname" | sed 's/_/-/g'`
        arg=`echo $arg | sed "s/^$optname/$optname_subst/"`
        case "$arg" in
            --domain=*) user_domain="$val" ;;
            --email=*) contact_email="$val" ;;
            --cert-path=*) cert_path="$val" ;;
            --help) usage ;;
            --debug) IS_DEBUG="--debug" ;;
            *) shell_quote_string "$arg" ;;
        esac
    done
    check_shell_arguments
}

function init_cert_path() {
    if [[ ! -n $cert_path ]] || [[ $cert_path == '' ]]; then
        create_dir $QLITE_SSL_PATH
        cert_path=$QLITE_SSL_PATH
    fi
    cert_path=$(readlink -f $cert_path)
    if [[ ! -n $cert_path ]] || [[ $cert_path == '' ]]; then
        log_error "$CERT_SAVE_PATH_PARSE_ERROR"
        exit 1
    fi
    if [ ! -d $cert_path ]; then
        create_dir $cert_path
        if [ ! -d $cert_path ]; then
            log_error "$CERT_SAVE_PATH_PARSE_ERROR"
            exit 1
        fi
    fi
    abs_cert_path=${cert_path}"/"${user_domain}
    create_dir $abs_cert_path
}

function check_shell_arguments() {
    if [[ ! -n $user_domain ]] || [[ ! -n $contact_email ]]; then
        log_error "$MISSING_PARAMETES_INPUT"
        usage
    fi
    init_cert_path
}

function log_to_log() {
    echo "[$(date)]" "$@" >>${QLITE_SSL_LOG_FILE}
}

function log_info() {
    if  [ -n "$1" ] ;then
        echo -e "[$(date)]" "\033[34m\033[01m$@\033[0m"
        log_to_log "$@"
    fi
}

function log_warn() {
    if  [ -n "$1" ] ;then
        echo -e "[$(date)]" "\033[33m\033[01m$@\033[0m"
        log_to_log "$@"
    fi
}

function log_success() {
    if  [ -n "$1" ] ;then
        echo -e "[$(date)]" "\033[32m\033[01m$@\033[0m"
        log_to_log "$@"
    fi
}

function log_error() {
    if  [ -n "$1" ] ;then
        echo -e "[$(date)]" "\033[31m\033[01m$@\033[0m"
        log_to_log "$@"
    fi
}

function log_error_without_datetime() {
    if  [ -n "$1" ] ;then
        echo -e "\033[31m\033[01m$@\033[0m"
        log_to_log "$@"
    fi
}

function is_command_exists() {
    local _command="$1"
    if ! [ -x "$(command -v "$_command")" ]; then
        if [ "$2" != "no" ]; then
            local _tip=$(printf "${MISSING_COMMAND_ERROR}" ${_command})
            log_error $_tip
        fi
        return 1
    fi
    return 0
}

function create_file() {
    local _file="$1"
    if [ -n $_file ]; then
        if [ ! -f $_file ]; then
            touch $_file
            log_to_log "create file ${_file}" >>${QLITE_SSL_LOG_FILE}
        fi
        if [ ! -f $_file ]; then
            local _i=$(printf "${CREATE_FILE_FAILED_ERROR}" ${_file})
            log_error $_i
            return 1
        fi
    fi
    return 0
}

function create_dir() {
    local _dir="$1"
    if [ -n $_dir ]; then
        if [ ! -d $_dir ]; then
            mkdir -p $_dir >/dev/null 2>&1
            log_to_log "create dir ${_dir}" >>${QLITE_SSL_LOG_FILE}
        fi
        if [ ! -d $_dir ]; then
            local _i=$(printf "${CREATE_DIR_FAILED_ERROR}" ${_dir})
            log_error $_i
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
    read -rep ${SELECT_TIP}_temp_selection
    printf '\n'
}

function show_agree_tip() {
    local agree_tip="$1"
    echo "$agree_tip""$SELECT_Y_N"
    read -rep ${SELECT_TIP}_temp_selection
    printf '\n'
}

function show_log_tip_exit() {
    if [ $1 -eq 1 ]; then
        local _exit_flag=1
    else
        local _exit_flag=0
    fi
    if [ ${install_nginx_success=1} == "0" ]; then
        uninstall_nginx
    fi
    log_error $QLITE_SSL_LOG_TIP
    exit ${_exit_flag}
}

function install_required_pkg() {
    log_info "$COMAND_CHECK_TIP"
    log_to_log "$system_package -y install $REQUIRED_PKGS"
    $system_package -y install $REQUIRED_PKGS >/dev/null 2>&1
}

function get_linux_info() {
    source /etc/os-release
    RELEASE=$ID
    if [ "$RELEASE" == "centos" ]; then
        release="centos"
        system_package="yum"
    elif [ "$RELEASE" == "debian" ]; then
        release="debian"
        system_package="apt-get"
    elif [ "$RELEASE" == "ubuntu" ]; then
        release="ubuntu"
        system_package="apt-get"
    fi
}

function check_selinux() {
    if [ -f "/etc/selinux/config" ]; then
        CHECK=$(grep SELINUX= /etc/selinux/config | grep -v "#")
        if [ "$CHECK" == "SELINUX=enforcing" ]; then
            log_info "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
            setenforce 0
            sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        elif [ "$CHECK" == "SELINUX=permissive" ]; then
            log_info "$(date +"%Y-%m-%d %H:%M:%S") - SELinux状态非disabled,关闭SELinux."
            setenforce 0
            sed -i 's/SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
        fi
    fi
}

# function check_centos() {
# }
#
# function check_ubuntu() {
# }
#
# function check_debian() {
# }

function check_linux_os() {
    check_selinux
    # case $release in
    #     "centos") check_centos
    #         ;;
    #     "ubuntu") check_ubuntu
    #         ;;
    #     "debian") check_debian
    #         ;;
    # esac
}

function check_dns_entries() {
    real_addr=$(ping "${user_domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    local_addr=$(curl -s ipv4.icanhazip.com)
    if [[ -n $real_addr ]] && [[ -n $local_addr ]] && [[ "$real_addr" == "$local_addr" ]]; then
        log_success "$DOMAIN_NAME_SYSTEM_TIP"
    else
        log_error "$DOMAIN_NAME_SYSTEM_ERROR"
        read -re user_domain
        check_dns_entries
    fi
}

function check_update_system_resource() {
    "$system_package" -y update >/dev/null 2>&1
}

function preinstall_check() {
    get_linux_info
    install_required_pkg
    check_linux_os
    check_update_system_resource
    check_dns_entries
}

function check_port() {
    local check_ports="$#"
    for _port in "$@"; do
        port=$(netstat -tlpn | awk -F '[: ]+' '$1=="tcp"{print $5}' | grep -w "$_port")
        if [ -n "$port" ]; then
            _process=$(netstat -tlpn | awk -F '[: ]+' '$5=='"$_port"'{print $9}')
            local _i=$(printf "${PORT_OCCUPATION_ERROR}" ${_port} ${_process})
            log_error _i
            exit 1
        fi
    done
}

function read_web_server() {
    if [ ! -n "$web_server" ]; then
        echo "$WEB_SERVER_SELECTED_TIP"
        show_select_item "${WEB_SERVER_ITEM[*]}"
        web_server=$_temp_selection
    fi
    case $web_server in
        1)
            web_server_plugin="nginx"
            if ! is_command_exists nginx no; then
                log_error ${WEB_SERVER_NOT_FOUND_ERROR}
                exit 1
            fi
            ;;
        2)
            web_server_plugin="apache"
            if ! is_command_exists apache no; then
                log_error ${WEB_SERVER_NOT_FOUND_ERROR}
                exit 1
            fi
            ;;
        3)
            web_server_plugin="standalone"
            check_port 80
            check_port 443
            ;;
        *)
            log_error "$ERROR_SELECT_INPUT"
            clear
            read_web_server
            ;;
    esac
}

function is_acme_downloaded() {
    if ! [ -d ${ACME_SHELL_DOWNLOAD_PATH} ]; then
        if [ "$1" != "no" ]; then
            log_warn "$ACME_SHELL_UNDOWNLOAD_ERROR"
        fi
        return 1
    fi
    return 0
}

function is_acme_existed() {
    if ! [ -x "$(command -v "$ACME_SHELL_PATH")" ]; then
        if [ "$1" != "no" ]; then
            log_warn "$ACME_SHELL_UNINSTALL_ERROR"
        fi
        return 1
    fi
    return 0
}

function download_acme() {
    cd ${LINUX_HOME_PATH}
    log_info "$ACME_SHELL_DOWNLOAD_TIP"
    if ! is_command_exists wget; then
        show_log_tip_exit 1
    fi
    local _acme_zip="acme.zip"
    local _acme_dir=$(echo ${ACME_SHELL_PROJECT_ENTRY}"-master")
    # git clone "$ACME_PROJECT_GITEE_GIT" >>${QLITE_SSL_LOG_FILE} 2>&1
    wget -q -O ${_acme_zip} "$ACME_PROJECT_GITEE_ZIP" >>${QLITE_SSL_LOG_FILE} 2>&1
    if [ $? -eq 0 ]; then
        unzip -qo ${_acme_zip} >/dev/null 2>&1
        rm -rf ${_acme_zip} >/dev/null 2>&1
        mv ${_acme_dir} ${ACME_SHELL_PROJECT_ENTRY} >/dev/null 2>&1
    fi
    if ! is_acme_downloaded no; then
        log_error "$ACME_SHELL_DOWNLOAD_FAILED"
        show_log_tip_exit 1
    fi
    log_success "$ACME_SHELL_DOWNLOAD_SUCCESS"
}

function install_acme() {
    log_info "$ACME_SHELL_INSTALL_TIP"
    cd ${ACME_SHELL_DOWNLOAD_PATH}
    ./${ACME_SHELL_PROJECT_ENTRY} --install $IS_DEBUG >>${QLITE_SSL_LOG_FILE} 2>&1
    if ! is_acme_existed no; then
        log_error "$ACME_SHELL_INSTALL_FAILED"
        show_log_tip_exit 1
    fi
    cd ${LINUX_HOME_PATH}
    log_success "$ACME_SHELL_INSTALL_SUCCESS"
}

function check_command_failed_reason() {
    local _is_unknown_error=0
    for error_item in "${ACME_ERROR_REASON[@]}"; do
        local _err_msg=$(grep "${error_item}" $QLITE_SSL_LOG_FILE)
        if [[ -n $_err_msg ]] && [[ $_err_msg != '' ]]; then
            _is_unknown_error=1
            case $error_item in
                ${ACME_ERROR_REASON[0]})log_error ${ACME_CERT_VERIFY_ERROR} ;;
                ${ACME_ERROR_REASON[1]})log_error ${ACME_CERT_REGISTER_ACCOUNT_ERROR} ;;
                ${ACME_ERROR_REASON[2]})log_error ${ACME_CERT_CREATE_NEW_ORDER_ERROR} ;;
            esac
        fi
    done
    if [[ ${_is_unknown_error} == 0 ]]; then
        log_error ${ACME_CERT_UNKNOWN_ERROR}
    fi
}

function issue_cert() {
    log_info $ACME_SHELL_CERT_ISSUE_TIP
    if [ "$web_server_plugin" == "standalone" ]; then
        if ! is_command_exists socat; then
            show_log_tip_exit 1
        fi
    fi
    "$ACME_SHELL_PATH" --issue -d "$user_domain" -d www."$user_domain" --"$web_server_plugin" --server "$DEFAULT_CA_SERVER" -m "$contact_email" $IS_DEBUG >>${QLITE_SSL_LOG_FILE} 2>&1
    if [ $? -eq 0 ] && test -s $ACME_SHELL_CERT_DOMAIN_CERT_PATH; then
        log_success ${ACME_SHELL_CERT_ISSUE_SUCCESS}
        return 0
    else
        check_command_failed_reason
        log_error ${ACME_SHELL_CERT_ISSUE_FAILED}
        return 1
    fi
}

function install_cert() {
    log_info "$ACME_SHELL_CERT_INSTALL_TIP"
    case $web_server in
        1)
            "$ACME_SHELL_PATH" --install-cert -d "$user_domain" \
                --cert-file "$abs_cert_path"/cert.pem \
                --key-file "$abs_cert_path"/key.pem \
                --fullchain-file "$abs_cert_path"/fullchain.pem \
                --reloadcmd "sudo nginx -c /etc/nginx/nginx.conf" \
                $IS_DEBUG >>${QLITE_SSL_LOG_FILE} 2>&1
            ;;
        2)
            "$ACME_SHELL_PATH" --install-cert -d "$user_domain" \
                --cert-file "$abs_cert_path"/cert.pem \
                --key-file "$abs_cert_path"/key.pem \
                --fullchain-file "$abs_cert_path"/fullchain.pem \
                --reloadcmd "service apache2 force-reload" \
                $IS_DEBUG >>${QLITE_SSL_LOG_FILE} 2>&1
            ;;
        *)
            "$ACME_SHELL_PATH" --install-cert -d "$user_domain" \
                --cert-file "$abs_cert_path"/cert.pem \
                --key-file "$abs_cert_path"/key.pem \
                --fullchain-file "$abs_cert_path"/fullchain.pem \
                $IS_DEBUG >>${QLITE_SSL_LOG_FILE} 2>&1
            ;;
    esac
    if [ $? -eq 0 ]; then
        log_success $ACME_SHELL_CERT_INSTALL_SUCCESS
        update_nginx_conf
        log_success "$CERT_SAVE_ABS_PATH_TIP"
        if [ $abs_cert_path != $QLITE_SSL_PATH ]; then
            cp -rf $abs_cert_path $QLITE_SSL_PATH >/dev/null 2>&1
        fi
        return 0
    else
        check_command_failed_reason
        log_error $ACME_SHELL_CERT_INSTALL_TIP
        return 1
    fi
}

function handle_acme_script() {
    if ! is_acme_existed; then
        if ! is_acme_downloaded; then
            download_acme
        fi
        install_acme
    fi
    check_qlite_ssl
    if [ "$cert_success" != "1" ]; then
        check_acme_cert
    fi
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
    if [ -f "$ACME_SHELL_CERT_DOMAIN_CERT_PATH" ]; then
        cd "$ACME_SHELL_CERT_DOMAIN_PATH"
        create_time=`stat -c %Y "$CERT_FILE_NAME"`
        now_time=`date +%s`
        minus=$(($now_time - $create_time ))
        if [ $minus -gt 5184000 ]; then
            log_info "$CERT_NEED_RENEW_INFO"
        else
            log_info "$CERT_NO_NEED_RENEW_INFO"
            cert_success="1"
            exit 1
        fi
        cd ${LINUX_HOME_PATH}
    fi
}

function check_qlite_ssl() {
    cert_success="0"
    if [ ! -d "$QLITE_SSL_PATH" ]; then
        if ! create_dir ${QLITE_SSL_PATH} && [[ ${IS_ONE_CLICK_DEPLOYMENT} == "0" ]]; then
            uninstall_nginx
            exit 1
        fi
    fi
    if [ ! -d "$QLITE_SSL_DOMAIN_PATH" ]; then
        if ! create_dir ${QLITE_SSL_DOMAIN_PATH} && [[ ${IS_ONE_CLICK_DEPLOYMENT} == "0" ]]; then
            uninstall_nginx
            exit 1
        fi
    fi
    if [ -f "$QLITE_SSL_DOMAIN_CERT_PATH" ]; then
        cd "$QLITE_SSL_DOMAIN_PATH"
        create_time=`stat -c %Y "$QLITE_SSL_CERT_FILE_NAME"`
        now_time=`date +%s`
        minus=$(($now_time - $create_time ))
        if [ $minus -gt 5184000 ]; then
            log_info "$CERT_NEED_RENEW_INFO"
        else
            log_info "$CERT_NO_NEED_RENEW_INFO"
            cert_success="1"
            exit 1
        fi
        cd ${LINUX_HOME_PATH}
    fi
}

function uninstall_nginx() {
    log_info "$NGINX_UNINSTALL_TIP"
    rm -rf "$NGINX_ROOT_PATH" >/dev/null 2>&1
    "$system_package" -y autoremove nginx >>${QLITE_SSL_LOG_FILE} 2>&1
    if ! is_command_exists nginx no; then
        log_success ${NGINX_UNINSTALL_SUCCESS}
    else
        log_error ${NGINX_UNINSTALL_ERROR}
    fi
}

function init_nginx_qlite_default_resource() {
    local need_update_nginx_conf=1
    if [ ! -f ${NGINX_QLITE_RESOURCE_INDEX_HTML} ]; then
        create_dir $NGINX_QLITE_RESOURCE_HTML
        if [ ! -f ${QLITE_SSL_INDEX_HTML} ]; then
            need_update_nginx_conf=0
        else
            cp ${QLITE_SSL_INDEX_HTML} ${NGINX_QLITE_RESOURCE_INDEX_HTML} >/dev/null 2>&1
        fi
    fi
    if [ ! -f ${NGINX_QLITE_RESOURCE_WELCOME_IMG} ]; then
        create_dir $NGINX_QLITE_RESOURCE_IMG
        if [ ! -f ${QLITE_SSL_WELCOME_IMAGE} ]; then
            need_update_nginx_conf=0
        else
            cp ${QLITE_SSL_WELCOME_IMAGE} ${NGINX_QLITE_RESOURCE_WELCOME_IMG} >/dev/null 2>&1
        fi
    fi

    if [ $need_update_nginx_conf -eq 0 ]; then
        cp ${QLITE_SSL_DOWNLOAD_INDEX_HTML} ${NGINX_QLITE_RESOURCE_INDEX_HTML} >/dev/null 2>&1
        chmod 666 ${NGINX_QLITE_RESOURCE_INDEX_HTML} >/dev/null 2>&1
        cp ${QLITE_SSL_DOWNLOAD_WELCOME_IMAGE} ${NGINX_QLITE_RESOURCE_WELCOME_IMG} >/dev/null 2>&1
        chmod 666 ${NGINX_QLITE_RESOURCE_WELCOME_IMG} >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            log_success $NGINX_GET_CONF_SUCCESS
            create_dir $QLITE_SSL_WWW
            return 0
        else
            log_error ${NGINX_GET_CONF_FAILED}
            return 1
        fi
    fi
}

function init_nginx_conf() {
    init_nginx_qlite_default_resource
    create_file /etc/nginx/nginx.conf
    cat << EOF | tee /etc/nginx/nginx.conf >>${QLITE_SSL_LOG_FILE} 2>&1
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
	# multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;

    server {
      listen 80;
      listen [::]:80;

      root $NGINX_QLITE_RESOURCE;
      index $NGINX_QLITE_RESOURCE_HTML_INDEX_HTML;

      server_name $user_domain www.$user_domain;

      location / {
          try_files \$uri \$uri/ =404;
      }
    }
}
EOF
}

function kill_nginx_process() {
    local _process_nginx=$(ps aux | grep "nginx: master process" | grep -v grep | awk '{print $2}')
    if [[ -n $_process_nginx ]] && [[ $_process_nginx != '' ]]; then
        log_to_log "_process_nginx=${_process_nginx}"
        kill -9 ${_process_nginx} >>${QLITE_SSL_LOG_FILE} 2>&1
        if [ "$?" -eq 0 ]; then
            echo "kill nginx success" >>${QLITE_SSL_LOG_FILE} 2>&1
        else
            echo "kill nginx failed" >>${QLITE_SSL_LOG_FILE} 2>&1
        fi
    fi
}

function update_nginx_conf() {
    cat << EOF | tee /etc/nginx/nginx.conf >>${QLITE_SSL_LOG_FILE} 2>&1
user root;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
  worker_connections 768;
  # multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    default_type application/octet-stream;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;

    server {
      listen 443 ssl;

      root $NGINX_QLITE_RESOURCE;
      index $NGINX_QLITE_RESOURCE_HTML_INDEX_HTML;

      server_name $user_domain www.$user_domain;
      ssl_certificate $abs_cert_path/cert.pem;
      ssl_certificate_key $abs_cert_path/key.pem;

      location / {
              try_files \$uri \$uri/ =404;
      }
    }

    server {
      listen 80;
      server_name $user_domain www.$user_domain;
      rewrite ^(.*)\$ https://\${server_name}\$1 permanent;
    }
}
EOF
    kill_nginx_process
    sleep 3
    nginx -c /etc/nginx/nginx.conf >>${QLITE_SSL_LOG_FILE} 2>&1
}

function install_nginx() {
    log_info "$NGINX_INSTALL_TIP"
    install_nginx_success="1"
    if [ -d $NGINX_ROOT_PATH ]; then
        local _datetime=$(date "+%s")
        create_dir "$QLITE_SSL_DOMAIN_BACKUP_NGINX"
        mv "$NGINX_ROOT_PATH" "$QLITE_SSL_DOMAIN_BACKUP_NGINX" >/dev/null 2>&1
    fi
    "$system_package" -y install nginx >>${QLITE_SSL_LOG_FILE} 2>&1
    if [ ! -d "$NGINX_ROOT_PATH" ]; then
        log_error "$NGINX_INSTALL_ERROR"
        exit 1
    fi
    if ! create_dir /etc/nginx/sites-available/; then
        uninstall_nginx
    fi
    if ! create_dir /etc/nginx/sites-enabled/; then
        uninstall_nginx
    fi
    log_success ${NGINX_INSTALL_SUCCESS}
    init_nginx_conf
    systemctl restart nginx >>${QLITE_SSL_LOG_FILE} 2>&1
    sleep 3
    install_nginx_success="0"
}

function one_click_deployment() {
    show_agree_tip "$ONE_CLICK_DEPLOYMENT_AGREEMENT"
    is_agree=$_temp_selection
    case "$is_agree" in
        y|Y)
            log_info "$ONE_CLICK_DEPLOYMENT_START"
            IS_ONE_CLICK_DEPLOYMENT=0
            preinstall_check
            ;;
        n|N)
            log_info "$ONE_CLICK_DEPLOYMENT_QUIT"
            IS_ONE_CLICK_DEPLOYMENT=1
            start_detail_menu
            ;;
        *)
            log_error "$ERROR_SELECT_INPUT"
            one_click_deployment
            ;;
    esac

    # 检查是否安装nginx
    if ! is_command_exists nginx no; then
        kill_nginx_process
        install_nginx
    else
        log_error "$NGINX_ALREADY_EXISTED_ERROR"
        exit 1
    fi
    web_server="nginx"
    web_server_plugin="nginx"
    handle_acme_script
}

function start_detail_menu() {
    show_select_item "${DETAIL_MENU_ITEM[*]}"
    menu_item=$_temp_selection
    case $menu_item in
        1)  # 一键部署HTTPS
            one_click_deployment
            ;;
        2)  # 自定义安装证书
            read_web_server
            preinstall_check
            handle_acme_script
            ;;
        3)  # 返回
            start_menu
            ;;
        *)
            log_error ${ERROR_SELECT_INPUT}
            start_detail_menu
            ;;
    esac
}

function uninstall_qlite_ssl() {
    if [ -d "$ACME_SHELL_INSTALL_PATH" ]; then
        "$ACME_SHELL_PATH" uninstall >>${QLITE_SSL_LOG_FILE} 2>&1
    fi
    if [ $? -eq 0 ]; then
        rm -rf "$ACME_SHELL_DOWNLOAD_PATH" && rm -rf "$ACME_SHELL_INSTALL_PATH"
    fi
    if [ -d "$QLITE_SSL_PATH" ]; then
        log_info $(printf ${QLITE_SSL_UNINSTALL_TIP} ${QLITE_SSL_PATH})
    fi
    if [ -d "$QLITE_SSL_DOWNLOAD_PATH" ]; then
        log_info $(printf ${QLITE_SSL_UNINSTALL_TIP} ${QLITE_SSL_DOWNLOAD_PATH})
    fi
    log_success "$ACME_SHELL_REMOVE_SUCCESS"
}

function renew_cert() {
    log_info ${CERT_RENEW_TIP}
    "$ACME_SHELL_PATH" --renew -d "$user_domain" --force >>${QLITE_SSL_LOG_FILE} 2>&1
    if [ $? -eq 0 ]; then
        log_success ${CERT_RENEW_SUCCESS}
        exit 0
    else
        check_command_failed_reason
        log_error ${CERT_RENEW_FAILED}
        show_log_tip_exit 1
    fi
}

function start_menu() {
    show_select_item "${START_MENU_ITEM[*]}"
    menu_item=$_temp_selection
    case $menu_item in
        1)
            # 安装证书
            start_detail_menu
            ;;
        2)  # 更新证书
            renew_cert
            exit 0
            ;;
        3)  # 卸载脚本
            uninstall_qlite_ssl
            exit 0
            ;;
        4)  # 退出
            exit 0
            ;;
        *)
            log_error ${ERROR_SELECT_INPUT}
            start_menu
            ;;
    esac
}

function init_log_file() {
    create_dir $QLITE_SSL_LOG
    create_file $QLITE_SSL_LOG_FILE
    echo "domain=${user_domain}, email=${contact_email}, cert-path=${cert_path}, IS_DEBUG=${IS_DEBUG}" >${QLITE_SSL_LOG_FILE}
}

function init_dir_file() {
    QLITE_SSL_DOMAIN_PATH=$(printf ${QLITE_SSL_DOMAIN_PATH} ${user_domain})
    QLITE_SSL_DOMAIN_BACKUP_NGINX=$(printf ${QLITE_SSL_DOMAIN_BACKUP_NGINX} ${user_domain})
    QLITE_SSL_DOMAIN_CERT_PATH=$(printf ${QLITE_SSL_DOMAIN_CERT_PATH} ${user_domain})
    CERT_SAVE_ABS_PATH_TIP=$(printf ${CERT_SAVE_ABS_PATH_TIP} ${abs_cert_path})
    ACME_SHELL_CERT_DOMAIN_PATH=$(printf ${ACME_SHELL_CERT_DOMAIN_PATH} ${user_domain})
    ACME_SHELL_CERT_DOMAIN_CERT_PATH=$(printf ${ACME_SHELL_CERT_DOMAIN_CERT_PATH} ${user_domain})
}
function pre_init() {
    init_dir_file
    init_log_file
}

function check_user_root(){
    if [ $UID -ne 0 ]; then
        echo "You must be root to run this script, please use root to install."
        exit 1
    fi
}

main() {
    cd ${LINUX_HOME_PATH}
    start_menu
}

check_user_root
parse_arguments "${@:1}"
pre_init
main
