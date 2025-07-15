#!/bin/bash
# hub-agent 跨平台智能安装脚本
# 从预编译二进制文件安装，无需编译环境

set -e

# 配置参数
APP_NAME="hub-agent"
REPO_URL="https://github.com/nieyu-ny/hub-client-setup.git"
INSTALL_DIR_LINUX="/opt/$APP_NAME"
INSTALL_DIR_MACOS="/usr/local/bin"
INSTALL_DIR_WINDOWS="C:\\Program Files\\$APP_NAME"
SERVICE_NAME="$APP_NAME"
SERVICE_USER="$APP_NAME"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[STEP]${NC} $1"; }

# 解析命令行参数
TOKEN=""
FORCE_REINSTALL=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -token=*) TOKEN="${1#*=}"; shift ;;
        --token=*) TOKEN="${1#*=}"; shift ;;
        -t) TOKEN="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --force) FORCE_REINSTALL=true; shift ;;
        *) error "未知参数: $1" ;;
    esac
done

[[ -z "$TOKEN" ]] && error "请提供token参数: -token=your_token"

# 检测操作系统
detect_os() {
    case "$OSTYPE" in
        linux-gnu*) echo "linux" ;;
        darwin*) echo "darwin" ;;
        msys*|cygwin*|win32*) echo "windows" ;;
        *) 
            if [[ -f /proc/version ]] && grep -q Microsoft /proc/version; then
                echo "linux"  # WSL视为Linux
            else
                error "不支持的操作系统: $OSTYPE"
            fi
            ;;
    esac
}

# 检测架构
detect_arch() {
    case $(uname -m) in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        i386|i686) echo "386" ;;
        *) echo "amd64" ;;  # 默认值
    esac
}

# 获取二进制文件名
get_binary_name() {
    local os=$(detect_os)
    case $os in
        linux) echo "hub-agent-linux" ;;
        darwin) echo "hub-agent-darwin" ;;
        windows) echo "hub-agent-windows.exe" ;;
        *) error "不支持的操作系统: $os" ;;
    esac
}

# 自动提权重新执行脚本
auto_elevate() {
    local os=$(detect_os)
    
    if [[ $EUID -ne 0 ]]; then
        info "检测到非root权限，尝试自动提权..."
        
        # 保存原始参数
        local orig_args=""
        for arg in "$@"; do
            if [[ "$arg" == *" "* ]]; then
                orig_args="$orig_args \"$arg\""
            else
                orig_args="$orig_args $arg"
            fi
        done
        
        if [[ "$os" == "linux" ]]; then
            # Linux: 尝试sudo
            if command -v sudo &> /dev/null; then
                log "使用sudo重新执行脚本..."
                exec sudo bash "$0" $orig_args
            else
                error "需要root权限，但sudo不可用。请以root身份运行此脚本"
            fi
        elif [[ "$os" == "darwin" ]]; then
            # macOS: 使用sudo
            if command -v sudo &> /dev/null; then
                log "使用sudo重新执行脚本..."
                exec sudo bash "$0" $orig_args
            else
                error "需要管理员权限，但sudo不可用"
            fi
        fi
    fi
}

# 检查并停止已存在的服务
stop_existing_service() {
    local os=$(detect_os)
    
    info "检查已存在的服务..."
    
    if [[ "$os" == "linux" ]]; then
        # 检查systemd服务
        if systemctl list-units --full -all | grep -Fq "${SERVICE_NAME}.service"; then
            warn "发现已存在的服务: $SERVICE_NAME"
            
            if systemctl is-active --quiet "$SERVICE_NAME"; then
                info "停止正在运行的服务..."
                systemctl stop "$SERVICE_NAME" || warn "停止服务失败"
            fi
            
            if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
                info "禁用服务自启动..."
                systemctl disable "$SERVICE_NAME" || warn "禁用服务失败"
            fi
            
            # 删除服务文件
            if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
                info "删除旧的服务文件..."
                rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
                systemctl daemon-reload
            fi
            
            log "已清理旧服务"
        fi
        
    elif [[ "$os" == "darwin" ]]; then
        # 检查LaunchDaemon
        local plist_path="/Library/LaunchDaemons/com.${SERVICE_NAME}.plist"
        if [[ -f "$plist_path" ]]; then
            warn "发现已存在的服务: com.${SERVICE_NAME}"
            
            # 尝试停止和卸载服务
            if launchctl list | grep -q "com.${SERVICE_NAME}"; then
                info "停止正在运行的服务..."
                launchctl stop "com.${SERVICE_NAME}" 2>/dev/null || warn "停止服务失败"
                launchctl unload "$plist_path" 2>/dev/null || warn "卸载服务失败"
            fi
            
            info "删除旧的服务文件..."
            rm -f "$plist_path"
            
            log "已清理旧服务"
        fi
    fi
}

# 安装依赖
install_dependencies() {
    local os=$(detect_os)
    
    if [[ "$os" == "linux" ]]; then
        info "安装依赖包..."
        if command -v apt-get &> /dev/null; then
            apt-get update -qq && apt-get install -y git curl wget
        elif command -v yum &> /dev/null; then
            yum install -y git curl wget
        elif command -v dnf &> /dev/null; then
            dnf install -y git curl wget
        elif command -v apk &> /dev/null; then
            apk add --no-cache git curl wget
        elif command -v pacman &> /dev/null; then
            pacman -S --noconfirm git curl wget
        else
            warn "无法识别包管理器，请手动安装 git, curl, wget"
        fi
    elif [[ "$os" == "darwin" ]]; then
        # 检查基本工具
        if ! command -v git &> /dev/null; then
            error "请先安装 Git (xcode-select --install)"
        fi
        if ! command -v curl &> /dev/null; then
            error "请先安装 curl"
        fi
    fi
}

# 下载二进制文件
download_binary() {
    local binary_name=$(get_binary_name)
    local temp_dir=$(mktemp -d)
    local download_dir="$temp_dir/hub-client-setup"
    
    info "下载二进制文件: $binary_name"
    
    cd "$temp_dir"
    git clone --depth 1 "$REPO_URL" || error "下载失败"
    
    if [[ ! -f "$download_dir/$binary_name" ]]; then
        error "二进制文件不存在: $binary_name"
    fi
    
    echo "$download_dir/$binary_name"
}

# Linux服务安装
setup_linux_service() {
    local binary_path=$(download_binary)
    local install_path="$INSTALL_DIR_LINUX/$APP_NAME"
    
    info "安装Linux服务..."
    
    # 停止并清理已存在的服务
    stop_existing_service
    
    # 创建用户
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR_LINUX" "$SERVICE_USER"
        log "创建服务用户: $SERVICE_USER"
    else
        log "服务用户已存在: $SERVICE_USER"
    fi
    
    # 创建目录并复制文件
    mkdir -p "$INSTALL_DIR_LINUX"
    
    # 如果二进制文件已存在且正在运行，先停止
    if [[ -f "$install_path" ]] && pgrep -f "$install_path" > /dev/null; then
        info "停止正在运行的进程..."
        pkill -f "$install_path" || true
        sleep 2
    fi
    
    cp "$binary_path" "$install_path"
    chmod +x "$install_path"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR_LINUX"
    
    # 创建systemd服务
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=$APP_NAME Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR_LINUX
ExecStart=$install_path -token=$TOKEN
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$APP_NAME

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR_LINUX

[Install]
WantedBy=multi-user.target
EOF
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    # 启用并启动服务
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    log "Linux服务安装完成"
    
    # 清理临时文件
    rm -rf "$(dirname "$binary_path")"
}

# macOS服务安装
setup_macos_service() {
    local binary_path=$(download_binary)
    local install_path="$INSTALL_DIR_MACOS/$APP_NAME"
    
    info "安装macOS服务..."
    
    # 停止并清理已存在的服务
    stop_existing_service
    
    # 复制二进制文件
    mkdir -p "$INSTALL_DIR_MACOS"
    
    # 如果二进制文件已存在且正在运行，先停止
    if [[ -f "$install_path" ]] && pgrep -f "$install_path" > /dev/null; then
        info "停止正在运行的进程..."
        pkill -f "$install_path" || true
        sleep 2
    fi
    
    cp "$binary_path" "$install_path"
    chmod +x "$install_path"
    
    # 创建LaunchDaemon
    local plist_path="/Library/LaunchDaemons/com.${APP_NAME}.plist"
    cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.${APP_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>$install_path</string>
        <string>-token=$TOKEN</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR_MACOS</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>Crashed</key>
        <true/>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardErrorPath</key>
    <string>/var/log/${APP_NAME}.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/${APP_NAME}.log</string>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
EOF
    
    chmod 644 "$plist_path"
    
    # 加载并启动服务
    launchctl load "$plist_path"
    launchctl start "com.${APP_NAME}"
    
    log "macOS服务安装完成"
    
    # 清理临时文件
    rm -rf "$(dirname "$binary_path")"
}

# 显示管理命令
show_management_commands() {
    local os=$(detect_os)
    
    echo ""
    echo "服务管理命令:" 
    
    if [[ "$os" == "linux" ]]; then
        echo "  启动服务: systemctl start $SERVICE_NAME"
        echo "  停止服务: systemctl stop $SERVICE_NAME"
        echo "  重启服务: systemctl restart $SERVICE_NAME"
        echo "  查看状态: systemctl status $SERVICE_NAME"
        echo "  查看日志: journalctl -u $SERVICE_NAME -f"
        echo "  禁用服务: systemctl disable $SERVICE_NAME"
        echo ""
        echo "服务信息:"
        echo "  安装路径: $INSTALL_DIR_LINUX"
        echo "  服务用户: $SERVICE_USER"
    elif [[ "$os" == "darwin" ]]; then
        echo "  启动服务: sudo launchctl start com.${APP_NAME}"
        echo "  停止服务: sudo launchctl stop com.${APP_NAME}"
        echo "  重启服务: sudo launchctl stop com.${APP_NAME} && sudo launchctl start com.${APP_NAME}"
        echo "  查看状态: sudo launchctl list | grep ${APP_NAME}"
        echo "  查看日志: tail -f /var/log/${APP_NAME}.log"
        echo "  卸载服务: sudo launchctl unload /Library/LaunchDaemons/com.${APP_NAME}.plist"
        echo ""
        echo "服务信息:"
        echo "  安装路径: $INSTALL_DIR_MACOS"
        echo "  配置文件: /Library/LaunchDaemons/com.${APP_NAME}.plist"
    fi
    
    echo "  开机启动: 已启用"
    echo ""
}

# 显示安装信息
show_install_info() {
    local os=$(detect_os)
    local arch=$(detect_arch)
    local binary_name=$(get_binary_name)
    
    echo "==============================================="
    echo "    $APP_NAME 一键安装程序"
    echo "==============================================="
    echo ""
    echo "安装信息:"
    echo "  操作系统: $os"
    echo "  架构: $arch"
    echo "  二进制文件: $binary_name"
    echo "  仓库: $REPO_URL"
    echo "  Token: ${TOKEN:0:8}..."
    if [[ "$FORCE_REINSTALL" == true ]]; then
        echo "  强制重装: 是"
    fi
    echo ""
}

# 验证安装
verify_installation() {
    local os=$(detect_os)
    
    info "验证安装..."
    
    sleep 5  # 等待服务启动
    
    if [[ "$os" == "linux" ]]; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "服务运行正常"
            return 0
        else
            warn "服务可能未正常启动"
            echo "服务状态:"
            systemctl status "$SERVICE_NAME" --no-pager -l || true
            return 1
        fi
    elif [[ "$os" == "darwin" ]]; then
        if launchctl list | grep -q "com.${APP_NAME}"; then
            log "服务运行正常"
            return 0
        else
            warn "服务可能未正常启动"
            echo "检查日志: tail /var/log/${APP_NAME}.log"
            return 1
        fi
    fi
}

# 主函数
main() {
    show_install_info
    
    local os=$(detect_os)
    
    # 自动提权
    auto_elevate "$@"
    
    install_dependencies
    
    case $os in
        linux)
            setup_linux_service
            ;;
        darwin)
            setup_macos_service
            ;;
        windows)
            error "Windows平台请使用PowerShell脚本安装"
            ;;
        *)
            error "不支持的平台: $os"
            ;;
    esac
    
    if verify_installation; then
        log "安装完成！$APP_NAME 服务已启动并设置为开机自启动"
    else
        warn "安装可能存在问题，请检查服务状态"
        exit 1
    fi
    
    show_management_commands
}

# 错误处理
trap 'error "安装过程中发生错误，请检查日志"' ERR

# 执行安装
main "$@"