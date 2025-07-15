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
while [[ $# -gt 0 ]]; do
    case $1 in
        -token=*) TOKEN="${1#*=}"; shift ;;
        --token=*) TOKEN="${1#*=}"; shift ;;
        -t) TOKEN="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
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

# 安装依赖
install_dependencies() {
    local os=$(detect_os)
    
    if [[ "$os" == "linux" ]]; then
        info "安装依赖包..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y git curl wget
        elif command -v yum &> /dev/null; then
            yum install -y git curl wget
        elif command -v dnf &> /dev/null; then
            dnf install -y git curl wget
        elif command -v apk &> /dev/null; then
            apk add --no-cache git curl wget
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
    
    # 创建用户
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR_LINUX" "$SERVICE_USER"
        log "创建服务用户: $SERVICE_USER"
    fi
    
    # 创建目录并复制文件
    mkdir -p "$INSTALL_DIR_LINUX"
    cp "$binary_path" "$install_path"
    chmod +x "$install_path"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR_LINUX"
    
    # 创建systemd服务
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=$APP_NAME Service
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR_LINUX
ExecStart=$install_path -token=$TOKEN
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # 启用并启动服务
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    log "Linux服务安装完成"
    echo ""
    echo "服务管理命令:"
    echo "  启动服务: systemctl start $SERVICE_NAME"
    echo "  停止服务: systemctl stop $SERVICE_NAME"
    echo "  重启服务: systemctl restart $SERVICE_NAME"
    echo "  查看状态: systemctl status $SERVICE_NAME"
    echo "  查看日志: journalctl -u $SERVICE_NAME -f"
    
    # 清理临时文件
    rm -rf "$(dirname "$binary_path")"
}

# macOS服务安装
setup_macos_service() {
    local binary_path=$(download_binary)
    local install_path="$INSTALL_DIR_MACOS/$APP_NAME"
    
    info "安装macOS服务..."
    
    # 复制二进制文件
    sudo mkdir -p "$INSTALL_DIR_MACOS"
    sudo cp "$binary_path" "$install_path"
    sudo chmod +x "$install_path"
    
    # 创建LaunchDaemon
    local plist_path="/Library/LaunchDaemons/com.${APP_NAME}.plist"
    sudo tee "$plist_path" > /dev/null <<EOF
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
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/${APP_NAME}.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/${APP_NAME}.log</string>
</dict>
</plist>
EOF
    
    # 加载并启动服务
    sudo launchctl load "$plist_path"
    sudo launchctl start "com.${APP_NAME}"
    
    log "macOS服务安装完成"
    echo ""
    echo "服务管理命令:"
    echo "  启动服务: sudo launchctl start com.${APP_NAME}"
    echo "  停止服务: sudo launchctl stop com.${APP_NAME}"
    echo "  重启服务: sudo launchctl stop com.${APP_NAME} && sudo launchctl start com.${APP_NAME}"
    echo "  查看日志: tail -f /var/log/${APP_NAME}.log"
    
    # 清理临时文件
    rm -rf "$(dirname "$binary_path")"
}

# 权限检查
check_permissions() {
    local os=$(detect_os)
    
    if [[ "$os" == "linux" ]]; then
        if [[ $EUID -ne 0 ]]; then
            error "Linux安装需要root权限，请使用 sudo 运行此脚本"
        fi
    elif [[ "$os" == "darwin" ]]; then
        # macOS需要sudo权限来安装系统服务
        if [[ $EUID -ne 0 ]]; then
            warn "macOS安装需要管理员权限"
            echo "请输入管理员密码来继续安装..."
            if ! sudo -v; then
                error "需要管理员权限才能继续安装"
            fi
        fi
    fi
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
    echo ""
}

# 验证安装
verify_installation() {
    local os=$(detect_os)
    
    info "验证安装..."
    
    sleep 3  # 等待服务启动
    
    if [[ "$os" == "linux" ]]; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "服务运行正常"
        else
            warn "服务可能未正常启动，请检查: systemctl status $SERVICE_NAME"
        fi
    elif [[ "$os" == "darwin" ]]; then
        if sudo launchctl list | grep -q "com.${APP_NAME}"; then
            log "服务运行正常"
        else
            warn "服务可能未正常启动，请检查日志"
        fi
    fi
}

# 主函数
main() {
    show_install_info
    
    local os=$(detect_os)
    
    check_permissions
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
    
    verify_installation
    
    echo ""
    log "安装完成！$APP_NAME 服务已启动并设置为开机自启动"
    echo ""
}

# 错误处理
trap 'error "安装过程中发生错误，请检查日志"' ERR

# 执行安装
main "$@"