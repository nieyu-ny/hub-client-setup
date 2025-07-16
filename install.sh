#!/bin/bash
# hub-agent 跨平台一键安装入口脚本
# 自动检测平台并执行相应的安装流程

set -e

# 配置参数
SCRIPT_BASE_URL="https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master"
BINARY_BASE_URL="https://github.com/nieyu-ny/hub-client-setup/raw/master"
APP_NAME="hub-agent"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[STEP]${NC} $1"; }
header() { echo -e "${PURPLE}$1${NC}"; }

# 显示帮助信息
show_help() {
    echo "hub-agent 跨平台一键安装程序"
    echo ""
    echo "用法:"
    echo "  $0 -token=YOUR_TOKEN              # 使用token安装"
    echo "  $0 --token YOUR_TOKEN             # 使用token安装"
    echo "  $0 --force                        # 强制重新安装"
    echo "  $0 -h                             # 显示帮助"
    echo ""
    echo "示例:"
    echo "  # Linux/macOS (自动提权):"
    echo "  curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.sh | bash -s -- -token=abc123"
    echo ""
    echo "  # Windows PowerShell (需管理员权限):"
    echo "  iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.ps1 | iex -Token abc123"
    echo ""
    echo "  # 强制重新安装:"
    echo "  bash install.sh -token=abc123 --force"
    echo ""
}

# 解析参数
TOKEN=""
FORCE_REINSTALL=false
EXTRA_ARGS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -token=*) TOKEN="${1#*=}"; shift ;;
        --token=*) TOKEN="${1#*=}"; shift ;;
        -t) TOKEN="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
        --force) FORCE_REINSTALL=true; EXTRA_ARGS="$EXTRA_ARGS --force"; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) error "未知参数: $1\n$(show_help)" ;;
    esac
done

if [[ -z "$TOKEN" ]]; then
    echo ""
    show_help
    error "请提供token参数"
fi

# 检测平台
detect_platform() {
    local os=""
    local arch=""
    
    # 检测操作系统
    case "$OSTYPE" in
        linux-gnu*) os="linux" ;;
        darwin*) os="darwin" ;;
        msys*|cygwin*|win32*) os="windows" ;;
        *) 
            # 尝试其他方法检测
            if [[ -f /proc/version ]] && grep -q Microsoft /proc/version; then
                os="wsl"
            elif [[ -f /proc/version ]]; then
                os="linux"
            else
                error "无法检测操作系统类型"
            fi
            ;;
    esac
    
    # 检测架构
    case $(uname -m 2>/dev/null || echo "unknown") in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        i386|i686) arch="386" ;;
        *) arch="amd64" ;; # 默认值
    esac
    
    echo "${os}-${arch}"
}

# 检查必要工具
check_requirements() {
    local os=$(echo $(detect_platform) | cut -d'-' -f1)
    
    if [[ "$os" == "windows" ]]; then
        return 0  # Windows会在PowerShell脚本中处理
    fi
    
    # 检查curl或wget
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        error "需要 curl 或 wget 来下载安装脚本"
    fi
    
    info "检查系统要求..."
}

# 检查权限提示
check_permission_hint() {
    local os=$(echo $(detect_platform) | cut -d'-' -f1)
    
    if [[ "$os" == "linux" || "$os" == "wsl" || "$os" == "darwin" ]]; then
        if [[ $EUID -ne 0 ]]; then
            info "注意: 安装过程将自动请求管理员权限"
            if [[ "$os" == "linux" || "$os" == "wsl" ]]; then
                info "如果系统提示，请输入sudo密码"
            elif [[ "$os" == "darwin" ]]; then
                info "如果系统提示，请输入管理员密码"
            fi
            echo ""
        fi
    fi
}

# Unix平台安装（Linux/macOS/WSL）
install_unix() {
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    
    info "检测到 $os 平台，使用Unix安装脚本..."
    
    # 构建参数
    local install_args="-token=$TOKEN"
    if [[ "$FORCE_REINSTALL" == true ]]; then
        install_args="$install_args --force"
    fi
    
    # 下载并执行Unix安装脚本
    local script_url="${SCRIPT_BASE_URL}/install-unix.sh"
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$script_url" | bash -s -- $install_args
    elif command -v wget &> /dev/null; then
        wget -qO- "$script_url" | bash -s -- $install_args
    else
        error "需要 curl 或 wget 来下载安装脚本"
    fi
}

# Windows平台安装
install_windows() {
    info "检测到Windows平台，启动PowerShell安装..."
    
    # 检查PowerShell
    local ps_cmd=""
    if command -v pwsh &> /dev/null; then
        ps_cmd="pwsh"
    elif command -v powershell &> /dev/null; then
        ps_cmd="powershell"
    else
        error "需要PowerShell来安装Windows版本"
    fi
    
    # PowerShell脚本URL
    local ps_script_url="${SCRIPT_BASE_URL}/install.ps1"
    
    # 构建PowerShell命令参数
    local ps_params="-Token \"$TOKEN\""
    if [[ "$FORCE_REINSTALL" == true ]]; then
        ps_params="$ps_params -Force"
    fi
    
    # 构建PowerShell命令
    local ps_command="iwr -useb '$ps_script_url' | iex"
    
    info "执行PowerShell安装命令..."
    echo "命令: $ps_cmd -ExecutionPolicy Bypass -Command \"$ps_command\" $ps_params"
    
    # 执行PowerShell安装
    "$ps_cmd" -ExecutionPolicy Bypass -Command "$ps_command" $ps_params
}

# 显示平台信息
show_platform_info() {
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    local arch=$(echo $platform | cut -d'-' -f2)
    
    header "==============================================="
    header "    $APP_NAME 跨平台一键安装程序"
    header "==============================================="
    echo ""
    
    info "平台检测结果:"
    echo "  操作系统: $os"
    echo "  架构: $arch"
    echo "  Token: ${TOKEN:0:8}..."
    if [[ "$FORCE_REINSTALL" == true ]]; then
        echo "  强制重装: 是"
    fi
    echo ""
    
    case $os in
        linux) echo "  将使用Linux安装脚本 (自动sudo提权)" ;;
        darwin) echo "  将使用macOS安装脚本 (自动sudo提权)" ;;
        windows) echo "  将使用Windows PowerShell安装脚本 (需要管理员权限)" ;;
        wsl) echo "  WSL环境，将使用Linux安装脚本 (自动sudo提权)" ;;
    esac
    echo ""
}

# 安装后信息
show_post_install_info() {
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    
    echo ""
    header "==============================================="
    header "    安装完成"
    header "==============================================="
    echo ""
    
    case $os in
        linux|wsl)
            echo "Linux 服务管理命令:"
            echo "  systemctl start $APP_NAME     # 启动服务"
            echo "  systemctl stop $APP_NAME      # 停止服务"
            echo "  systemctl restart $APP_NAME   # 重启服务"
            echo "  systemctl status $APP_NAME    # 查看状态"
            echo "  journalctl -u $APP_NAME -f    # 查看日志"
            echo ""
            echo "重新安装命令:"
            echo "  curl -fsSL $SCRIPT_BASE_URL/install.sh | bash -s -- -token=$TOKEN --force"
            ;;
        darwin)
            echo "macOS 服务管理命令:"
            echo "  sudo launchctl start com.$APP_NAME    # 启动服务"
            echo "  sudo launchctl stop com.$APP_NAME     # 停止服务"
            echo "  tail -f /var/log/$APP_NAME.log        # 查看日志"
            echo ""
            echo "重新安装命令:"
            echo "  curl -fsSL $SCRIPT_BASE_URL/install.sh | bash -s -- -token=$TOKEN --force"
            ;;
        windows)
            echo "Windows 服务管理命令:"
            echo "  Start-Service $APP_NAME        # 启动服务"
            echo "  Stop-Service $APP_NAME         # 停止服务"
            echo "  Restart-Service $APP_NAME      # 重启服务"
            echo "  Get-Service $APP_NAME          # 查看状态"
            echo ""
            echo "重新安装命令:"
            echo "  iwr -useb $SCRIPT_BASE_URL/install.ps1 | iex -Token \"$TOKEN\" -Force"
            ;;
    esac
    
    echo ""
    log "$APP_NAME 已成功安装并设置为开机自启动！"
    echo ""
    warn "注意: 如需卸载，请查看对应平台的服务管理命令"
}

# 检查网络连接
check_network() {
    info "检查网络连接..."
    
    if command -v curl &> /dev/null; then
        if ! curl -fsSL --connect-timeout 10 "$SCRIPT_BASE_URL/install-unix.sh" > /dev/null 2>&1; then
            error "无法连接到下载服务器，请检查网络连接"
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q --timeout=10 --spider "$SCRIPT_BASE_URL/install-unix.sh" 2>/dev/null; then
            error "无法连接到下载服务器，请检查网络连接"
        fi
    fi
}

# 主函数
main() {
    show_platform_info
    
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    
    check_requirements
    check_network
    check_permission_hint
    
    case $os in
        linux|wsl)
            install_unix
            ;;
        darwin)
            install_unix
            ;;
        windows)
            install_windows
            ;;
        *)
            error "不支持的平台: $os"
            ;;
    esac
    
    show_post_install_info
}

# 错误处理
trap 'error "安装过程中发生错误"' ERR

# 执行安装
main "$@"