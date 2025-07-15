#!/bin/bash
# hub-agent 跨平台一键安装入口脚本
# 自动检测平台并执行相应的安装流程

set -e

# 配置参数
SCRIPT_BASE_URL="https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/main"
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
    echo "  $0 -h                             # 显示帮助"
    echo ""
    echo "示例:"
    echo "  # Linux/macOS:"
    echo "  curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/main/install.sh | bash -s -- -token=abc123"
    echo ""
    echo "  # Windows PowerShell:"
    echo "  iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/main/install.ps1 | iex -Token abc123"
    echo ""
}

# 解析参数
TOKEN=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -token=*) TOKEN="${1#*=}"; shift ;;
        --token=*) TOKEN="${1#*=}"; shift ;;
        -t) TOKEN="$2"; shift 2 ;;
        --token) TOKEN="$2"; shift 2 ;;
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
    
    # 检查git（安装脚本会处理git安装）
    info "检查系统要求..."
}

# Unix平台安装（Linux/macOS/WSL）
install_unix() {
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    
    info "检测到 $os 平台，使用Unix安装脚本..."
    
    # 下载并执行Unix安装脚本
    local script_url="${SCRIPT_BASE_URL}/install-unix.sh"
    
    if command -v curl &> /dev/null; then
        curl -fsSL "$script_url" | bash -s -- -token="$TOKEN"
    elif command -v wget &> /dev/null; then
        wget -qO- "$script_url" | bash -s -- -token="$TOKEN"
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
    
    # 构建PowerShell命令
    local ps_command="iwr -useb '$ps_script_url' | iex"
    
    info "执行PowerShell安装命令..."
    echo "命令: $ps_cmd -ExecutionPolicy Bypass -Command \"$ps_command\" -Token \"${TOKEN:0:8}...\""
    
    # 执行PowerShell安装
    "$ps_cmd" -ExecutionPolicy Bypass -Command "$ps_command" -Token "$TOKEN"
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
    echo ""
    
    case $os in
        linux) echo "  将使用Linux安装脚本" ;;
        darwin) echo "  将使用macOS安装脚本" ;;
        windows) echo "  将使用Windows PowerShell安装脚本" ;;
        wsl) echo "  WSL环境，将使用Linux安装脚本" ;;
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
            ;;
        darwin)
            echo "macOS 服务管理命令:"
            echo "  sudo launchctl start com.$APP_NAME    # 启动服务"
            echo "  sudo launchctl stop com.$APP_NAME     # 停止服务"
            echo "  tail -f /var/log/$APP_NAME.log        # 查看日志"
            ;;
        windows)
            echo "Windows 服务管理命令:"
            echo "  Start-Service $APP_NAME        # 启动服务"
            echo "  Stop-Service $APP_NAME         # 停止服务"
            echo "  Restart-Service $APP_NAME      # 重启服务"
            echo "  Get-Service $APP_NAME          # 查看状态"
            ;;
    esac
    
    echo ""
    log "$APP_NAME 已成功安装并设置为开机自启动！"
}

# 主函数
main() {
    show_platform_info
    
    local platform=$(detect_platform)
    local os=$(echo $platform | cut -d'-' -f1)
    
    check_requirements
    
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