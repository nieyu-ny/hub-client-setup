<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用HTTP直接下载
    支持命令行参数和环境变量两种方式传递Token
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER Force
    强制重新安装，覆盖已存在的服务
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token"
.EXAMPLE
    $env:Token = "your_token"; PowerShell -ExecutionPolicy Bypass -File install.ps1
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token" -Force
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# 设置控制台编码为UTF-8
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    # 设置当前进程的编码
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
} catch {
    # 如果设置编码失败，继续执行
}

# 如果没有通过参数提供Token，尝试从环境变量获取
if ([string]::IsNullOrEmpty($Token)) {
    $Token = $env:Token
}

# 验证Token是否存在
if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "[ERROR] Token参数是必需的。请通过 -Token 参数或 `$env:Token 环境变量提供。" -ForegroundColor Red
    Write-Host "用法示例:" -ForegroundColor Yellow
    Write-Host "  PowerShell -File install.ps1 -Token `"your_token`"" -ForegroundColor White
    Write-Host "  或者:" -ForegroundColor Yellow
    Write-Host "  `$env:Token = `"your_token`"; PowerShell -File install.ps1" -ForegroundColor White
    exit 1
}

# 配置参数
$AppName = "hub-agent"
$BinaryBaseUrl = "https://github.com/nieyu-ny/hub-client-setup/raw/master"
$InstallDir = "C:\Program Files\$AppName"
$ServiceName = $AppName
$BinaryName = "hub-agent-windows.exe"

# 颜色输出函数
function Write-ColorOutput {
    param([string]$Message, [string]$Color = "Green")
    Write-Host $Message -ForegroundColor $Color
}

function Write-Info { Write-ColorOutput "[INFO] $args" "Green" }
function Write-Warn { Write-ColorOutput "[WARN] $args" "Yellow" }
function Write-Error { Write-ColorOutput "[ERROR] $args" "Red"; exit 1 }
function Write-Step { Write-ColorOutput "[STEP] $args" "Cyan" }

# 显示安装信息
function Show-InstallInfo {
    $arch = Get-Architecture
    
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    $AppName Windows 一键安装程序" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "安装信息:"
    Write-Host "  操作系统: Windows"
    Write-Host "  架构: $arch"
    Write-Host "  二进制文件: $BinaryName"
    Write-Host "  下载地址: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    if ($Force) {
        Write-Host "  强制重装: 是"
    }
    Write-Host ""
}

# 检查管理员权限
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 自动提权重新执行脚本
function Request-AdminElevation {
    if (-not (Test-AdminRights)) {
        Write-Step "检测到非管理员权限，尝试自动提权..."
        
        try {
            if ($MyInvocation.MyCommand.Path) {
                # 本地文件执行
                $scriptPath = $MyInvocation.MyCommand.Path
                $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`""
                if ($Force) {
                    $arguments += " -Force"
                }
                
                Start-Process -FilePath "PowerShell" -ArgumentList $arguments -Verb RunAs -Wait
                
            } else {
                # 通过管道执行时的处理
                Write-Info "脚本通过管道执行，需要管理员权限才能继续安装服务"
                Write-Error "请以管理员身份运行PowerShell后重新执行此命令"
            }
            
            Write-Info "管理员权限执行完成"
            exit 0
            
        } catch {
            Write-Error "无法获取管理员权限: $($_.Exception.Message)"
        }
    }
}

# 检测架构
function Get-Architecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { return "amd64" }  # 默认值
    }
}

# 检查网络连接
function Test-NetworkConnection {
    Write-Step "检查网络连接..."
    
    try {
        $testUrl = "$BinaryBaseUrl/$BinaryName"
        $response = Invoke-WebRequest -Uri $testUrl -Method Head -TimeoutSec 10 -UseBasicParsing
        Write-Info "网络连接正常"
    } catch {
        Write-Error "无法连接到下载服务器: $testUrl, 错误: $($_.Exception.Message)"
    }
}

# 停止并删除已存在的服务
function Remove-ExistingService {
    Write-Step "检查已存在的服务..."
    
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warn "发现已存在的服务: $ServiceName"
        
        if (-not $Force) {
            $confirmation = Read-Host "服务已存在，是否覆盖安装？(y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Info "安装已取消"
                exit 0
            }
        }
        
        Write-Info "停止并移除已存在的服务..."
        
        try {
            if ($existingService.Status -eq 'Running') {
                Write-Info "停止服务..."
                Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
                Start-Sleep 3
            }
            
            Write-Info "删除服务..."
            $result = & sc.exe delete $ServiceName 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Warn "删除服务时出现警告: $result"
            }
            Start-Sleep 2
            
            Write-Info "已清理旧服务"
            
        } catch {
            Write-Warn "清理旧服务时出现问题: $($_.Exception.Message)"
        }
    }
    
    # 检查并停止正在运行的进程
    $runningProcesses = Get-Process -Name $AppName -ErrorAction SilentlyContinue
    if ($runningProcesses) {
        Write-Info "停止正在运行的进程..."
        $runningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
    }
}

# 下载二进制文件
function Get-Binary {
    Write-Step "下载二进制文件..."
    
    $downloadUrl = "$BinaryBaseUrl/$BinaryName"
    $tempDir = $env:TEMP
    $binaryPath = Join-Path $tempDir $BinaryName
    
    try {
        Write-Info "从 $downloadUrl 下载二进制文件..."
        
        # 使用 Invoke-WebRequest 下载文件
        $progressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'  # 禁用进度条以提高性能
        
        Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing -TimeoutSec 300
        
        $ProgressPreference = $progressPreference  # 恢复进度条设置
        
        # 验证文件是否下载成功
        if (-not (Test-Path $binaryPath)) {
            throw "文件下载失败: $BinaryName"
        }
        
        # 验证文件大小
        $fileInfo = Get-Item $binaryPath
        if ($fileInfo.Length -lt 1024) {
            throw "下载的文件大小异常，可能下载失败"
        }
        
        Write-Info "二进制文件下载完成，大小: $([math]::Round($fileInfo.Length / 1024, 2))KB"
        return $binaryPath
        
    } catch {
        Write-Error "下载失败: $($_.Exception.Message)"
    }
}

# 安装应用程序
function Install-Application {
    $binaryPath = Get-Binary
    
    Write-Step "安装应用程序..."
    
    # 创建安装目录
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    
    # 复制二进制文件
    $targetPath = Join-Path $InstallDir "$AppName.exe"
    
    # 如果目标文件存在且正在运行，先停止相关进程
    if (Test-Path $targetPath) {
        $runningProcesses = Get-Process | Where-Object { $_.Path -eq $targetPath } -ErrorAction SilentlyContinue
        if ($runningProcesses) {
            Write-Info "停止正在运行的进程..."
            $runningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep 2
        }
    }
    
    Copy-Item -Path $binaryPath -Destination $targetPath -Force
    
    Write-Info "应用程序安装到: $targetPath"
    
    # 清理临时文件
    try {
        Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "清理临时文件失败: $($_.Exception.Message)"
    }
    
    return $targetPath
}

# 创建Windows服务
function Install-WindowsService {
    param([string]$BinaryPath)
    
    Write-Step "创建Windows服务..."
    
    # 服务路径（包含参数）
    $servicePath = "`"$BinaryPath`" -token=$Token"
    
    # 创建新服务 - 修复参数格式
    Write-Info "创建服务: $ServiceName"
    $result = & sc.exe create $ServiceName binPath= $servicePath start= auto 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "服务创建失败，错误代码: $LASTEXITCODE，详细信息: $result"
    }
    
    # 设置服务描述
    & sc.exe description $ServiceName "$AppName Service" | Out-Null
    
    # 配置服务失败时的重启策略
    & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    
    # 启动服务
    Write-Info "启动服务..."
    try {
        Start-Service -Name $ServiceName
        Write-Info "服务启动成功"
    } catch {
        Write-Warn "服务启动失败: $($_.Exception.Message)"
        Write-Info "请检查服务配置和日志"
    }
    
    Write-Info "Windows服务安装完成"
}

# 验证安装
function Test-Installation {
    Write-Step "验证安装..."
    
    Start-Sleep 5
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            Write-Info "服务运行正常"
            return $true
        } else {
            Write-Warn "服务状态: $($service.Status)"
            
            # 尝试重新启动服务
            Write-Info "尝试重新启动服务..."
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
            Start-Sleep 3
            
            $service = Get-Service -Name $ServiceName
            if ($service.Status -eq 'Running') {
                Write-Info "服务重启成功"
                return $true
            } else {
                Write-Warn "服务重启失败，状态: $($service.Status)"
                return $false
            }
        }
    } catch {
        Write-Warn "无法获取服务状态: $($_.Exception.Message)"
        return $false
    }
}

# 显示管理命令
function Show-ManagementCommands {
    Write-Host ""
    Write-Host "服务管理命令:" -ForegroundColor Yellow
    Write-Host "  启动服务: Start-Service $ServiceName" -ForegroundColor White
    Write-Host "  停止服务: Stop-Service $ServiceName" -ForegroundColor White
    Write-Host "  重启服务: Restart-Service $ServiceName" -ForegroundColor White
    Write-Host "  查看状态: Get-Service $ServiceName" -ForegroundColor White
    Write-Host "  查看日志: Get-EventLog -LogName Application -Source $AppName -Newest 10" -ForegroundColor White
    Write-Host ""
    Write-Host "服务配置:" -ForegroundColor Yellow
    Write-Host "  安装路径: $InstallDir" -ForegroundColor White
    Write-Host "  服务名称: $ServiceName" -ForegroundColor White
    Write-Host "  开机启动: 已启用" -ForegroundColor White
    Write-Host ""
    Write-Host "卸载命令:" -ForegroundColor Yellow
    Write-Host "  sc.exe delete $ServiceName" -ForegroundColor White
    Write-Host "  Remove-Item `"$InstallDir`" -Recurse -Force" -ForegroundColor White
    Write-Host ""
}

# 主函数
function Main {
    try {
        Show-InstallInfo
        
        # 检查并请求管理员权限
        Request-AdminElevation
        
        Test-NetworkConnection
        Remove-ExistingService
        $binaryPath = Install-Application
        Install-WindowsService -BinaryPath $binaryPath
        
        if (Test-Installation) {
            Write-Info "安装完成！$AppName 服务已启动并设置为开机自启动"
        } else {
            Write-Warn "安装可能存在问题，请检查服务状态"
        }
        
        Show-ManagementCommands
        
    } catch {
        Write-Error "安装失败: $($_.Exception.Message)"
    }
}

# 执行安装
Main