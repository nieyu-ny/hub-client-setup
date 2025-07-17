<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本（完整修复版）
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用HTTP直接下载
    支持命令行参数和环境变量两种方式传递Token
    修复了服务创建和字符编码问题
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
    $PSDefaultParameterValues['*:Encoding'] = 'utf8'
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

# 全局错误处理
$ErrorActionPreference = "Stop"

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
    Write-Host "    $AppName Windows 一键安装程序 v2.0" -ForegroundColor Cyan
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
                
                Write-Info "启动管理员权限进程..."
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
        return $true
    } catch {
        Write-Error "无法连接到下载服务器: $testUrl, 错误: $($_.Exception.Message)"
        return $false
    }
}

# 停止并删除已存在的服务
function Remove-ExistingService {
    Write-Step "检查已存在的服务..."
    
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warn "发现已存在的服务: $ServiceName (状态: $($existingService.Status))"
        
        if (-not $Force) {
            do {
                $confirmation = Read-Host "服务已存在，是否覆盖安装？(y/N)"
                $confirmation = $confirmation.Trim().ToLower()
            } while ($confirmation -notin @('y', 'n', 'yes', 'no', ''))
            
            if ($confirmation -in @('n', 'no', '')) {
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
                
                # 等待服务完全停止
                $timeout = 30
                while ((Get-Service -Name $ServiceName).Status -eq 'Running' -and $timeout -gt 0) {
                    Start-Sleep 1
                    $timeout--
                }
            }
            
            Write-Info "删除服务..."
            # 使用多种方法尝试删除服务
            try {
                # 方法1: 使用sc.exe
                $result = & sc.exe delete $ServiceName 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "sc.exe delete failed: $result"
                }
            } catch {
                # 方法2: 使用WMI
                Write-Warn "sc.exe删除失败，尝试WMI方法..."
                $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'"
                if ($service) {
                    $service.Delete() | Out-Null
                }
            }
            
            Start-Sleep 3
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
        
        # 删除可能存在的旧文件
        if (Test-Path $binaryPath) {
            Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
        }
        
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
            throw "下载的文件大小异常（$($fileInfo.Length) 字节），可能下载失败"
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
    
    try {
        # 创建安装目录
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Info "创建安装目录: $InstallDir"
        }
        
        # 复制二进制文件
        $targetPath = Join-Path $InstallDir "$AppName.exe"
        
        # 如果目标文件存在且正在运行，先停止相关进程
        if (Test-Path $targetPath) {
            $runningProcesses = Get-Process | Where-Object { 
                try { $_.Path -eq $targetPath } catch { $false }
            } -ErrorAction SilentlyContinue
            
            if ($runningProcesses) {
                Write-Info "停止正在运行的进程..."
                $runningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep 2
            }
        }
        
        # 复制文件
        Copy-Item -Path $binaryPath -Destination $targetPath -Force
        
        # 验证复制是否成功
        if (-not (Test-Path $targetPath)) {
            throw "文件复制失败"
        }
        
        Write-Info "应用程序安装到: $targetPath"
        
        # 清理临时文件
        try {
            Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warn "清理临时文件失败: $($_.Exception.Message)"
        }
        
        return $targetPath
        
    } catch {
        Write-Error "应用程序安装失败: $($_.Exception.Message)"
    }
}

# 创建Windows服务（修复版）
function Install-WindowsService {
    param([string]$BinaryPath)
    
    Write-Step "创建Windows服务..."
    
    try {
        # 构建服务命令行
        $servicePath = "`"$BinaryPath`" -token=`"$Token`""
        Write-Info "创建服务: $ServiceName"
        Write-Info "服务路径: $servicePath"
        
        # 方法1: 使用PowerShell New-Service (推荐)
        $serviceCreated = $false
        try {
            Write-Info "使用PowerShell New-Service创建服务..."
            New-Service -Name $ServiceName -BinaryPathName $servicePath -StartupType Automatic -Description "$AppName Service"
            $serviceCreated = $true
            Write-Info "PowerShell创建服务成功"
        } catch {
            Write-Warn "PowerShell创建服务失败: $($_.Exception.Message)"
        }
        
        # 方法2: 使用sc.exe作为备选
        if (-not $serviceCreated) {
            Write-Info "尝试使用sc.exe创建服务..."
            try {
                # 使用cmd执行sc命令避免PowerShell参数解析问题
                $scCmd = "sc create `"$ServiceName`" binPath= `"$servicePath`" start= auto"
                $result = cmd /c $scCmd 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    $serviceCreated = $true
                    Write-Info "sc.exe创建服务成功"
                } else {
                    throw "sc.exe失败，退出码: $LASTEXITCODE，输出: $result"
                }
            } catch {
                Write-Warn "sc.exe创建服务失败: $($_.Exception.Message)"
            }
        }
        
        # 方法3: 使用WMI作为最后备选
        if (-not $serviceCreated) {
            Write-Info "尝试使用WMI创建服务..."
            try {
                $serviceClass = Get-WmiObject -Class Win32_Service -List
                $result = $serviceClass.Create($servicePath, $ServiceName, $ServiceName, 16, 2, "Automatic", $false, $null, $null, $null, $null, $null)
                
                if ($result.ReturnValue -eq 0) {
                    $serviceCreated = $true
                    Write-Info "WMI创建服务成功"
                } else {
                    throw "WMI创建服务失败，返回值: $($result.ReturnValue)"
                }
            } catch {
                Write-Error "WMI创建服务失败: $($_.Exception.Message)"
            }
        }
        
        if (-not $serviceCreated) {
            throw "所有方法都无法创建服务"
        }
        
        # 设置服务描述
        try {
            & sc.exe description $ServiceName "$AppName Service" 2>&1 | Out-Null
        } catch {
            Write-Warn "设置服务描述失败: $($_.Exception.Message)"
        }
        
        # 配置服务失败时的重启策略
        try {
            & sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 2>&1 | Out-Null
        } catch {
            Write-Warn "设置服务重启策略失败: $($_.Exception.Message)"
        }
        
        Write-Info "Windows服务安装完成"
        
    } catch {
        Write-Error "创建Windows服务失败: $($_.Exception.Message)"
    }
}

# 启动服务
function Start-HubAgentService {
    Write-Step "启动服务..."
    
    try {
        Start-Service -Name $ServiceName
        Start-Sleep 3
        
        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq 'Running') {
            Write-Info "服务启动成功"
            return $true
        } else {
            Write-Warn "服务状态异常: $($service.Status)"
            return $false
        }
    } catch {
        Write-Warn "服务启动失败: $($_.Exception.Message)"
        return $false
    }
}

# 验证安装
function Test-Installation {
    Write-Step "验证安装..."
    
    try {
        # 检查二进制文件
        $binaryPath = Join-Path $InstallDir "$AppName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Warn "二进制文件不存在: $binaryPath"
            return $false
        }
        
        # 检查服务
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        Write-Info "服务状态: $($service.Status)"
        Write-Info "启动类型: $($service.StartType)"
        
        if ($service.Status -eq 'Running') {
            Write-Info "✓ 服务运行正常"
            return $true
        } else {
            Write-Warn "⚠ 服务未运行，尝试启动..."
            if (Start-HubAgentService) {
                return $true
            } else {
                Write-Warn "服务启动失败"
                return $false
            }
        }
    } catch {
        Write-Warn "验证安装失败: $($_.Exception.Message)"
        return $false
    }
}

# 显示管理命令
function Show-ManagementCommands {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "    安装完成！服务管理命令" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
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
    Write-Host "  Stop-Service $ServiceName" -ForegroundColor White
    Write-Host "  sc.exe delete $ServiceName" -ForegroundColor White
    Write-Host "  Remove-Item `"$InstallDir`" -Recurse -Force" -ForegroundColor White
    Write-Host ""
}

# 主函数
function Main {
    $startTime = Get-Date
    
    try {
        Show-InstallInfo
        
        # 检查并请求管理员权限
        Request-AdminElevation
        
        # 执行安装步骤
        if (-not (Test-NetworkConnection)) {
            return
        }
        
        Remove-ExistingService
        $binaryPath = Install-Application
        Install-WindowsService -BinaryPath $binaryPath
        
        # 启动服务
        if (-not (Start-HubAgentService)) {
            Write-Warn "服务启动失败，但安装已完成。请手动检查服务配置。"
        }
        
        # 验证安装
        $installSuccess = Test-Installation
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        
        if ($installSuccess) {
            Write-Host ""
            Write-Host "🎉 安装成功完成！" -ForegroundColor Green
            Write-Host "总耗时: $([math]::Round($duration.TotalSeconds, 1)) 秒" -ForegroundColor Cyan
            Show-ManagementCommands
        } else {
            Write-Host ""
            Write-Host "⚠ 安装可能存在问题，请检查服务状态和日志" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host ""
        Write-Host "❌ 安装失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "请检查错误信息并重试，或联系技术支持。" -ForegroundColor Yellow
        exit 1
    }
}

# 执行安装
Main