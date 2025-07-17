<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本（任务计划程序版本）
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用任务计划程序替代Windows服务
    支持命令行参数和环境变量两种方式传递Token
    解决了服务启动超时问题
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER Force
    强制重新安装，覆盖已存在的任务
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
$TaskName = "HubAgent"
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
    Write-Host "    $AppName Windows 一键安装程序 v3.0" -ForegroundColor Cyan
    Write-Host "    (任务计划程序版本)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "安装信息:"
    Write-Host "  操作系统: Windows"
    Write-Host "  架构: $arch"
    Write-Host "  二进制文件: $BinaryName"
    Write-Host "  下载地址: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host "  安装方式: 任务计划程序"
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
                $scriptPath = $MyInvocation.MyCommand.Path
                $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`""
                if ($Force) {
                    $arguments += " -Force"
                }
                
                Write-Info "启动管理员权限进程..."
                Start-Process -FilePath "PowerShell" -ArgumentList $arguments -Verb RunAs -Wait
                
            } else {
                Write-Info "脚本通过管道执行，需要管理员权限才能继续安装"
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
        default { return "amd64" }
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

# 清理已存在的服务和任务
function Remove-ExistingInstallation {
    Write-Step "清理已存在的安装..."
    
    # 检查并清理Windows服务
    $existingService = Get-Service -Name $AppName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warn "发现已存在的Windows服务: $AppName"
        
        if (-not $Force) {
            do {
                $confirmation = Read-Host "发现旧版本安装，是否覆盖安装？(y/N)"
                $confirmation = $confirmation.Trim().ToLower()
            } while ($confirmation -notin @('y', 'n', 'yes', 'no', ''))
            
            if ($confirmation -in @('n', 'no', '')) {
                Write-Info "安装已取消"
                exit 0
            }
        }
        
        try {
            if ($existingService.Status -eq 'Running') {
                Write-Info "停止Windows服务..."
                Stop-Service -Name $AppName -Force -ErrorAction SilentlyContinue
                Start-Sleep 3
            }
            
            Write-Info "删除Windows服务..."
            & sc.exe delete $AppName 2>&1 | Out-Null
            Start-Sleep 2
            Write-Info "已清理Windows服务"
        } catch {
            Write-Warn "清理Windows服务时出现问题: $($_.Exception.Message)"
        }
    }
    
    # 检查并清理任务计划程序任务
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Info "发现已存在的任务计划: $TaskName"
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Info "已清理任务计划"
        } catch {
            Write-Warn "清理任务计划时出现问题: $($_.Exception.Message)"
        }
    }
    
    # 停止正在运行的进程
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
        
        if (Test-Path $binaryPath) {
            Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
        }
        
        $progressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        
        Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing -TimeoutSec 300
        
        $ProgressPreference = $progressPreference
        
        if (-not (Test-Path $binaryPath)) {
            throw "文件下载失败: $BinaryName"
        }
        
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
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Info "创建安装目录: $InstallDir"
        }
        
        $targetPath = Join-Path $InstallDir "$AppName.exe"
        
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
        
        Copy-Item -Path $binaryPath -Destination $targetPath -Force
        
        if (-not (Test-Path $targetPath)) {
            throw "文件复制失败"
        }
        
        Write-Info "应用程序安装到: $targetPath"
        
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

# 创建任务计划程序任务
function Install-ScheduledTask {
    param([string]$BinaryPath)
    
    Write-Step "创建任务计划程序任务..."
    
    try {
        Write-Info "配置任务计划: $TaskName"
        Write-Info "程序路径: $BinaryPath"
        Write-Info "Token: $($Token.Substring(0, 8))..."
        
        # 创建任务触发器 - 系统启动时
        $trigger = New-ScheduledTaskTrigger -AtStartup
        
        # 创建任务动作
        $action = New-ScheduledTaskAction -Execute $BinaryPath -Argument "-token `"$Token`""
        
        # 创建任务主体设置 - 以SYSTEM权限运行
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # 创建任务设置
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
        
        # 注册任务
        Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description "$AppName Service (Managed by Task Scheduler)"
        
        Write-Info "任务计划创建成功"
        return $true
        
    } catch {
        Write-Error "创建任务计划失败: $($_.Exception.Message)"
        return $false
    }
}

# 启动任务
function Start-HubAgentTask {
    Write-Step "启动任务..."
    
    try {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep 3
        
        $task = Get-ScheduledTask -TaskName $TaskName
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
        
        if ($process) {
            Write-Info "任务启动成功，进程正在运行 (PID: $($process.Id))"
            return $true
        } else {
            Write-Warn "任务已启动但进程未找到"
            return $false
        }
    } catch {
        Write-Warn "任务启动失败: $($_.Exception.Message)"
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
        
        # 检查任务
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Info "任务状态: $($task.State)"
        
        # 检查进程
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Info "✓ 进程运行正常 (PID: $($process.Id))"
            return $true
        } else {
            Write-Warn "⚠ 进程未运行，尝试启动..."
            if (Start-HubAgentTask) {
                return $true
            } else {
                Write-Warn "任务启动失败"
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
    Write-Host "    安装完成！管理命令" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "任务管理命令:" -ForegroundColor Yellow
    Write-Host "  查看状态: Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo" -ForegroundColor White
    Write-Host "  启动任务: Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  停止进程: Stop-Process -Name $AppName -Force" -ForegroundColor White
    Write-Host "  重启服务: Stop-Process -Name $AppName -Force; Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  禁用任务: Disable-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  启用任务: Enable-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host ""
    Write-Host "进程管理命令:" -ForegroundColor Yellow
    Write-Host "  查看进程: Get-Process -Name $AppName" -ForegroundColor White
    Write-Host "  进程详情: Get-Process -Name $AppName | Format-List *" -ForegroundColor White
    Write-Host ""
    Write-Host "日志查询命令:" -ForegroundColor Yellow
    Write-Host "  任务日志: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'} -MaxEvents 10 | Where-Object {`$_.Message -match '$TaskName'}" -ForegroundColor White
    Write-Host "  系统日志: Get-EventLog -LogName System -Newest 10 | Where-Object {`$_.Message -match '$AppName'}" -ForegroundColor White
    Write-Host ""
    Write-Host "安装配置:" -ForegroundColor Yellow
    Write-Host "  安装路径: $InstallDir" -ForegroundColor White
    Write-Host "  任务名称: $TaskName" -ForegroundColor White
    Write-Host "  开机启动: ✓ 已启用" -ForegroundColor Green
    Write-Host "  运行权限: SYSTEM" -ForegroundColor White
    Write-Host "  故障重启: ✓ 已启用 (5分钟后重试，最多3次)" -ForegroundColor Green
    Write-Host ""
    Write-Host "完全卸载命令:" -ForegroundColor Red
    Write-Host "  Stop-Process -Name $AppName -Force -ErrorAction SilentlyContinue" -ForegroundColor White
    Write-Host "  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false" -ForegroundColor White
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
        
        Remove-ExistingInstallation
        $binaryPath = Install-Application
        
        if (-not (Install-ScheduledTask -BinaryPath $binaryPath)) {
            Write-Error "任务计划创建失败"
            return
        }
        
        # 启动任务
        if (-not (Start-HubAgentTask)) {
            Write-Warn "任务启动失败，但安装已完成。请手动检查任务配置。"
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
            Write-Host "⚠ 安装可能存在问题，请检查任务状态和日志" -ForegroundColor Yellow
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