<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本（任务计划程序版本 - 终极稳定版 v3.2）
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用任务计划程序替代Windows服务
    支持命令行参数和环境变量两种方式传递Token
    使用批处理文件实现简单可靠的日志记录
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER LogPath
    日志文件路径 (可选，默认: C:\ProgramData\hub-agent\logs\hub-agent.log)
.PARAMETER Force
    强制重新安装，覆盖已存在的任务
.EXAMPLE
    $env:Token = "your_token"; iwr -useb https://url/install.ps1 | iex
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\hub-agent\logs\hub-agent.log",

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
    Write-Host "  `$env:Token = `"your_token`"; iwr -useb https://url/install.ps1 | iex" -ForegroundColor White
    exit 1
}

# 配置参数
$AppName = "hub-agent"
$BinaryBaseUrl = "https://github.com/nieyu-ny/hub-client-setup/raw/master"
$InstallDir = "C:\Program Files\$AppName"
$TaskName = "HubAgent"
$BinaryName = "hub-agent-windows.exe"

# 处理日志路径
$LogDir = Split-Path $LogPath -Parent
if (-not $LogDir) {
    $LogDir = "C:\ProgramData\hub-agent\logs"
    $LogPath = Join-Path $LogDir "hub-agent.log"
}

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
    Write-Host "    $AppName Windows Installer v3.2-Ultimate" -ForegroundColor Cyan
    Write-Host "    (Task Scheduler + Simple Logging)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Info:"
    Write-Host "  Operating System: Windows"
    Write-Host "  Architecture: $arch"
    Write-Host "  Binary File: $BinaryName"
    Write-Host "  Download URL: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host "  Installation Method: Task Scheduler + Batch Script"
    Write-Host "  Log Path: $LogPath"
    if ($Force) {
        Write-Host "  Force Reinstall: Yes"
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
        Write-Step "Non-administrator privileges detected, attempting elevation..."

        try {
            if ($MyInvocation.MyCommand.Path) {
                $scriptPath = $MyInvocation.MyCommand.Path
                $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`" -LogPath `"$LogPath`""
                if ($Force) {
                    $arguments += " -Force"
                }

                Write-Info "Launching process with administrator privileges..."
                Start-Process -FilePath "PowerShell" -ArgumentList $arguments -Verb RunAs -Wait

            } else {
                Write-Info "Script is running via pipeline; administrator privileges are required to continue installation."
                Write-Error "Please run PowerShell as Administrator and re-execute this command."
            }

            Write-Info "Execution with administrator privileges completed."
            exit 0

        } catch {
            Write-Error "Failed to acquire administrator privileges: $($_.Exception.Message)"
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
    Write-Step "Checking network connection..."

    try {
        $testUrl = "$BinaryBaseUrl/$BinaryName"
        $response = Invoke-WebRequest -Uri $testUrl -Method Head -TimeoutSec 10 -UseBasicParsing
        Write-Info "Network connection is normal."
        return $true
    } catch {
        Write-Error "Failed to connect to the download server: $testUrl, Error: $($_.Exception.Message)"
        return $false
    }
}

# 创建日志配置和启动批处理文件
function Initialize-LoggingConfiguration {
    Write-Step "Initializing logging configuration..."

    try {
        # 创建日志目录
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            Write-Info "Created log directory: $LogDir"
        }

        # 设置日志目录权限
        $acl = Get-Acl $LogDir
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $LogDir -AclObject $acl

        # 创建批处理启动脚本（简单可靠）
        $batchScript = @"
@echo off
setlocal

rem hub-agent 启动批处理脚本 v3.2-Ultimate
rem 参数：%1 = Token

set "TOKEN=%~1"
set "APP_DIR=C:\Program Files\hub-agent"
set "LOG_FILE=$LogPath"
set "BINARY=%APP_DIR%\hub-agent.exe"

rem 确保日志目录存在
if not exist "$LogDir" mkdir "$LogDir"

rem 记录启动信息
echo [%date% %time%] [INFO] ======================================= >> "%LOG_FILE%"
echo [%date% %time%] [INFO] hub-agent starting (v3.2-Ultimate)... >> "%LOG_FILE%"
echo [%date% %time%] [INFO] Token: %TOKEN:~0,8%... >> "%LOG_FILE%"
echo [%date% %time%] [INFO] Binary: %BINARY% >> "%LOG_FILE%"
echo [%date% %time%] [INFO] Log: %LOG_FILE% >> "%LOG_FILE%"

rem 检查二进制文件是否存在
if not exist "%BINARY%" (
    echo [%date% %time%] [ERROR] Binary file not found: %BINARY% >> "%LOG_FILE%"
    exit /b 1
)

rem 启动主程序
echo [%date% %time%] [INFO] Starting hub-agent process... >> "%LOG_FILE%"

rem 启动程序并重定向输出到日志
"%BINARY%" -token "%TOKEN%" >> "%LOG_FILE%" 2>&1

rem 记录退出信息
echo [%date% %time%] [WARN] Process exited with code: %ERRORLEVEL% >> "%LOG_FILE%"
"@

        $batchScriptPath = Join-Path $InstallDir "hub-agent-start.bat"
        $batchScript | Out-File -FilePath $batchScriptPath -Encoding ASCII -Force

        Write-Info "Log configuration completed."
        Write-Info "Batch startup script created: $batchScriptPath"

        return $batchScriptPath

    } catch {
        Write-Error "Failed to initialize logging configuration: $($_.Exception.Message)"
        return $null
    }
}

# 清理已存在的服务和任务
function Remove-ExistingInstallation {
    Write-Step "Cleaning up existing installation..."

    # 检查并清理Windows服务
    $existingService = Get-Service -Name $AppName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warn "Existing Windows service found: $AppName"

        if (-not $Force) {
            do {
                $confirmation = Read-Host "An existing installation was found. Overwrite? (y/N)"
                $confirmation = $confirmation.Trim().ToLower()
            } while ($confirmation -notin @('y', 'n', 'yes', 'no', ''))

            if ($confirmation -in @('n', 'no', '')) {
                Write-Info "Installation cancelled."
                exit 0
            }
        }

        try {
            if ($existingService.Status -eq 'Running') {
                Write-Info "Stopping Windows service..."
                Stop-Service -Name $AppName -Force -ErrorAction SilentlyContinue
                Start-Sleep 3
            }

            Write-Info "Deleting Windows service..."
            & sc.exe delete $AppName 2>&1 | Out-Null
            Start-Sleep 2
            Write-Info "Windows service cleaned up."
        } catch {
            Write-Warn "An error occurred while cleaning up the Windows service: $($_.Exception.Message)"
        }
    }

    # 检查并清理任务计划程序任务
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Info "Existing scheduled task found: $TaskName"
        try {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Info "Scheduled task cleaned up."
        } catch {
            Write-Warn "An error occurred while cleaning up the scheduled task: $($_.Exception.Message)"
        }
    }

    # 停止正在运行的进程
    $runningProcesses = Get-Process -Name $AppName -ErrorAction SilentlyContinue
    if ($runningProcesses) {
        Write-Info "Stopping running processes..."
        $runningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep 2
    }
}

# 下载二进制文件
function Get-Binary {
    Write-Step "Downloading binary file..."

    $downloadUrl = "$BinaryBaseUrl/$BinaryName"
    $tempDir = $env:TEMP
    $binaryPath = Join-Path $tempDir $BinaryName

    try {
        Write-Info "Downloading binary from $downloadUrl..."

        if (Test-Path $binaryPath) {
            Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
        }

        $progressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryPath -UseBasicParsing -TimeoutSec 300

        $ProgressPreference = $progressPreference

        if (-not (Test-Path $binaryPath)) {
            throw "File download failed: $BinaryName"
        }

        $fileInfo = Get-Item $binaryPath
        if ($fileInfo.Length -lt 1024) {
            throw "Downloaded file size is abnormal ($($fileInfo.Length) bytes), possibly failed."
        }

        Write-Info "Binary downloaded successfully, size: $([math]::Round($fileInfo.Length / 1024, 2))KB"
        return $binaryPath

    } catch {
        Write-Error "Download failed: $($_.Exception.Message)"
    }
}

# 安装应用程序
function Install-Application {
    $binaryPath = Get-Binary

    Write-Step "Installing application..."

    try {
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Write-Info "Created installation directory: $InstallDir"
        }

        $targetPath = Join-Path $InstallDir "$AppName.exe"

        if (Test-Path $targetPath) {
            $runningProcesses = Get-Process | Where-Object {
                try { $_.Path -eq $targetPath } catch { $false }
            } -ErrorAction SilentlyContinue

            if ($runningProcesses) {
                Write-Info "Stopping running processes..."
                $runningProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep 2
            }
        }

        Copy-Item -Path $binaryPath -Destination $targetPath -Force

        if (-not (Test-Path $targetPath)) {
            throw "File copy failed"
        }

        Write-Info "Application installed at: $targetPath"

        try {
            Remove-Item $binaryPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Warn "Failed to clean up temporary file: $($_.Exception.Message)"
        }

        return $targetPath

    } catch {
        Write-Error "Application installation failed: $($_.Exception.Message)"
    }
}

# 创建任务计划程序任务（使用批处理脚本）
function Install-ScheduledTask {
    param([string]$BinaryPath, [string]$BatchScriptPath)

    Write-Step "Creating scheduled task with batch launcher..."

    try {
        Write-Info "Configuring scheduled task: $TaskName"
        Write-Info "Batch script: $BatchScriptPath"
        Write-Info "Token: $($Token.Substring(0, 8))..."

        # 创建任务触发器 - 系统启动时
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # 创建任务动作 - 运行批处理脚本
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$BatchScriptPath`" `"$Token`""

        # 创建任务主体设置 - 以SYSTEM权限运行
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # 创建任务设置
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        # 注册任务
        Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description "$AppName Service (Task Scheduler + Batch Logging v3.2)"

        Write-Info "Scheduled task created successfully with batch logging."
        return $true

    } catch {
        Write-Error "Failed to create scheduled task: $($_.Exception.Message)"
        return $false
    }
}

# 启动任务
function Start-HubAgentTask {
    Write-Step "Starting task..."

    try {
        Start-ScheduledTask -TaskName $TaskName
        Start-Sleep 5

        $task = Get-ScheduledTask -TaskName $TaskName
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue

        if ($process) {
            Write-Info "Task started successfully, process is running (PID: $($process.Id))"
            return $true
        } else {
            Write-Warn "Task started but process not found, checking logs..."
            Start-Sleep 5
            $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
            if ($process) {
                Write-Info "Process started with delay (PID: $($process.Id))"
                return $true
            } else {
                return $false
            }
        }
    } catch {
        Write-Warn "Failed to start task: $($_.Exception.Message)"
        return $false
    }
}

# 验证安装
function Test-Installation {
    Write-Step "Verifying installation..."

    try {
        # 检查二进制文件
        $binaryPath = Join-Path $InstallDir "$AppName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Warn "Binary file does not exist: $binaryPath"
            return $false
        }

        # 检查批处理脚本
        $batchPath = Join-Path $InstallDir "hub-agent-start.bat"
        if (-not (Test-Path $batchPath)) {
            Write-Warn "Batch script does not exist: $batchPath"
            return $false
        }

        # 检查任务
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Info "Task status: $($task.State)"

        # 检查进程
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Info "✓ Process is running normally (PID: $($process.Id))"

            # 检查日志文件
            Start-Sleep 3
            if (Test-Path $LogPath) {
                $logInfo = Get-Item $LogPath
                Write-Info "✓ Log file created: $LogPath"
                Write-Info "  Log file size: $([math]::Round($logInfo.Length/1KB, 2)) KB"
                Write-Info "  Last modified: $($logInfo.LastWriteTime)"
            } else {
                Write-Warn "⚠ Log file not found: $LogPath"
            }

            return $true
        } else {
            Write-Warn "⚠ Process is not running, attempting to start..."
            if (Start-HubAgentTask) {
                return $true
            } else {
                Write-Warn "Failed to start task, checking logs for errors..."
                if (Test-Path $LogPath) {
                    Write-Host "Recent log entries:" -ForegroundColor Yellow
                    Get-Content $LogPath -Tail 10 | ForEach-Object {
                        if ($_ -match "ERROR") {
                            Write-Host "  $_" -ForegroundColor Red
                        } elseif ($_ -match "WARN") {
                            Write-Host "  $_" -ForegroundColor Yellow
                        } elseif ($_ -match "v3.2-Ultimate") {
                            Write-Host "  $_" -ForegroundColor Green
                        } else {
                            Write-Host "  $_" -ForegroundColor White
                        }
                    }
                }
                return $false
            }
        }
    } catch {
        Write-Warn "Installation verification failed: $($_.Exception.Message)"
        return $false
    }
}

# 显示管理命令
function Show-ManagementCommands {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "    ✅ 安装完成！(v3.2-Ultimate)" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 任务管理命令:" -ForegroundColor Yellow
    Write-Host "  检查状态: Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo" -ForegroundColor White
    Write-Host "  启动任务: Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  停止进程: Stop-Process -Name $AppName -Force" -ForegroundColor White
    Write-Host "  重启服务: Stop-Process -Name $AppName -Force; Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host ""
    Write-Host "📊 进程管理命令:" -ForegroundColor Yellow
    Write-Host "  查看进程: Get-Process -Name $AppName" -ForegroundColor White
    Write-Host "  进程详情: Get-Process -Name $AppName | Format-List *" -ForegroundColor White
    Write-Host ""
    Write-Host "📝 日志管理命令:" -ForegroundColor Yellow
    Write-Host "  查看日志: Get-Content `"$LogPath`" -Tail 50" -ForegroundColor White
    Write-Host "  实时日志: Get-Content `"$LogPath`" -Wait -Tail 10" -ForegroundColor White
    Write-Host "  搜索错误: Get-Content `"$LogPath`" | Select-String `"ERROR`"" -ForegroundColor White
    Write-Host "  搜索今日: Get-Content `"$LogPath`" | Select-String `"$(Get-Date -Format 'yyyy-MM-dd')`"" -ForegroundColor White
    Write-Host ""
    Write-Host "⚙️ 安装信息:" -ForegroundColor Yellow
    Write-Host "  安装路径: $InstallDir" -ForegroundColor White
    Write-Host "  启动脚本: $InstallDir\hub-agent-start.bat" -ForegroundColor White
    Write-Host "  任务名称: $TaskName" -ForegroundColor White
    Write-Host "  日志路径: $LogPath" -ForegroundColor White
    Write-Host "  开机启动: ✓ 已启用" -ForegroundColor Green
    Write-Host "  运行权限: SYSTEM" -ForegroundColor White
    Write-Host "  故障重启: ✓ 已启用 (5分钟后重试，最多3次)" -ForegroundColor Green
    Write-Host ""

    # 快速状态检查
    Write-Host "🔍 当前状态:" -ForegroundColor Cyan
    $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "  ✅ 进程运行正常 (PID: $($process.Id))" -ForegroundColor Green
    } else {
        Write-Host "  ❌ 进程未运行" -ForegroundColor Red
    }

    if (Test-Path $LogPath) {
        $logInfo = Get-Item $LogPath
        Write-Host "  📄 日志文件: $([math]::Round($logInfo.Length/1KB, 2)) KB" -ForegroundColor Green
        Write-Host "  🕒 最后更新: $($logInfo.LastWriteTime)" -ForegroundColor White

        # 显示最新几行日志
        Write-Host ""
        Write-Host "📋 最新日志:" -ForegroundColor Cyan
        try {
            Get-Content $LogPath -Tail 5 | ForEach-Object {
                if ($_ -match "ERROR") {
                    Write-Host "  $_" -ForegroundColor Red
                } elseif ($_ -match "WARN") {
                    Write-Host "  $_" -ForegroundColor Yellow
                } elseif ($_ -match "v3.2-Ultimate") {
                    Write-Host "  $_" -ForegroundColor Green
                } else {
                    Write-Host "  $_" -ForegroundColor White
                }
            }
        } catch {
            Write-Host "  无法读取日志内容" -ForegroundColor Red
        }
    } else {
        Write-Host "  📄 日志文件: 未找到" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "🗑️ 完全卸载命令:" -ForegroundColor Red
    Write-Host "  Stop-Process -Name $AppName -Force -ErrorAction SilentlyContinue" -ForegroundColor White
    Write-Host "  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false" -ForegroundColor White
    Write-Host "  Remove-Item `"$InstallDir`" -Recurse -Force" -ForegroundColor White
    Write-Host "  Remove-Item `"$LogDir`" -Recurse -Force" -ForegroundColor White
    Write-Host ""
}

# 主函数
function Main {
    $startTime = Get-Date

    try {
        Show-InstallInfo

        # Check and request administrator privileges
        Request-AdminElevation

        # Execute installation steps
        if (-not (Test-NetworkConnection)) {
            return
        }

        Remove-ExistingInstallation
        $binaryPath = Install-Application

        # 初始化日志配置并创建批处理脚本
        $batchScriptPath = Initialize-LoggingConfiguration
        if (-not $batchScriptPath) {
            Write-Error "Failed to initialize logging configuration"
            return
        }

        if (-not (Install-ScheduledTask -BinaryPath $binaryPath -BatchScriptPath $batchScriptPath)) {
            Write-Error "Failed to create scheduled task"
            return
        }

        # Start task
        if (-not (Start-HubAgentTask)) {
            Write-Warn "Task failed to start, but installation is complete. Please check the task configuration and logs."
        }

        # Verify installation
        $installSuccess = Test-Installation

        $endTime = Get-Date
        $duration = $endTime - $startTime

        if ($installSuccess) {
            Write-Host ""
            Write-Host "🎉 安装完成！" -ForegroundColor Green
            Write-Host "⏱️ 总耗时: $([math]::Round($duration.TotalSeconds, 1)) 秒" -ForegroundColor Cyan
            Show-ManagementCommands
        } else {
            Write-Host ""
            Write-Host "⚠️ 安装可能存在问题，请检查任务状态和日志。" -ForegroundColor Yellow
            if (Test-Path $LogPath) {
                Write-Host ""
                Write-Host "📋 最新日志:" -ForegroundColor Yellow
                Get-Content $LogPath -Tail 10 | ForEach-Object {
                    if ($_ -match "ERROR") {
                        Write-Host "  $_" -ForegroundColor Red
                    } elseif ($_ -match "WARN") {
                        Write-Host "  $_" -ForegroundColor Yellow
                    } elseif ($_ -match "v3.2-Ultimate") {
                        Write-Host "  $_" -ForegroundColor Green
                    } else {
                        Write-Host "  $_" -ForegroundColor White
                    }
                }
            }
        }

    } catch {
        Write-Host ""
        Write-Host "❌ 安装失败: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "💡 请检查错误信息并重试，或联系技术支持。" -ForegroundColor Yellow
        exit 1
    }
}

# 执行安装
Main