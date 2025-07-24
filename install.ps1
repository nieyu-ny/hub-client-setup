<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本（任务计划程序版本 - 增强日志版）
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用任务计划程序替代Windows服务
    支持命令行参数和环境变量两种方式传递Token
    增加日志输出功能，支持自定义日志路径
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER LogPath
    日志文件路径 (可选，默认: C:\ProgramData\hub-agent\logs\hub-agent.log)
.PARAMETER Force
    强制重新安装，覆盖已存在的任务
.PARAMETER EnableVerboseLog
    启用详细日志模式
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token"
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token" -LogPath "C:\logs\hub-agent.log"
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token" -EnableVerboseLog
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\hub-agent\logs\hub-agent.log",

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [switch]$EnableVerboseLog
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
    Write-Host "  PowerShell -File install.ps1 -Token `"your_token`" -LogPath `"C:\logs\hub-agent.log`"" -ForegroundColor White
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
    Write-Host "    $AppName Windows One-Click Installer v4.0" -ForegroundColor Cyan
    Write-Host "    (Task Scheduler Version with Logging)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Info:"
    Write-Host "  Operating System: Windows"
    Write-Host "  Architecture: $arch"
    Write-Host "  Binary File: $BinaryName"
    Write-Host "  Download URL: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host "  Installation Method: Task Scheduler"
    Write-Host "  Log Path: $LogPath"
    Write-Host "  Verbose Logging: $EnableVerboseLog"
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
                if ($EnableVerboseLog) {
                    $arguments += " -EnableVerboseLog"
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

# 创建日志目录和配置
function Initialize-LoggingConfiguration {
    Write-Step "Initializing logging configuration..."

    try {
        # 创建日志目录
        if (-not (Test-Path $LogDir)) {
            New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
            Write-Info "Created log directory: $LogDir"
        }

        # 设置日志目录权限（允许应用程序写入）
        $acl = Get-Acl $LogDir
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $LogDir -AclObject $acl

        Write-Info "Log directory configured: $LogDir"
        Write-Info "Log file path: $LogPath"

        return $true
    } catch {
        Write-Error "Failed to initialize logging configuration: $($_.Exception.Message)"
        return $false
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

# 创建任务计划程序任务（带日志支持）
function Install-ScheduledTask {
    param([string]$BinaryPath)

    Write-Step "Creating scheduled task with logging support..."

    try {
        Write-Info "Configuring scheduled task: $TaskName"
        Write-Info "Executable path: $BinaryPath"
        Write-Info "Log path: $LogPath"
        Write-Info "Token: $($Token.Substring(0, 8))..."

        # 构建命令参数
        $arguments = "-token `"$Token`""

        # 添加日志参数（假设应用程序支持 -log 参数）
        $arguments += " -log `"$LogPath`""

        # 如果启用详细日志
        if ($EnableVerboseLog) {
            $arguments += " -verbose"
        }

        Write-Info "Command arguments: $arguments"

        # 创建任务触发器 - 系统启动时
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # 创建任务动作
        $action = New-ScheduledTaskAction -Execute $BinaryPath -Argument $arguments

        # 创建任务主体设置 - 以SYSTEM权限运行
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # 创建任务设置
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        # 注册任务
        Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description "$AppName Service (Managed by Task Scheduler with Logging)"

        Write-Info "Scheduled task created successfully with logging support."
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
        Start-Sleep 3

        $task = Get-ScheduledTask -TaskName $TaskName
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue

        if ($process) {
            Write-Info "Task started successfully, process is running (PID: $($process.Id))"
            return $true
        } else {
            Write-Warn "Task started but process not found"
            return $false
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

        # 检查任务
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Info "Task status: $($task.State)"

        # 检查进程
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Info "✓ Process is running normally (PID: $($process.Id))"

            # 检查日志文件是否被创建
            Start-Sleep 5  # 等待一些时间让应用程序创建日志
            if (Test-Path $LogPath) {
                Write-Info "✓ Log file created: $LogPath"
                $logSize = (Get-Item $LogPath).Length
                Write-Info "  Log file size: $logSize bytes"
            } else {
                Write-Warn "⚠ Log file not found: $LogPath"
                Write-Warn "  The application may not support the -log parameter or needs time to create the log file"
            }

            return $true
        } else {
            Write-Warn "⚠ Process is not running, attempting to start..."
            if (Start-HubAgentTask) {
                return $true
            } else {
                Write-Warn "Failed to start task"
                return $false
            }
        }
    } catch {
        Write-Warn "Installation verification failed: $($_.Exception.Message)"
        return $false
    }
}

# 显示管理命令（增强版）
function Show-ManagementCommands {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "    Installation Complete! Management Commands" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Task Management Commands:" -ForegroundColor Yellow
    Write-Host "  Check status: Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo" -ForegroundColor White
    Write-Host "  Start task: Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  Stop process: Stop-Process -Name $AppName -Force" -ForegroundColor White
    Write-Host "  Restart service: Stop-Process -Name $AppName -Force; Start-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  Disable task: Disable-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host "  Enable task: Enable-ScheduledTask -TaskName $TaskName" -ForegroundColor White
    Write-Host ""
    Write-Host "Process Management Commands:" -ForegroundColor Yellow
    Write-Host "  View process: Get-Process -Name $AppName" -ForegroundColor White
    Write-Host "  Process details: Get-Process -Name $AppName | Format-List *" -ForegroundColor White
    Write-Host ""
    Write-Host "Log Management Commands:" -ForegroundColor Yellow
    Write-Host "  View latest logs: Get-Content `"$LogPath`" -Tail 50" -ForegroundColor White
    Write-Host "  Follow logs: Get-Content `"$LogPath`" -Wait -Tail 10" -ForegroundColor White
    Write-Host "  View logs by time: Get-Content `"$LogPath`" | Select-String `"$(Get-Date -Format 'yyyy-MM-dd')`"" -ForegroundColor White
    Write-Host "  Clear logs: Clear-Content `"$LogPath`"" -ForegroundColor White
    Write-Host "  Log file info: Get-Item `"$LogPath`" | Format-List Name,Length,LastWriteTime" -ForegroundColor White
    Write-Host ""
    Write-Host "System Log Query Commands:" -ForegroundColor Yellow
    Write-Host "  Task logs: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'} -MaxEvents 10 | Where-Object {`$_.Message -match '$TaskName'}" -ForegroundColor White
    Write-Host "  System logs: Get-EventLog -LogName System -Newest 10 | Where-Object {`$_.Message -match '$AppName'}" -ForegroundColor White
    Write-Host ""
    Write-Host "Installation Info:" -ForegroundColor Yellow
    Write-Host "  Install path: $InstallDir" -ForegroundColor White
    Write-Host "  Task name: $TaskName" -ForegroundColor White
    Write-Host "  Log path: $LogPath" -ForegroundColor White
    Write-Host "  Log directory: $LogDir" -ForegroundColor White
    Write-Host "  Startup on boot: ✓ Enabled" -ForegroundColor Green
    Write-Host "  Run as: SYSTEM" -ForegroundColor White
    Write-Host "  Restart on failure: ✓ Enabled (Retry in 5 minutes, up to 3 times)" -ForegroundColor Green
    Write-Host "  Verbose logging: $EnableVerboseLog" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick Log Analysis:" -ForegroundColor Cyan
    if (Test-Path $LogPath) {
        $logInfo = Get-Item $LogPath
        Write-Host "  ✓ Log file exists" -ForegroundColor Green
        Write-Host "  Size: $([math]::Round($logInfo.Length/1KB, 2)) KB" -ForegroundColor White
        Write-Host "  Last modified: $($logInfo.LastWriteTime)" -ForegroundColor White
        Write-Host "  Recent entries:" -ForegroundColor White
        try {
            Get-Content $LogPath -Tail 3 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
        } catch {
            Write-Host "    Unable to read log content" -ForegroundColor Red
        }
    } else {
        Write-Host "  ⚠ Log file not found" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Full Uninstall Commands:" -ForegroundColor Red
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

        # Initialize logging configuration
        if (-not (Initialize-LoggingConfiguration)) {
            return
        }

        Remove-ExistingInstallation
        $binaryPath = Install-Application

        if (-not (Install-ScheduledTask -BinaryPath $binaryPath)) {
            Write-Error "Failed to create scheduled task"
            return
        }

        # Start task
        if (-not (Start-HubAgentTask)) {
            Write-Warn "Task failed to start, but installation is complete. Please manually check the task configuration."
        }

        # Verify installation
        $installSuccess = Test-Installation

        $endTime = Get-Date
        $duration = $endTime - $startTime

        if ($installSuccess) {
            Write-Host ""
            Write-Host "🎉 Installation completed successfully!" -ForegroundColor Green
            Write-Host "Total time elapsed: $([math]::Round($duration.TotalSeconds, 1)) seconds" -ForegroundColor Cyan
            Show-ManagementCommands
        } else {
            Write-Host ""
            Write-Host "⚠ There may be issues with the installation. Please check the task status and logs." -ForegroundColor Yellow
        }

    } catch {
        Write-Host ""
        Write-Host "❌ Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please check the error message and try again, or contact technical support." -ForegroundColor Yellow
        exit 1
    }
}

# 执行安装
Main