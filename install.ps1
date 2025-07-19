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
    Write-Host "    $AppName Windows One-Click Installer v3.0" -ForegroundColor Cyan
    Write-Host "    (Task Scheduler Version)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Info:"
    Write-Host "  Operating System: Windows"
    Write-Host "  Architecture: $arch"
    Write-Host "  Binary File: $BinaryName"
    Write-Host "  Download URL: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host "  Installation Method: Task Scheduler"
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
                $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`""
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

# 创建任务计划程序任务
function Install-ScheduledTask {
    param([string]$BinaryPath)

    Write-Step "Creating scheduled task..."

    try {
        Write-Info "Configuring scheduled task: $TaskName"
        Write-Info "Executable path: $BinaryPath"
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

        Write-Info "Scheduled task created successfully."
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

# 显示管理命令
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
    Write-Host "Log Query Commands:" -ForegroundColor Yellow
    Write-Host "  Task logs: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'} -MaxEvents 10 | Where-Object {`$_.Message -match '$TaskName'}" -ForegroundColor White
    Write-Host "  System logs: Get-EventLog -LogName System -Newest 10 | Where-Object {`$_.Message -match '$AppName'}" -ForegroundColor White
    Write-Host ""
    Write-Host "Installation Info:" -ForegroundColor Yellow
    Write-Host "  Install path: $InstallDir" -ForegroundColor White
    Write-Host "  Task name: $TaskName" -ForegroundColor White
    Write-Host "  Startup on boot: ✓ Enabled" -ForegroundColor Green
    Write-Host "  Run as: SYSTEM" -ForegroundColor White
    Write-Host "  Restart on failure: ✓ Enabled (Retry in 5 minutes, up to 3 times)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Full Uninstall Commands:" -ForegroundColor Red
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

        # Check and request administrator privileges
        Request-AdminElevation

        # Execute installation steps
        if (-not (Test-NetworkConnection)) {
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