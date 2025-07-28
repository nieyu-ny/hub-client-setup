<#
.SYNOPSIS
    hub-agent Windows平台多权限级别一键安装脚本
.DESCRIPTION
    支持管理员权限（系统级安装）和普通用户权限（用户级安装）两种模式
    自动检测权限级别并选择合适的安装方式
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER LogPath
    日志文件路径 (可选，根据权限级别自动选择默认路径)
.PARAMETER Force
    强制重新安装，覆盖已存在的任务
.PARAMETER UserMode
    强制使用用户模式安装（即使有管理员权限）
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token"
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token" -UserMode
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$LogPath,

    [Parameter(Mandatory=$false)]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [switch]$UserMode
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

# 检查管理员权限
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 获取安装配置（根据权限级别）
function Get-InstallConfig {
    $isAdmin = Test-AdminRights
    $useUserMode = $UserMode -or -not $isAdmin

    if ($useUserMode) {
        # 用户模式配置
        $config = @{
            Mode = "User"
            InstallDir = "$env:LOCALAPPDATA\Programs\$AppName"
            TaskName = "HubAgent-User"
            LogDir = "$env:LOCALAPPDATA\$AppName\logs"
            TaskPath = "\"
            Principal = $env:USERNAME
            RunLevel = "Limited"
            Description = "$AppName Service (User Mode)"
        }
    } else {
        # 系统模式配置
        $config = @{
            Mode = "System"
            InstallDir = "C:\Program Files\$AppName"
            TaskName = "HubAgent-System"
            LogDir = "C:\ProgramData\$AppName\logs"
            TaskPath = "\Microsoft\Windows\"
            Principal = "SYSTEM"
            RunLevel = "Highest"
            Description = "$AppName Service (System Mode)"
        }
    }

    # 设置日志路径
    if ([string]::IsNullOrEmpty($LogPath)) {
        $config.LogPath = Join-Path $config.LogDir "hub-agent.log"
    } else {
        $config.LogPath = $LogPath
        $config.LogDir = Split-Path $LogPath -Parent
    }

    return $config
}

# 显示安装信息
function Show-InstallInfo {
    param($Config)

    $arch = Get-Architecture

    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    $AppName Multi-Privilege Installer v4.0" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Info:"
    Write-Host "  Operating System: Windows"
    Write-Host "  Architecture: $arch"
    Write-Host "  Install Mode: $($Config.Mode)"
    Write-Host "  Current User: $env:USERNAME"
    Write-Host "  Admin Rights: $(if (Test-AdminRights) { 'Yes' } else { 'No' })"
    Write-Host "  Binary File: $BinaryName"
    Write-Host "  Install Dir: $($Config.InstallDir)"
    Write-Host "  Task Name: $($Config.TaskName)"
    Write-Host "  Run As: $($Config.Principal)"
    Write-Host "  Log Path: $($Config.LogPath)"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    if ($Force) {
        Write-Host "  Force Reinstall: Yes"
    }
    Write-Host ""
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

# 初始化日志配置
function Initialize-LoggingConfiguration {
    param($Config)

    Write-Step "Initializing logging configuration..."

    try {
        # 创建日志目录
        if (-not (Test-Path $Config.LogDir)) {
            New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null
            Write-Info "Created log directory: $($Config.LogDir)"
        }

        # 设置日志目录权限（仅在用户模式下或有权限时）
        if ($Config.Mode -eq "User" -or (Test-AdminRights)) {
            try {
                $acl = Get-Acl $Config.LogDir
                if ($Config.Mode -eq "System") {
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                } else {
                    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                }
                $acl.SetAccessRule($accessRule)
                Set-Acl -Path $Config.LogDir -AclObject $acl
            } catch {
                Write-Warn "Failed to set directory permissions: $($_.Exception.Message)"
            }
        }

        # 写入初始日志信息
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $initLog = @"
[$timestamp] [INFO] =======================================
[$timestamp] [INFO] hub-agent Installation Log v4.0
[$timestamp] [INFO] Installation Mode: $($Config.Mode)
[$timestamp] [INFO] Installation started at: $timestamp
[$timestamp] [INFO] User: $env:USERNAME
[$timestamp] [INFO] Token: $($Token.Substring(0, 8))...
[$timestamp] [INFO] Log Path: $($Config.LogPath)
[$timestamp] [INFO] =======================================
"@
        $initLog | Out-File -FilePath $Config.LogPath -Encoding UTF8 -Force

        Write-Info "Log configuration completed: $($Config.LogPath)"
        return $true

    } catch {
        Write-Warn "Failed to initialize logging configuration: $($_.Exception.Message)"
        return $false
    }
}

# 清理已存在的服务和任务
function Remove-ExistingInstallation {
    param($Config)

    Write-Step "Cleaning up existing installation..."

    # 检查并清理Windows服务（仅系统模式）
    if ($Config.Mode -eq "System") {
        $existingService = Get-Service -Name $AppName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Warn "Existing Windows service found: $AppName"

            if (-not $Force) {
                do {
                    $confirmation = Read-Host "An existing system installation was found. Overwrite? (y/N)"
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
    }

    # 检查并清理任务计划程序任务（两种模式都检查）
    $taskNames = @("HubAgent", "HubAgent-System", "HubAgent-User", $Config.TaskName)
    foreach ($taskName in $taskNames) {
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Write-Info "Existing scheduled task found: $taskName"

            if (-not $Force -and $taskName -eq $Config.TaskName) {
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
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Info "Scheduled task cleaned up: $taskName"
            } catch {
                Write-Warn "An error occurred while cleaning up the scheduled task: $($_.Exception.Message)"
            }
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
    param($Config)

    $binaryPath = Get-Binary

    Write-Step "Installing application..."

    try {
        if (-not (Test-Path $Config.InstallDir)) {
            New-Item -ItemType Directory -Path $Config.InstallDir -Force | Out-Null
            Write-Info "Created installation directory: $($Config.InstallDir)"
        }

        $targetPath = Join-Path $Config.InstallDir "$AppName.exe"

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

# 创建任务计划程序任务（支持用户和系统模式）
function Install-ScheduledTask {
    param($BinaryPath, $Config)

    Write-Step "Creating scheduled task ($($Config.Mode) mode)..."

    try {
        Write-Info "Configuring scheduled task: $($Config.TaskName)"
        Write-Info "Executable path: $BinaryPath"
        Write-Info "Run as: $($Config.Principal)"
        Write-Info "Log output: $($Config.LogPath)"

        # 创建任务触发器 - 用户登录时（用户模式）或系统启动时（系统模式）
        if ($Config.Mode -eq "User") {
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
        } else {
            $trigger = New-ScheduledTaskTrigger -AtStartup
        }

        # 创建带日志重定向的启动命令
        $logCommand = "cmd.exe"
        $logArgs = "/c `"cd /d `"$($Config.InstallDir)`" && echo [%date% %time%] [INFO] Starting hub-agent ($($Config.Mode) mode)... >> `"$($Config.LogPath)`" && `"$BinaryPath`" -token `"$Token`" >> `"$($Config.LogPath)`" 2>&1`""

        # 创建任务动作
        $action = New-ScheduledTaskAction -Execute $logCommand -Argument $logArgs

        # 创建任务主体设置
        if ($Config.Mode -eq "User") {
            $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        } else {
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        }

        # 创建任务设置
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        # 设置任务路径
        $taskPath = if ($Config.Mode -eq "User") { "\" } else { $Config.TaskPath }

        # 注册任务
        Register-ScheduledTask -TaskName $Config.TaskName -TaskPath $taskPath -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description $Config.Description

        Write-Info "Scheduled task created successfully in $($Config.Mode) mode."
        return $true

    } catch {
        Write-Error "Failed to create scheduled task: $($_.Exception.Message)"
        return $false
    }
}

# 启动任务
function Start-HubAgentTask {
    param($Config)

    Write-Step "Starting task..."

    try {
        Start-ScheduledTask -TaskName $Config.TaskName
        Start-Sleep 5

        $task = Get-ScheduledTask -TaskName $Config.TaskName
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
    param($Config)

    Write-Step "Verifying installation..."

    try {
        # 检查二进制文件
        $binaryPath = Join-Path $Config.InstallDir "$AppName.exe"
        if (-not (Test-Path $binaryPath)) {
            Write-Warn "Binary file does not exist: $binaryPath"
            return $false
        }

        # 检查任务
        $task = Get-ScheduledTask -TaskName $Config.TaskName -ErrorAction Stop
        Write-Info "Task status: $($task.State)"

        # 检查进程
        $process = Get-Process -Name $AppName -ErrorAction SilentlyContinue
        if ($process) {
            Write-Info "✓ Process is running normally (PID: $($process.Id))"

            # 检查日志文件
            if (Test-Path $Config.LogPath) {
                $logInfo = Get-Item $Config.LogPath
                Write-Info "✓ Log file exists: $($Config.LogPath)"
                Write-Info "  Log file size: $([math]::Round($logInfo.Length/1KB, 2)) KB"
                Write-Info "  Last modified: $($logInfo.LastWriteTime)"
            }

            return $true
        } else {
            Write-Warn "⚠ Process is not running, attempting to start..."
            if (Start-HubAgentTask -Config $Config) {
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
    param($Config)

    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host "    Installation Complete! ($($Config.Mode) Mode)" -ForegroundColor Green
    Write-Host "===============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Task Management Commands:" -ForegroundColor Yellow
    Write-Host "  Check status: Get-ScheduledTask -TaskName '$($Config.TaskName)' | Get-ScheduledTaskInfo" -ForegroundColor White
    Write-Host "  Start task: Start-ScheduledTask -TaskName '$($Config.TaskName)'" -ForegroundColor White
    Write-Host "  Stop process: Stop-Process -Name $AppName -Force" -ForegroundColor White
    Write-Host "  Restart service: Stop-Process -Name $AppName -Force; Start-ScheduledTask -TaskName '$($Config.TaskName)'" -ForegroundColor White
    Write-Host "  Disable task: Disable-ScheduledTask -TaskName '$($Config.TaskName)'" -ForegroundColor White
    Write-Host "  Enable task: Enable-ScheduledTask -TaskName '$($Config.TaskName)'" -ForegroundColor White
    Write-Host ""
    Write-Host "Log Management Commands:" -ForegroundColor Yellow
    Write-Host "  View logs: Get-Content `"$($Config.LogPath)`" -Tail 50" -ForegroundColor White
    Write-Host "  Follow logs: Get-Content `"$($Config.LogPath)`" -Wait -Tail 10" -ForegroundColor White
    Write-Host "  Search errors: Get-Content `"$($Config.LogPath)`" | Select-String `"ERROR`"" -ForegroundColor White
    Write-Host ""
    Write-Host "Installation Info:" -ForegroundColor Yellow
    Write-Host "  Install mode: $($Config.Mode)" -ForegroundColor White
    Write-Host "  Install path: $($Config.InstallDir)" -ForegroundColor White
    Write-Host "  Task name: $($Config.TaskName)" -ForegroundColor White
    Write-Host "  Log path: $($Config.LogPath)" -ForegroundColor White
    Write-Host "  Run as: $($Config.Principal)" -ForegroundColor White

    if ($Config.Mode -eq "User") {
        Write-Host "  Startup trigger: User Login" -ForegroundColor White
        Write-Host "  Scope: Current User Only" -ForegroundColor White
    } else {
        Write-Host "  Startup trigger: System Boot" -ForegroundColor White
        Write-Host "  Scope: All Users" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "Uninstall Commands:" -ForegroundColor Red
    Write-Host "  Stop-Process -Name $AppName -Force -ErrorAction SilentlyContinue" -ForegroundColor White
    Write-Host "  Unregister-ScheduledTask -TaskName '$($Config.TaskName)' -Confirm:`$false" -ForegroundColor White
    Write-Host "  Remove-Item `"$($Config.InstallDir)`" -Recurse -Force" -ForegroundColor White
    Write-Host "  Remove-Item `"$($Config.LogDir)`" -Recurse -Force" -ForegroundColor White
    Write-Host ""
}

# 安全写入日志函数
function Write-SafeLog {
    param([string]$Message, [string]$LogFile)

    $maxRetries = 3
    $retryCount = 0

    while ($retryCount -lt $maxRetries) {
        try {
            $Message | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
            break
        } catch {
            $retryCount++
            if ($retryCount -lt $maxRetries) {
                Start-Sleep -Milliseconds (200 * $retryCount)
            }
        }
    }
}

# 主函数
function Main {
    $startTime = Get-Date

    try {
        # 获取安装配置
        $config = Get-InstallConfig

        Show-InstallInfo -Config $config

        # 执行安装步骤
        if (-not (Test-NetworkConnection)) {
            return
        }

        # 初始化日志配置
        Initialize-LoggingConfiguration -Config $config | Out-Null

        Remove-ExistingInstallation -Config $config
        $binaryPath = Install-Application -Config $config

        if (-not (Install-ScheduledTask -BinaryPath $binaryPath -Config $config)) {
            Write-Error "Failed to create scheduled task"
            return
        }

        # 启动任务
        if (-not (Start-HubAgentTask -Config $config)) {
            Write-Warn "Task failed to start, but installation is complete. Please manually check the task configuration."
        }

        # 验证安装
        $installSuccess = Test-Installation -Config $config

        $endTime = Get-Date
        $duration = $endTime - $startTime

        # 写入安装完成日志
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $completionMessage = "[$timestamp] [INFO] Installation completed ($($config.Mode) mode). Duration: $([math]::Round($duration.TotalSeconds, 1)) seconds"
        Write-SafeLog -Message $completionMessage -LogFile $config.LogPath

        if ($installSuccess) {
            Write-Host ""
            Write-Host "🎉 Installation completed successfully!" -ForegroundColor Green
            Write-Host "Mode: $($config.Mode)" -ForegroundColor Cyan
            Write-Host "Total time elapsed: $([math]::Round($duration.TotalSeconds, 1)) seconds" -ForegroundColor Cyan
            Show-ManagementCommands -Config $config
        } else {
            Write-Host ""
            Write-Host "⚠ There may be issues with the installation. Please check the task status and logs." -ForegroundColor Yellow
            Write-Host "Log file: $($config.LogPath)" -ForegroundColor Cyan
        }

    } catch {
        Write-Host ""
        Write-Host "❌ Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please check the error message and try again, or contact technical support." -ForegroundColor Yellow

        # 写入错误日志
        if ($config -and $config.LogPath) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $errorMessage = "[$timestamp] [ERROR] Installation failed: $($_.Exception.Message)"
            Write-SafeLog -Message $errorMessage -LogFile $config.LogPath
        }

        exit 1
    }
}

# 执行安装
Main