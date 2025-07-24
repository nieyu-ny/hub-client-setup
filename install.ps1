<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本（任务计划程序版本 - 稳定日志版 v3.1-Final）
.DESCRIPTION
    从预编译二进制文件安装hub-agent，使用任务计划程序替代Windows服务
    支持命令行参数和环境变量两种方式传递Token
    通过PowerShell重定向实现日志记录和轮转功能（已修复参数传递问题）
.PARAMETER Token
    应用程序token (可选，如果未提供将从环境变量读取)
.PARAMETER LogPath
    日志文件路径 (可选，默认: C:\ProgramData\hub-agent\logs\hub-agent.log)
.PARAMETER MaxLogSizeMB
    单个日志文件最大大小（MB），默认: 10MB
.PARAMETER MaxLogFiles
    保留的日志文件数量，默认: 5个
.PARAMETER Force
    强制重新安装，覆盖已存在的任务
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token"
.EXAMPLE
    $env:Token = "your_token"; iwr -useb https://url/install.ps1 | iex
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Token,

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\hub-agent\logs\hub-agent.log",

    [Parameter(Mandatory=$false)]
    [int]$MaxLogSizeMB = 10,

    [Parameter(Mandatory=$false)]
    [int]$MaxLogFiles = 5,

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
    Write-Host "    $AppName Windows Installer v3.1-Final" -ForegroundColor Cyan
    Write-Host "    (Task Scheduler + Logging - Stable)" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Installation Info:"
    Write-Host "  Operating System: Windows"
    Write-Host "  Architecture: $arch"
    Write-Host "  Binary File: $BinaryName"
    Write-Host "  Download URL: $BinaryBaseUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host "  Installation Method: Task Scheduler with PowerShell Wrapper"
    Write-Host "  Log Path: $LogPath"
    Write-Host "  Max Log Size: ${MaxLogSizeMB}MB"
    Write-Host "  Max Log Files: $MaxLogFiles"
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
                $arguments = "-ExecutionPolicy Bypass -File `"$scriptPath`" -Token `"$Token`" -LogPath `"$LogPath`" -MaxLogSizeMB $MaxLogSizeMB -MaxLogFiles $MaxLogFiles"
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

# 创建日志配置和包装脚本
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

        # 创建包装脚本（修复版本）
        $wrapperScript = @"
# hub-agent 启动包装脚本 - 支持日志轮转 (Fixed Version)
param(
    [Parameter(Mandatory=`$true, Position=0)]
    [string]`$Token
)

`$ErrorActionPreference = "Continue"
`$AppName = "hub-agent"
`$InstallDir = "C:\Program Files\`$AppName"
`$LogPath = "$LogPath"
`$MaxLogSizeMB = $MaxLogSizeMB
`$MaxLogFiles = $MaxLogFiles
`$BinaryPath = Join-Path `$InstallDir "`$AppName.exe"

# 确保日志目录存在
`$logDir = Split-Path `$LogPath -Parent
if (-not (Test-Path `$logDir)) {
    New-Item -ItemType Directory -Path `$logDir -Force | Out-Null
}

# 日志轮转函数
function Invoke-LogRotation {
    if (Test-Path `$LogPath) {
        `$logFile = Get-Item `$LogPath
        `$logSizeMB = [math]::Round(`$logFile.Length / 1MB, 2)

        if (`$logSizeMB -gt `$MaxLogSizeMB) {
            `$logDir = Split-Path `$LogPath
            `$logName = [System.IO.Path]::GetFileNameWithoutExtension(`$LogPath)
            `$logExt = [System.IO.Path]::GetExtension(`$LogPath)

            # 轮转现有日志文件
            for (`$i = `$MaxLogFiles - 1; `$i -gt 0; `$i--) {
                `$oldFile = Join-Path `$logDir "`$logName.`$i`$logExt"
                `$newFile = Join-Path `$logDir "`$logName.`$(`$i + 1)`$logExt"

                if (Test-Path `$oldFile) {
                    if (`$i -eq (`$MaxLogFiles - 1)) {
                        Remove-Item `$oldFile -Force -ErrorAction SilentlyContinue
                    } else {
                        Move-Item `$oldFile `$newFile -Force -ErrorAction SilentlyContinue
                    }
                }
            }

            # 移动当前日志文件
            `$firstRotatedFile = Join-Path `$logDir "`$logName.1`$logExt"
            Move-Item `$LogPath `$firstRotatedFile -Force -ErrorAction SilentlyContinue

            # 写入轮转信息到新日志文件
            `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            "[`$timestamp] [INFO] Log rotated. Previous log size: `$logSizeMB MB" | Out-File -FilePath `$LogPath -Encoding UTF8
        }
    }
}

# 记录启动信息
`$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[`$timestamp] [INFO] =========================================" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
"[`$timestamp] [INFO] hub-agent starting... (v3.1-Final)" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
"[`$timestamp] [INFO] Token: `$(`$Token.Substring(0, 8))..." | Out-File -FilePath `$LogPath -Append -Encoding UTF8
"[`$timestamp] [INFO] Binary Path: `$BinaryPath" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
"[`$timestamp] [INFO] Log Path: `$LogPath" | Out-File -FilePath `$LogPath -Append -Encoding UTF8

# 执行日志轮转检查
Invoke-LogRotation

# 检查二进制文件是否存在
if (-not (Test-Path `$BinaryPath)) {
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[`$timestamp] [ERROR] Binary file not found: `$BinaryPath" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
    exit 1
}

# 启动主程序并重定向输出到日志
try {
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[`$timestamp] [INFO] Starting hub-agent process..." | Out-File -FilePath `$LogPath -Append -Encoding UTF8

    # 使用临时文件来处理输出重定向
    `$tempOutFile = Join-Path `$env:TEMP "hub-agent-out-`$(Get-Random).tmp"
    `$tempErrFile = Join-Path `$env:TEMP "hub-agent-err-`$(Get-Random).tmp"

    `$process = Start-Process -FilePath `$BinaryPath -ArgumentList "-token `"`$Token`"" -RedirectStandardOutput `$tempOutFile -RedirectStandardError `$tempErrFile -NoNewWindow -PassThru

    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[`$timestamp] [INFO] Process started with PID: `$(`$process.Id)" | Out-File -FilePath `$LogPath -Append -Encoding UTF8

    # 启动输出监控作业
    `$outputJob = Start-Job -ScriptBlock {
        param(`$OutFile, `$ErrFile, `$LogPath)
        while (`$true) {
            Start-Sleep 1
            if (Test-Path `$OutFile) {
                `$outContent = Get-Content `$OutFile -ErrorAction SilentlyContinue
                if (`$outContent) {
                    foreach (`$line in `$outContent) {
                        `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        "[`$timestamp] [OUT] `$line" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
                    }
                    Clear-Content `$OutFile -ErrorAction SilentlyContinue
                }
            }
            if (Test-Path `$ErrFile) {
                `$errContent = Get-Content `$ErrFile -ErrorAction SilentlyContinue
                if (`$errContent) {
                    foreach (`$line in `$errContent) {
                        `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        "[`$timestamp] [ERR] `$line" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
                    }
                    Clear-Content `$ErrFile -ErrorAction SilentlyContinue
                }
            }
        }
    } -ArgumentList `$tempOutFile, `$tempErrFile, `$LogPath

    # 监控进程，实现日志轮转
    while (!`$process.HasExited) {
        Start-Sleep 300  # 每5分钟检查一次日志大小
        Invoke-LogRotation
    }

    # 清理
    Stop-Job `$outputJob -ErrorAction SilentlyContinue
    Remove-Job `$outputJob -ErrorAction SilentlyContinue
    Remove-Item `$tempOutFile -ErrorAction SilentlyContinue
    Remove-Item `$tempErrFile -ErrorAction SilentlyContinue

    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[`$timestamp] [WARN] Process exited with code: `$(`$process.ExitCode)" | Out-File -FilePath `$LogPath -Append -Encoding UTF8

} catch {
    `$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[`$timestamp] [ERROR] Failed to start hub-agent: `$(`$_.Exception.Message)" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
    "[`$timestamp] [ERROR] Exception Details: `$(`$_.Exception.GetType().FullName)" | Out-File -FilePath `$LogPath -Append -Encoding UTF8
}
"@

        $wrapperScriptPath = Join-Path $InstallDir "hub-agent-wrapper.ps1"
        $wrapperScript | Out-File -FilePath $wrapperScriptPath -Encoding UTF8 -Force

        Write-Info "Log configuration completed."
        Write-Info "Wrapper script created: $wrapperScriptPath"

        return $wrapperScriptPath

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

# 创建任务计划程序任务（使用包装脚本）
function Install-ScheduledTask {
    param([string]$BinaryPath, [string]$WrapperScriptPath)

    Write-Step "Creating scheduled task with logging wrapper..."

    try {
        Write-Info "Configuring scheduled task: $TaskName"
        Write-Info "Wrapper script: $WrapperScriptPath"
        Write-Info "Token: $($Token.Substring(0, 8))..."

        # 创建任务触发器 - 系统启动时
        $trigger = New-ScheduledTaskTrigger -AtStartup

        # 创建任务动作 - 运行包装脚本（使用位置参数）
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WrapperScriptPath`" `"$Token`""

        # 创建任务主体设置 - 以SYSTEM权限运行
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        # 创建任务设置
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)

        # 注册任务
        Register-ScheduledTask -TaskName $TaskName -Trigger $trigger -Action $action -Principal $principal -Settings $settings -Description "$AppName Service (Task Scheduler + Logging v3.1-Final)"

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

        # 检查包装脚本
        $wrapperPath = Join-Path $InstallDir "hub-agent-wrapper.ps1"
        if (-not (Test-Path $wrapperPath)) {
            Write-Warn "Wrapper script does not exist: $wrapperPath"
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
                        if ($_ -match "\[ERROR\]") {
                            Write-Host "  $_" -ForegroundColor Red
                        } elseif ($_ -match "\[WARN\]") {
                            Write-Host "  $_" -ForegroundColor Yellow
                        } elseif ($_ -match "v3.1-Final") {
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
    Write-Host "    ✅ 安装成功！管理命令" -ForegroundColor Green
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
    Write-Host "  日志文件: Get-ChildItem `"$LogDir`" -Filter *.log" -ForegroundColor White
    Write-Host ""
    Write-Host "⚙️ 安装信息:" -ForegroundColor Yellow
    Write-Host "  安装路径: $InstallDir" -ForegroundColor White
    Write-Host "  任务名称: $TaskName" -ForegroundColor White
    Write-Host "  日志路径: $LogPath" -ForegroundColor White
    Write-Host "  日志大小限制: ${MaxLogSizeMB}MB" -ForegroundColor White
    Write-Host "  日志文件数量: $MaxLogFiles" -ForegroundColor White
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

        # 初始化日志配置并创建包装脚本
        $wrapperScriptPath = Initialize-LoggingConfiguration
        if (-not $wrapperScriptPath) {
            Write-Error "Failed to initialize logging configuration"
            return
        }

        if (-not (Install-ScheduledTask -BinaryPath $binaryPath -WrapperScriptPath $wrapperScriptPath)) {
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
                    if ($_ -match "\[ERROR\]") {
                        Write-Host "  $_" -ForegroundColor Red
                    } elseif ($_ -match "\[WARN\]") {
                        Write-Host "  $_" -ForegroundColor Yellow
                    } elseif ($_ -match "v3.1-Final") {
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