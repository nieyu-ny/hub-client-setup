<#
.SYNOPSIS
    hub-agent Windows平台一键安装脚本
.DESCRIPTION
    从预编译二进制文件安装hub-agent，无需编译环境
.PARAMETER Token
    应用程序token
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -File install.ps1 -Token "your_token"
.EXAMPLE
    PowerShell -ExecutionPolicy Bypass -Command "iwr -useb https://your-domain.com/install.ps1 | iex" -Token "your_token"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

# 配置参数
$AppName = "hub-agent"
$RepoUrl = "https://github.com/nieyu-ny/hub-client-setup.git"
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

# 检查管理员权限
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-AdminRights)) {
    Write-Error "请以管理员身份运行此脚本"
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

# 安装Git（如果需要）
function Install-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Step "安装Git..."
        
        # 检查是否有winget
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id Git.Git -e --source winget --silent
        } else {
            # 下载并安装Git
            $gitUrl = "https://github.com/git-for-windows/git/releases/latest/download/Git-2.43.0-64-bit.exe"
            $gitInstaller = "$env:TEMP\git-installer.exe"
            
            Write-Info "从 $gitUrl 下载Git..."
            Invoke-WebRequest -Uri $gitUrl -OutFile $gitInstaller -UseBasicParsing
            Start-Process -FilePath $gitInstaller -ArgumentList "/SILENT" -Wait
            Remove-Item $gitInstaller -Force
        }
        
        # 刷新环境变量
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH","User")
        
        # 验证安装
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            Write-Error "Git安装失败，请手动安装Git后重试"
        }
        
        Write-Info "Git安装完成"
    }
}

# 下载二进制文件
function Get-Binary {
    Write-Step "下载二进制文件..."
    
    $tempDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
    $repoDir = Join-Path $tempDir "hub-client-setup"
    
    try {
        Set-Location $tempDir
        
        Write-Info "克隆仓库: $RepoUrl"
        git clone --depth 1 $RepoUrl 2>$null
        
        $binaryPath = Join-Path $repoDir $BinaryName
        if (-not (Test-Path $binaryPath)) {
            throw "二进制文件不存在: $BinaryName"
        }
        
        Write-Info "找到二进制文件: $binaryPath"
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
    Copy-Item -Path $binaryPath -Destination $targetPath -Force
    
    Write-Info "应用程序安装到: $targetPath"
    
    # 清理临时文件
    $tempDir = Split-Path $binaryPath -Parent | Split-Path -Parent
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    
    return $targetPath
}

# 创建Windows服务
function Install-WindowsService {
    param([string]$BinaryPath)
    
    Write-Step "创建Windows服务..."
    
    # 服务路径（包含参数）
    $servicePath = "`"$BinaryPath`" -token=$Token"
    
    # 停止并删除已存在的服务
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Info "发现已存在的服务，正在移除..."
        
        if ($existingService.Status -eq 'Running') {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep 3
        }
        
        sc.exe delete $ServiceName | Out-Null
        Start-Sleep 2
    }
    
    # 创建新服务
    Write-Info "创建服务: $ServiceName"
    $result = sc.exe create $ServiceName binPath= $servicePath start= auto
    if ($LASTEXITCODE -ne 0) {
        Write-Error "服务创建失败: $result"
    }
    
    # 设置服务描述
    sc.exe description $ServiceName "$AppName Service" | Out-Null
    
    # 配置服务失败时的重启策略
    sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    
    # 启动服务
    Write-Info "启动服务..."
    Start-Service -Name $ServiceName
    
    # 验证服务状态
    Start-Sleep 3
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Running') {
        Write-Info "服务启动成功"
    } else {
        Write-Warn "服务状态: $($service.Status)"
    }
    
    Write-Info "Windows服务安装完成"
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
}

# 验证安装
function Test-Installation {
    Write-Step "验证安装..."
    
    Start-Sleep 3
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Info "服务运行正常"
        return $true
    } else {
        Write-Warn "服务可能未正常启动，请检查服务状态"
        return $false
    }
}

# 显示安装信息
function Show-InstallInfo {
    $arch = Get-Architecture
    
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "    $AppName Windows一键安装程序" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "安装信息:"
    Write-Host "  操作系统: Windows"
    Write-Host "  架构: $arch"
    Write-Host "  二进制文件: $BinaryName"
    Write-Host "  仓库: $RepoUrl"
    Write-Host "  Token: $($Token.Substring(0, [Math]::Min(8, $Token.Length)))..."
    Write-Host ""
}

# 主函数
function Main {
    try {
        Show-InstallInfo
        
        Install-Git
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