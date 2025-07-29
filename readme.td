$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="
iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.ps1 | iex

$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="; iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.ps1 | iex

Linux环境：
curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A=

sudo bash -c "curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="

查看服务日志
sudo journalctl -u hub-agent -f --no-pager -l

journalctl -u hub-agent -f

对象存储版本(源文件 D:\\dev\\stor-setup文件夹)：
第一版：
$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A=";iwr -useb https://files.node-x.xyz/stor-setup/install.ps1 | iex

第二版：
$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="; iwr -useb "https://files.node-x.xyz/stor-setup/install.ps1?t=$([System.DateTime]::UtcNow.Ticks)" | iex
自动提权：
Start-Process PowerShell -ArgumentList "-Command `"& {`$env:Token = 'MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A='; iwr -useb 'https://files.node-x.xyz/stor-setup/install.ps1?t=$([System.DateTime]::UtcNow.Ticks)' | iex}`"" -Verb RunAs

下载后执行：
$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="
iwr -useb "https://files.node-x.xyz/stor-setup/install.ps1?t=$([System.DateTime]::UtcNow.Ticks)" -OutFile "$env:TEMP\install.ps1"
PowerShell -ExecutionPolicy Bypass -File "$env:TEMP\install.ps1"

Linux环境：
curl -fsSL https://files.node-x.xyz/stor-setup/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A=

sudo bash -c "curl -fsSL https://files.node-x.xyz/stor-setup/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="