$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="
iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.ps1 | iex

$env:Token = "MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="; iwr -useb https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.ps1 | iex

Linux环境：
curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A=

sudo bash -c "curl -fsSL https://raw.githubusercontent.com/nieyu-ny/hub-client-setup/master/install.sh | bash -s -- -token=MyHUjM+kdqg3UVU50841PqhDXaY/nL4ffguwI/sEz+A="

查看服务日志
sudo journalctl -u hub-agent -f --no-pager -l

journalctl -u hub-agent -f