#!/bin/bash
set -e

SCRIPT_DIR=$(cd "$(dirname "$0")"; pwd)
SERVICE_NAME=mount_public_manager
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
PYTHON=/usr/bin/python3

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo "请用 root 权限运行本脚本！"
   exit 1
fi

# 检查依赖
if ! command -v $PYTHON &>/dev/null; then
    echo "未安装python3，正在安装..."
    apt update
    apt install python3 -y
fi
if ! python3 -c "import watchdog" &>/dev/null; then
    echo "未安装 python3-watchdog，正在安装..."
    apt update
    apt install python3-watchdog -y
fi

# 创建 systemd 服务文件
cat > $SERVICE_FILE <<EOF
[Unit]
Description=Mount Manager
After=multi-user.target
After=mountmgr.service
Wants=network.target

[Service]
Type=simple
ExecStart=$PYTHON $SCRIPT_DIR/mount_manager.py
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF


# 重新加载并启用服务
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl restart $SERVICE_NAME

echo "服务已安装并启动，请用 systemctl status $SERVICE_NAME 查看状态。"
