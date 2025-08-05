# 自动挂载公共目录给每个用户

---

此脚本支持**自动为指定用户组下的所有用户**批量挂载（bind mount）指定目录到`/vol1/{UID}/{目标子目录}`，支持自动授权 ACL 用户组权限、冲突策略及目录监听（新用户自动触发挂载）。

## 主要功能

- **自动挂载**：按`config.ini`配置将源目录绑定挂载到用户空间
- **冲突策略**：目录非空时可选择 跳过、覆盖、重命名(重命名旧文件/目录)
- **自动授权**：为用户组批量授权 ACL
- **自动卸载**：移除已不再配置的旧挂载点
- **实时监听**：监听`/vol1`下新用户目录自动补挂载

## 特别警告

- 脚本会自动检查并删除已删除的挂载点，但请自行检查挂载点是否被正确删除。
- 当用户/用户目录被删除时，脚本可能无法自动删除挂载点，或报错，请自行删除。
- 脚本需要以 root 权限运行，请自行确认脚本安全性。
- 脚本不会实时监听用户组变更，请自行重新运行脚本。
- 生产环境前请做好充分测试。

## 依赖

飞牛已经内置了 `mount`, `umount`, `setfacl` 命令，并默认安装了 Python 3.11.2 ，只需安装以下依赖：

`sudo apt install python3-watchdog -y`

## 使用说明

1. **编辑配置文件**

在脚本同目录下编写`config.ini`  

示例：

```ini
[公共目录1]
type = 本地存储
; type支持的值有：本地存储 / 外接存储 / 远程挂载
src = /vol02/1000-0-fc4f778a
; 源目录的绝对路径
dst = 公共目录
; 目标目录的名称，应该为一个目录名称，不要带任何中英文符号
groups = Users, Administrators
; 用户组，可多个，英文逗号分隔，只会为配置的用户组挂载，不在用户组的用户不会挂载, 如果要为全部用户挂载，请用 Users
conflict = 跳过
; 当目标目录非空时，处理冲突的方式，可选 跳过/覆盖/重命名

[公共目录2]
type = 本地存储
src = /vol1/公共目录2
dst = 公共照片
groups = Users
conflict = 覆盖
```

2. **测试运行脚本**

需以 root 用户运行：

```sh
sudo python3 script.py
```

启动后，会自动进行挂载，且保持监听状态，有新增用户目录会补全挂载，可以检查是否正常挂载。


3. 编写 systemd 服务

可以运行 `chmod +x install.sh` `sudo ./install.sh` 安装服务。

或者按照以下步骤手动创建服务：

```sh
sudo nano /etc/systemd/system/mount_public_manager.service
```

```
[Unit]
Description=Mount Public Manager
After=multi-user.target
Wants=network.target

[Service]
Type=simple
ExecStart=/bin/sleep 10
ExecStart=/usr/bin/python3 /path/to/script.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable mount_manager.service
sudo systemctl start mount_manager.service
sudo systemctl status mount_manager.service
```


4. **挂载/卸载记录**

挂载情况保存在`mount_manager.json`，包含已挂载的源/目标路径，可以查看该文件进行检查。


## 故障排查

- 挂载失败请检查：目标目录是否存在、权限是否足够、源目录是否存在
- 无法加载挂载记录：首次运行或记录文件丢失时提示，仅会影响自动卸载功能。
