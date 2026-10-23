# 安装并使用钱包

原生 GUI 安装包同时包含 Parano1d 钱包及其私有完整节点。应用会自行
启动、监控并停止该节点，日常使用无需终端。

## 选择安装包

请从 [GitHub 发布页面](https://github.com/proof-native/parano1d/releases)
下载与电脑匹配的 GUI 钱包：

| 平台 | 安装包 |
|---|---|
| Debian 或 Ubuntu，x86-64 | `parano1d-gui-vVERSION-linux-x86_64.deb` |
| Debian 或 Ubuntu，ARM64 | `parano1d-gui-vVERSION-linux-aarch64.deb` |
| Windows x86-64 | `parano1d-gui-vVERSION-windows-x86_64-setup.exe` |
| macOS Apple 芯片 | `parano1d-gui-vVERSION-macos-aarch64.dmg` |
| macOS Intel | `parano1d-gui-vVERSION-macos-x86_64.dmg` |

同时下载该版本的 `SHA256SUMS`，打开安装包前先进行校验：

```sh
# Linux
sha256sum parano1d-gui-vVERSION-linux-x86_64.deb

# macOS
shasum -a 256 parano1d-gui-vVERSION-macos-aarch64.dmg
```

Windows 请使用 PowerShell：

```powershell
Get-FileHash .\parano1d-gui-vVERSION-windows-x86_64-setup.exe -Algorithm SHA256
```

输出摘要必须与 `SHA256SUMS` 中对应的一行完全一致。

## 安装

### Linux

用系统的软件中心打开 `.deb`，或执行：

```sh
sudo apt install ./parano1d-gui-vVERSION-linux-x86_64.deb
```

然后从应用菜单启动 **Parano1d**。

### Windows

运行安装程序。默认按当前用户安装，不需要管理员权限。

在版本尚未使用 Authenticode 签名时，SmartScreen 可能提示发布者
未知。校验 SHA-256 后，选择 **更多信息**，再选择 **仍要运行**。

### macOS

打开 DMG，将 **Parano1d** 拖入 Applications。

在版本尚未通过 Apple Developer ID 公证时，请按住 Control 点击应用，
选择 **打开** 并确认。如果 macOS 仍然阻止启动，请在校验下载文件后
进入 **系统设置 → 隐私与安全性 → 仍要打开**。

## 首次启动

首次运行界面提供三种建立 256 位主密钥的方式：

- **生成**：创建新的随机密钥；
- **导入**：从已有的 64 个十六进制字符恢复密钥；
- **[使用照片](../wallet/photo-key.md)**：根据图像像素确定性地派生密钥。

选择前请阅读[首次运行与主密钥](../wallet/first-run.md)。主密钥控制
所有派生地址，项目方无法替你找回。

## 等待节点同步

顶部状态栏显示连接和同步状态。追赶网络期间，钱包仍可显示本地已有
数据；只有节点显示 **在线** 后，可用余额和当前槽位状态才是最新的规范值。

钱包的私有节点通过 TCP `9600` 接受入站和出站 P2P 流量。普通用户只靠
出站对等连接也能正常使用；开放入站 TCP `9600` 还可为网络提供更多
连接能力。

## 收款与发送

主页显示当前活动地址。使用旁边的复制按钮将完整地址发给付款人。

付款步骤：

1. 打开 **F1 → Main → Send**；
2. 粘贴有效的 `o1…` 地址；
3. 输入 NOID 数量；
4. 核对选定输入、输出和网络费；
5. 选择 **证明并发送**。

钱包在本机生成私有授权证明，再将完整交易意图提交给自己的节点。发送
成功后，最终面板会显示逻辑交易 ID。状态与确认行为详见
[发送 NOID](../wallet/send.md)。

## 卸载应用

卸载应用不会删除钱包数据。

Debian 或 Ubuntu：

```sh
sudo apt remove parano1d-gui
```

Windows 请使用 **已安装的应用 → Parano1d → 卸载**；macOS 则将
Applications 中的应用移到废纸篓。

钱包和节点数据仍保存在用户目录下的 `.parano1d` 中。只有在导出或
备份主密钥以及需要保留的收据后，才应删除该目录。

## 使用合约

打开 **F7 Contracts**，从模板创建条款、存入资金、调用合约或导入另一方文件。
参见[合约钱包指南](../contracts/gui.md)。请与主秘密一起备份公开条款和回执。
