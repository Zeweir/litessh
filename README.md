# LiteSSH

轻量级 Windows 桌面 SSH 客户端 — Rust + Tauri + xterm.js，单文件 exe，快速启动。

## 功能（v0.1 MVP）

- 主机列表管理（保存/编辑/删除，存于应用配置目录 `hosts.json`，密码不落盘）
- 标签页终端（xterm.js），支持多会话
- 密码 / 私钥（含 passphrase、`~` 路径）认证
- PTY 交互 shell、窗口大小自适应、Ctrl+Shift+C/V 复制粘贴
- known_hosts 主机密钥校验（TOFU）：首次连接弹窗确认 SHA256 指纹，密钥变更时强警告；记录存于应用配置目录 `known_hosts`（OpenSSH 格式）
- SFTP 文件面板（标签页 ⇄ 按钮）：远程目录浏览、上传/下载、新建目录、删除

## 结构

```
crates/ssh-core   # russh 封装：会话管理，与 UI 无关
crates/ssh-cli    # SSH 冒烟测试 CLI（无 GUI 验证用）
src-tauri/        # Tauri 应用：commands + 事件桥接 + 主机存储
src/ + index.html # 前端：侧边栏主机列表 + 标签页 xterm.js 终端
```

## 开发

```bash
npm install
npm run tauri dev        # 前端 vite dev + 桌面窗口
```

无 GUI 环境下验证 SSH 链路：

```bash
cargo build -p ssh-cli
./target/debug/ssh-cli --host 127.0.0.1 --port 22 --user me --key ~/.ssh/id_ed25519
```

## Windows 打包

```bash
npm run tauri build      # 产出 NSIS/msi 安装包与便携 exe
```

CI 已配置（`.github/workflows/build.yml`）：Windows runner 上自动构建。

## 路线图

- [x] SFTP 文件浏览/上传/下载
- [ ] 本地/远程/动态端口转发
- [x] known_hosts 主机密钥校验（TOFU）
- [ ] 读取 `~/.ssh/config`、命令片段库
- [ ] Windows 凭据管理器存密码
