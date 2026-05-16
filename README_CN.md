# WeChat macOS Exporter

`wechat-macos-exporter` 是一个面向 macOS 的微信聊天记录导出工具。它会识别本机微信数据目录、提取数据库密钥、列出会话，并把聊天记录导出成纯文本。

命令行仍然使用 `wechat-cli`。

## 它能做什么

- 在 macOS 上自动定位微信数据
- 从运行中的微信进程中提取 SQLCipher 密钥
- 使用 `sessions` 列出最近会话
- 使用 `history` 读取聊天记录
- 使用 `export --type text` 导出纯文本聊天记录

## 安装

```bash
git clone https://github.com/suttikeatot/wechat-macos-exporter.git
cd wechat-macos-exporter
python3 -m venv .venv
.venv/bin/pip install -e .
```

## 初始化

先确保微信正在运行，然后执行：

```bash
sudo wechat-cli init
```

在 macOS 上，终端通常需要开启“完全磁盘访问权限”。如果密钥提取时报 `task_for_pid failed`，请按照 `init` 的提示重新签名微信后再试。

## 列出会话

```bash
wechat-cli sessions --limit 50
```

如果想看更紧凑的文本输出，可以加 `--format text`。

## 仅导出文本

```bash
wechat-cli export "聊天名称" --format txt --type text --output chat.txt
```

常用参数：

- `--limit` 控制导出条数
- `--start-time` 和 `--end-time` 控制时间范围
- `--type text` 会排除图片、视频、语音、文件、表情等非文本消息

## 常见流程

1. 运行 `wechat-cli init`
2. 运行 `wechat-cli sessions` 找到目标聊天
3. 运行 `wechat-cli export "聊天名称" --format txt --type text --output chat.txt`

## 说明

- 这个仓库已经调整为我在这台 macOS 机器上验证过的工作流。
- 这里默认导出的是纯文本，不把图片和视频纳入导出流程。
- `.gitignore` 会把提取出来的密钥和导出文件留在本机，不会提交到 git。
