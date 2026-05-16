# WeChat macOS Exporter

`wechat-macos-exporter` is a macOS-focused WeChat history exporter. It detects the local WeChat data directory, extracts the database keys, lists chats, and exports chat history as plain text.

The CLI command stays `wechat-cli`.

## What it does

- Finds your local WeChat data on macOS
- Extracts SQLCipher keys from the running WeChat process
- Lists recent chats with `sessions`
- Reads chat history with `history`
- Exports text-only chat logs with `export --type text`

## Install

```bash
git clone https://github.com/suttikeatot/wechat-macos-exporter.git
cd wechat-macos-exporter
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Initialize

Make sure WeChat is running, then:

```bash
sudo wechat-cli init
```

On macOS, the terminal usually needs Full Disk Access. If key extraction fails with `task_for_pid failed`, re-open WeChat from the re-signed app copy or follow the prompt shown by `init`.

## List chats

```bash
wechat-cli sessions --limit 50
```

Use `--format text` if you want a compact human-readable list.

## Export text only

```bash
wechat-cli export "Chat Name" --format txt --type text --output chat.txt
```

Useful flags:

- `--limit` limits how many messages are exported
- `--start-time` and `--end-time` narrow the time window
- `--type text` excludes image, video, voice, file, sticker, and other non-text messages

## Typical flow

1. Run `wechat-cli init`
2. Run `wechat-cli sessions` to find the chat you want
3. Run `wechat-cli export "Chat Name" --format txt --type text --output chat.txt`

## Notes

- This repo has been adjusted for the macOS workflow verified on this machine.
- The export path is plain text only by default in the workflow I used here.
- Sensitive local artifacts such as extracted keys and exports are kept out of git by `.gitignore`.
