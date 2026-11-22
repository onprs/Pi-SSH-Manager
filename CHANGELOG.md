# Changelog

## [0.2.0] - 2026-11-22

### Changed

- 将斜杠命令更名为 `/ssh`，支持 `list`、`get`、`import` 子命令及主机别名自动补全。
- 将工具名称与扩展导出标识规范为 `ssh_manager`（`registerSshManager` / `sshManager`）。
- 将受管配置目录与 `~/.ssh/config` 区块标记统一为 `~/.ssh/pi-ssh-manager/` 与 `pi-ssh-manager`。

## [0.1.0] - 2026-11-22

### Added

- 新增 SSH 主机管理扩展工具与斜杠命令，支持查询、搜索、添加、更新和删除 SSH 主机配置。
- 支持递归解析 `~/.ssh/config` 及 `Include` 规则中的已有 OpenSSH 主机配置，并生成参数数组与安全连接命令。
- 支持从外部 OpenSSH 配置文件或目录导入主机记录、引用密钥、公钥及 `known_hosts` 主机指纹。
- 新增受管配置自动备份、写入失败回滚、符号链接目标防护，以及危险指令隐藏与条件配置告警提示。
- 支持 Windows、Linux 与 macOS，并作为标准 Pi Package 通过 `pi install` 安装加载。
