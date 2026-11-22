# Pi SSH Manager

为 [Pi](https://github.com/earendil-works/pi)（`@earendil-works/pi-coding-agent`）提供本机 SSH 主机查询与 OpenSSH 配置管理扩展，注册 `ssh_manager` 工具与 `/ssh` 交互式斜杠命令。

## 功能特性

- **主机列表与连接查询**：统一检索已有 OpenSSH 配置与受管主机记录，支持关键词搜索、分页及完整连接参数输出。
- **主机添加、更新与删除**：新增或增量修改主机别名、地址、端口、用户名、密钥路径、备注与其他 OpenSSH 选项；删除受管主机时保留既有密钥文件。
- **OpenSSH 配置导入**：支持从外部 OpenSSH 配置文件或目录导入主机，同时复制引用的密钥、相应公钥与 `known_hosts` 指纹记录，保留本机与来源原有记录。
- **自动备份与安全防护**：受管配置保存在 `~/.ssh/pi-ssh-manager/` 并通过 `Include` 接入 `~/.ssh/config`，修改前自动备份；查询结果不读取密钥内容，导入与解析过程不执行配置内声明的外部命令，遇到符号链接写入目标或无法完整解析的条件规则时自动中止并提示。
- **交互式管理与 AI 工具协同**：提供 `/ssh` 交互菜单、快捷子命令与主机别名自动补全，并允许 Pi 直接调用 `ssh_manager` 工具完成配置查询与维护。
- **跨平台支持**：支持 Windows、Linux 与 macOS。

## 环境要求

- Node.js `>= 22.19.0`
- 已安装 `@earendil-works/pi-coding-agent`（`pi` 命令可用）
- 使用生成的连接命令或连接远程主机时，本机需安装 OpenSSH 客户端（`ssh`）

## 安装

通过 npm 安装：

```bash
pi install npm:pi-ssh-manager
```

或通过 GitHub 仓库安装：

```bash
pi install https://github.com/onprs/Pi-SSH-Manager.git
```

单次会话临时加载试用：

```bash
pi -e npm:pi-ssh-manager
```

升级与卸载：

```bash
pi update --extensions
pi remove npm:pi-ssh-manager
```

## 快速开始

安装后启动 `pi`（或执行 `/reload`）：

1. 输入 `/ssh` 打开交互式管理菜单，进行查看、编辑、添加或导入操作。
2. 也可直接向 Pi 描述需求，例如“列出 SSH 主机”“查询某台主机的连接信息”“添加 SSH 主机”或“导入这个目录下的 SSH 配置”，由 Pi 调用 `ssh_manager` 工具处理。

## 斜杠命令

在 Pi 交互界面中可使用以下命令：

| 命令 | 说明 |
| --- | --- |
| `/ssh` | 打开主机查看、编辑、添加与导入交互菜单 |
| `/ssh list` | 列出本机已有及受管的 SSH 主机 |
| `/ssh get <主机别名>` | 查看指定主机的地址、密钥状态、连接命令与警告信息 |
| `/ssh import <配置文件或目录路径>` | 从指定 OpenSSH 配置或目录导入主机与凭据 |

## `ssh_manager` 工具说明

| 操作 (`action`) | 用途 | 主要参数 |
| --- | --- | --- |
| `list` | 列出或搜索主机 | `query`、`offset`、`limit` |
| `get` | 查询地址、端口、用户、密钥状态和连接参数 | `host` |
| `upsert` | 添加或更新受管主机 | `host`、`hostname`、`port`、`user`、`identityFiles`、`description`、`options` |
| `delete` | 删除受管的主机记录 | `host` |
| `import` | 导入外部 SSH 配置及引用凭据 | `source`、`overwrite` |

### 参数与配置规则

- 新增主机须提供 `host` 与 `hostname`，`port` 默认为 `22`。
- 更新已有受管主机时保留未提供的字段；传入空字符串可清除 `user` 或 `description`，传入空数组可清除 `identityFiles`；提供 `options` 时整体替换该主机的其他 OpenSSH 选项。
- 密钥路径支持绝对路径与 `~/` 路径（清空请传空数组或 `none`）。
- 导入时遇到同名受管主机默认保留现有记录，设置 `overwrite: true` 可覆盖更新。

## 数据目录与安全说明

- 受管主机数据、生成配置、导入密钥、受管 `known_hosts` 与配置备份保存在 `~/.ssh/pi-ssh-manager/`，并通过标记区块中的 `Include` 接入 `~/.ssh/config`，修改后可直接在终端使用 `ssh <主机别名>`。
- 修改受管文件或 `~/.ssh/config` 前会在 `~/.ssh/pi-ssh-manager/backups/` 自动保留备份。
- 若 `~/.ssh/config` 或受管目标文件为符号链接，写入操作将中止以保护现有链接配置。
- 本扩展仅作静态配置解析与管理，不主动建立 SSH 连接，不读取私钥文件内容，也不执行配置文件中的 `ProxyCommand`、`RemoteCommand` 或 `Match exec` 等指令。

## 开源协议

[MIT](./LICENSE)
