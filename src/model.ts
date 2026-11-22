import path from "node:path";

export interface SshHostRecord {
  alias: string;
  hostname: string;
  port: number;
  user?: string;
  identityFiles: string[];
  description?: string;
  options: Record<string, string | string[]>;
}

export interface SshHostPatch {
  host: string;
  hostname?: string;
  port?: number;
  user?: string;
  identityFiles?: string[];
  description?: string;
  options?: Record<string, string | string[]>;
}

export interface SshStore {
  version: 1;
  hosts: SshHostRecord[];
}

export interface SshPaths {
  home: string;
  sshDirectory: string;
  nativeConfig: string;
  directory: string;
  state: string;
  config: string;
  keys: string;
  knownHosts: string;
  backups: string;
}

export function getSshPaths(home: string): SshPaths {
  home = path.resolve(home);
  const sshDirectory = path.join(home, ".ssh");
  const directory = path.join(sshDirectory, "pi-ssh-manager");
  return {
    home,
    sshDirectory,
    nativeConfig: path.join(sshDirectory, "config"),
    directory,
    state: path.join(directory, "hosts.json"),
    config: path.join(directory, "config"),
    keys: path.join(directory, "keys"),
    knownHosts: path.join(directory, "known_hosts"),
    backups: path.join(directory, "backups"),
  };
}

export function validateAlias(alias: string): string {
  if (typeof alias !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(alias)) {
    throw new Error("[INVALID_HOST] 主机别名须为 1～255 个字母、数字、点、下划线或短横线，且以字母或数字开头。");
  }
  return alias;
}

function text(value: unknown, name: string, maximum = 2048): string {
  if (typeof value !== "string" || value.length > maximum || /[\x00-\x1f\x7f]/.test(value)) {
    throw new Error(`[INVALID_VALUE] ${name} 必须是长度不超过 ${maximum} 的单行文本。`);
  }
  return value;
}

export function normalizeOptions(value: unknown): Record<string, string | string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("[INVALID_OPTIONS] options 必须是 SSH 选项对象。");
  }
  const entries = Object.entries(value);
  if (entries.length > 96) throw new Error("[INVALID_OPTIONS] SSH 选项不能超过 96 项。");
  const reserved = new Set(["host", "match", "include", "hostname", "port", "user", "identityfile"]);
  const result: Record<string, string | string[]> = Object.create(null);
  for (const [key, raw] of entries) {
    const name = key.toLowerCase();
    if (!/^[a-z][a-z0-9]+$/.test(name) || reserved.has(name) || Object.hasOwn(result, name)) {
      throw new Error(`[INVALID_OPTION] 选项名称无效或重复：${key}；连接字段请使用对应参数。`);
    }
    const values = Array.isArray(raw) ? raw : [raw];
    if (values.length === 0 || values.length > 16) throw new Error(`[INVALID_OPTION] ${key} 须包含 1～16 个值。`);
    const normalized = values.map((item) => {
      const value = text(item, key);
      if (!value.trim() || value.trimStart().startsWith("#")) throw new Error(`[INVALID_OPTION] ${key} 的值为空。`);
      return value;
    });
    result[name] = Array.isArray(raw) ? normalized : normalized[0];
  }
  return result;
}

export function normalizeHost(patch: SshHostPatch, previous?: SshHostRecord): SshHostRecord {
  const alias = validateAlias(patch.host);
  const hostname = text(patch.hostname ?? previous?.hostname, "hostname", 255);
  if (!hostname || /[\s#"'\\]/.test(hostname) || hostname.startsWith("-")) {
    throw new Error("[INVALID_HOSTNAME] hostname 必须是有效的单个主机名或 IP 地址。");
  }
  const port = patch.port ?? previous?.port ?? 22;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("[INVALID_PORT] 端口须为 1～65535 的整数。");
  const user = text(patch.user ?? previous?.user ?? "", "user", 255);
  if (/[\s#"'\\]/.test(user) || user.startsWith("-")) throw new Error("[INVALID_USER] SSH 用户名无效。");
  const identityFiles = patch.identityFiles ?? previous?.identityFiles ?? [];
  if (!Array.isArray(identityFiles) || identityFiles.length > 8) throw new Error("[INVALID_IDENTITY] identityFiles 须为最多 8 项的路径数组。");
  const identities = [...new Set(identityFiles.map((item) => {
    const value = text(item, "identityFiles");
    if (!value.trim()) throw new Error("[INVALID_IDENTITY] 密钥路径不能为空。");
    return value;
  }))];
  const description = text(patch.description ?? previous?.description ?? "", "description", 1000);
  return {
    alias,
    hostname,
    port,
    ...(user ? { user } : {}),
    identityFiles: identities,
    ...(description ? { description } : {}),
    options: normalizeOptions(patch.options ?? previous?.options ?? {}),
  };
}

export function quoteSshPath(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

export function renderSshConfig(hosts: SshHostRecord[]): string {
  const lines = ["# 由 pi-ssh-manager 管理；请通过 Pi 的 ssh_manager 工具或 /ssh 修改。", ""];
  for (const host of [...hosts].sort((a, b) => a.alias.localeCompare(b.alias, "en"))) {
    if (host.description) lines.push(`# ${host.description}`);
    lines.push(`Host ${host.alias}`, `    HostName ${host.hostname}`, `    Port ${host.port}`);
    if (host.user) lines.push(`    User ${host.user}`);
    for (const identity of host.identityFiles) lines.push(`    IdentityFile ${quoteSshPath(identity)}`);
    for (const [key, value] of Object.entries(host.options).sort(([a], [b]) => a.localeCompare(b, "en"))) {
      for (const item of Array.isArray(value) ? value : [value]) lines.push(`    ${key} ${item}`);
    }
    lines.push("");
  }
  // Include 与父文件共享 Host 匹配状态，结束时恢复全局作用域。
  lines.push("Host *", "");
  return lines.join("\n");
}
