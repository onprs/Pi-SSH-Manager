import { createHash, randomUUID } from "node:crypto";
import type { Stats } from "node:fs";
import { chmod, lstat, mkdir, open, rename, rm, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { withFileMutationQueue } from "@earendil-works/pi-coding-agent";
import { readSshConfig, resolveSshHost, type SshConfigSnapshot } from "./config-reader.ts";
import { getSshPaths, normalizeHost, quoteSshPath, renderSshConfig, validateAlias, type SshHostPatch, type SshHostRecord, type SshPaths, type SshStore } from "./model.ts";

const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_STATE_BYTES = 16 * 1024 * 1024;
const MAX_HOSTS = 500;
const BEGIN = "# >>> pi-ssh-manager >>>";
const END = "# <<< pi-ssh-manager <<<";

type Asset = { content: Buffer; privateKey: boolean };
export interface SshManagerOptions { homeDir?: string }

function missing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException)?.code === "ENOENT";
}

function isHomeRelativePath(value: string): boolean {
  return value.startsWith("~/") || (process.platform === "win32" && value.startsWith("~\\"));
}

function expandHomePath(value: string, home: string): string {
  return isHomeRelativePath(value) ? path.join(home, value.slice(2)) : value;
}

async function readOptional(file: string, maximum = MAX_FILE_BYTES, rejectLinks = false): Promise<Buffer | undefined> {
  let info: Stats;
  try { info = await lstat(file); } catch (error) { if (missing(error)) return undefined; throw error; }
  if (rejectLinks && info.isSymbolicLink()) throw new Error(`[SYMLINK_REJECTED] 写入目标不能是符号链接：${file}`);
  if (!info.isFile() && !info.isSymbolicLink()) throw new Error(`[NOT_A_FILE] 需要普通文件：${file}`);
  // 文件句柄复核尺寸，避免链接目标和读取期间的变化绕过大小限制。
  const handle = await open(file, "r");
  try {
    const actual = await handle.stat();
    if (!actual.isFile() || actual.size > maximum) throw new Error(`[FILE_TOO_LARGE] 文件不是普通文件或超过 ${maximum} 字节：${file}`);
    const buffer = Buffer.alloc(actual.size + 1);
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > maximum || offset > actual.size) throw new Error(`[FILE_CHANGED] 读取期间文件大小发生变化：${file}`);
    return buffer.subarray(0, offset);
  } finally { await handle.close(); }
}

async function privateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`[INVALID_DIRECTORY] 配置目录须为真实目录：${directory}`);
  if (process.platform !== "win32") await chmod(directory, 0o700);
}

async function atomicWrite(file: string, content: string | Buffer): Promise<void> {
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    const handle = await open(temporary, "wx", 0o600);
    try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
    await rename(temporary, file);
  } finally { await rm(temporary, { force: true }); }
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function integrateConfig(original: string, managedConfig: string): string {
  let text = original.replace(/^\uFEFF/, "");
  const start = text.indexOf(BEGIN);
  if (start >= 0) {
    const end = text.indexOf(END, start);
    if (end < 0 || text.indexOf(BEGIN, start + BEGIN.length) >= 0) throw new Error("[INVALID_INCLUDE_BLOCK] ~/.ssh/config 中的 pi-ssh-manager 配置标记不完整或重复。");
    text = text.slice(0, start) + text.slice(end + END.length).replace(/^\r?\n/, "");
  }
  const block = `${BEGIN}\nInclude ${quoteSshPath(managedConfig)}\nHost *\n${END}\n`;
  return block + text;
}

export class SshManager {
  readonly paths: SshPaths;
  constructor(options: SshManagerOptions = {}) { this.paths = getSshPaths(options.homeDir ?? homedir()); }

  private async load(): Promise<SshStore> {
    const content = await readOptional(this.paths.state, MAX_STATE_BYTES, true);
    if (!content) return { version: 1, hosts: [] };
    let data: SshStore;
    try { data = JSON.parse(content.toString("utf8")); } catch { throw new Error("[INVALID_STORE] pi-ssh-manager 主机文件不是有效 JSON，请检查或从备份恢复。"); }
    if (data?.version !== 1 || !Array.isArray(data.hosts) || data.hosts.length > MAX_HOSTS) throw new Error("[INVALID_STORE] pi-ssh-manager 主机文件格式或版本无效。");
    const aliases = new Set<string>();
    const hosts = data.hosts.map((record) => {
      if (!record || typeof record !== "object") throw new Error("[INVALID_STORE] 主机记录无效。");
      const host = normalizeHost({ ...record, host: record.alias });
      if (aliases.has(host.alias)) throw new Error(`[INVALID_STORE] 主机别名重复：${host.alias}`);
      aliases.add(host.alias);
      return host;
    });
    return { version: 1, hosts };
  }

  private async snapshot(signal?: AbortSignal): Promise<SshConfigSnapshot> {
    return readSshConfig({ homeDir: this.paths.home, configPath: this.paths.nativeConfig, signal });
  }

  async list(query = "", offset = 0, limit = 50, signal?: AbortSignal) {
    if (!Number.isInteger(offset) || offset < 0 || !Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("[INVALID_PAGE] offset 须为非负整数，limit 须为 1～100。");
    return withFileMutationQueue(this.paths.nativeConfig, async () => {
      signal?.throwIfAborted();
      const store = await this.load();
      const snapshot = await this.snapshot(signal);
      const managed = new Map(store.hosts.map((host) => [host.alias, host]));
      const aliases = [...new Set([...snapshot.hosts.map((host) => host.alias), ...managed.keys()])].sort((a, b) => a.localeCompare(b, "en"));
      const filter = query.trim().toLowerCase();
      const matching = aliases.filter((alias) => {
        const record = managed.get(alias);
        return !filter || [alias, record?.hostname, record?.user, record?.description].some((value) => value?.toLowerCase().includes(filter));
      });
      const selected = matching.slice(offset, offset + limit);
      return {
        configPath: this.paths.nativeConfig,
        managedDirectory: this.paths.directory,
        hostCount: aliases.length,
        managedHostCount: managed.size,
        matchingHostCount: matching.length,
        offset,
        limit,
        hasMore: offset + selected.length < matching.length,
        hosts: selected.map((alias) => {
          const record = managed.get(alias);
          return { alias, managed: Boolean(record), ...(record ? { hostname: record.hostname, port: record.port, user: record.user, description: record.description } : {}) };
        }),
        warnings: snapshot.warnings.slice(0, 12).map((warning) => warning.length > 512 ? `${warning.slice(0, 512)}…` : warning),
        warningCount: snapshot.warnings.length,
        warningsTruncated: snapshot.warnings.length > 12,
        warningCategories: snapshot.warningCategories,
      };
    });
  }

  async get(alias: string, signal?: AbortSignal) {
    return withFileMutationQueue(this.paths.nativeConfig, async () => {
      signal?.throwIfAborted();
      const store = await this.load();
      const record = store.hosts.find((host) => host.alias === alias);
      let snapshot = await this.snapshot(signal);
      let configPath = this.paths.nativeConfig;
      if (record && !snapshot.hosts.some((host) => host.alias === alias)) {
        configPath = this.paths.config;
        snapshot = await readSshConfig({ homeDir: this.paths.home, configPath, signal });
      }
      const resolved = resolveSshHost(snapshot, alias);
      const sshArguments = ["-F", configPath, "--", alias];
      const identities = Array.isArray(resolved.options.identityfile) ? resolved.options.identityfile : [];
      const identityFiles = await Promise.all(identities.map(async (file) => {
        if (file === "none" || /%(?!%)/.test(file) || file.includes("${")) return { path: file, exists: null };
        const expanded = expandHomePath(file, this.paths.home);
        if (!path.isAbsolute(expanded)) return { path: file, exists: null };
        try { const info = await stat(expanded); return { path: file, exists: info.isFile() }; }
        catch (error) { if (missing(error)) return { path: file, exists: false }; return { path: file, exists: null }; }
      }));
      signal?.throwIfAborted();
      return {
        sshAlias: alias,
        managed: Boolean(record),
        description: record?.description,
        configPath,
        hostname: resolved.options.hostname ?? alias,
        port: resolved.options.port ? Number(resolved.options.port) : 22,
        user: resolved.options.user,
        sshArguments,
        command: ["ssh", ...sshArguments].map(shellQuote).join(" "),
        commandArgumentSafe: /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(alias),
        identityFiles,
        host: resolved,
      };
    });
  }

  async upsert(patch: SshHostPatch, signal?: AbortSignal) {
    return withFileMutationQueue(this.paths.nativeConfig, async () => {
      signal?.throwIfAborted();
      const store = await this.load();
      const index = store.hosts.findIndex((host) => host.alias === patch.host);
      const normalized = { ...patch };
      if (patch.identityFiles) normalized.identityFiles = patch.identityFiles.map((file) => {
        if (file === "none" || isHomeRelativePath(file) || path.isAbsolute(file)) return file;
        throw new Error("[INVALID_IDENTITY] 密钥路径须为绝对路径、~/ 开头的路径或 none。");
      });
      const host = normalizeHost(normalized, index >= 0 ? store.hosts[index] : undefined);
      if (index >= 0) store.hosts[index] = host;
      else store.hosts.push(host);
      const backupPath = await this.commit(store, new Map(), undefined, signal);
      return { action: "upsert", sshAlias: host.alias, created: index < 0, hostCount: store.hosts.length, configPath: this.paths.config, backupPath };
    });
  }

  async delete(alias: string, signal?: AbortSignal) {
    validateAlias(alias);
    return withFileMutationQueue(this.paths.nativeConfig, async () => {
      signal?.throwIfAborted();
      const store = await this.load();
      const index = store.hosts.findIndex((host) => host.alias === alias);
      if (index < 0) throw new Error(`[HOST_NOT_MANAGED] pi-ssh-manager 没有管理该别名：${alias}`);
      store.hosts.splice(index, 1);
      const backupPath = await this.commit(store, new Map(), undefined, signal);
      return { action: "delete", sshAlias: alias, hostCount: store.hosts.length, backupPath };
    });
  }

  async import(source: string, overwrite = false, signal?: AbortSignal) {
    return withFileMutationQueue(this.paths.nativeConfig, async () => {
      signal?.throwIfAborted();
      const sourcePath = isHomeRelativePath(source) ? expandHomePath(source, this.paths.home) : path.resolve(source);
      const sourceInfo = await lstat(sourcePath);
      const configPath = sourceInfo.isDirectory() ? path.join(sourcePath, "config") : sourcePath;
      const sourceDirectory = path.dirname(configPath);
      if (path.resolve(configPath) === this.paths.nativeConfig || configPath.startsWith(`${this.paths.directory}${path.sep}`)) throw new Error("[SELF_IMPORT] 请使用外部 SSH 配置作为导入来源。");
      const snapshot = await readSshConfig({ configPath, homeDir: path.dirname(sourceDirectory), signal });
      if (!snapshot.found) throw new Error(`[CONFIG_NOT_FOUND] 未找到 SSH 配置：${configPath}`);
      if (snapshot.warnings.length) throw new Error(`[IMPORT_INCOMPLETE] 配置无法完整解析：${snapshot.warnings.join("；")}`);
      if (!snapshot.hosts.length) throw new Error("[NO_HOSTS] 配置中没有具体的 Host 别名。");
      const store = await this.load();
      const assets = new Map<string, Asset>();
      const existing = new Map(store.hosts.map((host) => [host.alias, host]));
      const imported: string[] = [];
      const skipped: string[] = [];
      const knownHostContents: string[] = [];
      const defaultKnownHosts = await readOptional(path.join(sourceDirectory, "known_hosts"));
      if (defaultKnownHosts) knownHostContents.push(defaultKnownHosts.toString("utf8"));

      const sourceFile = (raw: string, host: { alias: string; hostname: string; user?: string; port: number }): string => {
        let value = raw.replaceAll("%%", "\u0000").replaceAll("%d", path.dirname(sourceDirectory)).replaceAll("%h", host.hostname).replaceAll("%n", host.alias).replaceAll("%p", String(host.port));
        if (host.user) value = value.replaceAll("%r", host.user);
        if (/%[A-Za-z]|\$\{/.test(value)) throw new Error(`[DYNAMIC_PATH] 无法解析 ${host.alias} 的文件路径：${raw}`);
        value = value.replaceAll("\u0000", "%");
        if (/^~[\\/]\.ssh[\\/]/.test(value)) return path.join(sourceDirectory, value.slice(7));
        if (/^~[\\/]/.test(value)) return path.join(path.dirname(sourceDirectory), value.slice(2));
        if (/^[A-Za-z]:[\\/]/.test(value)) {
          const normalized = value.replaceAll("\\", "/");
          const sshSegment = normalized.toLowerCase().lastIndexOf("/.ssh/");
          if (sshSegment < 0) throw new Error(`[WINDOWS_PATH] Windows 路径须位于来源 .ssh 目录：${raw}`);
          return path.join(sourceDirectory, normalized.slice(sshSegment + 6));
        }
        return path.isAbsolute(value) ? value : path.resolve(sourceDirectory, value);
      };
      const keyAsset = async (file: string, privateKey: boolean): Promise<string> => {
        signal?.throwIfAborted();
        const content = await readOptional(file);
        if (!content) throw new Error(`[IDENTITY_NOT_FOUND] 来源配置引用的文件不存在：${file}`);
        const digest = createHash("sha256").update(content).digest("hex").slice(0, 16);
        const basename = path.basename(file).replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 100);
        const target = path.join(this.paths.keys, `${basename}-${digest}`);
        assets.set(target, { content, privateKey });
        if (privateKey) {
          const publicContent = await readOptional(`${file}.pub`);
          if (publicContent) assets.set(`${target}.pub`, { content: publicContent, privateKey: false });
        }
        return target;
      };

      for (const summary of snapshot.hosts) {
        signal?.throwIfAborted();
        const alias = validateAlias(summary.alias);
        if (existing.has(alias) && !overwrite) { skipped.push(alias); continue; }
        const resolved = resolveSshHost(snapshot, alias);
        if (resolved.warnings.length || resolved.hiddenOptions.length || resolved.unsupportedOptions.length) {
          throw new Error(`[IMPORT_UNSUPPORTED] ${alias} 包含暂不支持导入的条件或选项：${[...resolved.warnings, ...resolved.hiddenOptions, ...resolved.unsupportedOptions].join("；")}`);
        }
        const { hostname, port, user, identityfile, certificatefile, userknownhostsfile, globalknownhostsfile, ...options } = resolved.options;
        const host = normalizeHost({ host: alias, hostname: typeof hostname === "string" ? hostname : alias, port: port ? Number(port) : 22, user: typeof user === "string" ? user : undefined, options });
        for (const file of Array.isArray(identityfile) ? identityfile : []) {
          host.identityFiles.push(file === "none" ? file : await keyAsset(sourceFile(file, host), true));
        }
        if (Array.isArray(certificatefile)) {
          host.options.certificatefile = [];
          for (const file of certificatefile) (host.options.certificatefile as string[]).push(quoteSshPath(await keyAsset(sourceFile(file, host), false)));
        }
        for (const [name, value] of [["userknownhostsfile", userknownhostsfile], ["globalknownhostsfile", globalknownhostsfile]] as const) {
          if (!value) continue;
          const files = Array.isArray(value) ? value : [value];
          const targetFiles: string[] = [];
          for (const file of files) {
            if (file === "none") { targetFiles.push("none"); continue; }
            targetFiles.push(quoteSshPath(await keyAsset(sourceFile(file, host), false)));
          }
          host.options[name] = targetFiles.join(" ");
        }
        if (!userknownhostsfile && defaultKnownHosts) host.options.userknownhostsfile = `${quoteSshPath(this.paths.knownHosts)} ${quoteSshPath(path.join(this.paths.sshDirectory, "known_hosts"))}`;
        existing.set(alias, host);
        imported.push(alias);
      }
      if (!imported.length) return { action: "import", source: configPath, imported, skipped, hostCount: store.hosts.length, copiedKeyCount: 0 };
      store.hosts = [...existing.values()];
      const previousKnownHosts = await readOptional(this.paths.knownHosts, MAX_FILE_BYTES, true);
      if (previousKnownHosts) knownHostContents.unshift(previousKnownHosts.toString("utf8"));
      const lines = [...new Set(knownHostContents.flatMap((text) => text.split(/\r?\n/)).filter((line) => line.trim()))];
      const knownHosts = lines.length ? `${lines.join("\n")}\n` : undefined;
      const backupPath = await this.commit(store, assets, knownHosts, signal);
      return { action: "import", source: configPath, imported, skipped, hostCount: store.hosts.length, copiedKeyCount: [...assets.values()].filter((asset) => asset.privateKey).length, copiedFileCount: assets.size, knownHostCount: lines.filter((line) => !line.startsWith("#")).length, configPath: this.paths.config, backupPath };
    });
  }

  private async commit(store: SshStore, assets: Map<string, Asset>, knownHosts?: string, signal?: AbortSignal): Promise<string | undefined> {
    signal?.throwIfAborted();
    if (store.hosts.length > MAX_HOSTS) throw new Error(`[HOST_LIMIT] 主机数量超过上限 ${MAX_HOSTS}。`);
    await privateDirectory(this.paths.sshDirectory);
    await privateDirectory(this.paths.directory);
    await privateDirectory(this.paths.keys);
    const state = `${JSON.stringify(store, null, 2)}\n`;
    if (Buffer.byteLength(state) > MAX_STATE_BYTES) throw new Error("[STORE_TOO_LARGE] 主机配置文件超过大小上限。");
    const config = renderSshConfig(store.hosts);
    if (Buffer.byteLength(config) > 1024 * 1024 || config.split("\n").length > 4900) throw new Error("[CONFIG_TOO_LARGE] 生成的 SSH 配置超过解析大小或指令数量上限。");
    const previousNative = await readOptional(this.paths.nativeConfig, MAX_FILE_BYTES, true);
    const updates = new Map<string, string>([
      [this.paths.state, state],
      [this.paths.config, config],
      [this.paths.nativeConfig, integrateConfig(previousNative?.toString("utf8") ?? "", this.paths.config)],
    ]);
    if (knownHosts !== undefined) {
      if (Buffer.byteLength(knownHosts) > MAX_FILE_BYTES) throw new Error("[KNOWN_HOSTS_TOO_LARGE] 合并后的主机指纹文件超过大小上限。");
      updates.set(this.paths.knownHosts, knownHosts);
    }
    const previous = new Map<string, Buffer | undefined>();
    for (const file of updates.keys()) previous.set(file, await readOptional(file, file === this.paths.state ? MAX_STATE_BYTES : MAX_FILE_BYTES, true));
    const changing = [...updates].filter(([file, content]) => previous.get(file)?.toString("utf8") !== content);
    let backupPath: string | undefined;
    if (changing.some(([file]) => previous.get(file) !== undefined)) {
      await privateDirectory(this.paths.backups);
      backupPath = path.join(this.paths.backups, `${new Date().toISOString().replaceAll(":", "-")}-${randomUUID().slice(0, 8)}`);
      await privateDirectory(backupPath);
      for (const [file] of changing) {
        const old = previous.get(file);
        if (old) await atomicWrite(path.join(backupPath, file === this.paths.nativeConfig ? "ssh-config" : path.basename(file)), old);
      }
    }
    signal?.throwIfAborted();
    // 先复制全部凭据再提交配置，配置始终引用已经存在的文件。
    for (const [file, asset] of assets) {
      signal?.throwIfAborted();
      const previousAsset = await readOptional(file, MAX_FILE_BYTES, true);
      if (previousAsset && !previousAsset.equals(asset.content)) throw new Error(`[ASSET_CONFLICT] 已存在不同内容的凭据文件：${file}`);
      if (!previousAsset) await atomicWrite(file, asset.content);
      else if (process.platform !== "win32") await chmod(file, 0o600);
    }
    const changed: string[] = [];
    try {
      for (const [file, content] of changing) {
        signal?.throwIfAborted();
        await atomicWrite(file, content);
        changed.push(file);
      }
    } catch (error) {
      const rollbackErrors: string[] = [];
      for (const file of changed.reverse()) {
        try {
          const content = previous.get(file);
          if (content) await atomicWrite(file, content);
          else await rm(file, { force: true });
        } catch { rollbackErrors.push(file); }
      }
      if (rollbackErrors.length) throw new Error(`[ROLLBACK_FAILED] 写入失败且部分文件恢复失败：${rollbackErrors.join("、")}；备份：${backupPath ?? "无"}`, { cause: error });
      throw error;
    }
    return backupPath;
  }
}
