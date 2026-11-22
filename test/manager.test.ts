import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it, type TestContext } from "node:test";
import { promisify } from "node:util";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerSshManager } from "../src/index.ts";
import { SshManager } from "../src/manager.ts";

const execute = promisify(execFile);

async function sshOptions(args: string[]): Promise<Record<string, string[]> | undefined> {
  try {
    const { stdout } = await execute("ssh", ["-G", ...args]);
    const result: Record<string, string[]> = {};
    for (const line of stdout.trim().split(/\r?\n/)) {
      const separator = line.indexOf(" ");
      if (separator <= 0) continue;
      const key = line.slice(0, separator);
      (result[key] ??= []).push(line.slice(separator + 1));
    }
    return result;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

async function createSymlinkOrSkip(target: string, linkPath: string, t: TestContext): Promise<boolean> {
  try {
    await symlink(target, linkPath);
    return true;
  } catch (error) {
    if (process.platform === "win32" && (error as NodeJS.ErrnoException)?.code === "EPERM") {
      t.skip("当前 Windows 环境未启用符号链接创建权限");
      return false;
    }
    throw error;
  }
}

describe("SshManager 管理、导入、OpenSSH 兼容与失败恢复", () => {
  it("完成外部配置导入、凭据隔离复制、增量更新、失败回滚、并发串行与工具调用", async (t) => {
    const temporary = await mkdtemp(path.join(tmpdir(), "pi-ssh-manager-"));
    try {
      const home = path.join(temporary, "home with spaces");
      const source = path.join(temporary, "source", ".ssh");
      await mkdir(path.join(home, ".ssh"), { recursive: true });
      await mkdir(source, { recursive: true });
      const originalConfig = "# 用户已有配置\nHost legacy\n  HostName legacy.example\n  User existing\nHost *\n  ConnectTimeout 9\n";
      const nativeConfig = path.join(home, ".ssh", "config");
      await writeFile(nativeConfig, originalConfig);
      const sourceConfig = [
        "Host alpha beta",
        "  BatchMode yes",
        "  IdentitiesOnly yes",
        "  StrictHostKeyChecking yes",
        "  ServerAliveInterval 60",
        "Host alpha",
        "  HostName alpha.example",
        "  User admin",
        "  Port 2222",
        '  IdentityFile "~/.ssh/private key"',
        "Host beta",
        "  HostName 192.0.2.12",
        "  User root",
        "  Port 22",
        "  IdentityFile C:/Users/test/.ssh/other_key",
        "",
      ].join("\n");
      await writeFile(path.join(source, "config"), sourceConfig);
      await writeFile(path.join(source, "private key"), "PRIVATE_KEY_SENTINEL_A\n", { mode: 0o755 });
      await writeFile(path.join(source, "private key.pub"), "PUBLIC_KEY_SENTINEL_A\n");
      await writeFile(path.join(source, "other_key"), "PRIVATE_KEY_SENTINEL_B\n");
      const sourceKnownHosts = "alpha.example ssh-ed25519 dGVzdA==\n192.0.2.12 ssh-ed25519 dGVzdDI=\n";
      await writeFile(path.join(source, "known_hosts"), sourceKnownHosts.replace("\n", "\r\n"));
      const nativeKnownHosts = "legacy.example ssh-ed25519 bGVnYWN5\n";
      await writeFile(path.join(home, ".ssh", "known_hosts"), nativeKnownHosts);

      const manager = new SshManager({ homeDir: home });
      const before = await manager.list();
      assert.equal(before.hostCount, 1, "应查询已有的 SSH 主机");
      assert.equal(before.managedHostCount, 0);

      const imported = await manager.import(source);
      assert.deepEqual(imported.imported, ["alpha", "beta"]);
      assert.equal(imported.copiedKeyCount, 2);
      assert.equal(imported.copiedFileCount, 3);
      assert.equal(imported.knownHostCount, 2);
      assert.ok(imported.backupPath, "已有配置修改前应保存备份");
      assert.equal(await readFile(path.join(imported.backupPath, "ssh-config"), "utf8"), originalConfig);
      assert.ok((await readFile(nativeConfig, "utf8")).endsWith(originalConfig), "应保留原配置及注释");
      assert.equal(await readFile(path.join(source, "config"), "utf8"), sourceConfig, "导入不能修改来源配置");
      assert.equal(await readFile(path.join(home, ".ssh", "known_hosts"), "utf8"), nativeKnownHosts, "导入不能覆盖本机主机指纹");
      assert.equal(await readFile(manager.paths.knownHosts, "utf8"), sourceKnownHosts);
      if (process.platform !== "win32") {
        assert.equal((await lstat(manager.paths.directory)).mode & 0o777, 0o700);
        assert.equal((await lstat(manager.paths.state)).mode & 0o777, 0o600);
        assert.equal((await lstat(manager.paths.config)).mode & 0o777, 0o600);
        assert.equal((await lstat(nativeConfig)).mode & 0o777, 0o600);
      }

      const alpha = await manager.get("alpha");
      assert.equal(alpha.hostname, "alpha.example");
      assert.equal(alpha.port, 2222);
      assert.equal(alpha.user, "admin");
      assert.equal(alpha.host.options.batchmode, "yes", "应保留多主机块的继承设置");
      assert.equal(alpha.host.options.serveraliveinterval, "60");
      assert.equal(alpha.host.options.connecttimeout, "9", "应保留本机全局配置的继承设置");
      assert.equal(alpha.identityFiles[0].exists, true);
      assert.ok(alpha.identityFiles[0].path.startsWith(manager.paths.keys));
      assert.equal(await readFile(alpha.identityFiles[0].path, "utf8"), "PRIVATE_KEY_SENTINEL_A\n");
      assert.equal(await readFile(`${alpha.identityFiles[0].path}.pub`, "utf8"), "PUBLIC_KEY_SENTINEL_A\n");
      if (process.platform !== "win32") assert.equal((await lstat(alpha.identityFiles[0].path)).mode & 0o777, 0o600);
      assert.ok(!JSON.stringify(alpha).includes("PRIVATE_KEY_SENTINEL"), "查询输出不能包含密钥内容");

      const nativeAlpha = await sshOptions(alpha.sshArguments);
      if (nativeAlpha) {
        assert.equal(nativeAlpha.hostname[0], "alpha.example");
        assert.equal(nativeAlpha.port[0], "2222");
        assert.equal(nativeAlpha.batchmode[0], "yes");
        assert.equal(nativeAlpha.connecttimeout[0], "9");
        assert.equal(
          path.normalize(nativeAlpha.identityfile[0]),
          path.normalize(alpha.identityFiles[0].path),
        );
        const nativeLegacy = await sshOptions(["-F", nativeConfig, "--", "legacy"]);
        assert.equal(nativeLegacy?.hostname[0], "legacy.example", "Include 不能破坏已有 Host 块的作用域");
      } else {
        t.diagnostic("当前环境未安装 OpenSSH 客户端，跳过 ssh -G 实机解析校验");
      }

      const beta = await manager.get("beta");
      assert.equal(beta.identityFiles[0].exists, true, "应转换 Windows .ssh 绝对路径");

      const repeated = await manager.import(source);
      assert.deepEqual(repeated.imported, []);
      assert.deepEqual(repeated.skipped, ["alpha", "beta"]);
      await manager.upsert({ host: "alpha", port: 2200, description: "数据库维护" });
      const updated = await manager.get("alpha");
      assert.equal(updated.port, 2200);
      assert.equal(updated.hostname, "alpha.example", "部分更新应保留未提供的字段");
      assert.equal(updated.host.options.batchmode, "yes");
      const search = await manager.list("数据库", 0, 1);
      assert.equal(search.matchingHostCount, 1);
      assert.equal(search.hosts[0].alias, "alpha");
      const page = await manager.list("a", 0, 1);
      assert.ok(page.hasMore, "应提供搜索分页");
      const overwritten = await manager.import(source, true);
      assert.equal(overwritten.imported.length, 2);
      assert.equal((await manager.get("alpha")).port, 2222);
      assert.equal((await readFile(nativeConfig, "utf8")).split("# >>> pi-ssh-manager >>>").length, 2, "重复写入不能重复添加 Include");

      await assert.rejects(() => manager.upsert({ host: "bad-host", hostname: "bad\nHost injected" }), /INVALID_/);
      await assert.rejects(() => manager.upsert({ host: "bad-host", hostname: "good.example", options: { Host: "injected" } }), /INVALID_OPTION/);
      await assert.rejects(() => manager.upsert({ host: "-bad", hostname: "good.example" }), /INVALID_HOST/);
      await assert.rejects(() => manager.upsert({ host: "bad-host", hostname: "good.example", identityFiles: ["relative_key"] }), /INVALID_IDENTITY/);
      await assert.rejects(() => manager.delete("legacy"), /HOST_NOT_MANAGED/);
      const noMatch = await manager.list("does-not-exist");
      assert.equal(noMatch.matchingHostCount, 0);

      const badSource = path.join(temporary, "unsupported", ".ssh");
      await mkdir(badSource, { recursive: true });
      const commandMarker = path.join(temporary, "command-ran");
      await writeFile(path.join(badSource, "config"), `Host unsupported\n HostName safe.example\n ProxyCommand touch ${commandMarker}\n`);
      await assert.rejects(() => manager.import(badSource), /IMPORT_UNSUPPORTED/);
      await assert.rejects(() => lstat(commandMarker), { code: "ENOENT" });
      await writeFile(path.join(badSource, "config"), "Host missing-key\n HostName safe.example\n IdentityFile ~/.ssh/missing\n");
      await assert.rejects(() => manager.import(badSource), /IDENTITY_NOT_FOUND/);
      assert.equal((await manager.list()).managedHostCount, 2, "导入失败不能写入部分主机");

      const stateBeforeFailure = await readFile(manager.paths.state, "utf8");
      const configBeforeFailure = await readFile(manager.paths.config, "utf8");
      const failing = new SshManager({ homeDir: home });
      failing.paths.nativeConfig = path.join(home, "missing-directory", "config");
      await assert.rejects(() => failing.upsert({ host: "must-rollback", hostname: "rollback.example" }), /ENOENT/);
      assert.equal(await readFile(manager.paths.state, "utf8"), stateBeforeFailure, "写入中途失败应恢复主机文件");
      assert.equal(await readFile(manager.paths.config, "utf8"), configBeforeFailure, "写入中途失败应恢复生成配置");

      await Promise.all(Array.from({ length: 6 }, (_, i) => manager.upsert({ host: `parallel-${i}`, hostname: `parallel-${i}.example` })));
      assert.equal((await manager.list("parallel-")).matchingHostCount, 6, "同一进程的并发更新不能丢失主机");
      await manager.delete("alpha");
      await assert.rejects(() => manager.get("alpha"), /HOST_NOT_FOUND/);
      assert.equal((await manager.get("legacy")).hostname, "legacy.example");
      assert.equal(await readFile(alpha.identityFiles[0].path, "utf8"), "PRIVATE_KEY_SENTINEL_A\n", "删除主机记录不应删除密钥文件");

      const cancelled = new AbortController();
      cancelled.abort();
      await assert.rejects(() => manager.upsert({ host: "cancelled", hostname: "cancelled.example" }, cancelled.signal), /AbortError/);
      assert.equal((await manager.list("cancelled")).matchingHostCount, 0);

      let tool: any;
      let command: any;
      registerSshManager(
        {
          registerTool(value: unknown) {
            tool = value;
          },
          registerCommand(name: string, value: unknown) {
            assert.equal(name, "ssh");
            command = value;
          },
        } as unknown as ExtensionAPI,
        { homeDir: home },
      );
      assert.equal(tool.name, "ssh_manager");
      assert.equal(tool.executionMode, "sequential");
      assert.ok(tool.outputSchema, "应声明结构化工具结果以便 codemode 使用");
      assert.equal(typeof command.handler, "function");

      const toolList = await tool.execute("list", { action: "list" });
      assert.equal(toolList.structuredContent.hostCount, 8);
      const toolWrite = await tool.execute("upsert", { action: "upsert", host: "via-tool", hostname: "via-tool.example", user: "operator", options: { ServerAliveInterval: "30" } });
      assert.equal(toolWrite.details.created, true);
      const toolGet = await tool.execute("get", { action: "get", host: "via-tool" });
      assert.equal(toolGet.structuredContent.hostname, "via-tool.example");
      assert.equal(toolGet.details.host.options.serveraliveinterval, "30");
      assert.ok(!toolGet.content[0].text.includes("PRIVATE_KEY_SENTINEL"));
      await assert.rejects(() => tool.execute("missing-host", { action: "get" }), /REQUIRED/);
      await tool.execute("delete", { action: "delete", host: "via-tool" });

      if (process.platform !== "win32") {
        await chmod(source, 0o700);
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });

  it("识别密钥文件符号链接状态并在写入目标为符号链接时中止", async (t) => {
    const temporary = await mkdtemp(path.join(tmpdir(), "pi-ssh-symlink-"));
    try {
      const home = path.join(temporary, "home");
      await mkdir(path.join(home, ".ssh"), { recursive: true });
      const manager = new SshManager({ homeDir: home });
      const keyTarget = path.join(temporary, "real-key");
      await writeFile(keyTarget, "KEY_DATA\n");

      const validIdentityLink = path.join(temporary, "identity-link");
      const brokenIdentityLink = path.join(temporary, "broken-identity-link");
      if (!(await createSymlinkOrSkip(keyTarget, validIdentityLink, t))) return;
      if (!(await createSymlinkOrSkip(path.join(temporary, "absent-identity"), brokenIdentityLink, t))) return;

      await manager.upsert({
        host: "identity-links",
        hostname: "links.example",
        identityFiles: [validIdentityLink, brokenIdentityLink],
      });
      assert.deepEqual(
        (await manager.get("identity-links")).identityFiles.map((identity) => identity.exists),
        [true, false],
        "密钥路径检查应识别有效链接和失效链接",
      );
      await manager.delete("identity-links");

      const linkedHome = path.join(temporary, "linked-home");
      await mkdir(path.join(linkedHome, ".ssh"), { recursive: true });
      const linkedTarget = path.join(temporary, "linked-target");
      const originalConfig = "Host legacy\n  HostName legacy.example\n";
      await writeFile(linkedTarget, originalConfig);
      if (!(await createSymlinkOrSkip(linkedTarget, path.join(linkedHome, ".ssh", "config"), t))) return;

      const linkedManager = new SshManager({ homeDir: linkedHome });
      await assert.rejects(() => linkedManager.upsert({ host: "linked", hostname: "linked.example" }), /SYMLINK_REJECTED/);
      assert.equal(await readFile(linkedTarget, "utf8"), originalConfig);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});
