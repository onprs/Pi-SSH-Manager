import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { readSshConfig, resolveSshHost } from "../src/config-reader.ts";
import { registerOnprsSSH } from "../src/index.ts";

describe("OpenSSH 静态配置读取与工具查询边界", () => {
  it("递归解析 Include、通配/否定 Host、隐藏危险指令并执行资源与敏感文件防护", async () => {
    const temporaryHome = await mkdtemp(path.join(tmpdir(), "pi-ssh-reader-"));
    const sshDirectory = path.join(temporaryHome, ".ssh");
    const includedDirectory = path.join(sshDirectory, "conf.d");
    const spacedDirectory = path.join(sshDirectory, "more configs");
    const restrictedDirectory = path.join(sshDirectory, "restricted");

    try {
      await Promise.all([
        mkdir(includedDirectory, { recursive: true }),
        mkdir(spacedDirectory, { recursive: true }),
        mkdir(restrictedDirectory, { recursive: true }),
      ]);

      await writeFile(
        path.join(sshDirectory, "config"),
        [
          'Include "more configs/host.conf"',
          "Host *",
          "Include conf.d/*.conf",
          "Include conf.d/%h.conf",
          "Include known_hosts",
          "Include key_sensitive",
          "",
          "Host target-one target-two",
          "  BatchMode yes",
          "  StrictHostKeyChecking accept-new",
          "  ProxyCommand helper --token secret-token",
          "  KnownHostsCommand lookup-host-key secret-known-host-token",
          "  PermitLocalCommand yes",
          "  LocalForward 9000 internal.example:9000",
          "",
          "Host target-one",
          "  Port 2201",
          "  User root",
          "",
          'Match exec "printf should-not-run"',
          "  HostName unsafe.example",
          "Match all",
          "",
          "Host parent-only",
          "  Include restricted/*.conf",
          "",
          "Host bracket[host]",
          "  HostName bracket.example",
          "Host hash#host # token 内的井号不是注释",
          "  HostName hash#node # 空白后的井号开始注释",
          "Host =equal-host",
          "  HostName =equal.example",
          `Host ${"a".repeat(300)}`,
          "Host long-value",
          `  HostName ${"x".repeat(600)}`,
          "Host unsafe;alias",
          "  HostName unsafe-alias.example",
        ].join("\n"),
        "utf8",
      );
      await writeFile(
        path.join(includedDirectory, "10-hosts.conf"),
        [
          "Host target-*",
          "  User wildcard-user",
          "Host target-* !target-two",
          "  ConnectTimeout 9",
          "Host target-one",
          "  HostName one.example",
          "  IdentityFile ~/.ssh/target-one",
          "  RemoteCommand run-sensitive-command",
          "Host target-two",
          "  HostName two.example",
          "  IdentityFile ~/.ssh/target-two",
        ].join("\n"),
        "utf8",
      );
      await writeFile(path.join(includedDirectory, "20-cycle.conf"), "Include config\n", "utf8");
      await writeFile(path.join(sshDirectory, "known_hosts"), "Host leaked-known-host\n", "utf8");
      await writeFile(path.join(sshDirectory, "key_sensitive"), "Host leaked-private-key\n", "utf8");
      await writeFile(
        path.join(spacedDirectory, "host.conf"),
        "Host extra-host\n  HostName extra.example\n",
        "utf8",
      );
      await writeFile(
        path.join(restrictedDirectory, "hidden.conf"),
        "Host unreachable-host\n  HostName unreachable.example\n",
        "utf8",
      );

      const snapshot = await readSshConfig({ homeDir: temporaryHome });
      assert.equal(snapshot.found, true, "应找到用户级 OpenSSH 配置");
      assert.equal(snapshot.configFiles.length, 5, "应递归读取主配置及其四个 Include 文件");
      assert.ok(snapshot.hosts.some((host) => host.alias === "target-one"), "应发现主配置中的第一个别名");
      assert.ok(snapshot.hosts.some((host) => host.alias === "target-two"), "应发现主配置中的第二个别名");
      assert.ok(snapshot.hosts.some((host) => host.alias === "extra-host"), "应处理带空格的 Include 路径");
      assert.ok(snapshot.hosts.some((host) => host.alias === "parent-only"), "应保留包含受限 Include 的父别名");
      assert.ok(snapshot.hosts.some((host) => host.alias === "bracket[host]"), "Host 中的方括号应按字面值处理");
      assert.ok(snapshot.hosts.some((host) => host.alias === "hash#host"), "token 中的井号应按字面值处理");
      assert.ok(snapshot.hosts.some((host) => host.alias === "equal-host"), "应处理等号连接的 Host 参数");
      assert.ok(snapshot.hosts.some((host) => host.alias === "long-value"), "超长配置值不应影响别名发现");
      assert.ok(snapshot.hosts.some((host) => host.alias === "unsafe;alias"), "应发现包含 shell 元字符的合法配置别名");
      assert.ok(!snapshot.hosts.some((host) => host.alias === "unreachable-host"), "不应暴露未激活 Include 中的别名");
      assert.ok(!snapshot.hosts.some((host) => host.alias.startsWith("leaked-")), "不应解析已知密钥或主机记录文件");
      assert.ok(snapshot.warnings.some((warning) => warning.includes("循环 Include")), "应报告循环 Include");
      assert.ok(snapshot.warnings.some((warning) => warning.includes("SSH 密钥或主机记录")), "应报告敏感 Include 文件被拒绝");
      assert.ok(snapshot.warningCategories.includes("sensitive_file_rejected"), "应保留敏感文件拒绝类别");
      assert.ok(snapshot.warnings.some((warning) => warning.includes("%h")), "应报告无法静态求值的 Include token");
      assert.ok(snapshot.warnings.some((warning) => warning.includes("Host 模式超过长度上限")), "应忽略超长 Host 模式并报告 warning");

      assert.throws(() => resolveSshHost(snapshot, "TARGET-ONE"), /HOST_NOT_FOUND/, "主机别名查找应遵循 OpenSSH 大小写敏感语义");

      const targetOne = resolveSshHost(snapshot, "target-one");
      assert.equal(targetOne.alias, "target-one", "应返回配置中大小写完全一致的别名");
      assert.equal(targetOne.options.hostname, "one.example", "应读取 Include 中的 HostName");
      assert.equal(targetOne.options.user, "wildcard-user", "应遵循 OpenSSH 的首个值优先规则");
      assert.equal(targetOne.options.port, "2201", "应合并后续具体 Host 块中的未设置选项");
      assert.equal(targetOne.options.connecttimeout, "9", "应应用带否定模式的通配 Host 块");
      assert.ok(Array.isArray(targetOne.options.identityfile), "IdentityFile 应按多值选项返回");
      assert.ok(targetOne.hiddenOptions.includes("proxycommand"), "应仅标记 ProxyCommand，不暴露原文");
      assert.ok(targetOne.hiddenOptions.includes("knownhostscommand"), "应仅标记 KnownHostsCommand，不暴露原文");
      assert.ok(targetOne.hiddenOptions.includes("permitlocalcommand"), "应标记允许执行本地命令的配置");
      assert.ok(targetOne.hiddenOptions.includes("remotecommand"), "应仅标记 RemoteCommand，不暴露原文");
      assert.ok(targetOne.hiddenOptions.includes("localforward"), "应仅标记转发项，不暴露原文");
      assert.ok(targetOne.warnings.some((warning) => warning.includes("Match 条件")), "应说明 Match 条件未求值");

      const targetTwo = resolveSshHost(snapshot, "target-two");
      assert.equal(targetTwo.options.connecttimeout, undefined, "否定 Host 模式应排除目标别名");
      assert.equal(targetTwo.options.hostname, "two.example", "应解析第二个具体别名");
      assert.equal(resolveSshHost(snapshot, "bracket[host]").options.hostname, "bracket.example", "方括号别名不应作为字符类");
      assert.equal(resolveSshHost(snapshot, "hash#host").options.hostname, "hash#node", "应保留 token 内的井号并移除行尾注释");
      assert.equal(resolveSshHost(snapshot, "equal-host").options.hostname, "equal.example", "应移除参数前的等号");

      const longValue = resolveSshHost(snapshot, "long-value");
      assert.ok(String(longValue.options.hostname).endsWith("…"), "超长单值配置应明确显示截断");
      assert.ok(longValue.warnings.some((warning) => warning.includes("配置值超过长度上限")), "超长单值配置应返回截断 warning");

      const serializedSnapshot = JSON.stringify(snapshot);
      assert.ok(!serializedSnapshot.includes("secret-token"), "公开快照不应包含配置指令原文");
      assert.ok(!serializedSnapshot.includes("secret-known-host-token"), "公开快照不应包含主机密钥命令原文");
      assert.ok(!serializedSnapshot.includes("run-sensitive-command"), "公开快照不应包含远程命令原文");

      let tool: any;
      registerOnprsSSH(
        {
          registerCommand() {},
          registerTool(definition: unknown) {
            tool = definition;
          },
        } as unknown as ExtensionAPI,
        { homeDir: temporaryHome },
      );
      assert.equal(tool?.name, "onprsSSH", "应注册 onprsSSH 工具");

      const listResult = await tool.execute("test-list", { action: "list" }, undefined, undefined);
      assert.equal(listResult.details.configPath, path.join(sshDirectory, "config"), "list 应报告配置路径");
      assert.ok(listResult.details.hosts.some((host: { alias: string }) => host.alias === "target-one"), "list 应返回具体主机别名");
      assert.ok(!listResult.content[0].text.includes("secret-token"), "list 输出不应包含隐藏配置值");

      const pagedResult = await tool.execute(
        "test-page",
        { action: "list", query: "target-", offset: 0, limit: 1 },
        undefined,
        undefined,
      );
      assert.equal(pagedResult.details.hosts.length, 1, "list 应遵守分页数量");
      assert.equal(pagedResult.details.matchingHostCount, 2, "list 应返回筛选后的总数");
      assert.equal(pagedResult.details.hasMore, true, "list 应说明还有后续分页");

      const getResult = await tool.execute(
        "test-get",
        { action: "get", host: "target-one" },
        undefined,
        undefined,
      );
      assert.equal(getResult.details.sshAlias, "target-one", "get 应返回 SSH 配置别名");
      assert.equal(getResult.details.commandArgumentSafe, true, "普通别名应标记为可安全传参");
      assert.equal(getResult.details.sshArguments.at(-2), "--", "SSH 参数应在别名前终止选项解析");
      assert.equal(getResult.details.host.options.hostname, "one.example", "get 应返回安全配置摘要");
      assert.ok(!getResult.content[0].text.includes("secret-token"), "get 输出不应包含 ProxyCommand 原文");
      assert.ok(!getResult.content[0].text.includes("secret-known-host-token"), "get 输出不应包含 KnownHostsCommand 原文");
      assert.ok(!getResult.content[0].text.includes("run-sensitive-command"), "get 输出不应包含 RemoteCommand 原文");

      const unsafeAliasResult = await tool.execute(
        "test-unsafe-alias",
        { action: "get", host: "unsafe;alias" },
        undefined,
        undefined,
      );
      assert.equal(unsafeAliasResult.details.commandArgumentSafe, false, "含 shell 元字符的别名应标记为不可直接拼接");
      assert.equal(unsafeAliasResult.details.sshArguments.at(-2), "--", "异常别名仍应提供参数数组形式");

      await assert.rejects(
        () => tool.execute("test-missing-host", { action: "get" }, undefined, undefined),
        /REQUIRED/,
        "get 缺少 host 时应失败",
      );
      await assert.rejects(
        () => tool.execute("test-unknown-host", { action: "get", host: "unknown" }, undefined, undefined),
        /HOST_NOT_FOUND/,
        "get 使用未知别名时应失败",
      );
    } finally {
      await rm(temporaryHome, { recursive: true, force: true });
    }
  });

  it("正确处理警告上限截断、节点预算、空目录及 AbortSignal 取消", async () => {
    const temporaryHome = await mkdtemp(path.join(tmpdir(), "pi-ssh-limits-"));
    try {
      const warningHome = path.join(temporaryHome, "warning-home");
      const warningSshDirectory = path.join(warningHome, ".ssh");
      await mkdir(warningSshDirectory, { recursive: true });
      await writeFile(
        path.join(warningSshDirectory, "config"),
        [
          "Host warning-host",
          "  HostName warning.example",
          ...Array.from({ length: 14 }, (_, index) => `Include conf.d/%h-${index}.conf`),
        ].join("\n"),
        "utf8",
      );

      let warningTool: any;
      registerOnprsSSH(
        {
          registerCommand() {},
          registerTool(definition: unknown) {
            warningTool = definition;
          },
        } as unknown as ExtensionAPI,
        { homeDir: warningHome },
      );

      const warningResult = await warningTool.execute("test-warning-limit", { action: "list" }, undefined, undefined);
      assert.ok(warningResult.details.warningCount > warningResult.details.warnings.length, "工具应返回截断前的 warning 总数");
      assert.equal(warningResult.details.warningsTruncated, true, "工具应明确标记 warning 列表已截断");
      assert.ok(warningResult.details.warnings.some((warning: string) => warning.includes("%h")), "公开 warning 应包含动态 Include 拒绝原因");
      assert.ok(warningResult.details.warningCategories.includes("dynamic_include_rejected"), "warning 截断后仍应保留动态 Include 类别");

      const nodeLimitHome = path.join(temporaryHome, "node-limit-home");
      const nodeLimitSshDirectory = path.join(nodeLimitHome, ".ssh");
      await mkdir(nodeLimitSshDirectory, { recursive: true });
      await writeFile(
        path.join(nodeLimitSshDirectory, "config"),
        [
          ...Array.from({ length: 5100 }, () => "Host *"),
          "Host after-node-limit",
          "  HostName ignored.example",
        ].join("\n"),
        "utf8",
      );
      const nodeLimitSnapshot = await readSshConfig({ homeDir: nodeLimitHome });
      assert.equal(nodeLimitSnapshot.hosts.length, 0, "达到节点预算后不应继续解析后续别名");
      assert.ok(nodeLimitSnapshot.warningCategories.includes("resource_limit"), "节点预算应返回资源限制类别");

      const emptyHome = path.join(temporaryHome, "empty-home");
      await mkdir(emptyHome, { recursive: true });
      const emptySnapshot = await readSshConfig({ homeDir: emptyHome });
      assert.equal(emptySnapshot.found, false, "缺少 ~/.ssh/config 时应平稳返回未找到");
      assert.equal(emptySnapshot.hosts.length, 0, "缺少配置时不应返回主机别名");

      const cancelled = new AbortController();
      cancelled.abort();
      await assert.rejects(
        () => readSshConfig({ homeDir: warningHome, signal: cancelled.signal }),
        /AbortError/,
        "解析开始前取消时应立即中止",
      );
    } finally {
      await rm(temporaryHome, { recursive: true, force: true });
    }
  });
});
