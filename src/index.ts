import { DEFAULT_MAX_BYTES, DEFAULT_MAX_LINES, truncateHead, type ExtensionAPI, type ExtensionContext } from "@earendil-works/pi-coding-agent";
import type { JsonObject } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { SshManager, type SshManagerOptions } from "./manager.ts";
import type { SshHostPatch } from "./model.ts";

export { readSshConfig, resolveSshHost, type ResolvedSshHost, type SshConfigReadOptions, type SshConfigSnapshot, type SshConfigSource, type SshHostSummary } from "./config-reader.ts";
export { SshManager, type SshManagerOptions } from "./manager.ts";
export { getSshPaths, normalizeHost, normalizeOptions, quoteSshPath, renderSshConfig, validateAlias, type SshHostPatch, type SshHostRecord, type SshPaths, type SshStore } from "./model.ts";

function stringEnum<T extends readonly string[]>(
  values: T,
  options?: { description?: string; default?: T[number] },
) {
  return Type.Unsafe<T[number]>({
    type: "string",
    enum: [...values],
    ...(options?.description && { description: options.description }),
    ...(options?.default && { default: options.default }),
  });
}

const parameters = Type.Object({
  action: Type.Optional(stringEnum(["list", "get", "upsert", "delete", "import"] as const, { description: "默认 list。get 查询连接信息；upsert 添加或更新主机；delete 删除受管理的主机；import 导入外部 SSH 配置和引用的密钥。" })),
  host: Type.Optional(Type.String({ description: "get/upsert/delete 使用的主机别名。", minLength: 1, maxLength: 255 })),
  query: Type.Optional(Type.String({ description: "list 的搜索词，可匹配别名及受管理主机的地址、用户和备注。", maxLength: 255 })),
  offset: Type.Optional(Type.Integer({ description: "list 的分页起点，默认 0。", minimum: 0 })),
  limit: Type.Optional(Type.Integer({ description: "list 的每页数量，默认 50，最大 100。", minimum: 1, maximum: 100 })),
  hostname: Type.Optional(Type.String({ description: "主机名或 IP；新增主机时必填。", minLength: 1, maxLength: 255 })),
  port: Type.Optional(Type.Integer({ description: "SSH 端口，新增时默认 22。", minimum: 1, maximum: 65535 })),
  user: Type.Optional(Type.String({ description: "SSH 用户名；空字符串清除显式用户名。", maxLength: 255 })),
  identityFiles: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 2048 }), { description: "密钥文件的绝对路径或 ~/ 路径；空数组清除显式密钥。", maxItems: 8 })),
  description: Type.Optional(Type.String({ description: "主机备注；空字符串清除备注。", maxLength: 1000 })),
  options: Type.Optional(Type.Record(Type.String(), Type.Union([Type.String({ maxLength: 2048 }), Type.Array(Type.String({ maxLength: 2048 }), { minItems: 1, maxItems: 16 })]), { description: "其他 OpenSSH 选项，值使用 SSH 配置语法；数组表示重复指令。提供时替换该主机原有的其他选项。" })),
  source: Type.Optional(Type.String({ description: "import 的来源目录或 config 文件路径。目录中引用的密钥和 known_hosts 会复制到 onprsSSH 数据目录。", minLength: 1, maxLength: 2048 })),
  overwrite: Type.Optional(Type.Boolean({ description: "import 时是否覆盖同名受管理主机，默认 false，保留现有记录。" })),
});

function result(data: Record<string, unknown>) {
  const serialized = JSON.stringify(data, null, 2);
  const truncated = truncateHead(serialized, { maxBytes: DEFAULT_MAX_BYTES, maxLines: DEFAULT_MAX_LINES });
  const value = truncated.truncated ? {
    outputTruncated: true,
    message: "结果超过输出上限，请缩小 query 或 limit 后重新查询。",
    action: data.action,
    sshAlias: data.sshAlias,
    hostCount: data.hostCount,
    matchingHostCount: data.matchingHostCount,
    sshArguments: data.sshArguments,
    configPath: data.configPath,
    commandArgumentSafe: data.commandArgumentSafe,
    hiddenOptions: (data.host as Record<string, unknown> | undefined)?.hiddenOptions,
    unsupportedOptions: (data.host as Record<string, unknown> | undefined)?.unsupportedOptions,
    warnings: ((data.host as Record<string, unknown> | undefined)?.warnings as string[] | undefined)?.slice(0, 12).map((warning) => warning.slice(0, 512)),
  } : data;
  const structuredContent: JsonObject = JSON.parse(JSON.stringify(value));
  return { content: [{ type: "text" as const, text: JSON.stringify(structuredContent, null, 2) }], details: structuredContent, structuredContent };
}

function required(value: string | undefined, field: string): string {
  if (!value?.trim()) throw new Error(`[REQUIRED] 缺少 ${field}。`);
  return value.trim();
}

async function editHost(manager: SshManager, ctx: ExtensionContext, alias?: string) {
  const details = alias ? await manager.get(alias) : undefined;
  const host = alias ?? await ctx.ui.input("主机别名");
  if (!host) return;
  const hostname = await ctx.ui.input("主机名或 IP", details ? String(details.hostname) : "");
  if (hostname === undefined) return;
  const user = await ctx.ui.input("SSH 用户名", details?.user ? String(details.user) : "");
  if (user === undefined) return;
  const port = await ctx.ui.input("SSH 端口", String(details?.port ?? 22));
  if (port === undefined) return;
  const identities = await ctx.ui.editor("密钥路径，每行一个", details?.identityFiles.map((identity) => identity.path).join("\n") ?? "");
  if (identities === undefined) return;
  const description = await ctx.ui.input("备注", details?.description ?? "");
  if (description === undefined) return;
  const saved = await manager.upsert({ host, hostname, user, port: Number(port), identityFiles: identities.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), description });
  ctx.ui.notify(`已${saved.created ? "添加" : "更新"}主机 ${host}。`, "info");
}

function describeHost(details: Awaited<ReturnType<SshManager["get"]>>): string {
  const lines = [details.sshAlias, `${details.user ? `${details.user}@` : ""}${details.hostname}:${details.port}`];
  if (details.description) lines.push(details.description);
  for (const identity of details.identityFiles) lines.push(`密钥：${identity.path}${identity.exists === false ? "（文件不存在）" : ""}`);
  if (details.host.hiddenOptions.length) lines.push(`附加选项：${details.host.hiddenOptions.join("、")}`);
  lines.push(`连接：${details.command}`);
  for (const warning of details.host.warnings) lines.push(warning);
  return lines.join("\n");
}

async function manageHost(manager: SshManager, ctx: ExtensionContext) {
  let offset = 0;
  while (true) {
    const page = await manager.list("", offset, 50);
    if (!page.hostCount) { ctx.ui.notify("还没有 SSH 主机。", "info"); return; }
    const labels = page.hosts.map((host) => `${host.alias}${host.description ? ` — ${host.description}` : ""}${host.managed ? "" : "（已有配置）"}`);
    const navigation = [...(offset > 0 ? ["上一页"] : []), ...(page.hasMore ? ["下一页"] : [])];
    const selected = await ctx.ui.select("选择 SSH 主机", [...labels, ...navigation]);
    if (!selected) return;
    if (selected === "上一页") { offset -= 50; continue; }
    if (selected === "下一页") { offset += 50; continue; }
    const host = page.hosts[labels.indexOf(selected)];
    if (!host) return;
    const details = await manager.get(host.alias);
    ctx.ui.notify(describeHost(details), "info");
    const action = await ctx.ui.select(host.alias, host.managed ? ["编辑主机", "删除主机", "复制连接命令到输入框", "返回"] : ["复制连接命令到输入框", "返回"]);
    if (action === "编辑主机") await editHost(manager, ctx, host.alias);
    if (action === "删除主机" && await ctx.ui.confirm("删除主机", `删除 ${host.alias} 的 onprsSSH 配置？`)) {
      await manager.delete(host.alias);
      ctx.ui.notify(`已删除主机 ${host.alias}。`, "info");
    }
    if (action === "复制连接命令到输入框") { ctx.ui.setEditorText(details.command); return; }
    return;
  }
}

export function registerOnprsSSH(pi: ExtensionAPI, options: SshManagerOptions = {}): void {
  const manager = new SshManager(options);
  pi.registerTool({
    name: "onprsSSH",
    label: "onprsSSH",
    description: "查询与维护本机 SSH 主机。支持列表、搜索、连接参数查询、主机添加/更新/删除，以及从 OpenSSH 配置导入主机、引用的密钥和 known_hosts。配置写入 ~/.ssh/onprsSSH 并通过 Include 接入 ~/.ssh/config；已有配置也可查询。修改前自动备份；删除仅移除受管理的主机记录。工具不建立连接，查询不读取密钥内容，导入和写入均不执行 SSH 配置中的命令。",
    promptSnippet: "查询 SSH 主机与连接参数，添加、更新、删除和导入 SSH 配置",
    promptGuidelines: [
      "需要 SSH 信息时使用 onprsSSH；可用 list 搜索别名，再用 get 取得连接信息与 sshArguments。",
      "执行 SSH 前检查 get 返回的 hiddenOptions、unsupportedOptions、warnings 和 commandArgumentSafe；通过参数数组传递 sshArguments，避免将主机名拼接到 shell。",
      "只在用户要求修改 SSH 配置时使用 upsert/delete/import。更新未提供的字段会保留原值，options 提供时整体替换。",
      "onprsSSH 的 get 只静态解析用户 SSH 配置，不求值 Match exec 或展开其他动态条件；含相关警告时先核对配置。",
    ],
    parameters,
    outputSchema: Type.Record(Type.String(), Type.Unknown()),
    executionMode: "sequential",
    async execute(_id, params, signal) {
      signal?.throwIfAborted();
      switch (params.action ?? "list") {
        case "list": return result(await manager.list(params.query, params.offset, params.limit, signal));
        case "get": return result(await manager.get(required(params.host, "host"), signal));
        case "upsert": return result(await manager.upsert({ ...params, host: required(params.host, "host") } as SshHostPatch, signal));
        case "delete": return result(await manager.delete(required(params.host, "host"), signal));
        case "import": return result(await manager.import(required(params.source, "source"), params.overwrite, signal));
      }
    },
  });

  pi.registerCommand("onprsSSH", {
    description: "管理 SSH 主机；支持 list、get <别名>、import <路径>",
    async handler(args, ctx) {
      try {
        if (!ctx.hasUI) throw new Error("当前模式请使用 onprsSSH 工具。");
        const command = args.trim();
        if (command === "list") {
          const page = await manager.list();
          ctx.ui.notify(page.hosts.length ? page.hosts.map((host) => `${host.alias}${host.hostname ? `  ${host.hostname}:${host.port}` : ""}`).join("\n") + (page.hasMore ? "\n还有更多主机，可在管理菜单中翻页查看。" : "") : "还没有 SSH 主机。", "info");
          return;
        }
        if (command.startsWith("get ")) { ctx.ui.notify(describeHost(await manager.get(required(command.slice(4), "主机别名"))), "info"); return; }
        if (command.startsWith("import ")) {
          const imported = await manager.import(required(command.slice(7), "来源路径"));
          ctx.ui.notify(`已导入 ${imported.imported.length} 个主机，保留 ${imported.skipped.length} 个同名主机。`, "info");
          return;
        }
        if (command) throw new Error("用法：/onprsSSH、/onprsSSH list、/onprsSSH get <别名>、/onprsSSH import <路径>。");
        const action = await ctx.ui.select("onprsSSH", ["查看和编辑主机", "添加主机", "导入 SSH 配置"]);
        if (action === "查看和编辑主机") await manageHost(manager, ctx);
        if (action === "添加主机") await editHost(manager, ctx);
        if (action === "导入 SSH 配置") {
          const source = await ctx.ui.input("SSH 配置文件或目录路径");
          if (!source) return;
          const conflict = await ctx.ui.select("遇到同名主机时", ["保留现有主机", "覆盖现有主机"]);
          if (!conflict) return;
          const imported = await manager.import(source, conflict === "覆盖现有主机");
          ctx.ui.notify(`已导入 ${imported.imported.length} 个主机，保留 ${imported.skipped.length} 个同名主机。`, "info");
        }
      } catch (error) { ctx.ui.notify(error instanceof Error ? error.message : String(error), "error"); }
    },
  });
}

export default function onprsSSH(pi: ExtensionAPI): void { registerOnprsSSH(pi); }
