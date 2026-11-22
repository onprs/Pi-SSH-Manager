import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { validateToolArguments } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import onprsSSH, {
  getSshPaths,
  normalizeHost,
  normalizeOptions,
  quoteSshPath,
  registerOnprsSSH,
  renderSshConfig,
  validateAlias,
} from "../src/index.ts";

describe("数据模型规范化与配置渲染", () => {
  it("校验别名、SSH 选项与主机记录并按固定顺序渲染", () => {
    assert.equal(validateAlias("prod.db-01_a"), "prod.db-01_a");
    assert.throws(() => validateAlias(""), /INVALID_HOST/);
    assert.throws(() => validateAlias(".leading-dot"), /INVALID_HOST/);
    assert.throws(() => validateAlias("-leading-dash"), /INVALID_HOST/);
    assert.throws(() => validateAlias("has space"), /INVALID_HOST/);

    const options = normalizeOptions({
      ServerAliveInterval: "30",
      CertificateFile: ["~/.ssh/cert1", "~/.ssh/cert2"],
    });
    assert.equal(Object.getPrototypeOf(options), null);
    assert.deepEqual({ ...options }, {
      serveraliveinterval: "30",
      certificatefile: ["~/.ssh/cert1", "~/.ssh/cert2"],
    });
    assert.throws(() => normalizeOptions({ HostName: "reserved.example" }), /INVALID_OPTION/);
    assert.throws(() => normalizeOptions({ ServerAliveInterval: "30", serveraliveinterval: "60" }), /INVALID_OPTION/);
    assert.throws(() => normalizeOptions({ BadOption: "# comment" }), /INVALID_OPTION/);
    assert.throws(() => normalizeOptions([]), /INVALID_OPTIONS/);

    const host = normalizeHost({
      host: "web",
      hostname: "web.example",
      identityFiles: ["/tmp/id_a", "/tmp/id_a"],
      description: "生产节点",
    });
    assert.equal(host.port, 22);
    assert.deepEqual(host.identityFiles, ["/tmp/id_a"]);

    const updated = normalizeHost({ host: "web", port: 2222, user: "", description: "" }, host);
    assert.equal(updated.hostname, "web.example");
    assert.equal(updated.port, 2222);
    assert.equal(updated.user, undefined);
    assert.equal(updated.description, undefined);

    assert.equal(quoteSshPath('/tmp/my "key"\\1'), '"/tmp/my \\"key\\"\\\\1"');

    const rendered = renderSshConfig([host]);
    assert.ok(rendered.includes("# 生产节点\nHost web\n    HostName web.example\n    Port 22\n"));
    assert.ok(rendered.trimEnd().endsWith("Host *"));

    const paths = getSshPaths("/tmp/demo-home");
    assert.equal(paths.directory, path.join(path.resolve("/tmp/demo-home"), ".ssh", "onprsSSH"));
  });
});

describe("扩展工具与斜杠命令注册及交互行为", () => {
  it("通过默认导出注册工具和命令并兼容参数 Schema 校验、导入及输出截断", async () => {
    const temporary = await mkdtemp(path.join(tmpdir(), "pi-ssh-ext-"));
    try {
      const home = path.join(temporary, "home");
      const source = path.join(temporary, "source");
      await mkdir(path.join(home, ".ssh"), { recursive: true });
      await mkdir(source, { recursive: true });
      await writeFile(
        path.join(source, "config"),
        "Host ext-alpha\n  HostName alpha.example\n  User deploy\n",
      );

      let registeredTool: any;
      let registeredCommand: any;
      const mockPi = {
        registerTool(definition: unknown) {
          registeredTool = definition;
        },
        registerCommand(_name: string, definition: unknown) {
          registeredCommand = definition;
        },
      } as unknown as ExtensionAPI;

      onprsSSH(mockPi);
      assert.equal(registeredTool.name, "onprsSSH");
      assert.equal(typeof registeredCommand.handler, "function");

      // 在独立 homeDir 上验证参数校验、工具执行与斜杠命令
      registerOnprsSSH(mockPi, { homeDir: home });
      const validated = validateToolArguments(registeredTool, {
        id: "call-1",
        name: "onprsSSH",
        arguments: { action: "import", source, overwrite: true },
        type: "toolCall",
      });
      assert.equal(validated.action, "import");
      assert.throws(() =>
        validateToolArguments(registeredTool, {
          id: "call-bad",
          name: "onprsSSH",
          arguments: { action: "invalid" },
          type: "toolCall",
        }),
      );

      const imported = await registeredTool.execute("imp", { action: "import", source });
      assert.deepEqual(imported.structuredContent.imported, ["ext-alpha"]);

      // 无 UI 模式执行命令应友好提示
      const notifications: Array<{ text: string; level: string }> = [];
      await registeredCommand.handler("list", {
        hasUI: false,
        ui: {
          notify(text: string, level = "info") {
            notifications.push({ text, level });
          },
        },
      });
      assert.equal(notifications.at(-1)?.level, "error");
      assert.ok(notifications.at(-1)?.text.includes("onprsSSH 工具"));

      // UI 模式下 list / get / import 与交互式菜单分支
      let editorText = "";
      const selectAnswers = ["查看和编辑主机", "ext-alpha", "复制连接命令到输入框", "添加主机"];
      const inputAnswers = ["ext-beta", "beta.example", "ops", "2202", "新增测试主机"];
      const uiCtx = {
        hasUI: true,
        ui: {
          notify(text: string, level = "info") {
            notifications.push({ text, level });
          },
          async select() {
            return selectAnswers.shift();
          },
          async input() {
            return inputAnswers.shift();
          },
          async editor() {
            return "";
          },
          async confirm() {
            return true;
          },
          setEditorText(text: string) {
            editorText = text;
          },
        },
      };

      await registeredCommand.handler("list", uiCtx);
      assert.ok(notifications.at(-1)?.text.includes("ext-alpha"));

      await registeredCommand.handler("get ext-alpha", uiCtx);
      assert.ok(notifications.at(-1)?.text.includes("deploy@alpha.example:22"));

      await registeredCommand.handler("bad-subcommand", uiCtx);
      assert.equal(notifications.at(-1)?.level, "error");

      await registeredCommand.handler("", uiCtx);
      assert.ok(editorText.includes("ext-alpha"));

      await registeredCommand.handler("", uiCtx);
      assert.ok(notifications.at(-1)?.text.includes("已添加主机 ext-beta"));

      // 构造超长主机列表以验证结果截断结构
      for (let i = 0; i < 100; i += 1) {
        await registeredTool.execute(`bulk-${i}`, {
          action: "upsert",
          host: `bulk-host-${String(i).padStart(3, "0")}`,
          hostname: `bulk-${i}.example`,
          description: "x".repeat(600),
        });
      }
      const truncatedList = await registeredTool.execute("list-big", { action: "list", limit: 100 });
      assert.equal(truncatedList.structuredContent.outputTruncated, true);
      assert.equal(truncatedList.structuredContent.hostCount, 102);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
});
