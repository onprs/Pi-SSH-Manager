import { homedir } from "node:os";
import type { Stats } from "node:fs";
import { lstat, opendir, readFile, readlink, realpath, stat } from "node:fs/promises";
import path from "node:path";

const MAX_CONFIG_FILES = 128;
const MAX_CONFIG_FILE_BYTES = 1024 * 1024;
const MAX_TOTAL_CONFIG_BYTES = 8 * 1024 * 1024;
const MAX_CONFIG_NODES = 5000;
const MAX_DISCOVERED_HOSTS = 500;
const MAX_HOST_PATTERN_LENGTH = 255;
const MAX_OPTION_VALUE_LENGTH = 512;
const MAX_MULTI_VALUE_COUNT = 8;
const MAX_MATCHED_BLOCKS = 16;
const MAX_DECLARATIONS_PER_HOST = 16;
const MAX_WARNINGS = 16;
const MAX_INCLUDE_PATTERNS = 256;
const MAX_INCLUDE_PATTERN_LENGTH = 1024;
const MAX_DIRECTORY_ENTRIES = 10_000;
const MAX_INCLUDE_MATCHES = 128;

const SAFE_SINGLE_VALUE_OPTIONS = new Set([
  "hostname",
  "user",
  "port",
  "hostkeyalias",
  "proxyjump",
  "canonicalizehostname",
  "batchmode",
  "identitiesonly",
  "preferredauthentications",
  "passwordauthentication",
  "kbdinteractiveauthentication",
  "pubkeyauthentication",
  "stricthostkeychecking",
  "hashknownhosts",
  "connecttimeout",
  "serveraliveinterval",
  "serveralivecountmax",
  "requesttty",
  "userknownhostsfile",
  "globalknownhostsfile",
  "addressfamily",
  "compression",
  "tcpkeepalive",
  "exitonforwardfailure",
  "forwardagent",
  "forwardx11",
  "loglevel",
]);

const SAFE_MULTI_VALUE_OPTIONS = new Set(["identityfile", "certificatefile"]);

const HIDDEN_OPTIONS = new Set([
  "proxycommand",
  "remotecommand",
  "localcommand",
  "localforward",
  "remoteforward",
  "dynamicforward",
  "sendenv",
  "setenv",
  "knownhostscommand",
  "permitlocalcommand",
]);

export interface SshConfigSource {
  path: string;
  line: number;
}

export interface SshHostSummary {
  alias: string;
  declaredAt: SshConfigSource[];
}

export interface ResolvedSshHost {
  alias: string;
  options: Record<string, string | string[]>;
  matchedBlocks: SshConfigSource[];
  hiddenOptions: string[];
  unsupportedOptions: string[];
  warnings: string[];
  warningCategories: string[];
}

export interface SshConfigSnapshot {
  found: boolean;
  configPath: string;
  configFiles: string[];
  hosts: SshHostSummary[];
  warnings: string[];
  warningCategories: string[];
}

export interface SshConfigReadOptions {
  homeDir?: string;
  configPath?: string;
  signal?: AbortSignal;
}

type ConfigDirective = {
  kind: "directive";
  keyword: string;
  arguments: string[];
  source: SshConfigSource;
};

type ConfigInclude = {
  kind: "include";
  documents: ConfigDocument[];
  source: SshConfigSource;
};

type ConfigNode = ConfigDirective | ConfigInclude;

type ConfigDocument = {
  path: string;
  nodes: ConfigNode[];
};

type ParseBudget = {
  count: number;
  totalBytes: number;
  nodeCount: number;
  includePatterns: number;
  directoryEntries: number;
  configFiles: Set<string>;
  warnings: string[];
  warningCategories: Set<string>;
  signal?: AbortSignal;
};

type EvaluationState = {
  active: boolean;
  matchedBlocks: SshConfigSource[];
  matchedBlocksTruncated: boolean;
  matchedDeclaredAlias: boolean;
  options: Map<string, string | string[]>;
  optionValuesTruncated: boolean;
  multiValuesTruncated: boolean;
  hiddenOptions: Set<string>;
  unsupportedOptions: Set<string>;
  hasUnevaluatedMatch: boolean;
};

const snapshotDocuments = new WeakMap<SshConfigSnapshot, ConfigDocument[]>();

export async function readSshConfig(
  options: SshConfigReadOptions = {},
): Promise<SshConfigSnapshot> {
  const homeDir = path.resolve(options.homeDir ?? homedir());
  const configPath = path.resolve(options.configPath ?? path.join(homeDir, ".ssh", "config"));
  const budget: ParseBudget = {
    count: 0,
    totalBytes: 0,
    nodeCount: 0,
    includePatterns: 0,
    directoryEntries: 0,
    configFiles: new Set<string>(),
    warnings: [],
    warningCategories: new Set<string>(),
    signal: options.signal,
  };
  budget.signal?.throwIfAborted();

  const root = await loadConfigDocument(configPath, homeDir, path.dirname(configPath), budget, new Set());
  if (!root) {
    const snapshot: SshConfigSnapshot = {
      found: false,
      configPath,
      configFiles: [],
      hosts: [],
      warnings: budget.warnings,
      warningCategories: [...budget.warningCategories],
    };
    snapshotDocuments.set(snapshot, []);
    return snapshot;
  }

  const documents = [root];
  const declaredHosts = collectDeclaredHosts(documents, budget);
  const discoveredHosts = [...declaredHosts.entries()]
    .map(([alias, declaredAt]) => ({ alias, declaredAt }))
    .filter(({ alias }) => evaluateHost(documents, alias, budget.signal).matchedDeclaredAlias)
    .sort((left, right) => left.alias.localeCompare(right.alias, "en", { sensitivity: "variant" }));

  const snapshot: SshConfigSnapshot = {
    found: true,
    configPath,
    configFiles: [...budget.configFiles].sort((left, right) => left.localeCompare(right, "en")),
    hosts: discoveredHosts,
    warnings: budget.warnings,
    warningCategories: [...budget.warningCategories].sort((left, right) => left.localeCompare(right, "en")),
  };
  snapshotDocuments.set(snapshot, documents);
  return snapshot;
}

export function resolveSshHost(snapshot: SshConfigSnapshot, requestedAlias: string): ResolvedSshHost {
  const alias = requestedAlias.trim();
  const summary = snapshot.hosts.find((host) => host.alias === alias);
  if (!summary) {
    throw new Error(`[HOST_NOT_FOUND] OpenSSH 配置中没有主机别名：${requestedAlias}`);
  }

  const evaluated = evaluateHost(snapshotDocuments.get(snapshot) ?? [], summary.alias);
  const options = Object.fromEntries(
    [...evaluated.options.entries()].sort(([left], [right]) => left.localeCompare(right, "en")),
  );
  const warnings = [...snapshot.warnings];
  if (evaluated.hasUnevaluatedMatch) {
    warnings.push("配置包含无法安全求值的 Match 条件；结果未包含这些条件块中的选项。");
  }
  if (evaluated.matchedBlocksTruncated) {
    warnings.push(`匹配配置块超过上限 ${MAX_MATCHED_BLOCKS}，来源列表已截断。`);
  }
  if (evaluated.multiValuesTruncated) {
    warnings.push(`多值配置项超过上限 ${MAX_MULTI_VALUE_COUNT}，其余值已截断。`);
  }
  if (evaluated.optionValuesTruncated) {
    warnings.push(`配置值超过长度上限 ${MAX_OPTION_VALUE_LENGTH}，返回值已截断。`);
  }

  return {
    alias: summary.alias,
    options,
    matchedBlocks: evaluated.matchedBlocks,
    hiddenOptions: [...evaluated.hiddenOptions].sort((left, right) => left.localeCompare(right, "en")),
    unsupportedOptions: [...evaluated.unsupportedOptions].sort(),
    warnings,
    warningCategories: [...new Set([
      ...snapshot.warningCategories,
      ...warnings.map(classifyWarning),
    ])].sort((left, right) => left.localeCompare(right, "en")),
  };
}

async function loadConfigDocument(
  requestedPath: string,
  homeDir: string,
  includeBaseDir: string,
  budget: ParseBudget,
  stack: Set<string>,
): Promise<ConfigDocument | undefined> {
  budget.signal?.throwIfAborted();
  if (budget.nodeCount >= MAX_CONFIG_NODES) {
    addWarning(budget, `配置节点超过上限 ${MAX_CONFIG_NODES}，其余配置已忽略。`);
    return undefined;
  }
  if (isSensitiveSshDataFile(requestedPath)) {
    addWarning(budget, `Include 指向已知 SSH 密钥或主机记录文件，已忽略：${path.basename(requestedPath)}`);
    return undefined;
  }
  if (process.platform === "win32" && isUncPath(requestedPath)) {
    addWarning(budget, "配置文件指向 UNC 路径；为避免隐式网络文件访问，已忽略。");
    return undefined;
  }
  if (process.platform === "win32" && !(await isSafeWindowsIncludePath(requestedPath, budget))) {
    return undefined;
  }
  if (budget.count >= MAX_CONFIG_FILES) {
    addWarning(budget, `配置文件数量超过上限 ${MAX_CONFIG_FILES}，其余 Include 已忽略。`);
    return undefined;
  }

  let canonicalPath: string;
  let fileStats: Stats;
  try {
    canonicalPath = await realpath(requestedPath);
    fileStats = await stat(canonicalPath);
  } catch {
    return undefined;
  }
  budget.signal?.throwIfAborted();
  if (!fileStats.isFile()) return undefined;
  if (fileStats.size > MAX_CONFIG_FILE_BYTES) {
    addWarning(budget, `配置文件超过 ${MAX_CONFIG_FILE_BYTES} 字节，已忽略：${canonicalPath}`);
    return undefined;
  }
  if (budget.totalBytes + fileStats.size > MAX_TOTAL_CONFIG_BYTES) {
    addWarning(budget, `配置文件总大小超过 ${MAX_TOTAL_CONFIG_BYTES} 字节，其余 Include 已忽略。`);
    return undefined;
  }

  const stackKey = normalizePathKey(canonicalPath);
  if (stack.has(stackKey)) {
    addWarning(budget, `检测到循环 Include，已忽略：${canonicalPath}`);
    return undefined;
  }

  budget.count += 1;
  budget.totalBytes += fileStats.size;
  budget.configFiles.add(canonicalPath);
  const nextStack = new Set(stack);
  nextStack.add(stackKey);

  const text = await readFile(canonicalPath, { encoding: "utf8", signal: budget.signal });
  const nodes: ConfigNode[] = [];
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);

  for (let index = 0; index < lines.length; index += 1) {
    budget.signal?.throwIfAborted();
    const tokens = tokenizeConfigLine(lines[index]);
    const parsed = splitDirective(tokens);
    if (!parsed) continue;

    const source = { path: canonicalPath, line: index + 1 };
    if (parsed.keyword !== "include") {
      if (parsed.keyword === "host") {
        const validPatterns = parsed.arguments.filter((pattern) => pattern.length <= MAX_HOST_PATTERN_LENGTH);
        if (validPatterns.length !== parsed.arguments.length) {
          addWarning(budget, `Host 模式超过长度上限 ${MAX_HOST_PATTERN_LENGTH}，已忽略：${canonicalPath}:${index + 1}`);
        }
        if (!reserveConfigNode(budget)) break;
        nodes.push({ kind: "directive", ...parsed, arguments: validPatterns, source });
      } else {
        if (!reserveConfigNode(budget)) break;
        nodes.push({ kind: "directive", ...parsed, source });
      }
      continue;
    }

    const includedDocuments: ConfigDocument[] = [];
    for (const includePattern of parsed.arguments) {
      budget.signal?.throwIfAborted();
      if (budget.includePatterns >= MAX_INCLUDE_PATTERNS) {
        addWarning(budget, `Include 模式数量超过上限 ${MAX_INCLUDE_PATTERNS}，其余模式已忽略。`);
        break;
      }
      budget.includePatterns += 1;
      const unsupportedReason = getUnsupportedIncludeReason(includePattern);
      if (unsupportedReason) {
        addWarning(budget, `${unsupportedReason}：${canonicalPath}:${index + 1}`);
        continue;
      }

      const expandedPaths = await expandIncludePattern(includePattern, homeDir, includeBaseDir, budget);
      for (const expandedPath of expandedPaths) {
        const included = await loadConfigDocument(
          expandedPath,
          homeDir,
          includeBaseDir,
          budget,
          nextStack,
        );
        if (included) includedDocuments.push(included);
      }
    }
    if (!reserveConfigNode(budget)) break;
    nodes.push({ kind: "include", documents: includedDocuments, source });
  }

  return { path: canonicalPath, nodes };
}

function collectDeclaredHosts(
  documents: ConfigDocument[],
  budget: ParseBudget,
): Map<string, SshConfigSource[]> {
  const hosts = new Map<string, SshConfigSource[]>();
  let limitReached = false;

  const visit = (document: ConfigDocument) => {
    if (limitReached) return;
    for (const node of document.nodes) {
      if (limitReached) return;
      if (node.kind === "include") {
        for (const included of node.documents) visit(included);
        continue;
      }
      if (node.keyword !== "host") continue;

      for (const pattern of node.arguments) {
        if (!isConcreteHostAlias(pattern)) continue;
        const sources = hosts.get(pattern);
        if (sources) {
          if (
            sources.length < MAX_DECLARATIONS_PER_HOST &&
            !sources.some((source) => source.path === node.source.path && source.line === node.source.line)
          ) {
            sources.push(node.source);
          }
          continue;
        }
        if (hosts.size >= MAX_DISCOVERED_HOSTS) {
          addWarning(budget, `主机别名超过上限 ${MAX_DISCOVERED_HOSTS}，其余别名已忽略。`);
          limitReached = true;
          return;
        }
        hosts.set(pattern, [node.source]);
      }
    }
  };

  for (const document of documents) visit(document);
  return hosts;
}

function evaluateHost(
  documents: ConfigDocument[],
  alias: string,
  signal?: AbortSignal,
): EvaluationState {
  const state: EvaluationState = {
    active: true,
    matchedBlocks: [],
    matchedBlocksTruncated: false,
    matchedDeclaredAlias: false,
    options: new Map(),
    optionValuesTruncated: false,
    multiValuesTruncated: false,
    hiddenOptions: new Set(),
    unsupportedOptions: new Set(),
    hasUnevaluatedMatch: false,
  };

  for (const document of documents) {
    signal?.throwIfAborted();
    evaluateDocument(document, alias, state, signal);
  }
  return state;
}

function evaluateDocument(
  document: ConfigDocument,
  alias: string,
  state: EvaluationState,
  signal?: AbortSignal,
): void {
  for (const node of document.nodes) {
    signal?.throwIfAborted();
    if (node.kind === "include") {
      if (state.active) {
        for (const included of node.documents) evaluateDocument(included, alias, state, signal);
      }
      continue;
    }

    if (node.keyword === "host") {
      state.active = hostMatchesPatterns(alias, node.arguments);
      if (state.active) {
        if (state.matchedBlocks.length < MAX_MATCHED_BLOCKS) state.matchedBlocks.push(node.source);
        else state.matchedBlocksTruncated = true;
        if (node.arguments.some((pattern) => isSameConcreteAlias(pattern, alias))) {
          state.matchedDeclaredAlias = true;
        }
      }
      continue;
    }

    if (node.keyword === "match") {
      const isUnconditional = node.arguments.length === 1 && node.arguments[0].toLowerCase() === "all";
      state.active = isUnconditional;
      if (!isUnconditional) state.hasUnevaluatedMatch = true;
      continue;
    }

    if (!state.active || node.arguments.length === 0) continue;
    const rawValue = node.arguments.join(" ");
    if (rawValue.length > MAX_OPTION_VALUE_LENGTH) state.optionValuesTruncated = true;
    const value = rawValue.length > MAX_OPTION_VALUE_LENGTH
      ? `${rawValue.slice(0, MAX_OPTION_VALUE_LENGTH)}…`
      : rawValue;

    if (SAFE_SINGLE_VALUE_OPTIONS.has(node.keyword)) {
      if (!state.options.has(node.keyword)) {
        const paths = node.keyword === "userknownhostsfile" || node.keyword === "globalknownhostsfile";
        state.options.set(node.keyword, paths ? node.arguments : value);
      }
      continue;
    }

    if (SAFE_MULTI_VALUE_OPTIONS.has(node.keyword)) {
      const current = state.options.get(node.keyword);
      const values = Array.isArray(current) ? current : current === undefined ? [] : [current];
      if (values.length < MAX_MULTI_VALUE_COUNT) values.push(value);
      else state.multiValuesTruncated = true;
      state.options.set(node.keyword, values);
      continue;
    }

    if (HIDDEN_OPTIONS.has(node.keyword)) state.hiddenOptions.add(node.keyword);
    else state.unsupportedOptions.add(node.keyword);
  }
}

function hostMatchesPatterns(alias: string, patterns: string[]): boolean {
  let positiveMatch = false;
  for (const rawPattern of patterns) {
    const negated = rawPattern.startsWith("!");
    const pattern = negated ? rawPattern.slice(1) : rawPattern;
    if (!pattern || !hostPatternMatches(alias, pattern)) continue;
    if (negated) return false;
    positiveMatch = true;
  }
  return positiveMatch;
}

function isConcreteHostAlias(pattern: string): boolean {
  return Boolean(pattern) && pattern.length <= 255 && !pattern.startsWith("!") && !/[?*]/.test(pattern);
}

function isSameConcreteAlias(pattern: string, alias: string): boolean {
  return isConcreteHostAlias(pattern) && pattern === alias;
}

function hostPatternMatches(alias: string, pattern: string): boolean {
  let aliasIndex = 0;
  let patternIndex = 0;
  let starIndex = -1;
  let retryAliasIndex = -1;

  while (aliasIndex < alias.length) {
    if (patternIndex < pattern.length && (pattern[patternIndex] === "?" || pattern[patternIndex] === alias[aliasIndex])) {
      aliasIndex += 1;
      patternIndex += 1;
      continue;
    }
    if (patternIndex < pattern.length && pattern[patternIndex] === "*") {
      starIndex = patternIndex;
      retryAliasIndex = aliasIndex;
      patternIndex += 1;
      continue;
    }
    if (starIndex >= 0) {
      patternIndex = starIndex + 1;
      retryAliasIndex += 1;
      aliasIndex = retryAliasIndex;
      continue;
    }
    return false;
  }

  while (patternIndex < pattern.length && pattern[patternIndex] === "*") patternIndex += 1;
  return patternIndex === pattern.length;
}

function tokenizeConfigLine(line: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: "'" | '"' | undefined;

  const pushCurrent = () => {
    if (!current) return;
    tokens.push(current);
    current = "";
  };

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (!quote && character === "#" && current.length === 0) break;

    if (character === "'" || character === '"') {
      if (!quote) {
        quote = character;
        continue;
      }
      if (quote === character) {
        quote = undefined;
        continue;
      }
    }

    if (character === "\\" && index + 1 < line.length) {
      const next = line[index + 1];
      if (/\s|[\\#"']/.test(next)) {
        current += next;
        index += 1;
        continue;
      }
    }

    if (!quote && /\s/.test(character)) {
      pushCurrent();
      continue;
    }
    current += character;
  }

  pushCurrent();
  return tokens;
}

function splitDirective(tokens: string[]): { keyword: string; arguments: string[] } | undefined {
  if (tokens.length === 0) return undefined;
  let keyword = tokens[0];
  let argumentsList = tokens.slice(1);
  const equalsIndex = keyword.indexOf("=");

  if (equalsIndex >= 0) {
    const firstArgument = keyword.slice(equalsIndex + 1);
    keyword = keyword.slice(0, equalsIndex);
    argumentsList = firstArgument ? [firstArgument, ...argumentsList] : argumentsList;
  } else if (argumentsList[0] === "=") {
    argumentsList = argumentsList.slice(1);
  } else if (argumentsList[0]?.startsWith("=")) {
    argumentsList = [argumentsList[0].slice(1), ...argumentsList.slice(1)];
  }

  keyword = keyword.trim().toLowerCase();
  if (!keyword) return undefined;
  return { keyword, arguments: argumentsList };
}

function getUnsupportedIncludeReason(rawPattern: string): string | undefined {
  if (rawPattern.length > MAX_INCLUDE_PATTERN_LENGTH) {
    return `Include 模式超过长度上限 ${MAX_INCLUDE_PATTERN_LENGTH}，已忽略`;
  }
  const unsupportedTokens = [...rawPattern.matchAll(/%([A-Za-z%])/g)]
    .map((match) => match[1])
    .filter((token) => token !== "d" && token !== "%");
  if (unsupportedTokens.length > 0) {
    return `Include 使用了无法静态求值的 token（${[...new Set(unsupportedTokens)].map((token) => `%${token}`).join(", ")}），已忽略`;
  }
  if (rawPattern.startsWith("~") && rawPattern !== "~" && !rawPattern.startsWith("~/") && !rawPattern.startsWith("~\\")) {
    return "Include 使用了无法静态解析的其他用户主目录，已忽略";
  }
  if (process.platform === "win32") {
    if (rawPattern.startsWith("\\") || rawPattern.startsWith("//")) {
      return "Include 指向 UNC 路径；为避免隐式网络文件访问，已忽略";
    }
    if (/^\/(?![a-zA-Z]\/)/.test(rawPattern)) {
      return "Include 使用了无法确定 MSYS 根目录的 POSIX 绝对路径，已忽略";
    }
  }
  return undefined;
}

async function expandIncludePattern(
  rawPattern: string,
  homeDir: string,
  baseDir: string,
  budget: ParseBudget,
): Promise<string[]> {
  const percentPlaceholder = "\u0000";
  let expanded = rawPattern
    .replaceAll("%%", percentPlaceholder)
    .replaceAll("%d", homeDir)
    .replaceAll(percentPlaceholder, "%");
  if (expanded === "~") expanded = homeDir;
  else if (expanded.startsWith("~/") || expanded.startsWith("~\\")) {
    expanded = path.join(homeDir, expanded.slice(2));
  }

  if (process.platform === "win32") {
    const msysPath = expanded.match(/^\/([a-zA-Z])\/(.*)$/);
    if (msysPath) expanded = `${msysPath[1]}:\\${msysPath[2]}`;
  }

  const absolutePattern = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(baseDir, expanded);
  const parsed = path.parse(absolutePattern);
  const segments = absolutePattern
    .slice(parsed.root.length)
    .split(/[\\/]+/)
    .filter(Boolean);
  let candidates = [parsed.root];

  for (const segment of segments) {
    budget.signal?.throwIfAborted();
    if (!hasGlobMagic(segment)) {
      candidates = candidates.map((candidate) => path.join(candidate, segment));
      if (process.platform === "win32") {
        for (const candidate of candidates) {
          if (!(await isSafeWindowsIncludePath(candidate, budget))) return [];
        }
      }
      continue;
    }

    const nextCandidates: string[] = [];
    for (const candidate of candidates) {
      if (process.platform === "win32" && !(await isSafeWindowsIncludePath(candidate, budget))) return [];
      let directory;
      try {
        directory = await opendir(candidate);
      } catch {
        continue;
      }
      for await (const entry of directory) {
        budget.signal?.throwIfAborted();
        if (budget.directoryEntries >= MAX_DIRECTORY_ENTRIES) {
          addWarning(budget, `Include 目录扫描超过上限 ${MAX_DIRECTORY_ENTRIES} 项，整个模式已忽略。`);
          return [];
        }
        budget.directoryEntries += 1;
        if (process.platform !== "win32" && entry.name.startsWith(".") && !segment.startsWith(".")) continue;
        if (!globMatches(entry.name, segment, process.platform === "win32")) continue;
        nextCandidates.push(path.join(candidate, entry.name));
        if (nextCandidates.length > MAX_INCLUDE_MATCHES) {
          addWarning(budget, `单个 Include 模式匹配超过上限 ${MAX_INCLUDE_MATCHES} 项，整个模式已忽略。`);
          return [];
        }
      }
    }
    candidates = nextCandidates.sort((left, right) => left.localeCompare(right, "en"));
  }

  const files: string[] = [];
  for (const candidate of candidates) {
    budget.signal?.throwIfAborted();
    if (process.platform === "win32" && !(await isSafeWindowsIncludePath(candidate, budget))) return [];
    try {
      if ((await stat(candidate)).isFile()) files.push(candidate);
    } catch {
      // OpenSSH 会静默忽略没有匹配文件的 Include。
    }
  }
  return files.sort((left, right) => left.localeCompare(right, "en"));
}

function isSensitiveSshDataFile(filePath: string): boolean {
  const fileName = path.basename(filePath).toLowerCase();
  if (/^(?:known_hosts|authorized_keys)(?:\.|$)/.test(fileName)) return true;
  if (/^(?:id_|key_)/.test(fileName) && !fileName.endsWith(".conf")) return true;
  return /\.(?:key|pem|ppk|pub)$/.test(fileName);
}

function isUncPath(value: string): boolean {
  const normalized = value.replaceAll("/", "\\").toLowerCase();
  if (normalized.startsWith("\\\\?\\unc\\")) return true;
  if (normalized.startsWith("\\\\?\\")) return false;
  return normalized.startsWith("\\\\");
}

async function isSafeWindowsIncludePath(candidate: string, budget: ParseBudget): Promise<boolean> {
  if (isUncPath(candidate)) {
    addWarning(budget, "Include 解析为 UNC 路径；为避免隐式网络文件访问，整个模式已忽略。");
    return false;
  }
  try {
    const fileStats = await lstat(candidate);
    if (!fileStats.isSymbolicLink()) return true;
    const linkTarget = await readlink(candidate);
    const resolvedTarget = path.isAbsolute(linkTarget)
      ? linkTarget
      : path.resolve(path.dirname(candidate), linkTarget);
    if (isUncPath(linkTarget) || isUncPath(resolvedTarget)) {
      addWarning(budget, "Windows Include 链接指向 UNC 路径；为避免隐式网络文件访问，整个模式已忽略。");
      return false;
    }
  } catch {
    return true;
  }
  return true;
}

function hasGlobMagic(value: string): boolean {
  return /[?*[]/.test(value);
}

function globMatches(value: string, pattern: string, caseInsensitive: boolean): boolean {
  let expression = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*") {
      expression += ".*";
      continue;
    }
    if (character === "?") {
      expression += ".";
      continue;
    }
    if (character === "[") {
      const closingIndex = pattern.indexOf("]", index + 1);
      if (closingIndex > index + 1) {
        let contents = pattern.slice(index + 1, closingIndex);
        if (contents.startsWith("!")) contents = `^${contents.slice(1)}`;
        expression += `[${contents.replaceAll("\\", "\\\\")}]`;
        index = closingIndex;
        continue;
      }
    }
    expression += escapeRegExp(character);
  }
  expression += "$";

  try {
    return new RegExp(expression, caseInsensitive ? "i" : undefined).test(value);
  } catch {
    return value.localeCompare(pattern, "en", { sensitivity: caseInsensitive ? "base" : "variant" }) === 0;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizePathKey(value: string): string {
  const normalized = path.normalize(value);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function reserveConfigNode(budget: ParseBudget): boolean {
  if (budget.nodeCount >= MAX_CONFIG_NODES) {
    addWarning(budget, `配置节点超过上限 ${MAX_CONFIG_NODES}，其余配置已忽略。`);
    return false;
  }
  budget.nodeCount += 1;
  return true;
}

function classifyWarning(warning: string): string {
  if (warning.includes("无法静态求值的 token")) return "dynamic_include_rejected";
  if (warning.includes("UNC") || warning.includes("MSYS 根目录")) return "network_or_ambiguous_path_rejected";
  if (warning.includes("SSH 密钥或主机记录")) return "sensitive_file_rejected";
  if (warning.includes("循环 Include")) return "include_cycle";
  if (warning.includes("Match 条件")) return "match_not_evaluated";
  if (warning.includes("截断") || warning.includes("长度上限")) return "value_truncated";
  if (warning.includes("超过上限") || warning.includes("总大小")) return "resource_limit";
  return "other";
}

function addWarning(budget: ParseBudget, warning: string): void {
  budget.warningCategories.add(classifyWarning(warning));
  if (budget.warnings.includes(warning)) return;
  if (budget.warnings.length < MAX_WARNINGS - 1) {
    budget.warnings.push(warning);
    return;
  }
  if (budget.warnings.length === MAX_WARNINGS - 1) {
    budget.warnings.push(`警告数量超过上限 ${MAX_WARNINGS - 1}，其余警告已省略。`);
  }
}
