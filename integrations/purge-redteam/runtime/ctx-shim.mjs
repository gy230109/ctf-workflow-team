/**
 * ctx-shim.mjs — 「cordis 插件 → 裸函数表」适配层（upstream 语义零改动）
 * =====================================================================
 *
 * 用途
 *   上游 `upstream/lib/redteam/tools.js` 是 DeepSeek Harness 的 cordis 插件形态：
 *   `export function apply(ctx)` 里用 `ctx.tools.register(withStructuredErrors(defineTool({…})))`
 *   逐个注册 56 个工具；`defineTool` 本身来自宿主包 `@deepseek-ai/dsh-tools`（运行时用
 *   `createRequire` 在 dsh 安装树里现场解析），CTF 系统里既没有 dsh 安装树也没有 tools 服务。
 *
 *   本文件只做两件事，**不重写任何业务逻辑**：
 *     1) 用一个最小 `ctx` 替身（只有 tools.register / get / redteam / effect / on / subagents /
 *        logger 七个成员）接住这 56 次注册，收集成 `Map<toolName, definition>`；
 *     2) 提供一个 identity 版 `defineTool`，顶掉 tools.js 里那句 `const defineTool = loadDefineTool()`。
 *        dsh 的 defineTool 只在参数 DSL 之上补框架元数据（output.render / 结构化校验），
 *        上游每个工具自己已经写了 `output: { schema, render }`，identity 化后 `execute(args, exec)`
 *        与返回值（JSON 字符串）完全保持 upstream 行为。
 *
 *   替换方式：不改磁盘上的 tools.js，用 `module.registerHooks()` 在 load 阶段对**唯一**
 *   锚点 `const defineTool = loadDefineTool()` 做一次字符串替换（锚点出现次数 ≠ 1 就抛
 *   INCOMPATIBLE_TOOLS_JS，绝不在版本漂移时静默跑错代码）。上游文件因此保持 1.6.60 原样，
 *   sha256 可复核。
 *
 * 参数 JSON Schema 的来源
 *   上游 `lib/redteam/schema.js` 是**数据库 DDL 与迁移**（不是工具 schema）；工具参数的唯一
 *   真实定义在 `tools.js` 的 `defineTool({ parameters })` DSL 里（
 *   `{type, required, description, enum, items, properties, default, additionalProperties}`）。
 *   本文件把这些 DSL 字面量机械转换为标准 JSON Schema（object/properties/required），
 *   不新增、不改写、不猜测任何参数名。`integrations/purge-redteam/schemas/*.json` 里保存的
 *   `parameters_js` 原始字面量可用来交叉核对转换结果。
 */

import { registerHooks } from 'node:module'
import { readFileSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join, resolve } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
export const UPSTREAM_ROOT = resolve(HERE, '..', 'upstream')
export const TOOLS_PATH = join(UPSTREAM_ROOT, 'lib', 'redteam', 'tools.js')

/** tools.js 里被替换的那一行（upstream 1.6.60 中唯一出现）。 */
const ANCHOR = 'const defineTool = loadDefineTool()'
/** 替换后读这个全局，值由 loadRedteamTools() 在导入前设置。 */
const ANCHOR_REPLACEMENT = 'const defineTool = globalThis.__PURGE_REDTEAM_DEFINE_TOOL__'

if (typeof globalThis.__PURGE_REDTEAM_DEFINE_TOOL__ !== 'function') {
  /* identity：upstream 自己提供了 output.render / 参数校验语义，这里不再叠加框架层。 */
  globalThis.__PURGE_REDTEAM_DEFINE_TOOL__ = (definition) => definition
}

let hooksInstalled = false

/** 只拦截 tools.js 一个模块；其它模块原样交给默认 loader。 */
function installToolsHook() {
  if (hooksInstalled) return
  const targetUrl = pathToFileURL(TOOLS_PATH).href
  const source = readFileSync(TOOLS_PATH, 'utf8')
  const hits = source.split(ANCHOR).length - 1
  if (hits !== 1) {
    throw Object.assign(new Error(`INCOMPATIBLE_TOOLS_JS: anchor "${ANCHOR}" found ${hits} time(s) in ${TOOLS_PATH}`), {
      code: 'INCOMPATIBLE_TOOLS_JS',
    })
  }
  registerHooks({
    load(url, context, nextLoad) {
      if (url !== targetUrl) return nextLoad(url, context)
      return {
        format: 'module',
        shortCircuit: true,
        source: source.replace(ANCHOR, ANCHOR_REPLACEMENT),
      }
    },
  })
  hooksInstalled = true
}

/* ------------------------------------------------------------------ JSON Schema 转换 */

/** DSL 里允许出现在参数节点上的键（其余键原样透传，便于上游加字段时不丢信息）。 */
const PARAM_KEYS = new Set([
  'type', 'description', 'enum', 'default', 'items', 'properties',
  'additionalProperties', 'minimum', 'maximum', 'pattern', 'format', 'title',
])

/**
 * 参数表（`{name: spec}`）→ `{properties, required}`。
 * 嵌套层（object 的 properties）与顶层共用这一份实现：`required: true` 一律提升成
 * 父层的 `required: [name]` 字符串数组，这是 JSON Schema 与上游 DSL 唯一的结构差异。
 */
function buildProps(parameters) {
  const props = parameters && typeof parameters === 'object' && !Array.isArray(parameters) ? parameters : {}
  const properties = {}
  const required = []
  for (const [name, spec] of Object.entries(props)) {
    properties[name] = specToSchema(spec)
    if (spec && typeof spec === 'object' && spec.required === true) required.push(name)
  }
  return { properties, required }
}

/** 单个参数节点 → JSON Schema（递归处理 items / properties）。 */
function specToSchema(spec) {
  if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) return {}
  const out = {}
  for (const [key, value] of Object.entries(spec)) {
    if (key === 'required') continue // 由父层 buildProps 收集成数组
    if (key === 'items') {
      out.items = Array.isArray(value) ? value.map(specToSchema) : specToSchema(value)
      continue
    }
    if (key === 'properties') {
      const inner = buildProps(value)
      out.properties = inner.properties
      if (inner.required.length > 0) out.required = inner.required
      if (out.additionalProperties === undefined) out.additionalProperties = false
      continue
    }
    if (!PARAM_KEYS.has(key)) { out[key] = value; continue }
    out[key] = value
  }
  return out
}

/** 参数表 → `{type:'object', properties, required, additionalProperties:false}`。 */
export function paramsToSchema(parameters) {
  const { properties, required } = buildProps(parameters)
  const schema = { type: 'object', properties }
  if (required.length > 0) schema.required = required
  schema.additionalProperties = false
  return schema
}

/* ------------------------------------------------------------------ ctx 替身 */

/**
 * 最小 ctx 替身。
 * @param store    RedteamStore 实例（upstream apply() 从 ctx.redteam 取，取不到会降级成 stub 并让所有工具报 store_missing）。
 * @param services 额外服务（`ctx.get(name)` 的返回值表）。
 */
export function createCtxShim({ store, services = {}, logger = null } = {}) {
  const registrations = new Map()
  const disposers = []
  const known = { redteam: store, ...services }

  const ctx = {
    /* tools.js 唯一的注册入口：ctx.tools.register(definition) → disposer */
    tools: {
      register(definition) {
        const toolName = definition && definition.name
        if (typeof toolName !== 'string' || toolName === '') {
          throw new Error('TOOL_WITHOUT_NAME: ctx.tools.register() 收到无名工具定义')
        }
        registrations.set(toolName, definition)
        const disposer = () => registrations.delete(toolName)
        disposers.push(disposer)
        return disposer
      },
    },
    /* 软取服务：上游用 ctx.get('redteam'|'skills'|'agentPresets')，取不到就是 undefined（上游有降级分支） */
    get(name) { return known[name] },
    /* 上游 apply() 直接读 ctx.redteam，并靠 ctx.redteam.root 现读并发上限 */
    get redteam() { return store },
    /* ctx.effect(fn)：上游用它包 subagent/end 解绑；替身里立即执行并收集 disposer */
    effect(fn) {
      try {
        const d = fn()
        if (typeof d === 'function') disposers.push(d)
        return d
      } catch {
        return () => {}
      }
    },
    /* 事件总线不在替身范围：subagent/end 永不到来，返回空 disposer（上游本身 try/catch 兜底） */
    on() { return () => {} },
    /* 没有子智能体平面：listChildren 返回空数组，代表「真实运行数 0」，不虚构占用 */
    subagents: {
      listChildren() { return [] },
      ...(services.subagents || {}),
    },
    logger: {
      warn: (...a) => { if (logger) logger.warn(...a) },
      info: () => {},
      debug: () => {},
      error: (...a) => { if (logger) logger.error(...a) },
    },
  }

  return {
    ctx,
    registrations,
    dispose() {
      for (const d of disposers.splice(0)) { try { d() } catch { /* ignore */ } }
      registrations.clear()
    },
  }
}

/* ------------------------------------------------------------------ 工具表装载 */

/**
 * 导入 upstream tools.js 并执行 apply(ctx)，返回 56 个工具的可调用表。
 *
 * @param opts.store      RedteamStore 实例
 * @param opts.services   额外 ctx.get() 服务
 * @param opts.logger     可选 logger（只在 stderr 用）
 * @returns `{ tools: Map<name, def>, ctx, dispose, toolsPath }`
 */
export async function loadRedteamTools(opts = {}) {
  installToolsHook()
  const shim = createCtxShim(opts)
  const mod = await import(pathToFileURL(TOOLS_PATH).href)
  if (typeof mod.apply !== 'function') throw new Error('INCOMPATIBLE_TOOLS_JS: tools.js 未导出 apply(ctx)')
  mod.apply(shim.ctx)
  return {
    tools: shim.registrations,
    ctx: shim.ctx,
    dispose: shim.dispose,
    toolsPath: TOOLS_PATH,
  }
}
