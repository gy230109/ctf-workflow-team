#!/usr/bin/env node
/**
 * redteam-mcp.mjs — 破甲红队运行时（CTF 系统侧）
 * ================================================
 * 把上游 `lib/redteam/tools.js`（cordis 插件形态，56 个工具）跑成可调用服务，
 * 供 CTF 系统 Python 侧（ctf_redteam_fusion.py）按工具名调用。
 *
 * 协议（契约见 integrations/purge-redteam/FUSION-CONTRACT.md）：
 *   {"op":"list"}                                     → {"ok":true,"tools":[{name,description,parameters}]}
 *   {"op":"call","tool":"redteam_x","args":{…},"case":"ctf-…"} → {"ok":true,"result":{…}}
 *   {"op":"store","name":"assetAdd","data":{…},"case":"ctf-…"} → {"ok":true,"result":{…}}   // 兼容旧桥
 * 错误统一 {"ok":false,"error":"CODE","detail":"…"}
 *
 * 运行：
 *   echo '{"op":"list"}' | node redteam-mcp.mjs --data-dir <dir>
 *   node redteam-mcp.mjs --data-dir <dir> --serve      # 每行一个请求
 */
import { createInterface } from 'node:readline'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RedteamStore, dispatchAsync } from '../upstream/lib/redteam/store-core.js'
import { loadRedteamTools, paramsToSchema } from './ctx-shim.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CTF_BASE = path.resolve(HERE, '..', '..', '..')          // D:\强网杯大师
const TASKS = path.join(CTF_BASE, '.local', 'ctf-system', 'tasks')
const CASE_RE = /^ctf-[a-f0-9]{16}$/

function fail(error, detail = '') {
  return { ok: false, error, detail }
}

function parseArgs(argv) {
  const out = { serve: false, dataDir: '' }
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--data-dir') { out.dataDir = argv[++i] || '' }
    else if (argv[i] === '--serve') { out.serve = true }
  }
  if (!out.dataDir) throw new Error('MISSING_DATA_DIR')
  return out
}

/** 存储路径不允许经过符号链接（沿用 bridge.mjs 的 noLinks 纪律）。 */
function noLinks(target) {
  for (let current = path.resolve(target); ; current = path.dirname(current)) {
    try { if (fs.lstatSync(current).isSymbolicLink()) return false } catch (e) { if (e.code !== 'ENOENT') return false }
    if (path.dirname(current) === current) break
  }
  return true
}

function caseDirOk(caseId) {
  if (typeof caseId !== 'string' || !CASE_RE.test(caseId)) return false
  return fs.existsSync(path.join(TASKS, caseId, 'task.json'))
}

function makeExec(caseId) {
  // 上游按 exec.agent.session.id 解析会话键；一个 CTF case 就是一个会话。
  return { agent: { session: { id: caseId } } }
}

function parseToolResult(value) {
  if (typeof value !== 'string') return value
  const text = value.trim()
  if (!text.startsWith('{') && !text.startsWith('[')) return { text: value }
  try { return JSON.parse(text) } catch { return { text: value } }
}

function catalogue(regs) {
  const tools = []
  for (const [name, def] of regs) {
    tools.push({
      name,
      description: def.description || '',
      parameters: paramsToSchema(def.parameters || {}),
    })
  }
  tools.sort((a, b) => a.name.localeCompare(b.name))
  return tools
}

async function main() {
  const { serve, dataDir } = parseArgs(process.argv.slice(2))
  if (!noLinks(dataDir)) return fail('LINKED_STORAGE_PATH', dataDir)
  fs.mkdirSync(dataDir, { recursive: true })

  const store = new RedteamStore(dataDir)
  const { tools, dispose } = await loadRedteamTools({ store })
  const bound = new Set()

  /** 保证 case 有 engagement 且已绑定到该会话（首调用一次 engagement_open）。 */
  async function ensureBound(caseId) {
    if (bound.has(caseId)) return null
    const open = tools.get('redteam_engagement_open')
    if (open === undefined) { bound.add(caseId); return null }
    const raw = await open.execute({ target: caseId, scope: [] }, makeExec(caseId))
    bound.add(caseId)
    return parseToolResult(raw)
  }

  async function handle(req) {
    if (!req || typeof req !== 'object') return fail('INVALID_REQUEST')
    const op = req.op

    if (op === 'list') {
      return { ok: true, count: tools.size, tools: catalogue(tools), source: 'upstream/lib/redteam/tools.js', degraded: false }
    }

    if (op === 'call') {
      const name = req.tool
      const def = tools.get(name)
      if (def === undefined) return fail('UNKNOWN_TOOL', String(name))
      const args = req.args && typeof req.args === 'object' && !Array.isArray(req.args) ? req.args : {}
      let caseId = req.case
      const opened = caseId ? await ensureBound(caseId) : null
      if (caseId && !caseDirOk(caseId) && name !== 'redteam_engagement_open') {
        return fail('UNKNOWN_CASE', `任务不存在：${caseId}`)
      }
      const raw = await def.execute(args, makeExec(caseId || 'ctf-0000000000000000'))
      return { ok: true, result: parseToolResult(raw), ...(opened ? { engagement: opened } : {}) }
    }

    if (op === 'store') {
      const data = req.data && typeof req.data === 'object' ? req.data : {}
      if (req.case && !caseDirOk(req.case)) return fail('UNKNOWN_CASE', `任务不存在：${req.case}`)
      const engagement = req.case ? store.openEngagement(req.case, [], { bindCurrent: false }).id : undefined
      const result = await dispatchAsync(store, { ...data, op: req.name, ...(engagement ? { engagement } : {}) })
      return { ok: true, result }
    }

    return fail('UNSUPPORTED_OP', String(op))
  }

  async function answer(line) {
    let req
    try { req = JSON.parse(line) } catch { return JSON.stringify(fail('INVALID_JSON')) }
    try {
      return JSON.stringify(await handle(req))
    } catch (e) {
      return JSON.stringify(fail('TOOL_FAILED', String((e && e.message) || e)))
    }
  }

  if (serve) {
    const rl = createInterface({ input: process.stdin })
    for await (const line of rl) {
      if (!line.trim()) continue
      process.stdout.write(`${await answer(line)}\n`)
    }
  } else {
    const chunks = []
    for await (const chunk of process.stdin) chunks.push(chunk)
    const text = Buffer.concat(chunks).toString('utf8').trim()
    process.stdout.write(`${await answer(text || '{"op":"list"}')}\n`)
  }
  try { dispose() } catch { /* ignore */ }
  store.close()
}

main().catch((e) => {
  process.stdout.write(`${JSON.stringify(fail('RUNTIME_FAILED', String((e && e.stack) || e)))}\n`)
  process.exitCode = 1
})
