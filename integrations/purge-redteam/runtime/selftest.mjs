#!/usr/bin/env node
/**
 * selftest.mjs —— 对 56 个红队工具做一次隔离冒烟。
 * 判据：不得崩溃/超时；返回 {ok:true} 或结构化业务错误（{ok:false,error|hint}）都算“工具可达”。
 * 用法：node selftest.mjs --data-dir <临时目录>
 */
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const RUNTIME = path.join(HERE, 'redteam-mcp.mjs')
const CTF_BASE = path.resolve(HERE, '..', '..', '..')
const CASE_RE = /^ctf-[a-f0-9]{16}$/

const dataDir = (() => {
  const i = process.argv.indexOf('--data-dir')
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fs.mkdtempSync(path.join(os.tmpdir(), 'purge-rt-'))
})()

const caseId = 'ctf-' + 'a1b2c3d4e5f60718'
const taskDir = path.join(CTF_BASE, '.local', 'ctf-system', 'tasks', caseId)
fs.mkdirSync(taskDir, { recursive: true })
const taskFile = path.join(taskDir, 'task.json')
const createdTask = !fs.existsSync(taskFile)
if (createdTask) fs.writeFileSync(taskFile, JSON.stringify({ task_id: caseId, title: 'runtime selftest', category: 'web' }), 'utf8')

function call(req) {
  const out = spawnSync(process.execPath, [RUNTIME, '--data-dir', dataDir], {
    input: JSON.stringify(req), encoding: 'utf8', timeout: 60000,
  })
  if (out.status !== 0 && !out.stdout) return { ok: false, error: 'EXIT_' + out.status, detail: (out.stderr || '').slice(-300) }
  try { return JSON.parse(out.stdout) } catch { return { ok: false, error: 'BAD_JSON', detail: String(out.stdout).slice(0, 200) } }
}

const listed = call({ op: 'list' })
if (!listed.ok) { console.error('list failed', listed); process.exit(1) }
const tools = listed.tools

call({ op: 'call', tool: 'redteam_engagement_open', args: { target: caseId, scope: [] }, case: caseId })

const argsFor = (name) => {
  if (name === 'redteam_engagement_open') return { target: caseId, scope: [] }
  if (name === 'redteam_asset_add') return { ip: '10.9.9.9', provenance: 'active', tool: 'selftest', engagement: caseId }
  if (name === 'redteam_session_info' || name === 'redteam_preflight' || name === 'redteam_agent_slot') return {}
  return { engagement: caseId }
}

const results = []
for (const t of tools) {
  const res = call({ op: 'call', tool: t.name, args: argsFor(t.name), case: caseId })
  const reachable = res.ok === true
  const businessError = res.ok === false && typeof res.error === 'string'
  results.push({ tool: t.name, reachable, error: res.error || '', detail: (res.detail || '').slice(0, 120) })
}

const pass = results.filter((r) => r.reachable).length
const biz = results.filter((r) => !r.reachable && r.error && !/^(RUNTIME_FAILED|BAD_JSON|EXIT_)/.test(r.error)).length
const hard = results.filter((r) => !r.reachable && /^(RUNTIME_FAILED|BAD_JSON|EXIT_)/.test(r.error || ''))

console.log(JSON.stringify({
  ok: hard.length === 0,
  total: results.length,
  reachable: pass,
  business_error: biz,
  hard_failure: hard.length,
  hard_failures: hard,
  data_dir: dataDir,
  case_id: caseId,
}, null, 2))

if (createdTask) fs.rmSync(taskDir, { recursive: true, force: true })
process.exit(hard.length === 0 ? 0 : 1)
