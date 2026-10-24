/** Keep CTF sessions on the shared system without changing any model account. */
export const name = 'ctf-route-guard';
export const inject = ['tools', 'systemPrompt'];
const operations = new Set(['ctf_system_status','ctf_start','ctf_tools','ctf_call',
  'ctf_analyze','ctf_note','ctf_progress','ctf_finish']);

/** Resolve only the eight public operations, including both installed namespaces. */
export function operation(name) {
  for (const prefix of ['mcp__ctf_system__','mcp__ctf-system__']) {
    if (name.startsWith(prefix)) {
      const value = name.slice(prefix.length);
      return operations.has(value) ? value : undefined;
    }
  }
  return undefined;
}

/** A CTF intake locks that agent's later executions to system tools. */
export function createGuard(mode = 'after_ctf_intake') {
  if (!['after_ctf_intake','always'].includes(mode)) throw new Error('Unknown CTF route mode');
  const active = new WeakSet();
  const unscoped = {};
  return (exec) => {
    const agent = exec.agent ?? unscoped;
    const op = operation(exec.name);
    if (op === 'ctf_start' || (op === 'ctf_progress' && exec.arguments?.task_id)) active.add(agent);
    if ((mode === 'always' || active.has(agent)) && !op) {
      return 'CTF_SYSTEM_ROUTE_REQUIRED: 本题已进入CTF系统；执行必须经ctf_analyze/ctf_call。系统报错时记录恢复决定或报告阻塞，禁止改用原生Shell、文件工具或其他Agent绕过。';
    }
    return undefined;
  };
}

/** Mount in the Harness profile, or use always inside a dedicated CTF preset. */
export function apply(ctx, config = {}) {
  const guard = createGuard(config.mode ?? 'after_ctf_intake');
  // tools.guard is an owned monotonic policy; later allow listeners cannot undo it.
  ctx.tools.guard(guard);
  ctx.systemPrompt.section({
    name: 'ctf-system:shared-workflow',
    order: ctx.systemPrompt.getSectionOrder('DEPLOYMENT_PERSONA_SUFFIX'),
    text: '处理CTF题时，先用CTF系统ctf_start建题，续题用ctf_progress。之后实际执行只用系统的ctf_analyze/ctf_call；按系统返回workflow.required_next操作。系统拥有规则、状态、证据和验证口径。当前模型负责推理与工具选择，不改变流程，不绕开系统，不另派模型证明接入。失败时读取原始错误，用ctf_note(resolve_error=true)记录诊断及下一步，无法恢复则ctf_finish(state=blocked)。系统外的工具没有自动留证保证。',
  });
}
