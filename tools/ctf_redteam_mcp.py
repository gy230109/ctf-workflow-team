"""把破甲红队工具并入 CTF 系统的 MCP 产品面（ctf_product.py 的 TOOLS）。

ctf_os.ALL_TOOLS 是内部工具表；真正给各 agent 客户端看到的是 ctf_product.TOOLS。
本模块把三族工具统一成 ctf_product 期望的 (description, inputSchema, handler) 结构：

  redteam_*        56 个（ctf_redteam_fusion）
  ctf_redteam_*    4 个语义只读（ctf_redteam_semantics）
  ctf_redteam_*    8 个兼容入口（ctf_redteam）

约定：参数里 `case` 与 `task_id` 等价，传哪个都行；两者都缺时按各工具自身默认处理。
"""
import json

# 反向映射：MCP 面用 task_id，红队工具内部用 case
_ALIASES = ('case', 'task_id')


def _wrap(handler):
    def call(args):
        if not isinstance(args, dict):
            raise ValueError('arguments must be an object')
        data = dict(args)
        if 'case' not in data and isinstance(data.get('task_id'), str):
            data['case'] = data['task_id']
        result = handler(data)
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                result = {'ok': True, 'text': result}
        if not isinstance(result, dict):
            result = {'ok': True, 'result': result}
        result.setdefault('ok', True)
        return result
    return call


def catalog():
    """{name: (description, inputSchema, handler(args)->dict)}；任一上游缺失时跳过该族。"""
    out = {}
    try:
        import ctf_redteam_fusion
        for name, entry in ctf_redteam_fusion.TOOLS.items():
            desc, schema = entry[1], entry[2]
            out[name] = (desc, schema, _wrap(entry[0]))
    except Exception:
        pass
    try:
        import ctf_redteam_semantics
        for name, entry in ctf_redteam_semantics.TOOLS.items():
            desc, schema = entry[1], entry[2]
            out[name] = (desc, schema, _wrap(entry[0]))
    except Exception:
        pass
    try:
        import ctf_redteam
        for name, entry in ctf_redteam.TOOLS.items():
            desc, schema = entry[1], entry[2]
            out[name] = (desc, schema, _wrap(entry[0]))
    except Exception:
        pass
    return out


if __name__ == '__main__':
    import sys
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
    cat = catalog()
    print(json.dumps({
        'count': len(cat),
        'redteam': len([n for n in cat if n.startswith('redteam_')]),
        'bridge': len([n for n in cat if n.startswith('ctf_redteam_')]),
        'sample': sorted(cat)[:8],
    }, ensure_ascii=False, indent=2))
