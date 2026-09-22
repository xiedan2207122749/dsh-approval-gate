/**
 * 规则路径匹配 + 判定文本解析回归测试（无框架，`node tests/rule-path-and-judge-parse.mjs`）。
 *
 * 复现的第二个事故（2026-09-22 实测，audit.log）：
 *   ① 路径规则失效：allowRules 的 contains 只匹配「操作理由」文本，模型没把路径写进理由时
 *      `contains:"d:\workspace\"` 整条不生效 → 退化成 flash 判定 → 判定器一波动就全转人工。
 *   ② DENY 误伤：denyKeywords 里的 'revoke' 命中的是理由散文（新增 RevokeDTO 的说明），
 *      不是命令本身 → 合法开发被拦。
 *   ③ 思考档判定不可用：判定路由不支持 effort "off" 时降级到默认档（带思考），模型先输出
 *      大段推理，256 token 被推理吃光、结论没吐出 → "flash 输出无法解析" → 转人工。
 *
 * 断言：
 *   ① 规则 contains 能命中「本次调用的真实文件路径」（理由里不含路径也放行，且不调用模型）
 *   ② 推理文本不参与结论判定（推理说 safe、结论说 RISKY → 按 RISKY）
 *   ③ 多条结论取最后一次
 *   ④ 不思考档 256 token、思考档 1024 token
 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const home = mkdtempSync(join(tmpdir(), 'approval-gate-rules-'))
process.env.DSH_HOME = home
const dataDir = join(home, 'auto-approve')
mkdirSync(dataDir, { recursive: true })
const allowlistPath = join(dataDir, 'allowlist.json')

function writeConfig(extra = {}) {
  writeFileSync(allowlistPath, JSON.stringify({
    version: 3,
    denyKeywords: [],
    allowRules: [],
    denyRules: [],
    hardCategories: ['deletion', 'credential', 'remote', 'system', 'bulk'],
    riskyThreshold: 3,
    judgeTimeoutMs: 20000,
    learning: { enabled: false },
    ...extra
  }, null, 2), 'utf8')
}
writeConfig()

const plugin = (await import('../src/index.mjs')).default

function makeHost(reply) {
  const calls = []
  let approvalHandler = null
  const ctx = {
    llm: {
      stream(options) {
        calls.push(options)
        return (async function* () { for (const chunk of reply(options)) yield chunk })()
      }
    },
    permissionPresets: { current: () => 'auto-approve' },
    get: (name) => name === 'agentDefaultModel'
      ? { currentSelection: () => ({ provider: 'modlens-zai-coding-cn', model: 'GLM-5.3' }) }
      : undefined,
    timeout: (ms) => new Promise((resolve) => { const t = setTimeout(resolve, ms); if (t.unref) t.unref() }),
    effect: (fn) => { const d = fn(); return typeof d === 'function' ? d : () => {} },
    on: (event, h) => { if (event === 'approval/request') approvalHandler = h; return () => {} },
    logger: { info() {}, warn() {}, error() {} }
  }
  plugin.apply(ctx)
  if (!approvalHandler) throw new Error('插件未注册 approval/request 处理器')
  return {
    calls,
    request: ({ callId, toolName, justification, filePath }) => approvalHandler({
      agent: {
        session: {
          id: 'session-test',
          cwd: 'D:\\deepSeekHarnessWorkspace',
          events: filePath === undefined ? [] : [{
            type: 'tool/call',
            data: { callId, name: toolName, arguments: JSON.stringify({ file_path: filePath }) }
          }]
        }
      },
      toolName,
      reason: `escalate sandbox to danger-full-access: ${justification}`,
      callId
    }, async () => 'allowed-once')
  }
}

const text = (t) => [{ type: 'text-delta', text: t }, { type: 'finish', reason: { kind: 'stop' } }]
let failed = 0
const check = (name, cond, detail) => {
  if (cond) { console.log(`  ✓ ${name}`) } else { failed++; console.error(`  ✗ ${name}${detail ? ' — ' + detail : ''}`) }
}

// ---- ① 规则 contains 命中真实文件路径（理由里没有路径）----
console.log('① 路径规则按「真实文件路径」匹配')
{
  writeConfig({
    allowRules: [{ tool: 'edit', mode: 'danger-full-access', contains: 'd:\\workspace\\', description: 'D:\\workspace 整树' }]
  })
  const host = makeHost(() => text('SAFE'))
  const out = await host.request({
    callId: 'call-rule',
    toolName: 'edit',
    justification: '中台工程 worktree 位于会话工作区外,需在 ServiceImpl 实现暂存数据删除方法',
    filePath: 'D:\\workspace\\suncent-api-platform\\src\\main\\java\\A.java'
  })
  check('理由不含路径也按规则放行', out === 'allowed-once', `实际 ${out}`)
  check('未调用判定模型（规则层短路）', host.calls.length === 0, `实际调用 ${host.calls.length} 次`)
}

// ---- ①b 路径不在规则内 → 仍走判定（规则没有被放宽）----
console.log('①b 路径不在规则内时不误放行')
{
  writeConfig({
    allowRules: [{ tool: 'edit', mode: 'danger-full-access', contains: 'd:\\workspace\\', description: 'D:\\workspace 整树' }]
  })
  const host = makeHost(() => text('RISKY:credential'))
  const out = await host.request({
    callId: 'call-out',
    toolName: 'edit',
    justification: '修改工作区外某项目的凭据配置',
    filePath: 'C:\\Users\\Administrator\\.dsh\\.credentials.yaml'
  })
  check('判定模型被调用（未被规则放行）', host.calls.length > 0, `实际 ${host.calls.length} 次`)
  check('返回人工路径（allowed-once 由下游人工批准）', out === 'allowed-once')
  const ev = readFileSync(join(dataDir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).pop()
  check('事件 category=credential（硬风险转人工）', ev.category === 'credential', JSON.stringify(ev.category))
}

// ---- ② 推理文本不参与结论判定 ----
console.log('② 推理里的 safe 不当作结论')
{
  writeConfig()
  rmSync(join(dataDir, 'events.jsonl'), { force: true })
  const host = makeHost(() => [
    { type: 'reasoning-delta', text: 'Let me analyze this request.\n- Tool: edit\n- This operation looks safe.\n' },
    { type: 'text-delta', text: 'RISKY:deletion' },
    { type: 'finish', reason: { kind: 'stop' } }
  ])
  await host.request({
    callId: 'call-reason',
    toolName: 'edit',
    justification: '删除历史遗留的临时表结构定义文件',
    filePath: 'D:\\workspace\\tmp\\Legacy.sql'
  })
  const ev = readFileSync(join(dataDir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).pop()
  check('按结论 RISKY:deletion 转人工（未被推理里的 safe 带偏）', ev.category === 'deletion' && ev.path === 'hard-category',
    `${ev.category}/${ev.path}`)
}

// ---- ③ 多条结论取最后一次 ----
console.log('③ 多条结论取最后一次')
{
  writeConfig()
  rmSync(join(dataDir, 'events.jsonl'), { force: true })
  const host = makeHost(() => text('SAFE\n\nWait, this touches credentials: RISKY:credential'))
  await host.request({
    callId: 'call-last',
    toolName: 'edit',
    justification: '更新工作区外的服务凭据引用',
    filePath: 'D:\\workspace\\svc\\application.yml'
  })
  const ev = readFileSync(join(dataDir, 'events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l)).pop()
  check('取最后一条结论 credential', ev.category === 'credential', JSON.stringify(ev.category))
}

// ---- ④ 思考档给足 token ----
console.log('④ token 上限随档位')
{
  writeConfig({ judgeModel: { provider: 'deepseek-official', model: 'deepseek-v4-flash' } })
  const supportOff = makeHost(() => text('SAFE'))
  await supportOff.request({ callId: 'c1', toolName: 'edit', justification: '常规改动', filePath: 'D:\\workspace\\a\\b.java' })
  check('支持 off 档 → maxTokens=256', supportOff.calls[0]?.maxTokens === 256 && supportOff.calls[0]?.reasoningEffort === 'off',
    `maxTokens=${supportOff.calls[0]?.maxTokens}`)

  const unsupported = {
    code: 'UNSUPPORTED_REASONING_EFFORT',
    message: 'provider "p" model "m" does not support reasoning effort "off"'
  }
  const noOff = makeHost((options) => options.reasoningEffort === 'off'
    ? [{ type: 'finish', reason: { kind: 'error', failure: unsupported } }]
    : text('SAFE'))
  await noOff.request({ callId: 'c2', toolName: 'edit', justification: '常规改动', filePath: 'D:\\workspace\\a\\c.java' })
  check('降级档 → maxTokens=1024 且不带 effort',
    noOff.calls[1]?.maxTokens === 1024 && noOff.calls[1]?.reasoningEffort === undefined,
    `maxTokens=${noOff.calls[1]?.maxTokens}`)
}

rmSync(home, { recursive: true, force: true })
if (failed > 0) {
  console.error(`\n${failed} 项断言失败`)
  process.exit(1)
}
console.log('\n全部断言通过')
