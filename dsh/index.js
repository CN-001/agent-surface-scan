import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { defineTool } from '@deepseek-ai/dsh-tools'
import Schema from '@deepseek-ai/schemastery'

export const name = 'agentscan'
export const inject = ['tools', 'skills']

export const Config = Schema.object({
  binaryPath: Schema.string().default(''),
  registerSkill: Schema.boolean().default(true),
  maxOutputChars: Schema.number().default(20000),
})

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url))
const SKILL_DIR = join(PACKAGE_ROOT, 'skills', 'agentscan')
const SKILL_PATH = join(SKILL_DIR, 'SKILL.md')

const INSTALL_HINT = 'surface-scan binary not found. Install it first:\n' +
  '  go install github.com/CN-001/agent-surface-scan/cmd/surface-scan@v0.2.1\n' +
  'or point the plugin at an existing binary via the agentscan.dsh.binaryPath setting.'

function sessionWorkspace(exec) {
  const cwd = exec?.agent?.session?.header?.cwd
  return resolve(typeof cwd === 'string' && cwd.trim() !== '' ? cwd : process.cwd())
}

function locateBinary(config) {
  const isWin = process.platform === 'win32'
  const exe = isWin ? 'surface-scan.exe' : 'surface-scan'
  const candidates = []
  if (config.binaryPath) {
    const p = isAbsolute(config.binaryPath) ? config.binaryPath : resolve(config.binaryPath)
    candidates.push(p)
    if (isWin && !p.endsWith('.exe')) candidates.push(p + '.exe')
  }
  candidates.push(exe) // resolve via PATH
  for (const c of candidates) {
    if (c.includes('/') || c.includes('\\')) {
      if (existsSync(c)) return c
      continue
    }
    const probe = spawnSync(isWin ? 'where' : 'which', [c], { timeout: 5000 })
    if (probe.status === 0 && String(probe.stdout).trim() !== '') return c
  }
  return ''
}

function readSkillDefinition() {
  const raw = readFileSync(SKILL_PATH, 'utf8')
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/)
  if (!match) throw new Error('agentscan-dsh: SKILL.md frontmatter not found')
  const fields = {}
  for (const line of match[1].split(/\r?\n/)) {
    const i = line.indexOf(':')
    if (i > 0) fields[line.slice(0, i).trim()] = line.slice(i + 1).trim()
  }
  return { name: fields.name, description: fields.description, content: match[2].trim() }
}

function registerSkills(ctx) {
  const top = readSkillDefinition()
  ctx.skills.register({
    ...top,
    source: 'bundled',
    provider: 'agentscan-dsh',
    resourceBase: { kind: 'directory', path: SKILL_DIR },
  })
}

function runScan(binary, args, timeoutMs) {
  const res = spawnSync(binary, args, {
    timeout: timeoutMs,
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
  })
  const out = []
  if (res.stdout && res.stdout.length) out.push(res.stdout.toString('utf8'))
  if (res.stderr && res.stderr.length) out.push(res.stderr.toString('utf8'))
  if (res.error) out.push(`scanner error: ${res.error.message}`)
  if (res.status !== 0) out.push(`[exit code: ${res.status}]`)
  return out.join('\n')
}

function clip(text, max) {
  if (text.length <= max) return text
  return text.slice(0, max) + `\n…(truncated to ${max} chars)`
}

export default function (ctx, config) {
  if (config.registerSkill) registerSkills(ctx)

  ctx.tools.register(defineTool({
    name: 'surface_scan',
    description:
      'Scan the AI-agent attack surface of a directory with agent-surface-scan: finds prompt-injection instructions, remote-code execution prompts, exfiltration, approval bypass, hidden characters, deceptive links, hardcoded secrets and dangerous MCP configs in files coding agents read (AGENTS.md, CLAUDE.md, README, issue templates, skills, MCP configs, docs). Static, safe, read-only. Use it before the agent reads untrusted repository files, or to audit the current workspace.',
    parameters: {
      path: {
        type: 'string',
        description: 'Directory to scan. Defaults to the session working directory.',
      },
      format: {
        type: 'string',
        description: 'Report format: text (default), markdown, json or sarif.',
      },
      exclude: {
        type: 'string',
        description: 'Comma-separated path patterns to exclude, e.g. "testdata,docs".',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const binary = locateBinary(config)
      if (!binary) return INSTALL_HINT
      const target = args.path && String(args.path).trim() !== ''
        ? resolve(String(args.path).trim())
        : sessionWorkspace(exec)
      const format = ['text', 'markdown', 'json', 'sarif'].includes(String(args.format))
        ? String(args.format)
        : 'text'
      const scanArgs = ['scan', target, '--format', format, '--fail-on', 'critical']
      if (args.exclude && String(args.exclude).trim() !== '') {
        scanArgs.push('--exclude', String(args.exclude).trim())
      }
      return clip(runScan(binary, scanArgs, 60000), config.maxOutputChars)
    },
  }))
}
