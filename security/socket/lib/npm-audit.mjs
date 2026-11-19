import { spawn } from 'node:child_process'
import path from 'node:path'
import {
  REPO_ROOT,
  REPORTS_DIR,
  errorText,
  extractIds,
  normalizeSeverity,
  nowIso,
  parseJsonLoose,
  truncate,
  writeFileSafe,
  writeReportJson,
} from './util.mjs'

const AUDIT_TIMEOUT_MS = 5 * 60 * 1000
const RAW_FILE = path.join(REPORTS_DIR, 'npm-audit.json')

// npm audit exits 1 when it finds vulnerabilities, so a non-zero exit is not a failure by itself.
export function runNpmAudit() {
  return new Promise((resolve) => {
    const runAt = nowIso()
    let stdout = ''
    let stderr = ''
    let timedOut = false
    let child
    try {
      child = spawn('npm', ['audit', '--json', '--legacy-peer-deps'], {
        cwd: REPO_ROOT,
        env: process.env,
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: process.platform === 'win32',
        windowsHide: true,
      })
    } catch (error) {
      resolve({ status: 'error', exitCode: null, runAt, body: null, detail: errorText(error) })
      return
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, AUDIT_TIMEOUT_MS)
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ status: 'error', exitCode: null, runAt, body: null, detail: errorText(error) })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      const body = parseJsonLoose(stdout)
      if (!body || typeof body !== 'object' || !body.vulnerabilities) {
        writeReportJson('npm-audit.json', {
          command: 'npm audit --json --legacy-peer-deps',
          exit_code: code,
          timed_out: timedOut,
          captured_at: runAt,
          output: null,
          output_text: truncate(stdout, 20000),
          stderr: truncate(stderr, 20000),
        })
        resolve({
          status: 'error',
          exitCode: code,
          runAt,
          body: null,
          detail: timedOut ? 'npm audit timed out' : truncate(stderr.trim() || 'npm audit did not return JSON', 600),
        })
        return
      }
      // Keep npm's own JSON byte-for-byte (after redaction) so the file matches what npm printed.
      writeFileSafe(RAW_FILE, stdout)
      resolve({ status: 'ok', exitCode: code, runAt, body, detail: '' })
    })
  })
}

function fixText(fixAvailable) {
  if (fixAvailable && typeof fixAvailable === 'object') {
    const target = fixAvailable.version ? `${fixAvailable.name ?? ''}@${fixAvailable.version}` : fixAvailable.name ?? ''
    return target ? `upgrade to ${target}` : 'yes'
  }
  if (fixAvailable === true) return 'yes'
  return 'no'
}

// Turns npm audit's per-package output into one row per (installed version, advisory).
// pathToVersion maps lockfile paths (for example node_modules/uuid) to installed versions.
export function normalizeAudit(body, pathToVersion) {
  const advisories = []
  const seen = new Set()
  for (const [name, vuln] of Object.entries(body?.vulnerabilities ?? {})) {
    const advisoryObjects = (Array.isArray(vuln.via) ? vuln.via : []).filter((item) => item && typeof item === 'object')
    if (advisoryObjects.length === 0) continue
    const versions = [...new Set((vuln.nodes ?? []).map((nodePath) => pathToVersion.get(nodePath)).filter(Boolean))]
    const installedVersions = versions.length > 0 ? versions : ['']
    for (const version of installedVersions) {
      for (const advisory of advisoryObjects) {
        const ghsa = extractIds(String(advisory.url ?? '')).ghsa[0] ?? ''
        const key = `${name}@${version}|${ghsa || advisory.title || advisory.source || ''}`
        if (seen.has(key)) continue
        seen.add(key)
        advisories.push({
          key: `${name}@${version}`,
          name,
          version,
          ghsa,
          title: advisory.title ?? '',
          severity: normalizeSeverity(advisory.severity),
          range: advisory.range ?? '',
          url: advisory.url ?? '',
          fixAvailable: fixText(vuln.fixAvailable),
          isDirect: vuln.isDirect === true,
          sourceId: advisory.source !== undefined ? String(advisory.source) : '',
        })
      }
    }
  }
  return advisories
}
