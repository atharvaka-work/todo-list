import { spawn } from 'node:child_process'
import path from 'node:path'
import {
  PACKAGE_DIR,
  REPO_ROOT,
  errorText,
  extractIds,
  findFirstByKey,
  nowIso,
  normalizeSeverity,
  parseJsonLoose,
  readJson,
  redact,
  sleep,
  truncate,
  writeReportJson,
} from './util.mjs'

const CLI_ENTRY = path.join(PACKAGE_DIR, 'node_modules', 'socket', 'bin', 'cli.js')

// Socket's documented scan_state values while a scan is still being processed.
const PROCESSING_STATES = new Set(['pending', 'precrawl', 'resolve', 'scan'])

// Every call uses JSON output and no prompts. The banner is hidden by --no-banner.
const COMMON_FLAGS = ['--json', '--no-banner', '--no-interactive', '--no-spinner']

const CREATE_TIMEOUT_MS = 10 * 60 * 1000
const CALL_TIMEOUT_MS = 2 * 60 * 1000
const VIEW_TIMEOUT_MS = 10 * 60 * 1000

function runCli(args, token, timeoutMs) {
  return new Promise((resolve) => {
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const child = spawn(process.execPath, [CLI_ENTRY, ...args], {
      cwd: REPO_ROOT,
      // The token goes in the child's environment, never in argv, so it is not visible in process listings.
      env: { ...process.env, SOCKET_CLI_API_TOKEN: token },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    })
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, timeoutMs)
    child.stdout.on('data', (chunk) => {
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      stderr += chunk
    })
    child.on('error', (error) => {
      clearTimeout(timer)
      resolve({ code: -1, stdout: redact(stdout), stderr: redact(errorText(error)), timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout: redact(stdout), stderr: redact(stderr), timedOut })
    })
  })
}

export function socketCliVersion() {
  try {
    return readJson(path.join(PACKAGE_DIR, 'node_modules', 'socket', 'package.json')).version
  } catch {
    return 'unknown'
  }
}

function describeFailure(result) {
  const parsed = parseJsonLoose(result.stdout) ?? parseJsonLoose(result.stderr)
  const message = typeof parsed?.message === 'string' ? parsed.message : ''
  const data = typeof parsed?.data === 'string' ? parsed.data : ''
  const text = [message, data, result.stderr].filter(Boolean).join(' | ').replace(/\s+/g, ' ').trim()
  const status = text.match(/\b(401|402|403|404|429|500|502|503)\b/)
  const retry = text.match(/retry-after[^0-9]*(\d+)/i)
  return {
    message: truncate(text || `exit code ${result.code}`, 600),
    exitCode: result.code,
    httpStatus: status ? Number(status[1]) : null,
    retryAfterSeconds: retry ? Number(retry[1]) : null,
    timedOut: result.timedOut,
  }
}

// Socket output shapes are documented in the OpenAPI spec, but field names are only checked
// against a live run. These helpers look in the likely places and report what they found.
export function findScanId(body) {
  const keys = ['id', 'scanId', 'scan_id', 'fullScanId', 'full_scan_id']
  for (const candidate of [body, body?.data, body?.scan]) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      for (const key of keys) {
        if (typeof candidate[key] === 'string' && candidate[key]) return candidate[key]
      }
    }
  }
  return null
}

export function findScanState(body) {
  for (const candidate of [body, body?.data, body?.scan]) {
    if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
      if (typeof candidate.scan_state === 'string') return candidate.scan_state
      if (typeof candidate.scanState === 'string') return candidate.scanState
    }
  }
  return null
}

function findReportUrl(body) {
  for (const candidate of [body, body?.data]) {
    if (candidate && typeof candidate === 'object' && typeof candidate.html_report_url === 'string') {
      return candidate.html_report_url
    }
  }
  return ''
}

// The view output is either one JSON document or newline-delimited JSON records.
export function parseRecords(text) {
  const whole = parseJsonLoose(text)
  const body = whole && typeof whole === 'object' && !Array.isArray(whole) && 'data' in whole && whole.ok !== false
    ? whole.data
    : whole
  if (Array.isArray(body)) return { records: body, parseErrors: 0, format: 'json' }
  if (body && typeof body === 'object' && Array.isArray(body.artifacts)) {
    const records = [...body.artifacts]
    if (body.scores) records.push({ _type: 'scores', value: body.scores })
    return { records, parseErrors: 0, format: 'json' }
  }
  const records = []
  let parseErrors = 0
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    try {
      records.push(JSON.parse(trimmed))
    } catch {
      parseErrors += 1
    }
  }
  return { records, parseErrors, format: 'ndjson' }
}

function normalizeAlert(alert) {
  const props = alert?.props && typeof alert.props === 'object' ? alert.props : {}
  const ids = extractIds(JSON.stringify({ type: alert?.type, props }))
  const category = alert?.category ?? 'other'
  const isCve = category === 'vulnerability'
    || ids.ghsa.length > 0
    || ids.cve.length > 0
    || /cve|vulnerab/i.test(String(alert?.type ?? ''))
  const findingClass = isCve ? 'cve' : category === 'supplyChainRisk' ? 'supply_chain' : 'other'
  const urlValue = findFirstByKey(props, /url|link|href|reference/i)
  return {
    key: alert?.key ?? '',
    type: alert?.type ?? '',
    category,
    findingClass,
    severity: normalizeSeverity(alert?.severity),
    severityRaw: alert?.severity ?? '',
    action: alert?.action ?? '',
    file: alert?.file ?? '',
    ghsaIds: ids.ghsa,
    cveIds: ids.cve,
    title: props.title ?? props.summary ?? alert?.type ?? '',
    description: props.description ?? props.summary ?? '',
    affectedRange: findFirstByKey(props, /range/i) ?? '',
    fixedVersion: findFirstByKey(props, /fixed|patched/i) ?? alert?.fix?.version ?? '',
    remediation: [alert?.fix?.type, alert?.fix?.description].filter(Boolean).join(': '),
    referenceUrl: typeof urlValue === 'string' && urlValue.startsWith('http') ? urlValue : '',
  }
}

function normalizeArtifact(raw) {
  const namespace = typeof raw.namespace === 'string' ? raw.namespace.replace(/^%40/, '') : ''
  const bareName = raw.name ?? ''
  const scope = namespace.replace(/^@/, '')
  const name = scope ? `@${scope}/${bareName}` : bareName
  const version = raw.version ?? ''
  return {
    ecosystem: raw.type ?? 'npm',
    name,
    version,
    key: `${name}@${version}`,
    direct: raw.direct === true,
    dev: raw.dev === true,
    dead: raw.dead === true,
    license: raw.license ?? '',
    score: raw.score && typeof raw.score === 'object' ? raw.score : null,
    alerts: (Array.isArray(raw.alerts) ? raw.alerts : []).map(normalizeAlert),
  }
}

export function normalizeRecords(records) {
  const artifacts = []
  let scores = null
  for (const record of records) {
    if (!record || typeof record !== 'object') continue
    if (record._type === 'scores') {
      scores = record.value ?? null
    } else if (typeof record.name === 'string' && typeof record.version === 'string') {
      artifacts.push(normalizeArtifact(record))
    }
  }
  return { artifacts, scores }
}

function failure(result, detail) {
  return { ...result, status: 'error', detail: detail ?? '' }
}

// Runs one Socket scan and returns the normalized result. Failures are recorded, not thrown.
export async function runSocketScan({ token, orgSlug, repoName, branchName, targets, pollSeconds, timeoutSeconds }) {
  const result = {
    status: 'skipped',
    detail: '',
    scanId: null,
    scanState: '',
    htmlReportUrl: '',
    startedAt: nowIso(),
    completedAt: '',
    cliVersion: socketCliVersion(),
    artifacts: [],
    scores: null,
    parseErrors: 0,
    httpStatus: null,
    retryAfterSeconds: null,
  }

  if (!token) {
    result.detail = 'SOCKET_CLI_API_TOKEN is not set. Socket was not run.'
    return result
  }
  if (!orgSlug) {
    result.detail = 'SOCKET_CLI_ORG_SLUG is not set. Socket was not run.'
    return result
  }

  // The CLI ignores SOCKET_CLI_ORG_SLUG for these commands, so the org is passed on every call.
  const orgArgs = ['--org', orgSlug]

  try {
    const create = await runCli(
      // --default-branch marks this branch as the repo's default. Socket's Alerts page only shows
      // scans from the default branch, so without it the scan never appears there.
      ['scan', 'create', ...COMMON_FLAGS, ...orgArgs, '--repo', repoName, '--branch', branchName, '--default-branch', '--cwd', REPO_ROOT, ...targets],
      token,
      CREATE_TIMEOUT_MS,
    )
    const createBody = parseJsonLoose(create.stdout)
    writeEnvelope('socket-scan-create.json', 'socket scan create', create, createBody)
    if (create.code !== 0) {
      const info = describeFailure(create)
      return failure({ ...result, ...info }, info.message)
    }

    result.scanId = findScanId(createBody)
    result.htmlReportUrl = findReportUrl(createBody)
    if (!result.scanId) {
      return failure(result, 'scan id was not found in the create output (see reports/socket-scan-create.json)')
    }

    const deadline = Date.now() + timeoutSeconds * 1000
    let lastMeta = null
    let state = null
    let unknownStreak = 0
    for (;;) {
      const meta = await runCli(['scan', 'metadata', result.scanId, ...COMMON_FLAGS, ...orgArgs], token, CALL_TIMEOUT_MS)
      lastMeta = meta
      if (meta.code !== 0) {
        writeEnvelope('socket-scan-metadata.json', 'socket scan metadata', meta, parseJsonLoose(meta.stdout))
        return failure({ ...result, ...describeFailure(meta) }, describeFailure(meta).message)
      }
      const metaBody = parseJsonLoose(meta.stdout)
      state = findScanState(metaBody)
      unknownStreak = state === null ? unknownStreak + 1 : 0
      result.scanState = state ?? 'unknown'
      if (state !== null && !PROCESSING_STATES.has(state)) break
      if (state === null && unknownStreak >= 3) break
      if (Date.now() >= deadline) {
        writeEnvelope('socket-scan-metadata.json', 'socket scan metadata', lastMeta, parseJsonLoose(lastMeta.stdout))
        return {
          ...result,
          status: 'incomplete',
          detail: `scan still in state "${state}" after ${timeoutSeconds}s. Findings were not read, so this is not a clean result.`,
        }
      }
      await sleep(pollSeconds * 1000)
    }
    writeEnvelope('socket-scan-metadata.json', 'socket scan metadata', lastMeta, parseJsonLoose(lastMeta.stdout))

    const view = await runCli(['scan', 'view', result.scanId, '--stream', ...COMMON_FLAGS, ...orgArgs], token, VIEW_TIMEOUT_MS)
    if (view.code !== 0) {
      writeEnvelope('socket-scan-view.json', 'socket scan view', view, parseJsonLoose(view.stdout))
      return failure({ ...result, ...describeFailure(view) }, describeFailure(view).message)
    }
    const parsed = parseRecords(view.stdout)
    writeEnvelope('socket-scan-view.json', 'socket scan view', view, parsed.records)

    const normalized = normalizeRecords(parsed.records)
    result.parseErrors = parsed.parseErrors
    result.artifacts = normalized.artifacts
    result.scores = normalized.scores
    result.completedAt = nowIso()
    if (normalized.artifacts.length === 0) {
      return {
        ...result,
        status: 'empty',
        detail: 'Socket returned no package artifacts. See reports/socket-scan-view.json.',
      }
    }
    return {
      ...result,
      status: 'ok',
      detail: state === null
        ? 'scan_state was missing from metadata; results were read after the view call.'
        : `scan finished with state "${state}"`,
    }
  } catch (error) {
    return failure(result, truncate(redact(errorText(error)), 600))
  }
}

// Saves the raw output of one CLI call. The file is always valid JSON, and the token is redacted.
function writeEnvelope(file, command, result, parsedOutput) {
  writeReportJson(file, {
    command,
    exit_code: result.code,
    timed_out: result.timedOut,
    captured_at: nowIso(),
    output: parsedOutput ?? null,
    output_text: parsedOutput === null || parsedOutput === undefined ? truncate(result.stdout, 20000) : undefined,
    stderr: truncate(result.stderr, 20000),
  })
}
