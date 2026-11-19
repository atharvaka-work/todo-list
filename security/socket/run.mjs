// Runs Socket.dev and npm audit against the root lockfile, then writes the comparison reports.
// Usage: npm run security:socket   (from the repository root)
import path from 'node:path'
import { compareResults } from './lib/compare.mjs'
import { buildInventory, ROOT_LOCKFILE } from './lib/lockfile.mjs'
import { normalizeAudit, runNpmAudit } from './lib/npm-audit.mjs'
import { writeReports } from './lib/report.mjs'
import { runSocketScan, socketCliVersion } from './lib/socket.mjs'
import { REPO_ROOT, errorText, log, nowIso, redact, registerSecret } from './lib/util.mjs'

const DEFAULT_REPO_NAME = 'todo-list'
const DEFAULT_BRANCH_NAME = 'main'
const DEFAULT_POLL_SECONDS = 10
const DEFAULT_POLL_TIMEOUT_SECONDS = 900

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback
}

function emptySocket(status, detail) {
  return {
    status,
    detail,
    scanId: null,
    scanState: '',
    htmlReportUrl: '',
    cliVersion: socketCliVersion(),
    artifacts: [],
    scores: null,
  }
}

async function main() {
  const token = process.env.SOCKET_CLI_API_TOKEN ?? ''
  const orgSlug = process.env.SOCKET_CLI_ORG_SLUG ?? ''
  registerSecret(token)
  const repoName = process.env.SOCKET_REPO_NAME || DEFAULT_REPO_NAME
  const branchName = process.env.SOCKET_BRANCH_NAME || DEFAULT_BRANCH_NAME
  const pollSeconds = positiveInt(process.env.SOCKET_POLL_SECONDS, DEFAULT_POLL_SECONDS)
  const timeoutSeconds = positiveInt(process.env.SOCKET_POLL_TIMEOUT_SECONDS, DEFAULT_POLL_TIMEOUT_SECONDS)

  log('Reading the root lockfile...')
  const inventory = buildInventory()
  log(`Inventory: ${inventory.counts.total} packages (${inventory.counts.direct} direct, ${inventory.counts.transitive} transitive).`)

  const generatedAt = nowIso()
  const [socketResult, auditResult] = await Promise.all([
    runSocketSafely({ token, orgSlug, repoName, branchName, pollSeconds, timeoutSeconds }),
    runAuditSafely(),
  ])

  const audit = {
    status: auditResult.status,
    detail: auditResult.detail,
    exitCode: auditResult.exitCode,
    advisories: auditResult.body ? normalizeAudit(auditResult.body, inventory.pathToVersion) : [],
  }

  const comparison = compareResults({ inventory, audit, socket: socketResult })
  const outputs = await writeReports({
    meta: {
      generatedAt,
      repoRoot: REPO_ROOT,
      lockfile: path.relative(REPO_ROOT, ROOT_LOCKFILE),
    },
    inventory,
    audit,
    socket: socketResult,
    comparison,
  })

  log(`Socket status: ${socketResult.status}${socketResult.detail ? ` (${socketResult.detail})` : ''}`)
  log(`npm audit status: ${audit.status}${audit.detail ? ` (${audit.detail})` : ''}`)
  log(`Comparison rows: ${outputs.rowCount} (coverage gaps: ${outputs.gapCount}, not comparable: ${outputs.unavailableCount})`)
  log(`Wrote ${path.relative(REPO_ROOT, outputs.xlsx)}`)
  log(`Wrote ${path.relative(REPO_ROOT, outputs.csv)}`)
  log('Raw outputs are in reports/ (socket-scan-*.json, npm-audit.json).')
}

async function runSocketSafely(options) {
  if (!options.token) {
    log('SOCKET_CLI_API_TOKEN is not set. Skipping Socket; npm audit results are still reported.')
    return emptySocket('skipped', 'SOCKET_CLI_API_TOKEN is not set. Socket was not run.')
  }
  try {
    const result = await runSocketScan({
      token: options.token,
      orgSlug: options.orgSlug,
      repoName: options.repoName,
      branchName: options.branchName,
      targets: ['package.json', 'package-lock.json'],
      pollSeconds: options.pollSeconds,
      timeoutSeconds: options.timeoutSeconds,
    })
    return result
  } catch (error) {
    return emptySocket('error', redact(errorText(error)))
  }
}

async function runAuditSafely() {
  try {
    return await runNpmAudit()
  } catch (error) {
    return { status: 'error', exitCode: null, runAt: nowIso(), body: null, detail: redact(errorText(error)) }
  }
}

main().catch((error) => {
  process.stderr.write(`security:socket failed: ${redact(errorText(error))}\n`)
  process.exitCode = 1
})
