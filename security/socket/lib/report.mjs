import path from 'node:path'
import ExcelJS from 'exceljs'
import { REPORTS_DIR, writeFileSafe } from './util.mjs'

export const CSV_FILE = path.join(REPORTS_DIR, 'socket-security-report.csv')
export const XLSX_FILE = path.join(REPORTS_DIR, 'socket-security-report.xlsx')

const MAX_CELL = 30000
const FORMULA_START = /^[=+\-@\t\r]/
// Scoped npm names such as @scope/name are plain text, not formulas.
const SCOPED_NAME = /^@[a-z0-9][a-z0-9._~-]*\/[^\s]+$/i

// Excel and other spreadsheet apps run text that starts with = + - @ as a formula. Prefix those with a quote.
export function safeCell(value) {
  if (value === undefined || value === null) return ''
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  let text = String(value)
  if (FORMULA_START.test(text) && !SCOPED_NAME.test(text)) text = `'${text}`
  return text.length > MAX_CELL ? `${text.slice(0, MAX_CELL - 3)}...` : text
}

function csvField(value) {
  const text = safeCell(value)
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

function toCsv(columns, rows) {
  const lines = [columns.map((column) => csvField(column.header)).join(',')]
  for (const row of rows) {
    lines.push(columns.map((column) => csvField(row[column.key])).join(','))
  }
  return lines.join('\r\n')
}

const COMPARISON_COLUMNS = [
  { header: 'Package', key: 'name', width: 34 },
  { header: 'Version', key: 'version', width: 14 },
  { header: 'Category', key: 'category', width: 14 },
  { header: 'Classification', key: 'classification', width: 30 },
  { header: 'Direct', key: 'directLabel', width: 10 },
  { header: 'Dependency Type', key: 'depType', width: 16 },
  { header: 'Socket Vulnerabilities', key: 'socketFindingCount', width: 14 },
  { header: 'Socket Advisory IDs', key: 'socketIds', width: 30 },
  { header: 'Socket Severity', key: 'socketSeverities', width: 14 },
  { header: 'Socket Titles', key: 'socketTitles', width: 50 },
  { header: 'npm Audit Vulnerabilities', key: 'auditFindingCount', width: 14 },
  { header: 'npm Audit Advisory IDs', key: 'auditIds', width: 30 },
  { header: 'npm Audit Severity', key: 'auditSeverities', width: 14 },
  { header: 'npm Audit Titles', key: 'auditTitles', width: 50 },
  { header: 'npm Audit Affected Range', key: 'auditRanges', width: 24 },
  { header: 'npm Audit Fix', key: 'auditFix', width: 24 },
  { header: 'Match Type', key: 'matchType', width: 16 },
  { header: 'In Socket Scan', key: 'socketInScanLabel', width: 12 },
  { header: 'Note', key: 'note', width: 70 },
]

// Adds the display-only columns used by both outputs.
function decorateRows(rows) {
  return rows.map((row) => ({
    ...row,
    directLabel: row.direct ? 'direct' : 'transitive',
    depType: row.dev ? 'development' : 'production',
    socketInScanLabel: row.socketInScan ? 'yes' : 'no',
  }))
}

const INVENTORY_COLUMNS = [
  { header: 'Package', key: 'name', width: 34 },
  { header: 'Version', key: 'version', width: 14 },
  { header: 'Direct', key: 'directLabel', width: 12 },
  { header: 'Dependency Type', key: 'depType', width: 16 },
  { header: 'Optional', key: 'optional', width: 10 },
  { header: 'Lockfile Path', key: 'lockPath', width: 60 },
  { header: 'License', key: 'license', width: 18 },
  { header: 'Socket Vulnerabilities', key: 'socketFindingCount', width: 14 },
  { header: 'npm Audit Vulnerabilities', key: 'auditFindingCount', width: 14 },
  { header: 'Category', key: 'category', width: 14 },
]

const SOCKET_FINDING_COLUMNS = [
  { header: 'Package', key: 'package', width: 34 },
  { header: 'Version', key: 'version', width: 14 },
  { header: 'Finding Class', key: 'findingClass', width: 14 },
  { header: 'Alert Type', key: 'type', width: 26 },
  { header: 'Category', key: 'category', width: 16 },
  { header: 'Severity', key: 'severity', width: 12 },
  { header: 'Action', key: 'action', width: 14 },
  { header: 'GHSA IDs', key: 'ghsaIds', width: 26 },
  { header: 'CVE IDs', key: 'cveIds', width: 22 },
  { header: 'Title', key: 'title', width: 50 },
  { header: 'Affected Range', key: 'affectedRange', width: 22 },
  { header: 'Fixed Version', key: 'fixedVersion', width: 16 },
  { header: 'Remediation', key: 'remediation', width: 36 },
  { header: 'Reference URL', key: 'referenceUrl', width: 50 },
  { header: 'Direct', key: 'directLabel', width: 12 },
  { header: 'Dependency Type', key: 'depType', width: 16 },
  { header: 'File', key: 'file', width: 30 },
]

// Real coverage gaps: one scanner saw something the other did not, or the scanner could not check it.
const CONTENT_GAP_CLASSIFICATIONS = [
  'potential_socket_miss',
  'package_not_in_socket_scan',
  'outside_affected_range',
  'socket_only_not_in_npm_audit',
]
// Rows that could not be compared because a scanner did not produce usable results.
const UNAVAILABLE_CLASSIFICATIONS = ['socket_scan_unavailable', 'npm_audit_unavailable']
const COVERAGE_CLASSIFICATIONS = [...CONTENT_GAP_CLASSIFICATIONS, ...UNAVAILABLE_CLASSIFICATIONS]

export function socketFindingRows(artifacts) {
  const rows = []
  for (const artifact of artifacts ?? []) {
    for (const alert of artifact.alerts ?? []) {
      rows.push({
        package: artifact.name,
        version: artifact.version,
        findingClass: alert.findingClass,
        type: alert.type,
        category: alert.category,
        severity: alert.severity,
        action: alert.action,
        ghsaIds: alert.ghsaIds.join('; '),
        cveIds: alert.cveIds.join('; '),
        title: alert.title,
        affectedRange: alert.affectedRange,
        fixedVersion: alert.fixedVersion,
        remediation: alert.remediation,
        referenceUrl: alert.referenceUrl,
        direct: artifact.direct,
        dev: artifact.dev,
        file: alert.file,
      })
    }
  }
  return rows.map((row) => ({
    ...row,
    directLabel: row.direct ? 'direct' : 'transitive',
    depType: row.dev ? 'development' : 'production',
  }))
}

function summaryRows({ meta, inventory, audit, socket, stats }) {
  const rows = [
    ['Section', 'Item', 'Value'],
    ['Run', 'Generated at', meta.generatedAt],
    ['Run', 'Repository root', meta.repoRoot],
    ['Run', 'Lockfile scanned', meta.lockfile],
    ['Run', 'Socket CLI version', socket.cliVersion],
    ['Run', 'npm audit exit code', audit.exitCode ?? ''],
    ['Socket', 'Status', socket.status],
    ['Socket', 'Detail', socket.detail],
    ['Socket', 'Scan ID', socket.scanId ?? ''],
    ['Socket', 'Final scan state', socket.scanState],
    ['Socket', 'Socket report URL', socket.htmlReportUrl],
    ['Socket', 'Packages in Socket scan', stats.socketArtifacts],
    ['Socket', 'Packages with Socket vulnerability alerts', stats.socketVulnerablePackages],
    ['npm audit', 'Status', audit.status],
    ['npm audit', 'Detail', audit.detail],
    ['npm audit', 'Advisory entries', stats.auditAdvisories],
    ['npm audit', 'Packages with npm audit vulnerabilities', stats.auditVulnerablePackages],
    ['Inventory', 'Packages in lockfile', inventory.counts.total],
    ['Inventory', 'Direct', inventory.counts.direct],
    ['Inventory', 'Transitive', inventory.counts.transitive],
    ['Inventory', 'Production', inventory.counts.production],
    ['Inventory', 'Development', inventory.counts.development],
    ['Comparison', 'Both scanners found a vulnerability', stats.byCategory.both],
    ['Comparison', 'Socket only', stats.byCategory.socket_only],
    ['Comparison', 'npm audit only', stats.byCategory.audit_only],
    ['Comparison', 'Neither scanner found a vulnerability', stats.byCategory.neither],
    ['Comparison', 'OSV alias data loaded', stats.osvAliasesLoaded ? 'yes' : 'no'],
  ]
  for (const [classification, count] of Object.entries(stats.classifications).sort()) {
    rows.push(['Classification', classification, count])
  }
  rows.push(['Limitations', 'Socket scan', 'Socket findings depend on the Socket plan and what its scanner covers. Free-plan limits apply (1,000 scans per month, 500 API requests per hour).'])
  rows.push(['Limitations', 'npm audit', 'npm audit uses the npm registry advisory database. Its results can differ from Socket and from OSV.'])
  rows.push(['Limitations', 'Scope', 'Only the root project lockfile (package-lock.json) is scanned. security/socket/ has its own lockfile and is not part of this report.'])
  return rows
}

// Writes the CSV and XLSX outputs. Returns the file paths.
export async function writeReports({ meta, inventory, audit, socket, comparison }) {
  const decorated = decorateRows(comparison.rows)
  const csv = toCsv(COMPARISON_COLUMNS, decorated)
  writeFileSafe(CSV_FILE, `\uFEFF${csv}\r\n`)

  const workbook = new ExcelJS.Workbook()
  workbook.creator = 'todo-list security:socket'
  workbook.created = new Date()

  const summary = workbook.addWorksheet('Scan Summary')
  for (const row of summaryRows({ meta, inventory, audit, socket, stats: comparison.stats })) {
    summary.addRow(row.map(safeCell))
  }
  summary.getRow(1).font = { bold: true }
  summary.columns = [{ width: 20 }, { width: 46 }, { width: 90 }]
  summary.views = [{ state: 'frozen', ySplit: 1 }]

  const inventorySheet = workbook.addWorksheet('Dependency Inventory')
  const inventoryRows = inventory.entries.map((entry) => {
    const row = comparison.rows.find((item) => item.key === entry.key)
    return {
      name: entry.name,
      version: entry.version,
      directLabel: entry.direct ? 'direct' : 'transitive',
      depType: entry.dev ? 'development' : 'production',
      optional: entry.optional,
      lockPath: entry.lockPath,
      license: entry.license,
      socketFindingCount: row?.socketFindingCount ?? 0,
      auditFindingCount: row?.auditFindingCount ?? 0,
      category: row?.category ?? 'neither',
    }
  })
  writeTable(inventorySheet, INVENTORY_COLUMNS, inventoryRows)

  const findingsSheet = workbook.addWorksheet('Socket Findings')
  const findingRows = socketFindingRows(socket.artifacts)
  if (findingRows.length === 0) {
    findingsSheet.addRow([socketEmptyMessage(socket)])
    findingsSheet.getRow(1).font = { bold: true }
  } else {
    writeTable(findingsSheet, SOCKET_FINDING_COLUMNS, findingRows)
  }

  const comparisonSheet = workbook.addWorksheet('Cross-Scanner Comparison')
  writeTable(comparisonSheet, COMPARISON_COLUMNS, decorated)

  const coverageSheet = workbook.addWorksheet('Coverage & Gaps')
  const gapRows = decorated.filter((row) => COVERAGE_CLASSIFICATIONS.includes(row.classification))
  writeTable(coverageSheet, COMPARISON_COLUMNS, gapRows)

  await workbook.xlsx.writeFile(XLSX_FILE)
  return {
    csv: CSV_FILE,
    xlsx: XLSX_FILE,
    rowCount: decorated.length,
    gapCount: decorated.filter((row) => CONTENT_GAP_CLASSIFICATIONS.includes(row.classification)).length,
    unavailableCount: decorated.filter((row) => UNAVAILABLE_CLASSIFICATIONS.includes(row.classification)).length,
  }
}

function socketEmptyMessage(socket) {
  if (socket.status === 'ok') return 'Socket returned no alerts for this scan.'
  return `Socket did not produce findings (status: ${socket.status}). ${safeCell(socket.detail)}`
}

function writeTable(sheet, columns, rows) {
  sheet.columns = columns.map((column) => ({ header: column.header, key: column.key, width: column.width }))
  sheet.getRow(1).font = { bold: true }
  for (const row of rows) {
    const values = {}
    for (const column of columns) values[column.key] = safeCell(row[column.key])
    sheet.addRow(values)
  }
  sheet.views = [{ state: 'frozen', ySplit: 1 }]
  if (rows.length > 0) {
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } }
  }
}