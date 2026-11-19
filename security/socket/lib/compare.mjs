import { existsSync } from 'node:fs'
import path from 'node:path'
import semver from 'semver'
import { REPORTS_DIR, readJson, uniq } from './util.mjs'

export const CATEGORY_ORDER = ['both', 'socket_only', 'audit_only', 'neither']

// Loads GHSA <-> CVE alias groups from the OSV offline output, if it exists.
// Returns a function that maps any advisory ID to a canonical representative.
export function loadAliasResolver() {
  const parent = new Map()
  const find = (id) => {
    if (!parent.has(id)) parent.set(id, id)
    let root = id
    while (parent.get(root) !== root) root = parent.get(root)
    parent.set(id, root)
    return root
  }
  const union = (a, b) => {
    const rootA = find(a)
    const rootB = find(b)
    if (rootA !== rootB) parent.set(rootA, rootB)
  }

  const osvFile = path.join(REPORTS_DIR, 'osv-offline.json')
  let loaded = false
  if (existsSync(osvFile)) {
    try {
      const osv = readJson(osvFile)
      for (const result of osv.results ?? []) {
        for (const pkg of result.packages ?? []) {
          for (const group of pkg.groups ?? []) {
            const ids = uniq([...(group.ids ?? []), ...(group.aliases ?? [])]).map((id) => String(id).toUpperCase())
            for (let i = 1; i < ids.length; i += 1) union(ids[0], ids[i])
          }
          loaded = true
        }
      }
    } catch {
      loaded = false
    }
  }

  return {
    loaded,
    canonical: (id) => find(String(id).toUpperCase()),
  }
}

function isInRange(version, range) {
  if (!version || !range) return null
  try {
    return semver.satisfies(version, range, { includePrerelease: true })
  } catch {
    return null
  }
}

function summarizeSocket(alerts) {
  return {
    count: alerts.length,
    ids: uniq(alerts.flatMap((alert) => [...alert.ghsaIds, ...alert.cveIds])),
    severities: uniq(alerts.map((alert) => alert.severity)),
    titles: uniq(alerts.map((alert) => alert.title)),
  }
}

function summarizeAudit(advisories) {
  return {
    count: advisories.length,
    ids: uniq(advisories.map((advisory) => advisory.ghsa)),
    severities: uniq(advisories.map((advisory) => advisory.severity)),
    titles: uniq(advisories.map((advisory) => advisory.title)),
    ranges: uniq(advisories.map((advisory) => advisory.range)),
    fixes: uniq(advisories.map((advisory) => advisory.fixAvailable)),
  }
}

// Decides how the two scanners' IDs relate: the same ID, an alias match (GHSA <-> CVE), or no shared ID.
function matchIds(socketIds, auditIds, resolver) {
  if (socketIds.length === 0 || auditIds.length === 0) return 'no_shared_id'
  const direct = socketIds.some((id) => auditIds.includes(id))
  if (direct) return 'same_id'
  const socketCanon = new Set(socketIds.map((id) => resolver.canonical(id)))
  const aliasHit = auditIds.some((id) => socketCanon.has(resolver.canonical(id)))
  return aliasHit ? 'alias' : 'no_shared_id'
}

function classify({ category, audit, row, matchType, auditRangeOutside }) {
  if (category === 'both') {
    if (matchType === 'same_id') return 'matched_same_id'
    if (matchType === 'alias') return 'alias_resolved'
    return 'matched_package_version_only'
  }
  if (category === 'audit_only') {
    if (auditRangeOutside) return 'outside_affected_range'
    if (!row.socketInScan) return 'package_not_in_socket_scan'
    return 'potential_socket_miss'
  }
  if (category === 'socket_only') {
    if (audit.status !== 'ok') return 'npm_audit_unavailable'
    return 'socket_only_not_in_npm_audit'
  }
  return 'no_findings'
}

// Builds one comparison row per installed package version across the inventory, Socket, and npm audit.
export function compareResults({ inventory, audit, socket }) {
  const resolver = loadAliasResolver()
  const socketStatus = socket.status
  const socketUsable = socketStatus === 'ok'
  const auditUsable = audit.status === 'ok'

  const byKey = new Map()
  const ensure = (key, base) => {
    if (!byKey.has(key)) byKey.set(key, { key, ...base })
    return byKey.get(key)
  }

  for (const entry of inventory.entries) {
    ensure(entry.key, {
      name: entry.name,
      version: entry.version,
      direct: entry.direct,
      dev: entry.dev,
      inInventory: true,
      lockPath: entry.lockPath,
    })
  }

  const socketArtifactKeys = new Set()
  const socketAlertsByKey = new Map()
  for (const artifact of socket.artifacts ?? []) {
    socketArtifactKeys.add(artifact.key)
    const vulns = artifact.alerts.filter((alert) => alert.findingClass === 'cve')
    ensure(artifact.key, {
      name: artifact.name,
      version: artifact.version,
      direct: artifact.direct,
      dev: artifact.dev,
      inInventory: false,
    })
    socketAlertsByKey.set(artifact.key, vulns)
  }

  const auditByKey = new Map()
  for (const advisory of audit.advisories ?? []) {
    ensure(advisory.key, {
      name: advisory.name,
      version: advisory.version,
      direct: advisory.isDirect,
      dev: false,
      inInventory: false,
    })
    if (!auditByKey.has(advisory.key)) auditByKey.set(advisory.key, [])
    auditByKey.get(advisory.key).push(advisory)
  }

  const rows = []
  for (const base of byKey.values()) {
    const socketAlerts = socketUsable ? socketAlertsByKey.get(base.key) ?? [] : []
    const auditAdvisories = auditUsable ? auditByKey.get(base.key) ?? [] : []
    const socketSummary = summarizeSocket(socketAlerts)
    const auditSummary = summarizeAudit(auditAdvisories)

    const socketFound = socketSummary.count > 0
    const auditFound = auditSummary.count > 0
    const category = socketFound && auditFound
      ? 'both'
      : socketFound
        ? 'socket_only'
        : auditFound
          ? 'audit_only'
          : 'neither'

    const socketIds = uniq(socketSummary.ids.map((id) => id.toUpperCase()))
    const auditIds = uniq(auditSummary.ids.map((id) => id.toUpperCase()))
    const matchType = category === 'both' ? matchIds(socketIds, auditIds, resolver) : 'not_applicable'

    // The advisory range only tells us anything when it is known and the installed version is outside it.
    const installedOutside = auditAdvisories.length > 0 && auditAdvisories.every((advisory) => isInRange(base.version, advisory.range) === false)

    const row = {
      ...base,
      direct: base.direct === true,
      dev: base.dev === true,
      inInventory: base.inInventory === true,
      socketInScan: socketArtifactKeys.has(base.key),
      category,
      matchType,
      socketFindingCount: socketSummary.count,
      socketIds: socketIds.join('; '),
      socketSeverities: socketSummary.severities.join('; '),
      socketTitles: socketSummary.titles.join(' | '),
      auditFindingCount: auditSummary.count,
      auditIds: auditIds.join('; '),
      auditSeverities: auditSummary.severities.join('; '),
      auditTitles: auditSummary.titles.join(' | '),
      auditRanges: auditSummary.ranges.join('; '),
      auditFix: auditSummary.fixes.join('; '),
    }

    // Priority: a missing scanner explains the row first, because its empty result means "unknown", not "clean".
    let classification
    if (!socketUsable) {
      classification = 'socket_scan_unavailable'
    } else if (!auditUsable && category === 'neither') {
      classification = 'npm_audit_unavailable'
    } else {
      classification = classify({
        category,
        audit,
        row,
        matchType,
        auditRangeOutside: installedOutside,
      })
    }
    row.classification = classification
    row.note = noteFor(row, socketStatus, audit.status, resolver.loaded)
    rows.push(row)
  }

  rows.sort((a, b) => {
    const order = CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category)
    return order || a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version))
  })

  return {
    rows,
    stats: buildStats(rows, inventory, socket, audit, resolver.loaded),
  }
}

function noteFor(row, socketStatus, auditStatus, osvAliasesLoaded) {
  switch (row.classification) {
    case 'potential_socket_miss':
      return 'npm audit reports a vulnerability for this exact version; Socket returned no vulnerability alert. Check this one manually.'
    case 'package_not_in_socket_scan':
      return 'npm audit reports a vulnerability, but this package version is not in the Socket scan artifact list.'
    case 'outside_affected_range':
      return 'npm audit advisory range does not include the installed version.'
    case 'alias_resolved':
      return osvAliasesLoaded
        ? 'Socket and npm audit used different IDs (GHSA vs CVE) for the same issue; matched through OSV aliases.'
        : 'Socket and npm audit used different IDs; matched on package version only (OSV aliases not available).'
    case 'matched_same_id':
      return 'Both scanners reported the same advisory ID.'
    case 'matched_package_version_only':
      return 'Both scanners reported a vulnerability for this version, but no shared advisory ID could be compared.'
    case 'socket_only_not_in_npm_audit':
      return 'Socket reported a vulnerability that npm audit did not list.'
    case 'npm_audit_unavailable':
      return `npm audit did not run successfully (status: ${auditStatus}).`
    case 'socket_scan_unavailable':
      return `Socket results are not usable (status: ${socketStatus}). Socket was not compared for this row.`
    case 'no_findings':
      return 'Neither scanner reported a vulnerability for this version.'
    default:
      return ''
  }
}

function buildStats(rows, inventory, socket, audit, osvAliasesLoaded) {
  const count = (predicate) => rows.filter(predicate).length
  const byCategory = Object.fromEntries(CATEGORY_ORDER.map((category) => [category, count((row) => row.category === category)]))
  const classifications = {}
  for (const row of rows) classifications[row.classification] = (classifications[row.classification] ?? 0) + 1
  return {
    inventory: inventory.counts,
    socketStatus: socket.status,
    socketArtifacts: socket.artifacts?.length ?? 0,
    socketVulnerablePackages: count((row) => row.socketFindingCount > 0),
    auditStatus: audit.status,
    auditAdvisories: audit.advisories?.length ?? 0,
    auditVulnerablePackages: count((row) => row.auditFindingCount > 0),
    byCategory,
    classifications,
    osvAliasesLoaded,
  }
}
