import path from 'node:path'
import { REPO_ROOT, readJson } from './util.mjs'

export const ROOT_MANIFEST = path.join(REPO_ROOT, 'package.json')
export const ROOT_LOCKFILE = path.join(REPO_ROOT, 'package-lock.json')

// Lockfile keys look like "node_modules/a" or "node_modules/a/node_modules/@scope/b".
// The package name is whatever follows the last "node_modules/".
export function nameFromLockKey(key) {
  const marker = 'node_modules/'
  const index = key.lastIndexOf(marker)
  if (index === -1) return ''
  return key.slice(index + marker.length)
}

// Builds the inventory from the root lockfile (lockfileVersion 2 or 3 "packages" map).
export function buildInventory(lockfile = readJson(ROOT_LOCKFILE)) {
  const packages = lockfile.packages ?? {}
  const root = packages[''] ?? {}
  const directProd = new Set(Object.keys(root.dependencies ?? {}))
  const directDev = new Set(Object.keys(root.devDependencies ?? {}))
  const directOptional = new Set(Object.keys(root.optionalDependencies ?? {}))

  const entries = []
  const pathToVersion = new Map()
  for (const [key, meta] of Object.entries(packages)) {
    if (key === '' || meta.link) continue
    const name = nameFromLockKey(key)
    if (!name || !meta.version) continue
    pathToVersion.set(key, meta.version)
    const direct = directProd.has(name) || directDev.has(name) || directOptional.has(name)
    entries.push({
      key: `${name}@${meta.version}`,
      name,
      version: meta.version,
      lockPath: key,
      direct,
      dev: meta.dev === true,
      optional: meta.optional === true,
      license: meta.license ?? '',
      integrity: meta.integrity ?? '',
    })
  }
  entries.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))

  return {
    entries,
    pathToVersion,
    counts: {
      total: entries.length,
      direct: entries.filter((entry) => entry.direct).length,
      transitive: entries.filter((entry) => !entry.direct).length,
      production: entries.filter((entry) => !entry.dev).length,
      development: entries.filter((entry) => entry.dev).length,
    },
  }
}
