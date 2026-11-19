import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const libDir = path.dirname(fileURLToPath(import.meta.url))

export const PACKAGE_DIR = path.resolve(libDir, '..')
export const REPO_ROOT = path.resolve(PACKAGE_DIR, '..', '..')
export const REPORTS_DIR = path.join(REPO_ROOT, 'reports')

// Every value that must never reach a log line or a saved file goes here.
const secrets = new Set()

export function registerSecret(value) {
  if (typeof value === 'string' && value.length >= 6) secrets.add(value)
}

export function redact(text) {
  let out = String(text ?? '')
  for (const secret of secrets) out = out.split(secret).join('[REDACTED]')
  return out
}

export function log(message) {
  process.stdout.write(`${redact(message)}\n`)
}

export function nowIso() {
  return new Date().toISOString()
}

export function errorText(error) {
  return error instanceof Error ? error.message : String(error)
}

export function truncate(text, max = 500) {
  const value = String(text ?? '')
  return value.length > max ? `${value.slice(0, max - 3)}...` : value
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// Reads a file as text. npm and PowerShell redirects can write UTF-16 with a BOM.
export function readText(file) {
  const bytes = readFileSync(file)
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return bytes.subarray(2).toString('utf16le')
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return bytes.subarray(3).toString('utf8')
  return bytes.toString('utf8')
}

export function readJson(file) {
  return JSON.parse(readText(file))
}

// Parses CLI output that may have noise before the JSON. Returns null when no JSON is found.
export function parseJsonLoose(text) {
  const trimmed = String(text ?? '').trim()
  if (!trimmed) return null
  try {
    return JSON.parse(trimmed)
  } catch {
    // fall through and look for the first JSON start character
  }
  const start = trimmed.search(/[[{]/)
  if (start === -1) return null
  try {
    return JSON.parse(trimmed.slice(start))
  } catch {
    return null
  }
}

export function writeFileSafe(file, text) {
  mkdirSync(path.dirname(file), { recursive: true })
  writeFileSync(file, redact(text), 'utf8')
}

export function writeReportJson(name, value) {
  writeFileSafe(path.join(REPORTS_DIR, name), `${JSON.stringify(value, null, 2)}\n`)
}

const GHSA_PATTERN = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/gi
const CVE_PATTERN = /CVE-\d{4}-\d{4,}/gi

export function extractIds(text) {
  const source = String(text ?? '')
  const ghsa = new Set((source.match(GHSA_PATTERN) || []).map((id) => id.toUpperCase()))
  const cve = new Set((source.match(CVE_PATTERN) || []).map((id) => id.toUpperCase()))
  return { ghsa: [...ghsa], cve: [...cve] }
}

const SEVERITY_LABELS = {
  low: 'Low',
  middle: 'Medium',
  medium: 'Medium',
  moderate: 'Medium',
  high: 'High',
  critical: 'Critical',
}

export function normalizeSeverity(value) {
  if (!value) return ''
  return SEVERITY_LABELS[String(value).toLowerCase()] ?? String(value)
}

// Finds the first string or number whose key matches the pattern, searching nested objects.
export function findFirstByKey(value, pattern, depth = 4) {
  if (!value || typeof value !== 'object' || depth < 0) return undefined
  for (const [key, child] of Object.entries(value)) {
    if (pattern.test(key) && (typeof child === 'string' || typeof child === 'number') && child !== '') {
      return child
    }
  }
  for (const child of Object.values(value)) {
    if (child && typeof child === 'object') {
      const found = findFirstByKey(child, pattern, depth - 1)
      if (found !== undefined) return found
    }
  }
  return undefined
}

export function uniq(values) {
  return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ''))]
}
