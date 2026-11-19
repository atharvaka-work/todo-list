# Socket.dev scan and npm audit comparison

This folder runs a Socket.dev scan of the project's root lockfile, runs `npm audit` on the same project, and writes one comparison report. It is separate from the app: nothing here changes the app code, the root dependencies, or the root `package-lock.json`.

## What it produces

All outputs go to the repository's `reports/` folder.

| File | What it is |
| --- | --- |
| `socket-security-report.xlsx` | Five sheets: Scan Summary, Dependency Inventory, Socket Findings, Cross-Scanner Comparison, Coverage & Gaps |
| `socket-security-report.csv` | The Cross-Scanner Comparison table as plain CSV (UTF-8 with BOM, opens in Excel) |
| `socket-scan-create.json` | Raw output of `socket scan create` (Socket CLI) |
| `socket-scan-metadata.json` | Raw output of `socket scan metadata` (last poll) |
| `socket-scan-view.json` | Raw output of `socket scan view --stream` |
| `npm-audit.json` | Raw output of `npm audit --json --legacy-peer-deps` |

The `reports/*.json` files are git-ignored. The CSV and XLSX are not.

## Requirements

- Node.js 22 or newer.
- The root project's dependencies installed (`npm install` in the repository root).
- For Socket results: a Socket.dev API token and the organization slug it belongs to. The free plan is enough for this report.

## Install

From the repository root:

```powershell
npm --prefix security/socket ci
```

This installs the pinned versions of `socket` (1.14.0), `exceljs`, and `semver` from `security/socket/package-lock.json`.

## Configure

The runner reads these environment variables. Set them in the same terminal you run the report from. Do not put the token in a file that is committed.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `SOCKET_CLI_API_TOKEN` | For Socket results | none | Socket API token. Passed only to the Socket CLI process, never printed or written to a file. |
| `SOCKET_CLI_ORG_SLUG` | For Socket results | none | Socket organization slug. Passed to the CLI as `--org`. |
| `SOCKET_REPO_NAME` | No | `todo-list` | Repository name shown in Socket. |
| `SOCKET_BRANCH_NAME` | No | `main` | Branch name shown in Socket. |
| `SOCKET_POLL_SECONDS` | No | `10` | Seconds between status checks while Socket processes the scan. |
| `SOCKET_POLL_TIMEOUT_SECONDS` | No | `900` | Maximum seconds to wait for the scan to finish. |

PowerShell:

```powershell
$env:SOCKET_CLI_API_TOKEN = "<your token>"
$env:SOCKET_CLI_ORG_SLUG = "<your org slug>"
```

bash:

```bash
export SOCKET_CLI_API_TOKEN="<your token>"
export SOCKET_CLI_ORG_SLUG="<your org slug>"
```

Copy the organization slug from your Socket dashboard. It is the organization identifier that Socket uses in its URLs and API.

## Run

From the repository root:

```powershell
npm run security:socket
```

The command always runs npm audit and writes the reports, even if Socket is not configured. If `SOCKET_CLI_API_TOKEN` or `SOCKET_CLI_ORG_SLUG` is missing, Socket is skipped and every row is marked `socket_scan_unavailable`. The Scan Summary sheet says why.

Exit code `0` means the reports were written. Exit code `1` means they could not be written, for example because the lockfile could not be read.

## Reading the comparison

Each row is one installed package version (`name@version`) from the lockfile.

Category:

- `both`: Socket and npm audit both report a vulnerability for this version.
- `socket_only`: Socket reports one; npm audit does not.
- `audit_only`: npm audit reports one; Socket does not.
- `neither`: neither scanner reports a vulnerability.

Classification explains the category:

- `potential_socket_miss`: npm audit reports a vulnerability and Socket returned no alert for this version. Check these first.
- `package_not_in_socket_scan`: npm audit reports a vulnerability, but Socket's scan does not include this package version.
- `outside_affected_range`: npm audit's advisory range does not include the installed version, so the finding may not apply.
- `socket_only_not_in_npm_audit`: Socket reports a vulnerability that npm audit does not list.
- `matched_same_id`: both scanners reported the same advisory ID.
- `alias_resolved`: both reported the issue under different IDs (GHSA and CVE). They were matched through the OSV alias data in `reports/osv-offline.json`, if present.
- `matched_package_version_only`: both reported a vulnerability for this version, but no advisory ID could be compared.
- `socket_scan_unavailable`: Socket did not produce usable results, so the row could not be compared.
- `npm_audit_unavailable`: npm audit did not produce usable results.
- `no_findings`: neither scanner reported a vulnerability.

The Coverage & Gaps sheet lists the rows that need attention: the content gaps and the unavailable rows.

## Troubleshooting

- **Socket status `error` with "org" in the message**: `SOCKET_CLI_ORG_SLUG` is missing or wrong.
- **Socket status `error` with an HTTP 401 or 403**: the token is invalid or does not have the `full-scans:create` scope.
- **Socket status `error` with HTTP 429**: the free plan limit was reached (500 API requests per hour). Wait and run again.
- **Socket status `incomplete`**: the scan did not finish within `SOCKET_POLL_TIMEOUT_SECONDS`. Increase it and run again.
- **Socket status `empty`**: Socket returned no package records. Check `socket-scan-view.json`.
- **npm audit status `error`**: check `npm-audit.json` and the npm registry configuration. npm audit needs access to the registry.

## Limitations

- Socket's findings depend on its own scanner and on the plan. A Socket result of "no alerts" does not mean the package is free of vulnerabilities.
- npm audit uses the npm advisory database. It can differ from Socket and from OSV.
- Only the root `package-lock.json` is scanned. `security/socket/` has its own lockfile and is not part of the report.
- This tool's own dependencies have known issues. Check them with `npm --prefix security/socket audit`. When this was written, the audit reported `zod` 3.25.76 (a dependency of `@socketsecurity/socket-patch`, which `socket` 1.14.0 uses) as high severity, which makes `socket` 1.14.0 show as high severity too. It also reported `uuid` 8.3.2 (a dependency of `exceljs`) as moderate. No fixed `socket` release existed yet, and the `zod` fix is a major-version change. Review these before relying on the tool in CI.
- The raw Socket output is saved so the parsing can be checked against the real response. If Socket changes its output format, the normalizer in `lib/socket.mjs` may need an update.

## Files

- `run.mjs`: entry point. Runs Socket and npm audit, compares them, and writes the reports.
- `lib/socket.mjs`: runs the Socket CLI (create, metadata polling, view) and normalizes the result.
- `lib/npm-audit.mjs`: runs `npm audit --json` and normalizes its advisories.
- `lib/lockfile.mjs`: reads the root lockfile and builds the dependency inventory.
- `lib/compare.mjs`: matches the two results and assigns categories and classifications.
- `lib/report.mjs`: writes the CSV and the XLSX.
- `lib/util.mjs`: shared helpers, including token redaction and reading UTF-16 output from PowerShell.
