# sscan — Security Scan (without Docker)

Local security scanning — SAST (Semgrep) and SCA (Trivy) — no Docker required.

## Prerequisites

```bash
brew install semgrep trivy
```

## Usage via npx

Run from your project directory:

```bash
# All scans
npx git+https://github.com/RafalskyKos/sscan.git

# SAST only (Semgrep)
npx git+https://github.com/RafalskyKos/sscan.git sast

# SCA only (Trivy)
npx git+https://github.com/RafalskyKos/sscan.git sca

# Check dependencies
npx git+https://github.com/RafalskyKos/sscan.git check-deps
```

### Scan target

By default scans the current directory. If you launch `sscan` from inside an
`app` directory, it scans the parent project directory instead, while keeping
reports in the directory where the command was launched.

Override the scan target with:

```bash
TARGET_PATH=/path/to/project npx git+https://github.com/RafalskyKos/sscan.git all
```

## Reports

Before each scan, old reports are removed.

Reports are saved in `./.security-scan-reports/` in SARIF format, split by severity:

- `.security-scan-reports/gl-sast-report-critical.sarif`
- `.security-scan-reports/gl-sast-report-high.sarif`
- `.security-scan-reports/gl-sast-report-medium.sarif`
- `.security-scan-reports/gl-sast-report-low.sarif`
- `.security-scan-reports/gl-dependency-scanning-report-critical.sarif`
- `.security-scan-reports/gl-dependency-scanning-report-high.sarif`
- `.security-scan-reports/gl-dependency-scanning-report-medium.sarif`
- `.security-scan-reports/gl-dependency-scanning-report-low.sarif`

Only files with findings are created. SARIF files can be viewed in VS Code with the SARIF Viewer extension.

The script also creates or updates `.gitignore` in the launch directory with:

```gitignore
## Security Reports:
.security-scan-reports
```
