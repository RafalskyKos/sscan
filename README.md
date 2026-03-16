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
npx git+ssh://git@github-work:RafalskyKos/sscan.git

# SAST only (Semgrep)
npx git+ssh://git@github-work:RafalskyKos/sscan.git sast

# SCA only (Trivy)
npx git+ssh://git@github-work:RafalskyKos/sscan.git sca

# Check dependencies
npx git+ssh://git@github-work:RafalskyKos/sscan.git check-deps
```

### Custom target path

By default scans the current directory. Override with:

```bash
TARGET_PATH=/path/to/project npx git+ssh://git@github-work:RafalskyKos/sscan.git all
```

## Reports

Reports are saved in `./reports/` in SARIF format:

- `reports/gl-sast-report.sarif` — SAST results
- `reports/gl-dependency-scanning-report.sarif` — SCA results

SARIF files can be viewed in VS Code with the SARIF Viewer extension.
