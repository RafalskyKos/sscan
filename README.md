# Security Scan Local (without Docker)

Local security scanning — SAST (Semgrep) and SCA (Trivy) — without Docker.

## Prerequisites

Install the required tools:

```bash
brew install semgrep trivy
```

Verify installation:

```bash
npm run check-deps
```

## Usage

Run all scans:

```bash
npm run scan:all
```

Run only SAST (Semgrep):

```bash
npm run scan:sast
```

Run only SCA (Trivy):

```bash
npm run scan:sca
```

### Custom target path

By default scans the parent directory (`..`). Override with:

```bash
TARGET_PATH=/path/to/project npm run scan:all
```

## Reports

Reports are saved in `reports/` in SARIF format:

- `reports/gl-sast-report.sarif` — SAST results
- `reports/gl-dependency-scanning-report.sarif` — SCA results

SARIF files can be viewed in VS Code with the SARIF Viewer extension.
