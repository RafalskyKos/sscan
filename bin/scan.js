#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PACKAGE_DIR = path.resolve(__dirname, "..");
const RUN_DIR = process.cwd();
const REPORTS_DIR_NAME = ".security-scan-reports";
const TARGET_PATH = getTargetPath();
const REPORTS_DIR = path.join(RUN_DIR, REPORTS_DIR_NAME);

// Colors
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"];

// --- Path helpers ---

function getTargetPath() {
  if (process.env.TARGET_PATH) return path.resolve(process.env.TARGET_PATH);

  let dir = RUN_DIR;
  while (true) {
    if (path.basename(dir) === "app") return path.dirname(dir);

    const parent = path.dirname(dir);
    if (parent === dir) return RUN_DIR;
    dir = parent;
  }
}

// --- SARIF severity helpers ---

function getSemgrepSeverity(result, rulesMap) {
  const rule = rulesMap[result.ruleId];
  if (!rule) return "medium";

  // Check tags for explicit severity
  const tags = (rule.properties && rule.properties.tags) || [];
  for (const tag of tags) {
    const upper = tag.toUpperCase();
    if (upper.includes("CRITICAL") && !upper.includes("CONFIDENCE"))
      return "critical";
    if (upper.includes("HIGH") && !upper.includes("CONFIDENCE")) return "high";
    if (upper.includes("MEDIUM") && !upper.includes("CONFIDENCE"))
      return "medium";
    if (upper.includes("LOW") && !upper.includes("CONFIDENCE")) return "low";
  }

  // Fall back to SARIF level
  const level =
    (rule.defaultConfiguration && rule.defaultConfiguration.level) || "warning";
  if (level === "error") return "high";
  if (level === "warning") return "medium";
  return "low";
}

function getTrivySeverity(result, rulesMap) {
  // Trivy puts security-severity score in rule properties
  const rule = rulesMap[result.ruleId];
  if (rule && rule.properties && rule.properties["security-severity"]) {
    const score = parseFloat(rule.properties["security-severity"]);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  // Fall back to result level
  const level = result.level || "warning";
  if (level === "error") return "high";
  if (level === "warning") return "medium";
  return "low";
}

function splitSarifBySeverity(reportPath, baseName, getSeverityFn) {
  if (!fs.existsSync(reportPath)) return null;

  const data = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const run = data.runs && data.runs[0];
  if (!run || !run.results || run.results.length === 0) {
    console.log(dim(`  No findings to split.`));
    fs.rmSync(reportPath, { force: true });
    return {};
  }

  // Build rules map
  const rules = (run.tool && run.tool.driver && run.tool.driver.rules) || [];
  const rulesMap = {};
  for (const rule of rules) {
    rulesMap[rule.id] = rule;
  }

  // Group results by severity
  const groups = { critical: [], high: [], medium: [], low: [] };
  for (const result of run.results) {
    const severity = getSeverityFn(result, rulesMap);
    groups[severity].push(result);
  }

  // Write separate SARIF files for each non-empty group
  const summary = {};
  for (const level of SEVERITY_LEVELS) {
    if (groups[level].length === 0) continue;

    // Collect only referenced rules
    const usedRuleIds = new Set(groups[level].map((r) => r.ruleId));
    const filteredRules = rules.filter((r) => usedRuleIds.has(r.id));

    const splitData = {
      ...data,
      runs: [
        {
          ...run,
          results: groups[level],
          tool: {
            ...run.tool,
            driver: { ...run.tool.driver, rules: filteredRules },
          },
        },
      ],
    };

    const outPath = path.join(REPORTS_DIR, `${baseName}-${level}.sarif`);
    fs.writeFileSync(outPath, JSON.stringify(splitData, null, 2));
    summary[level] = groups[level].length;
  }

  // Remove the original full report
  fs.rmSync(reportPath, { force: true });

  return summary;
}

function printSummary(summary, reportBaseName) {
  if (!summary || Object.keys(summary).length === 0) return;

  console.log("  Results by severity:");
  for (const level of SEVERITY_LEVELS) {
    if (!summary[level]) continue;
    const color = level === "critical" || level === "high" ? red : yellow;
    console.log(
      color(`    ${level.toUpperCase()}: ${summary[level]} findings`) +
        dim(` → ${REPORTS_DIR_NAME}/${reportBaseName}-${level}.sarif`),
    );
  }
}

// --- Tool checks ---

function checkCommand(name) {
  try {
    const loc = execSync(`command -v ${name}`, { encoding: "utf8" }).trim();
    console.log(`${green("✓")} ${name} found: ${loc}`);
    return true;
  } catch {
    console.log(red(`Error: '${name}' is not installed.`));
    console.log(`  Install with: brew install ${name}`);
    return false;
  }
}

function checkDeps() {
  console.log("Checking required tools...");
  const semgrepOk = checkCommand("semgrep");
  const trivyOk = checkCommand("trivy");
  console.log();
  if (!semgrepOk || !trivyOk) {
    console.log(red("Some tools are missing. Install them with:"));
    console.log("  brew install semgrep trivy");
    return false;
  }
  console.log(green("All tools are installed."));
  return true;
}

function prepareReportsDir() {
  if (fs.existsSync(REPORTS_DIR)) {
    console.log(dim(`Removing old reports: ${REPORTS_DIR}`));
    fs.rmSync(REPORTS_DIR, { recursive: true, force: true });
  }

  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function ensureReportsGitignore() {
  const gitignorePath = path.join(RUN_DIR, ".gitignore");
  const entryRegex = /(^|\r?\n)\.security-scan-reports\/?(\r?\n|$)/;

  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, "utf8");
    if (entryRegex.test(content)) return;

    const prefix = content.endsWith("\n") ? "\n" : "\n\n";
    fs.appendFileSync(
      gitignorePath,
      `${prefix}## Security Reports:\n${REPORTS_DIR_NAME}\n`,
    );
    return;
  }

  fs.writeFileSync(
    gitignorePath,
    `## Security Reports:\n${REPORTS_DIR_NAME}\n`,
  );
}

function prepareScan() {
  ensureReportsGitignore();
  prepareReportsDir();
}

// --- Scans ---

function runSast() {
  console.log(yellow("Starting SAST scan (Semgrep)..."));
  console.log(`  Started from: ${RUN_DIR}`);
  console.log(`  Target: ${TARGET_PATH}`);
  console.log(`  Reports: ${REPORTS_DIR}`);
  console.log("  This may take a few minutes...\n");

  const ignoreFile = path.join(TARGET_PATH, ".semgrepignore");
  const ignoreLocalFile = path.join(TARGET_PATH, ".semgrepignore.local");
  let copiedIgnore = false;
  let copiedIgnoreLocal = false;

  if (!fs.existsSync(ignoreFile)) {
    fs.copyFileSync(path.join(PACKAGE_DIR, ".semgrepignore"), ignoreFile);
    copiedIgnore = true;
  }
  if (!fs.existsSync(ignoreLocalFile)) {
    fs.copyFileSync(
      path.join(PACKAGE_DIR, ".semgrepignore.local"),
      ignoreLocalFile,
    );
    copiedIgnoreLocal = true;
  }

  const reportPath = path.join(REPORTS_DIR, "gl-sast-report.sarif");

  try {
    execSync(
      [
        "semgrep scan",
        "--config auto",
        "--sarif",
        `--output "${reportPath}"`,
        '--exclude "jenkins/*"',
        '--exclude "docker/*"',
        '--exclude "security-scan/*"',
        '--exclude "security-scan-local/*"',
        '--exclude "security-scan-npx/*"',
        `"${TARGET_PATH}"`,
      ].join(" "),
      { stdio: "inherit" },
    );
  } catch {
    // semgrep returns non-zero when findings exist
  }

  if (copiedIgnore) fs.rmSync(ignoreFile, { force: true });
  if (copiedIgnoreLocal) fs.rmSync(ignoreLocalFile, { force: true });

  if (fs.existsSync(reportPath)) {
    console.log(`\n${green("✓ SAST scan complete. Splitting by severity...")}`);
    const summary = splitSarifBySeverity(
      reportPath,
      "gl-sast-report",
      getSemgrepSeverity,
    );
    printSummary(summary, "gl-sast-report");
  } else {
    console.log(
      `\n${yellow("⚠ Warning: SAST report not generated. The scan may have failed.")}`,
    );
  }
}

function runSca() {
  console.log(yellow("Starting SCA scan (Trivy)..."));
  console.log(`  Started from: ${RUN_DIR}`);
  console.log(`  Target: ${TARGET_PATH}`);
  console.log(`  Reports: ${REPORTS_DIR}`);
  console.log("  This may take a few minutes...\n");

  const reportPath = path.join(
    REPORTS_DIR,
    "gl-dependency-scanning-report.sarif",
  );

  try {
    execSync(
      [
        "trivy fs",
        "--scanners vuln,secret,misconfig",
        "--format sarif",
        `--output "${reportPath}"`,
        `"${TARGET_PATH}"`,
      ].join(" "),
      { stdio: "inherit" },
    );
  } catch {
    // trivy may return non-zero
  }

  if (fs.existsSync(reportPath)) {
    console.log(
      `\n${green("✓ SCA scan complete. Splitting by severity...")}`,
    );
    const summary = splitSarifBySeverity(
      reportPath,
      "gl-dependency-scanning-report",
      getTrivySeverity,
    );
    printSummary(summary, "gl-dependency-scanning-report");
  } else {
    console.log(
      `\n${yellow("⚠ Warning: SCA report not generated. The scan may have failed.")}`,
    );
  }
}

// --- Help ---

function showHelp() {
  console.log(`Usage: npx sscan [sast|sca|all|check-deps]

Scan types:
  sast         Run SAST scan only (Semgrep)
  sca          Run SCA scan only (Trivy)
  all          Run all scans (default)
  check-deps   Check if required tools are installed

Environment variables:
  TARGET_PATH  Path to project to scan

Default target:
  If launched inside an app directory, scans the parent project directory.
  Otherwise scans the current directory.

Reports are split by severity into separate SARIF files:
  .security-scan-reports/gl-sast-report-critical.sarif
  .security-scan-reports/gl-sast-report-high.sarif
  .security-scan-reports/gl-sast-report-medium.sarif
  .security-scan-reports/gl-sast-report-low.sarif`);
}

// --- Main ---

const arg = process.argv[2] || "all";

switch (arg) {
  case "sast":
    if (checkDeps()) {
      prepareScan();
      runSast();
      console.log("\nSAST scan completed!");
    }
    break;
  case "sca":
    if (checkDeps()) {
      prepareScan();
      runSca();
      console.log("\nSCA scan completed!");
    }
    break;
  case "all":
    if (checkDeps()) {
      prepareScan();
      runSast();
      console.log();
      runSca();
      console.log(`\n${green("All scans completed!")}`);
    }
    break;
  case "check-deps":
    checkDeps();
    break;
  case "--help":
  case "-h":
    showHelp();
    break;
  default:
    console.log(`Unknown option: ${arg}\n`);
    showHelp();
    process.exit(1);
}
