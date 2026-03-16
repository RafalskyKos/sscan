#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const PACKAGE_DIR = path.resolve(__dirname, "..");
const TARGET_PATH = process.env.TARGET_PATH || process.cwd();
const REPORTS_DIR = path.join(TARGET_PATH, "reports");

// Colors
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;

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

function ensureReportsDir() {
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
}

function runSast() {
  console.log(yellow("Starting SAST scan (Semgrep)..."));
  console.log(`  Target: ${TARGET_PATH}`);
  console.log("  This may take a few minutes...\n");

  // Copy .semgrepignore to target if not present
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

  // Clean up
  if (copiedIgnore) fs.rmSync(ignoreFile, { force: true });
  if (copiedIgnoreLocal) fs.rmSync(ignoreLocalFile, { force: true });

  if (fs.existsSync(reportPath)) {
    console.log(`\n${green("✓ SAST report saved to reports/gl-sast-report.sarif")}`);
  } else {
    console.log(
      `\n${yellow("⚠ Warning: SAST report not generated. The scan may have failed.")}`,
    );
  }
}

function runSca() {
  console.log(yellow("Starting SCA scan (Trivy)..."));
  console.log(`  Target: ${TARGET_PATH}`);
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
      `\n${green("✓ SCA report saved to reports/gl-dependency-scanning-report.sarif")}`,
    );
  } else {
    console.log(
      `\n${yellow("⚠ Warning: SCA report not generated. The scan may have failed.")}`,
    );
  }
}

function showHelp() {
  console.log(`Usage: npx sscan [sast|sca|all|check-deps]

Scan types:
  sast         Run SAST scan only (Semgrep)
  sca          Run SCA scan only (Trivy)
  all          Run all scans (default)
  check-deps   Check if required tools are installed

Environment variables:
  TARGET_PATH  Path to project to scan (default: current directory)

Reports are saved in ./reports/ directory in SARIF format.`);
}

// Main
const arg = process.argv[2] || "all";

switch (arg) {
  case "sast":
    if (checkDeps()) {
      ensureReportsDir();
      runSast();
      console.log("\nSAST scan completed!");
    }
    break;
  case "sca":
    if (checkDeps()) {
      ensureReportsDir();
      runSca();
      console.log("\nSCA scan completed!");
    }
    break;
  case "all":
    if (checkDeps()) {
      ensureReportsDir();
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
