# complyscan

> Static compliance scanner for EU AI Act Article 12 — checks your Terraform infrastructure for logging and traceability gaps before they become audit findings.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/complyscan.svg)](https://www.npmjs.com/package/complyscan)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

---

## What is this?

The **EU AI Act** (Regulation 2024/1689) requires providers of high-risk AI systems to maintain comprehensive logs of system operation to ensure traceability, accountability, and post-incident auditability. **Article 12** specifically mandates that high-risk AI systems automatically record events throughout their operational lifetime.

`complyscan` scans your **Terraform HCL source files** (and soon Terraform plan/state JSON) and reports exactly which Article 12 controls are passing, failing, or cannot be verified statically — giving you a clear, actionable compliance gap report without needing to deploy anything.

---

## Rules

`complyscan` currently implements 6 compliance checks, all mapped to Article 12 of the EU AI Act:

| Rule ID | Severity | Check |
|---|---|---|
| `S-12.1.1` | FAIL | AWS Bedrock model invocation logging is configured |
| `S-12.1.2a` | FAIL | CloudWatch log group used for Bedrock logs has a retention policy |
| `S-12.1.2b` | FAIL | S3 bucket used for Bedrock logs has a lifecycle policy |
| `S-12.x.1` | WARN | S3 log bucket has versioning enabled |
| `S-12.x.2a` | WARN | S3 log bucket has server-side encryption configured |
| `S-12.x.4` | FAIL | A CloudTrail trail is present and enabled |

Each finding is one of: **PASS**, **FAIL**, **WARN**, **SKIP**, or **INCONCLUSIVE** (when the value cannot be resolved statically, e.g. it comes from a variable with no default).

---

## Prerequisites

`complyscan` converts Terraform HCL to JSON internally using [`hcl2json`](https://github.com/tmccombs/hcl2json). Install it before running:

```bash
# macOS
brew install hcl2json

# Linux — download the binary for your platform from:
# https://github.com/tmccombs/hcl2json/releases
```

**Node.js 18+** is required.

---

## Installation

### From npm (recommended)

```bash
npm install -g complyscan
```

### From source

```bash
git clone https://github.com/your-org/complyscan.git
cd complyscan
npm install
npm run build
npm link   # makes `complyscan` available globally
```

---

## Usage

### Source scan (Terraform HCL)

Point `complyscan` at any directory containing `.tf` files:

```bash
complyscan <directory> [options]
```

**Options:**

| Flag | Default | Description |
|---|---|---|
| `-f, --format <format>` | `terminal` | Output format: `terminal` or `json` |
| `--no-strict` | — | Treat `INCONCLUSIVE` findings as non-blocking. By default, `INCONCLUSIVE` blocks like `FAIL` (safer for CI) |

**Examples:**

```bash
# Scan a Terraform module, human-readable output
complyscan ./infra/

# Scan and output machine-readable JSON
complyscan ./infra/ --format json

# Scan in non-strict mode (INCONCLUSIVE won't block CI)
complyscan ./infra/ --no-strict

# Use in a CI pipeline
complyscan ./infra/ --format json | tee compliance-report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No `FAIL`, `WARN`, or `INCONCLUSIVE` findings |
| `1` | One or more `FAIL`, `WARN`, or `INCONCLUSIVE` findings (in strict mode) |
| `2` | Tool error — invalid directory, `hcl2json` not found, etc. |

---

## Output

### Terminal (default)

```
complyscan — EU AI Act Article 12 Compliance Scan
──────────────────────────────────────────────────

✓ [PASS] S-12.1.1  Bedrock invocation logging is configured (main).
✓ [PASS] S-12.1.2a CloudWatch log group /aws/bedrock/prod has a retention policy (365 days).
✓ [PASS] S-12.1.2b S3 bucket prod-ai-audit-logs has a lifecycle policy.
✓ [PASS] S-12.x.1  S3 bucket prod-ai-audit-logs has versioning enabled.
✓ [PASS] S-12.x.2a S3 bucket prod-ai-audit-logs has server-side encryption configured.
✗ [FAIL] S-12.x.4  No aws_cloudtrail resource found.
          Remediation: Add an aws_cloudtrail resource with enable_logging = true.

────────────────────────────────────────────────────────
Summary: 6 checks | 1 FAIL | 0 WARN | 5 PASS | 0 SKIP | 0 INCONCLUSIVE
```

### JSON

```json
{
  "summary": {
    "total": 6,
    "pass": 5,
    "fail": 1,
    "warn": 0,
    "skip": 0,
    "inconclusive": 0
  },
  "findings": [
    {
      "ruleId": "S-12.x.4",
      "status": "FAIL",
      "severity": "FAIL",
      "message": "No aws_cloudtrail resource found.",
      "remediation": "Add an aws_cloudtrail resource with enable_logging = true.",
      "regulatoryReference": "EU AI Act Article 12"
    }
  ]
}
```

---

## CI Integration

### GitHub Actions

```yaml
- name: Compliance scan
  run: |
    npm install -g complyscan
    complyscan ./infra/ --format json | tee compliance-report.json
  continue-on-error: false

- name: Upload compliance report
  uses: actions/upload-artifact@v4
  with:
    name: compliance-report
    path: compliance-report.json
```

### GitLab CI

```yaml
compliance:
  stage: validate
  script:
    - npm install -g complyscan
    - complyscan ./infra/ --format json | tee compliance-report.json
  artifacts:
    paths:
      - compliance-report.json
```

---

## Roadmap

| Sprint | Status | Scope |
|---|---|---|
| **1A** | ✅ Done | Terraform HCL source scanning — 6 Article 12 rules |
| **1B** | 🔄 In progress | `--plan` mode: scan `terraform show -json` plan/state output — eliminates `INCONCLUSIVE` for CI gates |
| **1C** | Planned | CDK and CloudFormation support; additional FR-2 checks |

### Sprint 1B preview — plan/state mode

Once 1B lands, `complyscan` will accept Terraform plan JSON as input. Because plan output contains fully-resolved values (no variables), this eliminates most `INCONCLUSIVE` findings and is the recommended path for CI compliance gates.

```bash
# Pre-deployment gate (recommended CI workflow)
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
complyscan --plan plan.json --format json

# Post-deployment audit
terraform show -json > state.json
complyscan --plan state.json --mode post --format json
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for significant changes.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-change`
3. Install dependencies: `npm install`
4. Run tests: `npm test`
5. Build: `npm run build`
6. Submit a pull request

### Adding a new rule

Each rule lives in `src/rules/` and implements the `ScanRule` interface from `src/types.ts`. The rule ID should follow the `S-12.x.y` naming convention and include a `regulatoryReference` mapping to the specific Article 12 sub-clause.

---

## License

Copyright 2026 — Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, distribute, and modify this software under the terms of the Apache 2.0 license. See the [LICENSE](LICENSE) file for the full license text.

---

## Disclaimer

`complyscan` is a static analysis tool. A fully passing scan means your Terraform configuration **declares** the required controls — it does not verify that deployed infrastructure is operating correctly, that log data is actually being written, or that your system meets all requirements of the EU AI Act in its entirety. Always combine static scanning with runtime monitoring and legal review.
