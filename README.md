# infrarails

> Static compliance scanner for AWS AI infrastructure - checks your Terraform for the logging, retention, and traceability gaps that surface at audit time, mapped to **EU AI Act Article 12**, **NIST AI RMF**, and **ISO/IEC 42001**.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/infrarails.svg)](https://www.npmjs.com/package/infrarails)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

---

## What is this?

`infrarails` is built for teams running **high-risk AI systems on AWS Bedrock**. It reads your **Terraform HCL source files** (and `.tf.json` files emitted by cdktf, Terragrunt, and other generators) and reports exactly which infrastructure-layer controls are passing, failing, or cannot be verified statically - giving you a clear, actionable readiness report without needing to deploy anything.

Each finding is cross-referenced against three frameworks:

- **EU AI Act** (Regulation 2024/1689) - Article 12 logging and traceability
- **NIST AI RMF 1.0** - GOVERN / MEASURE / MANAGE functions
- **ISO/IEC 42001:2023** - Annex A controls (A.6.2.x event logging, A.7.x data quality)

Concretely, the scanner inspects Terraform for the AWS primitives that back AI logging on Bedrock:

- `aws_bedrock_model_invocation_logging_configuration` (whether invocation logging is configured and which modalities are enabled)
- The CloudWatch log group or S3 bucket that Bedrock writes to (retention, lifecycle, encryption, versioning)
- `aws_cloudtrail` (an enabled trail covering control-plane events)
- Local vs remote Terraform modules (so cross-stack logging topologies are flagged rather than silently passed)

The scanner is **deliberately conservative**: when it cannot prove a control is in place, it emits `INCONCLUSIVE` rather than `PASS` or `FAIL`. For a compliance tool, "we couldn't verify" is the only honest answer when the evidence is split across stacks, modules, or runtime values.

> ### Important: this is a prerequisite, not a certificate of compliance
>
> A fully passing `infrarails` run is a **necessary but not sufficient** condition for EU AI Act / NIST AI RMF / ISO 42001 conformance. `infrarails` only verifies that a narrow set of AWS Bedrock infrastructure primitives are **declared** in your Terraform. It does **not** evaluate organisational, procedural, application-level, or runtime controls. See the disclaimer at the bottom of every report for the full scope statement.

---

## Quick start

```bash
# 1. Install hcl2json (one-time, see Prerequisites)
brew install hcl2json

# 2. Install infrarails
npm install -g infrarails

# 3. Scan a Terraform directory
infrarails ./infra/

# 4. Or generate an HTML report
infrarails ./infra/ --format html > report.html
```

---

## Rules

`infrarails` ships **7 rules** mapped to Article 12 of the EU AI Act, with cross-references to NIST AI RMF and ISO/IEC 42001. Each finding is one of: **PASS**, **FAIL**, **WARN**, **SKIP**, or **INCONCLUSIVE**.

| Rule ID | Severity | Phase | Check |
|---|---|---|---|
| `S-12.1.1` | FAIL | 1 | AWS Bedrock model invocation logging is configured when Bedrock is in use |
| `S-12.1.2a` | FAIL | 2 | CloudWatch log group used for Bedrock logs has a retention policy >= 365 days |
| `S-12.1.2b` | FAIL | 2 | S3 bucket used for Bedrock logs has a lifecycle policy >= 365 days |
| `S-12.x.1` | WARN | 2 | S3 log bucket has versioning (or object lock) enabled |
| `S-12.x.2a` | WARN | 2 | S3 log bucket has KMS server-side encryption configured |
| `S-12.x.4` | FAIL | 2 | A CloudTrail trail is present and enabled |
| `S-12.x.5` | WARN | 2 | Flags remote modules whose contents the scanner cannot inspect |

Retention thresholds: **WARN** at >= 180 days, **PASS** at >= 365 days.

---

## Architecture

`infrarails` is a small, layered TypeScript pipeline. Each layer has a narrow contract, which makes the rule logic easy to read and the failure modes easy to reason about.

```
   +------------------+
   |  CLI (commander) |   src/index.ts - argv parsing, exit codes
   +--------+---------+
            |
   +--------v---------+
   |     Parser       |   src/parser.ts
   |  .tf  -> hcl2json|   recursively walks the directory, skips
   |  .tf.json -> JSON|   node_modules / vendor / examples / .* etc.
   +--------+---------+
            | ParsedFile[] (filePath, json, rawHcl)
   +--------v---------+
   |     Resolver     |   src/resolver.ts
   |  var / local /   |   classifies values as literal | address |
   |  data / module   |   unresolvable (with a reason code)
   +--------+---------+
            |
   +--------v---------+
   | Two-phase Runner |   src/runner.ts
   |                  |
   |  Phase 1 rules --+--> populate ScanContext via src/context.ts
   |  Phase 2 rules --+--> consume ScanContext (bucket / log-group names,
   |                  |    unresolved refs, strictAccountLogging flag)
   +--------+---------+
            | Finding[]
   +--------v---------+
   |    Formatter     |   src/formatter.ts - terminal, JSON, or HTML
   +------------------+
```

**Why two phases?** Most rules need to know *which buckets and log groups Bedrock is actually writing to* before they can check encryption, versioning, retention, etc. Phase 1 (currently just `S-12.1.1`) walks `aws_bedrock_model_invocation_logging_configuration` blocks and resolves their `bucket_name` / `log_group_name` fields into a `ScanContext`. Phase 2 rules use that context to scope their checks - e.g. `S-12.x.2a` only flags encryption gaps on buckets that are *actually* receiving Bedrock logs, not every bucket in the repo.

**The resolver** is what makes the scanner robust on real-world Terraform. A `bucket_name` field can be a literal, a `var.X`, a `local.Y`, a reference to another `aws_s3_bucket`, an SSM parameter, a module output, or a complex interpolation. The resolver classifies each into one of three outcomes:

| Outcome | Example | What rules do with it |
|---|---|---|
| **literal** | `"prod-ai-audit-logs"` | Use the value directly |
| **address** | `aws_s3_bucket.logs.id` resolved to its `bucket` attribute | Use the resolved name |
| **unresolvable** | `var.bucket_name` (no default), `data.aws_ssm_parameter.X.value`, `module.logging.bucket` | Emit `INCONCLUSIVE` instead of guessing |

The unresolvable cases get categorised (`var-no-default`, `data-source-ssm`, `module-output`, ...) so the finding message can tell the operator *why* the value couldn't be checked statically.

### Scanner directory traversal

The parser recursively walks the target directory and parses every `.tf` and `.tf.json` file it finds. **Local modules are scanned as part of the same pass** (e.g. `./modules/bedrock_logging/main.tf` is read alongside the root). The following directories are skipped automatically:

```
node_modules, venv, env, __pycache__,
examples, test, tests, vendor, .* (any dotfile/dir)
```

Remote modules (registry, git, http) are not fetched - their contents are invisible to a static scan, so `S-12.x.5` flags them and `S-12.1.1` factors them into its INCONCLUSIVE reasoning.

---

## Scenarios it can handle

The hardest part of static compliance scanning isn't matching resource types - it's distinguishing *"this is genuinely missing"* from *"this lives somewhere I can't see."* `infrarails` handles both, and it tells you which one you're looking at.

### Direct, in-file Bedrock + logging -> PASS

Bedrock resource and `aws_bedrock_model_invocation_logging_configuration` in the same scanned tree, with at least one modality enabled (or all modality toggles unset, which is AWS's enable-all default).

```hcl
resource "aws_bedrockagent_agent" "support_bot" { ... }

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config { bucket_name = "prod-ai-audit-logs" }
  }
}
```
-> `S-12.1.1: PASS`

### All modality toggles explicitly false -> FAIL

A logging resource exists but every `*_data_delivery_enabled` is `false`. AWS will accept this configuration, but no events will actually be written.

```hcl
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    text_data_delivery_enabled      = false
    image_data_delivery_enabled     = false
    embedding_data_delivery_enabled = false
    video_data_delivery_enabled     = false
    s3_config { bucket_name = "logs" }
  }
}
```
-> `S-12.1.1: FAIL - all data-delivery toggles set to false`

### Bedrock used, no logging in scanned files -> INCONCLUSIVE (default) or FAIL (strict)

By default, the scanner assumes account-baseline patterns are common (logging configured once at the org/account level, not per-stack) and emits `INCONCLUSIVE` so it doesn't generate false positives for teams with that topology. Pass `--strict-account-logging` to flip this to `FAIL` when you know the entire estate is in scope.

### Cross-stack baseline logging -> INCONCLUSIVE (with reason)

When the scanner sees Bedrock usage *and* hints that logging is wired up via another stack - a `data.terraform_remote_state.account_baseline.outputs.log_bucket` reference, a baseline-logging module call, or an input key like `log_bucket` / `bedrock_logs_bucket` on a module - it emits `INCONCLUSIVE` with the specific cross-stack pointer that triggered the decision. **This overrides `--strict-account-logging`**: when there is positive evidence of external logging, the scanner won't FAIL.

### Indirect-only Bedrock signals -> always INCONCLUSIVE

IAM grants for `bedrock:*` actions, VPC endpoints to `bedrock-runtime`, or `aws_bedrock_foundation_model` data sources are *signals* that something nearby uses Bedrock - but the deploying resource may live in another stack entirely. These are never confident `FAIL`s, even under `--strict-account-logging`.

### Local modules -> scanned recursively

`module "bedrock_logging" { source = "./modules/bedrock_logging" }` is followed transparently - the module's `.tf` files are parsed alongside the root and contribute to the same context.

### Remote modules -> flagged, never scanned

Registry, git, http, and bitbucket sources can't be inspected statically. `S-12.x.5` emits an `INCONCLUSIVE` per remote module so they show up in the report instead of being silently ignored. If your only Bedrock-related logic is inside a remote module, `S-12.1.1` also emits an INCONCLUSIVE rather than a misleading SKIP.

### Variables, locals, and data sources -> resolved when possible

| Expression | Behavior |
|---|---|
| `"literal-bucket"` | Used directly |
| `var.bucket_name` with `default = "x"` | Resolved to `"x"` |
| `var.bucket_name` with no default | INCONCLUSIVE (`var-no-default`) |
| `local.bucket = "x"` | Resolved to `"x"` |
| `aws_s3_bucket.logs.id` | Resolved to that bucket's `bucket` attribute, if scanned |
| `data.aws_ssm_parameter.X.value` | INCONCLUSIVE (`data-source-ssm`) |
| `module.X.output_name` | INCONCLUSIVE (`module-output`) |
| `prefix-${var.X}` | INCONCLUSIVE (`complex-interpolation`) |

Variable resolution is **module-scoped** - a `var.foo` in `./modules/bedrock_logging/main.tf` only resolves against `variable` blocks in that same directory, not against unrelated `variable "foo"` declarations elsewhere in the tree.

### `.tf.json` support

cdktf, Terragrunt, and various code generators emit Terraform configuration as JSON. The parser handles `.tf.json` files alongside `.tf` - both produce the same internal representation.

---

## How to use

### Command

```bash
infrarails <directory> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --format <format>` | `terminal` | Output format: `terminal`, `json`, or `html` |
| `--no-strict` | strict on | Treat `INCONCLUSIVE` findings as non-blocking. By default INCONCLUSIVE blocks the exit code like FAIL - for a compliance tool, "we couldn't verify" should not pass a CI gate silently. |
| `--strict-account-logging` | off | When set, missing `aws_bedrock_model_invocation_logging_configuration` is treated as `FAIL` instead of `INCONCLUSIVE`. Use this only when the scanned tree is the entire infra estate (no separate account-baseline stack). External-logging hints still downgrade to INCONCLUSIVE. |
| `--version` | - | Print version |
| `-h, --help` | - | Print help |

### Examples

```bash
# Scan a Terraform module, human-readable output
infrarails ./infra/

# Generate an HTML report (with collapsible sections, framework pills, disclaimer)
infrarails ./infra/ --format html > report.html

# Output machine-readable JSON for CI/CD
infrarails ./infra/ --format json | tee compliance-report.json

# Non-strict mode (INCONCLUSIVE will not block CI)
infrarails ./infra/ --no-strict

# Strict account-logging - fail when Bedrock is used but no logging config is in the tree
infrarails ./infra/ --strict-account-logging
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No blocking findings |
| `1` | One or more blocking findings (FAIL, WARN; plus INCONCLUSIVE in strict mode) |
| `2` | Tool error - invalid directory, `hcl2json` not found, etc. |

---

## Prerequisites

`infrarails` converts Terraform HCL to JSON internally using [`hcl2json`](https://github.com/tmccombs/hcl2json). Install it before running:

```bash
# macOS
brew install hcl2json

# Linux - download the binary for your platform from:
# https://github.com/tmccombs/hcl2json/releases
```

**Node.js 18+** is required.

---

## Installation

### From npm (recommended)

```bash
npm install -g infrarails
```

### From source

```bash
git clone https://github.com/your-org/infrarails.git
cd infrarails
npm install
npm run build
npm link   # makes `infrarails` available globally
```

---

## Output formats

### Terminal (default)

Colour-coded, grouped by status, with framework cross-references on each finding:

```
infrarails - Compliance Report
EU AI Act Article 12  ·  NIST AI RMF  ·  ISO/IEC 42001

1 passed   1 failed   0 warnings   1 inconclusive   3 skipped

- FAIL (1) -

✗ S-12.1.2a  CloudWatch log group "/aws/bedrock/model-invocation-logs" has no retention_in_days declared.
   ./infra/bedrock/main.tf:23
   → Set retention_in_days explicitly: a value >= 180 (recommended: 365)...
   EU Article 12(1)  ·  NIST MANAGE 4.1, MANAGE 4.3, MEASURE 3.2  ·  ISO A.6.2.8, A.6.2.6

- INCONCLUSIVE (1) -

? S-12.x.4  No aws_cloudtrail found in scanned files...
   → Verify CloudTrail is enabled in your AWS account...
   EU Article 12  ·  NIST MANAGE 4.1, GOVERN 1.4, MEASURE 2.7  ·  ISO A.6.2.8, A.3.3

Disclaimer: This report reflects the findings of an automated static analysis...
```

### HTML

Self-contained, single-file HTML report with:

- Summary bar with counts per status
- Collapsible sections per status (FAIL/WARN/INCONCLUSIVE expanded by default; PASS/SKIP collapsed)
- Coloured framework pills (EU / NIST / ISO) with hover tooltips showing the full control description
- Print-friendly CSS (collapsed sections hidden, no shadows)
- Full disclaimer block at the bottom

```bash
infrarails ./infra/ --format html > report.html
open report.html
```

### JSON

```json
{
  "summary": {
    "total": 6,
    "pass": 1,
    "fail": 1,
    "warn": 0,
    "skip": 3,
    "inconclusive": 1
  },
  "findings": [
    {
      "ruleId": "S-12.1.2a",
      "status": "FAIL",
      "description": "CloudWatch log group ... has no retention_in_days declared.",
      "remediation": "Set retention_in_days explicitly...",
      "regulatoryReference": "EU AI Act Article 12(1) - Logs retained for appropriate period",
      "nistReference": "NIST AI RMF: MANAGE 4.1 (post-deployment monitoring); MANAGE 4.3 (incident communication); MEASURE 3.2 (risk tracking)",
      "isoReference": "ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (operation and monitoring)"
    }
  ]
}
```

---

## CI integration

### GitHub Actions

```yaml
- name: Compliance scan
  run: |
    npm install -g infrarails
    infrarails ./infra/ --format json | tee compliance-report.json
  continue-on-error: false

- name: Upload HTML report
  run: infrarails ./infra/ --format html > report.html

- name: Upload artifacts
  uses: actions/upload-artifact@v4
  with:
    name: compliance-report
    path: |
      compliance-report.json
      report.html
```

### GitLab CI

```yaml
compliance:
  stage: validate
  script:
    - npm install -g infrarails
    - infrarails ./infra/ --format json | tee compliance-report.json
    - infrarails ./infra/ --format html > report.html
  artifacts:
    paths:
      - compliance-report.json
      - report.html
```

### Recommendation for CI gates

In a CI pipeline you have two reasonable choices:

- **Strict mode (default)** - `INCONCLUSIVE` blocks the build. Forces engineers to prove logging is in place (or wave the finding through explicitly). Best for high-assurance environments.
- **`--no-strict`** - only `FAIL`/`WARN` block. Best when you have a known cross-stack logging topology that the scanner cannot reach from a single repo.

Once Sprint 1B (`--plan` mode) lands, scanning Terraform plan JSON eliminates most INCONCLUSIVEs because plan output contains fully-resolved values.

---

## Roadmap

| Sprint | Status | Scope |
|---|---|---|
| **1A** | Done | Terraform HCL/JSON source scanning - 7 rules, value resolver, two-phase engine, cross-stack/local-module detection, NIST + ISO cross-references, terminal/JSON/HTML outputs |
| **1B** | In progress | `--plan` mode: scan `terraform show -json` plan/state output - eliminates `INCONCLUSIVE` for CI gates |
| **1C** | Planned | CDK and CloudFormation support; Bedrock Agent guardrail rules; additional FR-2 checks |

### Sprint 1B preview - plan/state mode

Once 1B lands, `infrarails` will accept Terraform plan JSON as input. Because plan output contains fully-resolved values (no variables, no unbuilt module outputs), this eliminates most `INCONCLUSIVE` findings and is the recommended path for CI compliance gates.

```bash
# Pre-deployment gate (recommended CI workflow)
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json
infrarails --plan plan.json --format json

# Post-deployment audit
terraform show -json > state.json
infrarails --plan state.json --mode post --format json
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

Each rule lives in `src/rules/` and implements the `ScanRule` interface from `src/types.ts`. The rule ID should follow the `S-12.x.y` naming convention and include `regulatoryReference`, `nistReference`, and `isoReference` strings mapping to the specific controls. Register the new rule in [src/rules/index.ts](src/rules/index.ts).

Set `phase1: true` only if the rule needs to populate `ScanContext` for other rules to consume (currently just `S-12.1.1`). Most new rules should be phase 2 - they read context built in phase 1 and inspect specific resource types.

Test fixtures for end-to-end scenarios live under [test/fixtures/bedrock-logging-combos/](test/fixtures/bedrock-logging-combos/) - each subdirectory is a self-contained Terraform configuration that exercises one scenario (e.g. `cross-stack-baseline-logging`, `remote-module-bedrock-logging`, `strict-mode-fail`).

---

## License

Copyright 2026 - Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, distribute, and modify this software under the terms of the Apache 2.0 license. See the [LICENSE](LICENSE) file for the full license text.

---

## Disclaimer

This report reflects the findings of an automated static analysis of your AWS AI infrastructure configuration against selected controls from the **EU AI Act**, **NIST AI RMF**, and **ISO/IEC 42001**. A passing result indicates that the scanned Terraform configuration satisfies the specific infrastructure-layer prerequisite checked - it does not constitute compliance with any of these frameworks, nor does it substitute for a formal audit, certification, or conformity assessment conducted by an accredited body.

Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the scope of infrastructure scanning. This report should be treated as a **pre-audit readiness input**, not an attestation of conformance.
