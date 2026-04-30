# complyscan

> Static compliance scanner for EU AI Act Article 12 - checks your Terraform infrastructure for logging and traceability gaps before they become audit findings.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/complyscan.svg)](https://www.npmjs.com/package/complyscan)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

---

## What is this?

The **EU AI Act** (Regulation 2024/1689) requires providers of high-risk AI systems to maintain comprehensive logs of system operation to ensure traceability, accountability, and post-incident auditability. **Article 12** specifically mandates that high-risk AI systems automatically record events throughout their operational lifetime.

`complyscan` is built for teams running **high-risk AI systems on AWS Bedrock**. It reads your **Terraform HCL source files** (and `.tf.json` files emitted by cdktf, Terragrunt, and other generators) and reports exactly which Article 12 logging controls are passing, failing, or cannot be verified statically - giving you a clear, actionable compliance gap report without needing to deploy anything.

Concretely, the scanner inspects Terraform for the AWS primitives that back Article 12 logging on Bedrock:

- `aws_bedrock_model_invocation_logging_configuration` (whether invocation logging is configured and which modalities are enabled)
- The CloudWatch log group or S3 bucket that Bedrock writes to (retention, lifecycle, encryption, versioning)
- `aws_cloudtrail` (an enabled trail covering control-plane events)
- Local vs remote Terraform modules (so cross-stack logging topologies are flagged rather than silently passed)

The scanner is **deliberately conservative**: when it cannot prove a control is in place, it emits `INCONCLUSIVE` rather than `PASS` or `FAIL`. For a compliance tool, "we couldn't verify" is the only honest answer when the evidence is split across stacks, modules, or runtime values.

> ### Important: this is a prerequisite, not a certificate of compliance
>
> A fully passing complyscan run is a **necessary but not sufficient** condition for EU AI Act Article 12 conformance. complyscan only verifies that a narrow set of AWS Bedrock logging primitives are **declared** in your Terraform. It does **not** evaluate:
>
> - Non-AWS or non-Bedrock AI workloads (Azure OpenAI, Vertex AI, self-hosted models, SageMaker, etc.)
> - Application-level event logging, prompt/response capture, decision traceability, or human-oversight records
> - Whether deployed infrastructure actually emits logs, or whether logs are being retained, protected, and reviewed in practice
> - Other Article 12 obligations around log content, integrity, retention duration relative to the system's intended purpose, and downstream-deployer access
> - The remaining EU AI Act requirements outside Article 12 (risk management, data governance, technical documentation, conformity assessment, post-market monitoring, etc.)
>
> Treat a green complyscan as evidence that the **infrastructure baseline** for Article 12 logging is in place. Full Article 12 (and EU AI Act) compliance still requires application-level controls, runtime verification, organisational processes, and legal review.

---

## Quick start

```bash
# 1. Install hcl2json (one-time, see Prerequisites)
brew install hcl2json

# 2. Install complyscan
npm install -g complyscan

# 3. Scan a Terraform directory
complyscan ./infra/
```

---

## Rules

`complyscan` ships **7 rules** mapped to Article 12 of the EU AI Act. Each finding is one of: **PASS**, **FAIL**, **WARN**, **SKIP**, or **INCONCLUSIVE**.

| Rule ID | Severity | Phase | Check |
|---|---|---|---|
| `S-12.1.1` | FAIL | 1 | AWS Bedrock model invocation logging is configured when Bedrock is in use |
| `S-12.1.2a` | FAIL | 2 | CloudWatch log group used for Bedrock logs has a retention policy ≥ 365 days |
| `S-12.1.2b` | FAIL | 2 | S3 bucket used for Bedrock logs has a lifecycle policy ≥ 365 days |
| `S-12.x.1` | WARN | 2 | S3 log bucket has versioning (or object lock) enabled |
| `S-12.x.2a` | WARN | 2 | S3 log bucket has KMS server-side encryption configured |
| `S-12.x.4` | FAIL | 2 | A CloudTrail trail is present and enabled |
| `S-12.x.5` | WARN | 2 | Flags remote modules whose contents the scanner cannot inspect |

Retention thresholds: **WARN** at ≥ 180 days, **PASS** at ≥ 365 days.

---

## Architecture

complyscan is a small, layered TypeScript pipeline. Each layer has a narrow contract, which makes the rule logic easy to read and the failure modes easy to reason about.

```
   ┌──────────────────┐
   │  CLI (commander) │   src/index.ts - argv parsing, exit codes
   └────────┬─────────┘
            │
   ┌────────▼─────────┐
   │     Parser       │   src/parser.ts
   │  .tf  → hcl2json │   recursively walks the directory, skips
   │  .tf.json → JSON │   node_modules / vendor / examples / .* etc.
   └────────┬─────────┘
            │ ParsedFile[] (filePath, json, rawHcl)
   ┌────────▼─────────┐
   │     Resolver     │   src/resolver.ts
   │  var / local /   │   classifies values as literal | address |
   │  data / module   │   unresolvable (with a reason code)
   └────────┬─────────┘
            │
   ┌────────▼─────────┐
   │ Two-phase Runner │   src/runner.ts
   │                  │
   │  Phase 1 rules ──┼──► populate ScanContext via src/context.ts
   │  Phase 2 rules ──┼──► consume ScanContext (bucket / log-group names,
   │                  │    unresolved refs, strictAccountLogging flag)
   └────────┬─────────┘
            │ Finding[]
   ┌────────▼─────────┐
   │    Formatter     │   src/formatter.ts - terminal or JSON
   └──────────────────┘
```

**Why two phases?** Most rules need to know *which buckets and log groups Bedrock is actually writing to* before they can check encryption, versioning, retention, etc. Phase 1 (currently just `S-12.1.1`) walks `aws_bedrock_model_invocation_logging_configuration` blocks and resolves their `bucket_name` / `log_group_name` fields into a `ScanContext`. Phase 2 rules use that context to scope their checks - e.g. `S-12.x.2a` only flags encryption gaps on buckets that are *actually* receiving Bedrock logs, not every bucket in the repo.

**The resolver** is what makes the scanner robust on real-world Terraform. A `bucket_name` field can be a literal, a `var.X`, a `local.Y`, a reference to another `aws_s3_bucket`, an SSM parameter, a module output, or a complex interpolation. The resolver classifies each into one of three outcomes:

| Outcome | Example | What rules do with it |
|---|---|---|
| **literal** | `"prod-ai-audit-logs"` | Use the value directly |
| **address** | `aws_s3_bucket.logs.id` resolved to its `bucket` attribute | Use the resolved name |
| **unresolvable** | `var.bucket_name` (no default), `data.aws_ssm_parameter.X.value`, `module.logging.bucket` | Emit `INCONCLUSIVE` instead of guessing |

The unresolvable cases get categorized (`var-no-default`, `data-source-ssm`, `module-output`, …) so the finding message can tell the operator *why* the value couldn't be checked statically.

### Scanner directory traversal

The parser recursively walks the target directory and parses every `.tf` and `.tf.json` file it finds. **Local modules are scanned as part of the same pass** (e.g. `./modules/bedrock_logging/main.tf` is read alongside the root). The following directories are skipped automatically:

```
node_modules, venv, env, __pycache__,
examples, test, tests, vendor, .* (any dotfile/dir)
```

Remote modules (registry, git, http) are not fetched - their contents are invisible to a static scan, so `S-12.x.5` flags them and `S-12.1.1` factors them into its INCONCLUSIVE reasoning.

---

## Scenarios it can handle

The hardest part of static compliance scanning isn't matching resource types - it's distinguishing *"this is genuinely missing"* from *"this lives somewhere I can't see."* complyscan handles both, and it tells you which one you're looking at.

### Direct, in-file Bedrock + logging → PASS

Bedrock resource and `aws_bedrock_model_invocation_logging_configuration` in the same scanned tree, with at least one modality enabled (or all modality toggles unset, which is AWS's enable-all default).

```hcl
resource "aws_bedrockagent_agent" "support_bot" { ... }

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config { bucket_name = "prod-ai-audit-logs" }
  }
}
```
→ `S-12.1.1: PASS`

### All modality toggles explicitly false → FAIL

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
→ `S-12.1.1: FAIL - all data-delivery toggles set to false`

### Bedrock used, no logging in scanned files → INCONCLUSIVE (default) or FAIL (strict)

By default, the scanner assumes account-baseline patterns are common (logging configured once at the org/account level, not per-stack) and emits `INCONCLUSIVE` so it doesn't generate false positives for teams with that topology. Pass `--strict-account-logging` to flip this to `FAIL` when you know the entire estate is in scope.

### Cross-stack baseline logging → INCONCLUSIVE (with reason)

When the scanner sees Bedrock usage *and* hints that logging is wired up via another stack - a `data.terraform_remote_state.account_baseline.outputs.log_bucket` reference, a baseline-logging module call, or an input key like `log_bucket` / `bedrock_logs_bucket` on a module - it emits `INCONCLUSIVE` with the specific cross-stack pointer that triggered the decision. **This overrides `--strict-account-logging`**: when there is positive evidence of external logging, the scanner won't FAIL.

```hcl
resource "aws_bedrockagent_agent" "support_bot" { ... }

data "terraform_remote_state" "account_baseline" {
  backend = "s3"
  config  = { ... }
}

resource "aws_s3_bucket_policy" "bedrock_logs" {
  bucket = data.terraform_remote_state.account_baseline.outputs.log_bucket
  policy = "{}"
}
```
→ `S-12.1.1: INCONCLUSIVE - cross-stack reference to account_baseline.log_bucket suggests logging is configured externally`

### Indirect-only Bedrock signals → always INCONCLUSIVE

IAM grants for `bedrock:*` actions, VPC endpoints to `bedrock-runtime`, or `aws_bedrock_foundation_model` data sources are *signals* that something nearby uses Bedrock - but the deploying resource may live in another stack entirely. These are never confident `FAIL`s, even under `--strict-account-logging`.

### Local modules → scanned recursively

`module "bedrock_logging" { source = "./modules/bedrock_logging" }` is followed transparently - the module's `.tf` files are parsed alongside the root and contribute to the same context.

### Remote modules → flagged, never scanned

Registry, git, http, and bitbucket sources can't be inspected statically. `S-12.x.5` emits an `INCONCLUSIVE` per remote module so they show up in the report instead of being silently ignored. If your only Bedrock-related logic is inside a remote module, `S-12.1.1` also emits an INCONCLUSIVE rather than a misleading SKIP.

### Variables, locals, and data sources → resolved when possible

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
complyscan <directory> [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-f, --format <format>` | `terminal` | Output format: `terminal` or `json` |
| `--no-strict` | strict on | Treat `INCONCLUSIVE` findings as non-blocking. By default INCONCLUSIVE blocks the exit code like FAIL - for a compliance tool, "we couldn't verify" should not pass a CI gate silently. |
| `--strict-account-logging` | off | When set, missing `aws_bedrock_model_invocation_logging_configuration` is treated as `FAIL` instead of `INCONCLUSIVE`. Use this only when the scanned tree is the entire infra estate (no separate account-baseline stack). External-logging hints still downgrade to INCONCLUSIVE. |
| `--version` | - | Print version |
| `-h, --help` | - | Print help |

### Examples

```bash
# Scan a Terraform module, human-readable output
complyscan ./infra/

# Scan and output machine-readable JSON
complyscan ./infra/ --format json

# Non-strict mode (INCONCLUSIVE will not block CI)
complyscan ./infra/ --no-strict

# Strict account-logging - fail when Bedrock is used but no logging config is in the tree
complyscan ./infra/ --strict-account-logging

# Use in a CI pipeline and persist the report
complyscan ./infra/ --format json | tee compliance-report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No blocking findings |
| `1` | One or more blocking findings (FAIL, WARN; plus INCONCLUSIVE in strict mode) |
| `2` | Tool error - invalid directory, `hcl2json` not found, etc. |

---

## Prerequisites

`complyscan` converts Terraform HCL to JSON internally using [`hcl2json`](https://github.com/tmccombs/hcl2json). Install it before running:

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

## Output

### Terminal (default)

```
complyscan - EU AI Act Article 12 Compliance Scan
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

### Recommendation for CI gates

In a CI pipeline you have two reasonable choices:

- **Strict mode (default)** - `INCONCLUSIVE` blocks the build. Forces engineers to prove logging is in place (or wave the finding through explicitly). Best for high-assurance environments.
- **`--no-strict`** - only `FAIL`/`WARN` block. Best when you have a known cross-stack logging topology that the scanner cannot reach from a single repo.

Once Sprint 1B (`--plan` mode) lands, scanning Terraform plan JSON eliminates most INCONCLUSIVEs because plan output contains fully-resolved values.

---

## Roadmap

| Sprint | Status | Scope |
|---|---|---|
| **1A** | ✅ Done | Terraform HCL/JSON source scanning - 7 Article 12 rules, value resolver, two-phase engine, cross-stack/local-module detection |
| **1B** | 🔄 In progress | `--plan` mode: scan `terraform show -json` plan/state output - eliminates `INCONCLUSIVE` for CI gates |
| **1C** | Planned | CDK and CloudFormation support; additional FR-2 checks |

### Sprint 1B preview - plan/state mode

Once 1B lands, `complyscan` will accept Terraform plan JSON as input. Because plan output contains fully-resolved values (no variables, no unbuilt module outputs), this eliminates most `INCONCLUSIVE` findings and is the recommended path for CI compliance gates.

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

Each rule lives in `src/rules/` and implements the `ScanRule` interface from `src/types.ts`. The rule ID should follow the `S-12.x.y` naming convention and include a `regulatoryReference` mapping to the specific Article 12 sub-clause. Register the new rule in [src/rules/index.ts](src/rules/index.ts).

Set `phase1: true` only if the rule needs to populate `ScanContext` for other rules to consume (currently just `S-12.1.1`). Most new rules should be phase 2 - they read context built in phase 1 and inspect specific resource types.

Test fixtures for end-to-end scenarios live under [test/fixtures/bedrock-logging-combos/](test/fixtures/bedrock-logging-combos/) - each subdirectory is a self-contained Terraform configuration that exercises one scenario (e.g. `cross-stack-baseline-logging`, `remote-module-bedrock-logging`, `strict-mode-fail`).

---

## License

Copyright 2026 - Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, distribute, and modify this software under the terms of the Apache 2.0 license. See the [LICENSE](LICENSE) file for the full license text.

---

## Disclaimer

`complyscan` is a static analysis tool. A fully passing scan means your Terraform configuration **declares** the required AWS Bedrock logging controls - it does not verify that deployed infrastructure is operating correctly, that log data is actually being written, or that your system meets all requirements of the EU AI Act in its entirety. complyscan covers a single slice of Article 12 (AWS Bedrock infrastructure-level logging) and is a **prerequisite for**, not a **substitute for**, full Article 12 compliance. Always combine static scanning with runtime monitoring, application-level traceability, organisational controls, and legal review.
