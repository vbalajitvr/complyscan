# infrarails

> Static compliance scanner for AWS AI infrastructure - checks your Terraform for the risk-management (Article 9 - Bedrock Guardrails) and logging, retention, and traceability (Article 12) gaps that surface at audit time, mapped to **EU AI Act**, **NIST AI RMF**, and **ISO/IEC 42001**.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![npm version](https://img.shields.io/npm/v/infrarails.svg)](https://www.npmjs.com/package/infrarails)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org/)

---

## What is this?

`infrarails` is built for teams running **high-risk AI systems on AWS Bedrock**. It reads your **Terraform HCL source files** (and `.tf.json` files emitted by cdktf, Terragrunt, and other generators) and reports exactly which infrastructure-layer controls are passing, failing, or cannot be verified statically - giving you a clear, actionable readiness report without needing to deploy anything.

Each finding is cross-referenced against three frameworks:

- **EU AI Act** (Regulation 2024/1689) - Article 9 (risk management for high-risk AI) and Article 12 (logging and traceability)
- **NIST AI RMF 1.0** - GOVERN / MEASURE / MANAGE / MAP functions
- **ISO/IEC 42001:2023** - Annex A controls (A.6.1.x objectives, A.6.2.x event logging / verification / deployment)

Concretely, the scanner inspects Terraform for the AWS primitives that back AI risk management and logging on Bedrock:

- `aws_bedrockagent_agent` (whether a guardrail is attached, with a numbered version rather than DRAFT)
- `aws_bedrock_guardrail` / `aws_bedrock_guardrail_version` (presence in the scanned tree when any Bedrock workload is detected)
- `aws_bedrock_model_invocation_logging_configuration` (whether invocation logging is configured and which modalities are enabled)
- The CloudWatch log group or S3 bucket that Bedrock writes to (retention, lifecycle, encryption, versioning); CloudWatch subscription filters as a forwarder signal
- `aws_cloudtrail` (an enabled trail covering control-plane events)
- Local vs remote Terraform modules (so cross-stack logging / risk-management topologies are flagged rather than silently passed)

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
infrarails ./infra/ --format html -o report.html
```

---

## Rules

`infrarails` ships **9 rules** mapped to Articles 9 and 12 of the EU AI Act, with cross-references to NIST AI RMF and ISO/IEC 42001. Each finding is one of: **PASS**, **FAIL**, **WARN**, **SKIP**, or **INCONCLUSIVE**.

| Rule ID | Severity | Phase | Article | Check |
|---|---|---|---|---|
| `S-9.x.1` | FAIL | 2 | 9 | Bedrock Agents must have a versioned guardrail attached (Agent-attached guardrails only - raw InvokeModel/Converse SDK calls are out of scope for static IaC scanning) |
| `S-9.x.2` | WARN | 2 | 9 | When Bedrock is in use, at least one `aws_bedrock_guardrail` should be declared in scanned Terraform (presence-level signal; complements `S-9.x.1`) |
| `S-12.1.1` | FAIL | 1 | 12 | AWS Bedrock model invocation logging is configured when Bedrock is in use |
| `S-12.1.2a` | WARN | 2 | 12 | CloudWatch log group used for Bedrock logs has a retention policy >= 180 days, or a forwarder pipe to an external log system was detected |
| `S-12.1.2b` | FAIL | 2 | 12 | S3 bucket used for Bedrock logs has a lifecycle policy >= 365 days |
| `S-12.x.1` | WARN | 2 | 12 | S3 log bucket has versioning (or object lock) enabled |
| `S-12.x.2a` | WARN | 2 | 12 | S3 log bucket has KMS server-side encryption configured |
| `S-12.x.4` | FAIL | 2 | 12 | A CloudTrail trail is present and enabled |
| `S-12.x.5` | WARN | 2 | 12 | Flags remote modules whose contents the scanner cannot inspect |

Retention thresholds for `S-12.1.2a`: **PASS** at >= 365 days (or `retention_in_days = 0` for never-expire), **WARN** for everything else. The rule is intentionally WARN-only - in real enterprise estates, retention is often satisfied by a forwarder shipping logs to Datadog/Splunk/SIEM owned by a separate platform repo, by a central log-archive account (Control Tower / Landing Zone), or by an auto-subscription Lambda deployed out-of-band. A static single-repo scan cannot prove that retention is *missing*, so the rule warns rather than fails. When a `aws_cloudwatch_log_subscription_filter` targeting the log group is present in the scanned files, the WARN message says so explicitly; otherwise the message reminds the reader that forwarders are commonly out-of-repo and need to be verified at the destination.

Retention threshold for `S-12.1.2b`: **FAIL** below 365 days.

---

## Architecture

`infrarails` is a small, layered TypeScript pipeline: a parser that turns `.tf` / `.tf.json` files into a uniform JSON representation (via [`hcl2json`](https://github.com/tmccombs/hcl2json)), a value **resolver** that classifies every expression as `literal`, `address`, or `unresolvable` (with a reason code), and a **two-phase rule engine** - Phase 1 builds a `ScanContext` of the buckets and log groups Bedrock is actually writing to, and Phase 2 rules consume that context to scope their checks. Local modules are walked transparently; remote modules are flagged but never fetched.

For the full pipeline diagram, the resolver outcome table, the `ScanContext` shape, and guidance for adding new rules, see **[ARCHITECTURE.md](ARCHITECTURE.md)**.

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

### Short retention with a CloudWatch subscription filter -> WARN (forwarder-aware)

A common enterprise pattern: the app team's Terraform declares a Bedrock log group with `retention_in_days = 7` because the actual retention lives at a Datadog/Splunk/SIEM destination subscribed via `aws_cloudwatch_log_subscription_filter`. `S-12.1.2a` detects the subscription filter (matching by literal name, resource address, or resolved variable/local) and emits a WARN whose remediation explicitly notes the filter and reminds the reader to verify destination retention. When no filter is found in scanned files, the WARN remediation instead reminds the reader that forwarders are commonly owned by a separate platform repo or central log-archive account - the scanner cannot tell the difference between "no forwarder anywhere" and "forwarder in another repo." Either way, the rule is WARN-only and never FAILs on retention alone.

### Bedrock Guardrails - Agent-attached vs SDK runtime

Bedrock Guardrails attach to two surfaces: **(a)** Bedrock Agents via the `guardrail_configuration` block on `aws_bedrockagent_agent` - declared in HCL, statically verifiable; **(b)** raw `InvokeModel` / `Converse` SDK calls via the `guardrailIdentifier` parameter - passed in application code (Python/TypeScript/Java), invisible to a static IaC scanner.

`S-9.x.1` covers (a): for every `aws_bedrockagent_agent` it checks that a `guardrail_configuration` block is present, that `guardrail_identifier` is non-empty, and that `guardrail_version` is a numbered version rather than `"DRAFT"` (DRAFT versions are mutable and not auditable as a fixed control).

`S-9.x.2` covers a weaker but useful presence-level question: **"Bedrock is being used somewhere - is at least one `aws_bedrock_guardrail` declared anywhere in the scanned Terraform?"** It WARNs (never FAILs) when no guardrail is found, because guardrails are commonly defined in a separate security/platform stack and a single-repo scan can't see those. The remediation message names all three real possibilities: declare here, scan the security stack, or pass `guardrailIdentifier` in SDK code.

Neither rule attempts to verify (b) - that's an application-layer control surface (code review, SDK linting, runtime tracing) and is explicitly called out in both rules' descriptions and remediation messages so users don't read a passing `S-9.x.1` as covering their SDK-driven workloads.

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
| `-o, --output <file>` | stdout | Write the rendered report to a file instead of stdout. Avoids the need to shell-redirect for `html`/`json` and prevents the common footgun of dumping markup into the terminal. When `-f html` or `-f json` is used without `-o` *and* stdout is a TTY, the CLI prints a one-line tip to stderr suggesting `-o`. The tip is silent when piped or redirected, so existing scripts and CI invocations are unaffected. |
| `--no-strict` | strict on | Treat `INCONCLUSIVE` findings as non-blocking. By default INCONCLUSIVE blocks the exit code like FAIL - for a compliance tool, "we couldn't verify" should not pass a CI gate silently. |
| `--strict-account-logging` | off | When set, missing `aws_bedrock_model_invocation_logging_configuration` is treated as `FAIL` instead of `INCONCLUSIVE`. Use this only when the scanned tree is the entire infra estate (no separate account-baseline stack). External-logging hints still downgrade to INCONCLUSIVE. |
| `--version` | - | Print version |
| `-h, --help` | - | Print help |

### Examples

```bash
# Scan a Terraform module, human-readable output
infrarails ./infra/

# Generate an HTML report (with collapsible sections, framework pills, disclaimer)
infrarails ./infra/ --format html -o report.html

# Or with shell redirection (still works)
infrarails ./infra/ --format html > report.html

# Output machine-readable JSON for CI/CD
infrarails ./infra/ --format json -o compliance-report.json

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

1 passed   0 failed   1 warnings   1 inconclusive   3 skipped

- WARN (1) -

⚠ S-12.1.2a  CloudWatch log group "/aws/bedrock/model-invocation-logs" has no retention_in_days declared.
   ./infra/bedrock/main.tf:23
   → Set retention_in_days explicitly: a value >= 180 (recommended: 365). No CloudWatch subscription filter was found in the scanned Terraform, but forwarders are commonly owned by a separate platform repo (Datadog/Splunk forwarder Lambda, central log-archive account, auto-subscription Lambda)...
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
infrarails ./infra/ --format html -o report.html
open report.html
```

### JSON

```json
{
  "summary": {
    "total": 6,
    "pass": 1,
    "fail": 0,
    "warn": 1,
    "skip": 3,
    "inconclusive": 1
  },
  "findings": [
    {
      "ruleId": "S-12.1.2a",
      "status": "WARN",
      "description": "CloudWatch log group ... has no retention_in_days declared.",
      "remediation": "Set retention_in_days explicitly... No CloudWatch subscription filter was found in the scanned Terraform...",
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
    infrarails ./infra/ --format json -o compliance-report.json
  continue-on-error: false

- name: Upload HTML report
  run: infrarails ./infra/ --format html -o report.html

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
    - infrarails ./infra/ --format json -o compliance-report.json
    - infrarails ./infra/ --format html -o report.html
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

See the **[Adding a new rule](ARCHITECTURE.md#adding-a-new-rule)** section in [ARCHITECTURE.md](ARCHITECTURE.md), which covers the `ScanRule` interface, the two-phase model, naming conventions, and the test-fixture layout.

---

## License

Copyright 2026 - Licensed under the [Apache License, Version 2.0](LICENSE).

You may use, distribute, and modify this software under the terms of the Apache 2.0 license. See the [LICENSE](LICENSE) file for the full license text.

---

## Disclaimer

This report reflects the findings of an automated static analysis of your AWS AI infrastructure configuration against selected controls from the **EU AI Act**, **NIST AI RMF**, and **ISO/IEC 42001**. A passing result indicates that the scanned Terraform configuration satisfies the specific infrastructure-layer prerequisite checked - it does not constitute compliance with any of these frameworks, nor does it substitute for a formal audit, certification, or conformity assessment conducted by an accredited body.

Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the scope of infrastructure scanning. This report should be treated as a **pre-audit readiness input**, not an attestation of conformance.
