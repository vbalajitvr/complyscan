# Release Notes

## v0.1.0 — Initial release

`infrarails` v0.1.0 is the first public release: a static compliance scanner for AWS AI infrastructure declared in Terraform. It reads `.tf` and `.tf.json` source files and reports whether the AWS Bedrock primitives backing **EU AI Act** Article 9 (risk management) and Article 12 (logging and traceability) are in place, with cross-references to **NIST AI RMF 1.0** and **ISO/IEC 42001:2023**.

> See [README.md](README.md) for the full feature description, install instructions, and rule reference.

### Highlights

- **9 compliance rules** mapped to EU AI Act Articles 9 & 12, with NIST AI RMF and ISO/IEC 42001 cross-references on every finding.
- **Two-phase rule engine** — Phase 1 builds a `ScanContext` (the buckets and log groups Bedrock writes to); Phase 2 rules consume that context to scope their checks.
- **Conservative-by-design verdicts** — `INCONCLUSIVE` is a first-class status, not a hidden pass. When the scanner cannot prove a control, it says so.
- **Forwarder-aware retention checks** — `S-12.1.2a` detects `aws_cloudwatch_log_subscription_filter` targeting the Bedrock log group and adjusts its WARN message accordingly.
- **Cross-stack topology handling** — `--strict-account-logging` flips missing-logging from `INCONCLUSIVE` to `FAIL` for teams whose scanned tree is the whole estate; the default avoids false positives for account-baseline patterns.
- **Local modules walked transparently; remote modules flagged** via `S-12.x.5` (`INCONCLUSIVE` per remote source — registry/git/http/bitbucket).
- **Variable, local, and resource-attribute resolution** with module-scoped variable lookup (no cross-module variable bleed) and explicit reason codes for unresolvable expressions (`var-no-default`, `data-source-ssm`, `module-output`, `complex-interpolation`).
- **Four output formats**: `terminal` (colour-coded, grouped by status), `json` (machine-readable for CI), `html` (single-file, collapsible sections, framework pills, print CSS), and `pdf` (paginated, `pdfkit`-rendered, no headless Chromium).
- **Cross-platform**: native macOS, Linux, and Windows (PowerShell / `cmd.exe`); WSL supported.
- **Three exit codes** for clean CI gating: `0` clean, `1` blocking findings (FAIL/WARN; plus INCONCLUSIVE under default strict mode), `2` tool error.

### Rules in this release

| Rule ID | Severity | Article | Check |
|---|---|---|---|
| `S-9.x.1` | FAIL | 9 | Bedrock Agents must have a versioned guardrail attached (numbered version, not `DRAFT`) |
| `S-9.x.2` | WARN | 9 | When Bedrock is in use, at least one `aws_bedrock_guardrail` should be declared in the scanned tree |
| `S-12.1.1` | FAIL | 12 | AWS Bedrock model invocation logging is configured when Bedrock is in use |
| `S-12.1.2a` | WARN | 12 | CloudWatch retention >= 180 days, or a forwarder subscription filter is detected |
| `S-12.1.2b` | FAIL | 12 | S3 lifecycle policy >= 180 days (FAIL <180; WARN 180–364; PASS >=365) |
| `S-12.x.1` | FAIL | 12 | S3 log bucket has versioning (or object lock) enabled |
| `S-12.x.2a` | FAIL | 12 | S3 log bucket has KMS server-side encryption configured |
| `S-12.x.4` | FAIL | 12 | A CloudTrail trail is present and enabled |
| `S-12.x.5` | WARN | 12 | Flags remote modules whose contents the scanner cannot inspect |

### CLI

```bash
infrarails <directory> [options]
```

| Flag | Description |
|---|---|
| `-f, --format <terminal\|json\|html\|pdf>` | Output format. `pdf` requires `-o`. |
| `-o, --output <file>` | Write the rendered report to a file. |
| `--no-strict` | Treat `INCONCLUSIVE` as non-blocking. |
| `--strict-account-logging` | Treat missing Bedrock logging as `FAIL` instead of `INCONCLUSIVE`. |
| `--version`, `-h, --help` | Standard. |

### Install

```bash
# npm (recommended)
npm install -g infrarails

# Prerequisite on PATH
brew install hcl2json   # macOS — see README for Linux/Windows
```

Requires Node 18+ to run the published CLI; contributors running the test suite need Node 20.x, 22.x, or 24+ (vitest 4.x).

### Known limitations

- Static IaC scanning only — runtime guardrail attachment via the `InvokeModel` / `Converse` SDK `guardrailIdentifier` parameter is **not** verifiable from Terraform and is explicitly out of scope (called out in `S-9.x.1` / `S-9.x.2` remediation messages).
- Remote modules (registry, git, http, bitbucket) are flagged but never fetched.
- Expressions backed by SSM data sources, module outputs, or complex interpolations resolve to `INCONCLUSIVE` with a reason code rather than a confident verdict.
- A fully passing run is a **necessary but not sufficient** condition for EU AI Act / NIST AI RMF / ISO 42001 conformance. See the disclaimer in [README.md](README.md#disclaimer).

### What's next

- **Sprint 1B (in progress)** — `--plan` mode: scan `terraform show -json` plan/state output. Plan output contains fully-resolved values, which eliminates most `INCONCLUSIVE` findings and is the recommended path for CI compliance gates.
- **Sprint 1C (planned)** — CDK and CloudFormation support; additional Bedrock Agent guardrail rules.

### License

Apache-2.0. See [LICENSE](LICENSE).
