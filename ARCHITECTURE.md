# infrarails - Architecture

This document describes the internal pipeline of `infrarails`. For installation, usage, rules, and CI integration, see the [README](README.md).

---

## Pipeline overview

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
   |    Formatter     |   src/formatter.ts - terminal, JSON, HTML, or PDF
   +------------------+
```

The CLI ([src/index.ts](src/index.ts)) validates `--format` against the four supported values and exits with code `2` on an unknown value, so an older globally-installed binary asked for `pdf` cannot silently fall through to terminal mode and write ANSI text into a `.pdf` file. PDF additionally requires `-o`: it is binary and cannot be sensibly streamed to a TTY.

### PDF rendering

PDF output is generated procedurally with [`pdfkit`](https://pdfkit.org/) rather than by rendering HTML through a headless browser. Reasons:

- **No Chromium dependency.** Shipping a headless browser would add ~150MB and require system libraries (`libnss3`, `libatk1.0-0`, ...) that are awkward in CI containers and Lambda layers.
- **Deterministic layout.** Procedural drawing gives stable pagination across runs, which matters for diffing reports.
- **Portable.** `pdfkit` is pure JS, so the same code path works on macOS, Linux, and inside WSL without per-OS install steps.

The trade-off is that the PDF and HTML formatters do not share a renderer — the layout is reimplemented using `pdfkit` primitives (text, rounded rects, framework-coloured pills) rather than CSS. Both formats follow the same visual language (status pills, grouped sections, framework refs) but neither is a translation of the other.

### Platform note: how the parser invokes hcl2json

The parser ([src/parser.ts](src/parser.ts)) invokes `hcl2json` via `spawnSync('hcl2json', [], { input: rawHcl })` — piping the HCL source over stdin with no shell in between. This is portable across macOS, Linux, and native Windows:

- **No `/bin/bash` dependency** — earlier revisions used `execSync` with `shell: '/bin/bash'` and a here-string (`hcl2json <<< '...'`), which broke native Windows. The current call uses no shell, so Node resolves the executable directly (`hcl2json` on POSIX, `hcl2json.exe` on win32).
- **No temp files** — the `.tf` source is piped over stdin, so we never write to disk between the file read and `hcl2json`.
- **No quote-escaping** — the previous bash here-string had to escape single quotes in the HCL source, which is a known footgun on configurations containing arbitrary string literals. Stdin avoids the problem entirely.

Errors surface with the file path, the `hcl2json` exit status, and the captured stderr, so a syntax error in a single `.tf` file produces a debuggable message rather than a raw `Error: Command failed`.

---

## Why two phases?

Most rules need to know *which buckets and log groups Bedrock is actually writing to* before they can check encryption, versioning, retention, etc. Phase 1 (currently just `S-12.1.1`) walks `aws_bedrock_model_invocation_logging_configuration` blocks and resolves their `bucket_name` / `log_group_name` fields into a `ScanContext`. Phase 2 rules use that context to scope their checks - e.g. `S-12.x.2a` only flags encryption gaps on buckets that are *actually* receiving Bedrock logs, not every bucket in the repo.

This split is what lets the scanner stay quiet about resources that aren't part of the AI logging path - a CI artifact bucket without KMS encryption is not a Bedrock-logging finding, and Phase 2 rules know that because Phase 1 told them.

---

## The resolver

The resolver is what makes the scanner robust on real-world Terraform. A `bucket_name` field can be a literal, a `var.X`, a `local.Y`, a reference to another `aws_s3_bucket`, an SSM parameter, a module output, or a complex interpolation. The resolver classifies each into one of three outcomes:

| Outcome | Example | What rules do with it |
|---|---|---|
| **literal** | `"prod-ai-audit-logs"` | Use the value directly |
| **address** | `aws_s3_bucket.logs.id` resolved to its `bucket` attribute | Use the resolved name |
| **unresolvable** | `var.bucket_name` (no default), `data.aws_ssm_parameter.X.value`, `module.logging.bucket` | Emit `INCONCLUSIVE` instead of guessing |

The unresolvable cases get categorised with a reason code (`var-no-default`, `local-not-literal`, `data-source-ssm`, `data-source-other`, `module-output`, `complex-interpolation`, `unknown-format`) so the finding message can tell the operator *why* the value couldn't be checked statically. This matters at audit time - "we couldn't verify because the bucket name comes from SSM" is a different remediation than "we couldn't verify because the variable has no default."

Variable resolution is **module-scoped** - a `var.foo` in `./modules/bedrock_logging/main.tf` only resolves against `variable` blocks in that same directory, not against unrelated `variable "foo"` declarations elsewhere in the tree.

---

## Scanner directory traversal

The parser recursively walks the target directory and parses every `.tf` and `.tf.json` file it finds. **Local modules are scanned as part of the same pass** (e.g. `./modules/bedrock_logging/main.tf` is read alongside the root). The following directories are skipped automatically:

```
node_modules, venv, env, __pycache__,
examples, test, tests, testdata, fixtures, vendor,
.* (any dotfile/dir)
```

Remote modules (registry, git, http) are not fetched - their contents are invisible to a static scan, so `S-12.x.5` flags them and `S-12.1.1` factors them into its INCONCLUSIVE reasoning.

---

## ScanContext

`src/context.ts` builds a `ScanContext` after Phase 1 runs. Phase 2 rules read it to scope their checks. The shape:

| Field | Type | Purpose |
|---|---|---|
| `bedrockLoggingDetected` | `boolean` | Did Phase 1 find an `aws_bedrock_model_invocation_logging_configuration` resource? Logging-related Phase 2 rules (`cw-retention`, `s3-lifecycle`, `s3-versioning`, `s3-encryption`) SKIP when false; rules with their own detection logic (e.g. `agent-guardrail`, `guardrail-presence`, `cloudtrail`, `module-wall`) ignore it. |
| `logBucketNames` | `string[]` | Resolved S3 bucket names that Bedrock writes to (literals or fully-qualified addresses). Used to scope `S-12.x.1`, `S-12.x.2a`, `S-12.1.2b`. |
| `logGroupNames` | `string[]` | Resolved CloudWatch log group names that Bedrock writes to. Used to scope `S-12.1.2a`. |
| `unresolvedBucketRefs` | `UnresolvedRef[]` | Bucket references that could not be resolved statically. Phase 2 rules emit `INCONCLUSIVE` per ref. |
| `unresolvedGroupRefs` | `UnresolvedRef[]` | Log-group references that could not be resolved statically. Same handling. |
| `strictAccountLogging` | `boolean` | When true, missing logging is `FAIL` instead of `INCONCLUSIVE`. The flag is the only knob that flips this verdict — no naming-based heuristics (cross-stack remote-state references, baseline-named modules, logging-shaped input keys) downgrade it. |

---

## Adding a new rule

Each rule lives in `src/rules/` and implements the `ScanRule` interface from `src/types.ts`. The rule ID follows an `S-<article>.<x>.<y>` naming convention where `<article>` is the EU AI Act article number the rule maps to (e.g. `S-9.x.1` for Article 9 risk-management rules, `S-12.1.2a` for Article 12 logging rules). The rule includes `regulatoryReference`, `nistReference`, and `isoReference` strings mapping to specific controls. Register the new rule in [src/rules/index.ts](src/rules/index.ts).

Set `phase1: true` only if the rule needs to populate `ScanContext` for other rules to consume (currently just `S-12.1.1`). Most new rules should be Phase 2 - they read context built in Phase 1 and inspect specific resource types.

Test fixtures for end-to-end scenarios live under [test/fixtures/bedrock-logging-combos/](test/fixtures/bedrock-logging-combos/) - each subdirectory is a self-contained Terraform configuration that exercises one scenario (e.g. `cross-stack-baseline-logging`, `remote-module-bedrock-logging`, `strict-mode-fail`).
