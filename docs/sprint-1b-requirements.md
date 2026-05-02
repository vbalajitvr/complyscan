# Sprint 1B — Plan/State JSON Scanning

**Parent:** Sprint 1A (source HCL scanning — unchanged, kept as-is)

**Sprint scope:** Add `--plan` mode that accepts `terraform show -json` output as input. Source scanning remains the default. Plan scanning is the audit-grade path that eliminates INCONCLUSIVE.

---

## What Sprint 1B Is NOT

- Does not remove Sprint 1A source scanning
- Does not change any of the 6 rule modules
- Does not change output formats
- Does not add new compliance checks (those are Sprint 1C+)
- Does not add CDK or CloudFormation support

---

## FR-4: Plan/State JSON Input Mode

### FR-4.1 — CLI Flag

```bash
# Sprint 1A (unchanged)
infrarails <directory> [--format terminal|json]

# Sprint 1B (new, additive)
infrarails --plan <file>          # from file
infrarails --plan -               # from stdin
infrarails --plan <file> [--format terminal|json] [--mode pre|post]
```

`--mode pre` (default): input is `terraform show -json plan.tfplan`. Labels output as pre-deployment gate.

`--mode post`: input is `terraform show -json` (state, no plan file). Labels output as post-deployment audit evidence.

Exit codes unchanged from Sprint 1A:
- `0` — no FAIL or WARN
- `1` — any FAIL or WARN
- `2` — tool error (malformed JSON, unrecognised format, file not found)

---

### FR-4.2 — Supported Input Formats

**Format A — Plan JSON** (`terraform show -json plan.tfplan`)

```json
{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [ ... ],
      "child_modules": [ ... ]
    }
  }
}
```

**Format B — State JSON** (`terraform show -json`)

```json
{
  "format_version": "0.2",
  "values": {
    "root_module": {
      "resources": [ ... ],
      "child_modules": [ ... ]
    }
  }
}
```

Auto-detection: if `planned_values` exists at root → plan mode. If `values` exists → state mode. If neither → exit 2 with clear error.

---

### FR-4.3 — Resource Structure

Each resource in `resources[]`:

```json
{
  "address": "aws_s3_bucket.logs",
  "mode": "managed",
  "type": "aws_s3_bucket",
  "name": "logs",
  "values": {
    "bucket": "prod-ai-audit-logs-eu-west-1"
  },
  "sensitive_values": {
    "bucket": false
  }
}
```

Module-nested resource:

```json
{
  "address": "module.logging.aws_s3_bucket.logs",
  "mode": "managed",
  "type": "aws_s3_bucket",
  "name": "logs",
  "values": { ... },
  "sensitive_values": { ... }
}
```

Only `mode: "managed"` resources are scanned. `mode: "data"` resources are skipped.

---

### FR-4.4 — Parser Requirements

**Recursive module traversal**

Traverse `root_module.resources[]` then recurse into `root_module.child_modules[]`. `child_modules` can nest arbitrarily. Every managed resource at any depth is included.

**Internal type:**

```typescript
export interface PlanResource {
  address: string;          // "aws_s3_bucket.logs" or "module.x.aws_s3_bucket.logs"
  type: string;             // "aws_s3_bucket"
  name: string;             // "logs"
  moduleAddress?: string;   // "module.logging" or undefined for root
  values: Record<string, unknown>;
  sensitiveValues: Record<string, unknown>;
}
```

**Sensitive value detection**

A field is sensitive if:
1. Its value in `values` is the literal string `"(sensitive value)"`, OR
2. The corresponding path in `sensitive_values` is `true`

**Error handling:**

| Condition | Behaviour |
|---|---|
| File not found | Exit 2 with clear message |
| Not valid JSON | Exit 2 with parse error |
| Neither `planned_values` nor `values` at root | Exit 2 with format error |
| Empty resource list | Continue — rules produce WARN/FAIL naturally |
| `format_version` not recognised | Log warning, continue (forward-compatible) |

---

### FR-4.5 — Sensitive Value Handling

The only legitimate INCONCLUSIVE case in plan mode. When Terraform has redacted a value (e.g. a bucket name marked `sensitive = true`):

- Do NOT add to `logBucketNames` / `logGroupNames`
- Add to `sensitiveBucketRefs` / `sensitiveGroupRefs` on ScanContext
- Dependent rules emit INCONCLUSIVE with reason `sensitive-value` and message:
  *"Bucket name at `logging_config.s3_config.bucket_name` is marked sensitive in the Terraform plan. Cannot verify bucket-level checks statically. Inspect the deployed bucket directly in AWS."*

In practice bucket names are almost never marked sensitive. This case is documented, not a design gap.

---

## Updated ScanContext (Plan Mode)

```typescript
export interface ScanContext {
  bedrockLoggingDetected: boolean;
  logBucketNames: string[];
  logGroupNames: string[];

  // Sprint 1A fields (source mode only)
  unresolvedBucketRefs: UnresolvedRef[];
  unresolvedGroupRefs: UnresolvedRef[];

  // Sprint 1B fields (plan mode only)
  sensitiveBucketRefs: Array<{ address: string; field: string }>;
  sensitiveGroupRefs: Array<{ address: string; field: string }>;
}
```

---

## Log Bucket Identification — Plan Mode

Same algorithm as Sprint 1A `buildScanContext`, now reading `values` directly. No resolver needed — plan JSON gives resolved literals.

1. Find all `aws_bedrock_model_invocation_logging_configuration` resources in `PlanResource[]`
2. Read `values.logging_config[0].s3_config[0].bucket_name` → `logBucketNames`
3. Read `values.logging_config[0].cloudwatch_config[0].log_group_name` → `logGroupNames`
4. Read `values.logging_config[0].cloudwatch_config[0].large_data_delivery_s3_config[0].bucket_name` → `logBucketNames`
5. If any field is `"(sensitive value)"` → `sensitiveBucketRefs` or `sensitiveGroupRefs`
6. Deduplicate both lists

All 5 delivery combos handled identically to Sprint 1A — same paths, same logic, no special casing.

| Combo | s3_config | cloudwatch_config | large_data_delivery_s3_config | Result |
|---|---|---|---|---|
| S3 only | ✅ | — | — | 1 bucket |
| CW only | — | ✅ | — | 1 log group |
| CW + S3 | ✅ | ✅ | — | 1 bucket + 1 log group |
| CW + large-data | — | ✅ | ✅ | 1 log group + 1 bucket (large-data) |
| CW + S3 + large-data | ✅ | ✅ | ✅ | 2 buckets + 1 log group |

---

## Rule Interface — Plan Mode

Rules are called with `PlanResource[]` instead of `ParsedFile[]`. The `ScanRule` interface gains an optional `runPlan` method:

```typescript
export interface ScanRule {
  id: string;
  description: string;
  severity: 'FAIL' | 'WARN';
  regulatoryReference: string;
  phase1?: boolean;

  // Sprint 1A: source mode
  run(files: ParsedFile[], context: ScanContext): Finding[];

  // Sprint 1B: plan mode (optional)
  runPlan?(resources: PlanResource[], context: ScanContext): Finding[];
}
```

`findPlanResources(resources, type)` replaces `findResources(files, type)` in plan mode:

```typescript
export function findPlanResources(
  resources: PlanResource[],
  resourceType: string,
): PlanResource[];
// Implementation: resources.filter(r => r.type === resourceType)
```

The `body` of each found resource is `resource.values`. The `filePath` in findings is `resource.address`.

---

## `matchesBucket` — Plan Mode

In plan mode bucket names are always resolved literals. Matching is a direct equality check:

```typescript
function matchesBucketPlan(
  values: Record<string, unknown>,
  targetBucketNames: string[],
): boolean {
  const bucket = getNestedValue(values, 'bucket');
  return typeof bucket === 'string' && targetBucketNames.includes(bucket);
}
```

No reference resolution. No address matching. No files parameter.

---

## Runner Changes

```typescript
export function runScan(files: ParsedFile[]): Finding[];            // Sprint 1A unchanged
export function runPlanScan(resources: PlanResource[]): Finding[];  // Sprint 1B new
```

`runPlanScan` mirrors `runScan`:
1. Phase 1: run `phase1` rules via `runPlan()` with empty context → detect Bedrock logging
2. Build `ScanContext` via `buildPlanScanContext(resources)`
3. Phase 2: run remaining rules via `runPlan()` with populated context
4. Return all findings

---

## Output Changes

### Terminal — new header line in plan mode

```
infrarails — EU AI Act Article 12 Compliance Scan
Mode: pre-deployment  |  Source: plan.json
──────────────────────────────────────────────────

✓ [PASS] S-12.1.1 Bedrock invocation logging is configured (main).
  aws_bedrock_model_invocation_logging_configuration.main

✗ [FAIL] S-12.x.4 No aws_cloudtrail resource found.
  Remediation: Add an aws_cloudtrail resource with enable_logging = true.

────────────────────────────────────────────────────────
Summary: 6 checks | 1 FAIL | 0 WARN | 4 PASS | 0 SKIP | 0 INCONCLUSIVE
```

### JSON — new `metadata` block

```json
{
  "metadata": {
    "scanMode": "plan",
    "planMode": "pre",
    "source": "plan.json",
    "generatedAt": "2026-04-22T11:00:00Z"
  },
  "summary": {
    "total": 6,
    "pass": 4,
    "fail": 1,
    "warn": 0,
    "skip": 1,
    "inconclusive": 0
  },
  "findings": [ ... ]
}
```

Source scan JSON (`infrarails <dir>`) adds `"scanMode": "source"` and omits `planMode`.

---

## File Structure — New Files Only

```
src/
  plan-parser.ts         ← NEW: parses plan/state JSON → PlanResource[]
  plan-context.ts        ← NEW: buildPlanScanContext(resources) → ScanContext
  plan-runner.ts         ← NEW: runPlanScan(resources) → Finding[]

test/
  unit/
    plan-parser.test.ts  ← NEW
    plan-context.test.ts ← NEW
    plan-runner.test.ts  ← NEW
  fixtures/
    plan-json/
      compliant.json
      non-compliant.json
      partial.json
      sensitive-value.json
      no-bedrock.json
      combos/
        s3-only.json
        cw-only.json
        cw-and-s3.json
        cw-large-data.json
        cw-s3-large-data.json
  e2e/
    cli-plan.test.ts     ← NEW (separate from existing cli.test.ts)
```

Existing Sprint 1A files are untouched.

---

## Plan JSON Fixture Shape

All fixtures use real `terraform show -json` output structure. Example `compliant.json`:

```json
{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_bedrock_model_invocation_logging_configuration.main",
          "mode": "managed",
          "type": "aws_bedrock_model_invocation_logging_configuration",
          "name": "main",
          "values": {
            "logging_config": [{
              "embedding_data_delivery_enabled": true,
              "text_data_delivery_enabled": true,
              "s3_config": [{ "bucket_name": "prod-ai-audit-logs", "key_prefix": "bedrock/" }],
              "cloudwatch_config": [{
                "log_group_name": "/aws/bedrock/prod",
                "role_arn": "arn:aws:iam::123456789012:role/bedrock-cw-role",
                "large_data_delivery_s3_config": []
              }]
            }]
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_s3_bucket_lifecycle_configuration.logs",
          "mode": "managed",
          "type": "aws_s3_bucket_lifecycle_configuration",
          "name": "logs",
          "values": {
            "bucket": "prod-ai-audit-logs",
            "rule": [{ "id": "retain", "status": "Enabled", "expiration": [{ "days": 365 }] }]
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_s3_bucket_versioning.logs",
          "mode": "managed",
          "type": "aws_s3_bucket_versioning",
          "name": "logs",
          "values": {
            "bucket": "prod-ai-audit-logs",
            "versioning_configuration": [{ "status": "Enabled" }]
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_s3_bucket_server_side_encryption_configuration.logs",
          "mode": "managed",
          "type": "aws_s3_bucket_server_side_encryption_configuration",
          "name": "logs",
          "values": {
            "bucket": "prod-ai-audit-logs",
            "rule": [{
              "apply_server_side_encryption_by_default": [{ "sse_algorithm": "aws:kms" }]
            }]
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_cloudwatch_log_group.bedrock_logs",
          "mode": "managed",
          "type": "aws_cloudwatch_log_group",
          "name": "bedrock_logs",
          "values": {
            "name": "/aws/bedrock/prod",
            "retention_in_days": 365
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_cloudtrail.main",
          "mode": "managed",
          "type": "aws_cloudtrail",
          "name": "main",
          "values": {
            "name": "ai-audit-trail",
            "s3_bucket_name": "prod-ai-audit-logs",
            "enable_logging": true,
            "is_multi_region_trail": true,
            "include_global_service_events": true
          },
          "sensitive_values": {}
        }
      ],
      "child_modules": []
    }
  }
}
```

---

## Workflow Integration

**Pre-deployment CI gate:**

```bash
# Step 1 — needs AWS credentials (existing CI step)
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json

# Step 2 — no credentials needed
infrarails --plan plan.json --format json
```

**Post-deployment audit (scheduled, e.g. nightly):**

```bash
terraform show -json > state.json
infrarails --plan state.json --mode post --format json
# Store output as compliance artefact
```

**Local developer workflow:**

```bash
# Already running plan anyway before applying
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan | infrarails --plan -
```

---

## Open Questions

| Question | Decision needed |
|---|---|
| Should `runPlan` be optional or mandatory on `ScanRule`? | Optional preserves backward compat. Mandatory forces completeness. |
| Should `--plan` mode support `--format markdown` and `--format sarif`? | Defer to Sprint 1C or include now? |
| Should `metadata.source` include full path or filename only? | Filename only recommended (avoid leaking paths in audit reports) |
| Should `--mode post` warn explicitly that it detects config drift, not runtime compliance? | Yes — add note in terminal output and JSON metadata |
| Should the `compliant.json` fixture also cover the module-nested resource case? | Recommended — add `child_modules` variant fixture |

---

## Connections

- Previous sprint: Sprint 1A — source HCL scanning (unchanged)
- Next sprint: Sprint 1C — CDK + CloudFormation checks + remaining FR-2 checks
- Parent spec: article-12-source-scanner-requirements
