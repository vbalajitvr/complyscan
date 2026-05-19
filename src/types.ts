export type FindingStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'INCONCLUSIVE';

export interface Finding {
  ruleId: string;
  status: FindingStatus;
  filePath: string;
  line?: number;
  description: string;
  remediation: string;
  regulatoryReference: string;
  nistReference?: string;
  isoReference?: string;
  // Set when an INCONCLUSIVE finding is driven by an unresolvable expression.
  // Carried on the Finding so the strict-mode post-processor in runScan can
  // decide whether the reason is escalatable to FAIL (most are) or genuinely
  // unknowable (plan-known-after-apply, plan-sensitive-redacted).
  unresolvedReason?: UnresolvableReason;
}

export interface ScanRule {
  id: string;
  description: string;
  severity: 'FAIL' | 'WARN';
  regulatoryReference: string;
  nistReference?: string;
  isoReference?: string;
  phase1?: boolean;
  run(files: ParsedFile[], context: ScanContext): Finding[];
}

export type UnresolvableReason =
  | 'var-no-default'
  | 'local-not-literal'
  | 'data-source-ssm'
  | 'data-source-other'
  | 'module-output'
  | 'complex-interpolation'
  | 'unknown-format'
  | 'plan-known-after-apply'
  | 'plan-sensitive-redacted'
  | 'plan-deferred-data-source'
  | 'plan-remote-state-unreachable'
  | 'plan-instances-divergent';

export interface UnresolvedRef {
  expression: string;
  reason: UnresolvableReason;
  sourceField: string;
}

export type ResolutionResult =
  | { kind: 'literal'; value: string }
  | { kind: 'address'; value: string; resourceType: string; resourceName: string }
  | { kind: 'unresolvable'; expression: string; reason: UnresolvableReason; sourceField: string };

export interface PlanResource {
  address: string;
  type: string;
  name: string;
  values: Record<string, unknown>;
  unknownPaths: Set<string>;
  sensitivePaths: Set<string>;
}

export interface PlanDeletion {
  address: string;
  type: string;
  name: string;
  before: Record<string, unknown>;
  replaceWithCreate: boolean;
}

export interface PlanOverlay {
  formatVersion: string;
  terraformVersion: string;
  // First-instance-by-normalised-key (legacy / convenience): one entry per
  // unique "<type>.<name>", losing per-instance detail for count/for_each.
  // Kept for backward-compatibility with callers that only need a summary.
  // For per-instance accuracy, use `instancesByNormalised`.
  resources: Map<string, PlanResource>;
  // All plan instances grouped by normalised "<type>.<name>" key. For a
  // resource with `count = 3`, this list has 3 PlanResource entries with
  // distinct `address` (e.g. `aws_s3_bucket.logs[0]`, `[1]`, `[2]`).
  // `after_unknown` / `after_sensitive` from resource_changes are attached
  // to the matching instance by full address, so unknowns in instance [1]
  // do not bleed into instance [0]'s safety filters.
  instancesByNormalised: Map<string, PlanResource[]>;
  deletions: Map<string, PlanDeletion>;
  flags: { noActionableChanges: boolean };
  variables: Map<string, string | number | boolean>;
  // Scalar outputs from `planned_values.child_modules[].outputs`, keyed by the
  // expression form Terraform uses to reference them: `module.<path>.<name>`,
  // with `[...]` index segments stripped so refs to count/for_each modules
  // resolve regardless of which instance the expression names.
  outputs: Map<string, { value: string | number | boolean; sensitive: boolean }>;
}

export interface ScanContext {
  bedrockLoggingDetected: boolean;
  logBucketNames: string[];
  logGroupNames: string[];
  unresolvedBucketRefs: UnresolvedRef[];
  unresolvedGroupRefs: UnresolvedRef[];
  // When false (default), S-12.1.1 returns INCONCLUSIVE for "Bedrock used but no
  // logging config in scanned files" - most enterprises put the logging config
  // in a separate account-baseline stack and a hard FAIL is wrong. When true,
  // the scanner is told the entire infra estate is in scope and missing logging
  // is a real FAIL.
  strictAccountLogging: boolean;
  // Plan overlay (from `terraform show -json`) used by rules and the resolver
  // to elevate INCONCLUSIVE findings to PASS/FAIL and to surface resources
  // buried inside remote modules. Undefined when --plan was not supplied.
  planOverlay?: PlanOverlay;
}

export interface ParsedFile {
  filePath: string;
  json: HCL2JSONOutput;
  rawHcl: string;
}

export interface HCL2JSONOutput {
  resource?: Record<string, Record<string, Record<string, unknown>[]>>;
  data?: Record<string, Record<string, Record<string, unknown>[]>>;
  variable?: Record<string, Record<string, unknown>[]>;
  locals?: Record<string, unknown>[];
  module?: Record<string, Array<Record<string, unknown>>>;
  [key: string]: unknown;
}
