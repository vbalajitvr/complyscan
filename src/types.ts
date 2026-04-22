export type FindingStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP' | 'INCONCLUSIVE';

export interface Finding {
  ruleId: string;
  status: FindingStatus;
  filePath: string;
  line?: number;
  description: string;
  remediation: string;
  regulatoryReference: string;
}

export interface ScanRule {
  id: string;
  description: string;
  severity: 'FAIL' | 'WARN';
  regulatoryReference: string;
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
  | 'unknown-format';

export interface UnresolvedRef {
  expression: string;
  reason: UnresolvableReason;
  sourceField: string;
}

export type ResolutionResult =
  | { kind: 'literal'; value: string }
  | { kind: 'address'; value: string; resourceType: string; resourceName: string }
  | { kind: 'unresolvable'; expression: string; reason: UnresolvableReason; sourceField: string };

export interface ScanContext {
  bedrockLoggingDetected: boolean;
  logBucketNames: string[];
  logGroupNames: string[];
  unresolvedBucketRefs: UnresolvedRef[];
  unresolvedGroupRefs: UnresolvedRef[];
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
  [key: string]: unknown;
}
