import { ParsedFile, ScanContext, HCL2JSONOutput, PlanOverlay } from '../../../src/types';

/**
 * Build a minimal PlanOverlay for tests that only need the overlay to be
 * "present" (e.g. to suppress remote-module INCONCLUSIVEs). The overlay
 * contains no resources, deletions, or variables - rules that read those
 * collections will see them as empty.
 */
export function emptyPlanOverlay(): PlanOverlay {
  return {
    formatVersion: '1.2',
    terraformVersion: '1.7.5',
    resources: new Map(),
    deletions: new Map(),
    flags: { noActionableChanges: false },
    variables: new Map(),
    outputs: new Map(),
  };
}

/**
 * Create a ParsedFile from a plain resource object for testing.
 */
export function makeParsedFile(
  resources: Record<string, Record<string, Record<string, unknown>[]>>,
  filePath = 'test.tf',
  rawHcl = ''
): ParsedFile {
  const json: HCL2JSONOutput = { resource: resources };
  return { filePath, json, rawHcl };
}

export function emptyContext(opts?: {
  strictAccountLogging?: boolean;
  planOverlay?: PlanOverlay;
}): ScanContext {
  return {
    bedrockLoggingDetected: false,
    logBucketNames: [],
    logGroupNames: [],
    unresolvedBucketRefs: [],
    unresolvedGroupRefs: [],
    strictAccountLogging: opts?.strictAccountLogging ?? false,
    planOverlay: opts?.planOverlay,
  };
}

export function bedrockContext(opts?: {
  bucketNames?: string[];
  groupNames?: string[];
  unresolvedBucketRefs?: ScanContext['unresolvedBucketRefs'];
  unresolvedGroupRefs?: ScanContext['unresolvedGroupRefs'];
  strictAccountLogging?: boolean;
  planOverlay?: PlanOverlay;
}): ScanContext {
  return {
    bedrockLoggingDetected: true,
    logBucketNames: opts?.bucketNames ?? ['my-ai-log-bucket'],
    logGroupNames: opts?.groupNames ?? ['/aws/bedrock/invocation-logs'],
    unresolvedBucketRefs: opts?.unresolvedBucketRefs ?? [],
    unresolvedGroupRefs: opts?.unresolvedGroupRefs ?? [],
    strictAccountLogging: opts?.strictAccountLogging ?? false,
    planOverlay: opts?.planOverlay,
  };
}
