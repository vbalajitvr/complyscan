import { ParsedFile, ScanContext, HCL2JSONOutput } from '../../../src/types';

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

export function emptyContext(opts?: { strictAccountLogging?: boolean }): ScanContext {
  return {
    bedrockLoggingDetected: false,
    logBucketNames: [],
    logGroupNames: [],
    unresolvedBucketRefs: [],
    unresolvedGroupRefs: [],
    strictAccountLogging: opts?.strictAccountLogging ?? false,
  };
}

export function bedrockContext(opts?: {
  bucketNames?: string[];
  groupNames?: string[];
  unresolvedBucketRefs?: ScanContext['unresolvedBucketRefs'];
  unresolvedGroupRefs?: ScanContext['unresolvedGroupRefs'];
  strictAccountLogging?: boolean;
}): ScanContext {
  return {
    bedrockLoggingDetected: true,
    logBucketNames: opts?.bucketNames ?? ['my-ai-log-bucket'],
    logGroupNames: opts?.groupNames ?? ['/aws/bedrock/invocation-logs'],
    unresolvedBucketRefs: opts?.unresolvedBucketRefs ?? [],
    unresolvedGroupRefs: opts?.unresolvedGroupRefs ?? [],
    strictAccountLogging: opts?.strictAccountLogging ?? false,
  };
}
