import { ParsedFile, ScanContext, UnresolvedRef } from './types';
import { findResources, getNestedValue } from './utils/resource-helpers';
import { resolveExpression } from './resolver';

/**
 * Build a ScanContext by extracting log bucket and log group names
 * from aws_bedrock_model_invocation_logging_configuration resources.
 *
 * Resolved refs (literals + addresses) populate logBucketNames / logGroupNames.
 * Unresolvable refs (var-no-default, SSM, module output, complex interpolation, ...)
 * populate unresolvedBucketRefs / unresolvedGroupRefs so dependent rules can emit
 * INCONCLUSIVE findings instead of silently skipping.
 */
export function buildScanContext(files: ParsedFile[]): ScanContext {
  const context: ScanContext = {
    bedrockLoggingDetected: false,
    logBucketNames: [],
    logGroupNames: [],
    unresolvedBucketRefs: [],
    unresolvedGroupRefs: [],
  };

  const loggingConfigs = findResources(files, 'aws_bedrock_model_invocation_logging_configuration');
  if (loggingConfigs.length === 0) return context;

  context.bedrockLoggingDetected = true;

  for (const config of loggingConfigs) {
    extractBucket(config.body, 'logging_config.s3_config.bucket_name', files, context, config.filePath);
    extractGroup(config.body, 'logging_config.cloudwatch_config.log_group_name', files, context, config.filePath);
    extractBucket(
      config.body,
      'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      files,
      context,
      config.filePath,
    );
  }

  context.logBucketNames = [...new Set(context.logBucketNames)];
  context.logGroupNames = [...new Set(context.logGroupNames)];
  context.unresolvedBucketRefs = dedupeUnresolved(context.unresolvedBucketRefs);
  context.unresolvedGroupRefs = dedupeUnresolved(context.unresolvedGroupRefs);

  return context;
}

function extractBucket(
  body: Record<string, unknown>,
  path: string,
  files: ParsedFile[],
  context: ScanContext,
  sourceFilePath?: string,
): void {
  const ref = getNestedValue(body, path);
  if (ref === undefined) return;
  const result = resolveExpression(ref, files, path, sourceFilePath);
  if (!result) return;
  if (result.kind === 'literal' || result.kind === 'address') {
    context.logBucketNames.push(result.value);
  } else {
    context.unresolvedBucketRefs.push({
      expression: result.expression,
      reason: result.reason,
      sourceField: result.sourceField,
    });
  }
}

function extractGroup(
  body: Record<string, unknown>,
  path: string,
  files: ParsedFile[],
  context: ScanContext,
  sourceFilePath?: string,
): void {
  const ref = getNestedValue(body, path);
  if (ref === undefined) return;
  const result = resolveExpression(ref, files, path, sourceFilePath);
  if (!result) return;
  if (result.kind === 'literal' || result.kind === 'address') {
    context.logGroupNames.push(result.value);
  } else {
    context.unresolvedGroupRefs.push({
      expression: result.expression,
      reason: result.reason,
      sourceField: result.sourceField,
    });
  }
}

function dedupeUnresolved(refs: UnresolvedRef[]): UnresolvedRef[] {
  const seen = new Set<string>();
  return refs.filter((r) => {
    const key = `${r.expression}|${r.reason}|${r.sourceField}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
