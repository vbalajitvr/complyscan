import { Finding, ParsedFile, UnresolvedRef } from '../types';
import { explainReason, resolveExpression } from '../resolver';

/**
 * Build an INCONCLUSIVE finding for a rule that depends on a Bedrock-logging
 * reference we could not resolve statically (var with no default, SSM, module
 * output, etc.). Used to make the scanner honest when source-only scanning
 * cannot verify the check — instead of silently SKIP-ing.
 */
export function inconclusiveFromUnresolved(
  ruleId: string,
  regulatoryReference: string,
  ref: UnresolvedRef,
  scope: 'bucket' | 'log group',
): Finding {
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `Cannot verify ${ruleId} for ${scope} reference \`${ref.expression}\` (at ${ref.sourceField}): ${explainReason(ref.reason)}`,
    remediation:
      'Either reference the resource via `aws_s3_bucket.<name>.id` / `aws_cloudwatch_log_group.<name>.name` so static scanning can follow it, or run complyscan against `terraform show -json plan.json` for full apply-time resolution.',
    regulatoryReference,
  };
}

/**
 * Find all resources of a given type across all parsed files.
 * Returns an array of { name, body, filePath, rawHcl }.
 */
export function findResources(
  files: ParsedFile[],
  resourceType: string
): Array<{ name: string; body: Record<string, unknown>; filePath: string; rawHcl: string }> {
  const results: Array<{ name: string; body: Record<string, unknown>; filePath: string; rawHcl: string }> = [];

  for (const file of files) {
    const typeBlock = file.json.resource?.[resourceType];
    if (!typeBlock) continue;

    for (const [name, bodies] of Object.entries(typeBlock)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      results.push({
        name,
        body: body as Record<string, unknown>,
        filePath: file.filePath,
        rawHcl: file.rawHcl,
      });
    }
  }

  return results;
}

/**
 * Get a nested value from an HCL2JSON object, auto-unwrapping single-element arrays.
 * Path is dot-separated: "logging_config.s3_config.bucket_name"
 */
export function getNestedValue(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) return undefined;

    // Auto-unwrap single-element arrays
    if (Array.isArray(current) && current.length === 1) {
      current = current[0];
    }

    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  // Final unwrap
  if (Array.isArray(current) && current.length === 1) {
    current = current[0];
  }

  return current;
}

/**
 * Check if a resource's bucket attribute matches one of the target bucket names.
 *
 * Targets may be:
 *   - A literal bucket name:                "my-log-bucket"
 *   - A fully-qualified resource address:   "aws_s3_bucket.logs"
 *     (used when the actual name contains unresolvable interpolations)
 *
 * If files are provided, also attempts to resolve variable/local references
 * in the bucket attribute (e.g., ${var.log_bucket}).
 */
export function matchesBucket(
  body: Record<string, unknown>,
  resourceName: string,
  targetBucketNames: string[],
  files?: ParsedFile[]
): boolean {
  if (targetBucketNames.length === 0) return false;

  const bucket = getNestedValue(body, 'bucket');

  // Check the "bucket" attribute directly (literal name match)
  if (typeof bucket === 'string' && targetBucketNames.includes(bucket)) {
    return true;
  }

  // Check if the resource name itself matches any target literal
  if (targetBucketNames.includes(resourceName)) {
    return true;
  }

  // Check against fully-qualified address targets: "aws_s3_bucket.<resourceName>"
  if (targetBucketNames.includes(`aws_s3_bucket.${resourceName}`)) {
    return true;
  }

  // Check if the bucket attribute is a reference (e.g. "${aws_s3_bucket.logs.id}")
  // and one of the targets is that resource's address
  if (typeof bucket === 'string') {
    const refMatch = bucket.match(
      /^\$\{(aws_s3_bucket\.[a-z0-9_]+)\.[^}]+\}$|^(aws_s3_bucket\.[a-z0-9_]+)\.[a-z0-9_]+$/
    );
    if (refMatch) {
      const resourceAddr = refMatch[1] ?? refMatch[2];
      if (targetBucketNames.includes(resourceAddr)) return true;
    }
  }

  // If files provided, try resolving variable/local references
  if (files && typeof bucket === 'string') {
    const result = resolveExpression(bucket, files);
    if (result?.kind === 'literal' && targetBucketNames.includes(result.value)) {
      return true;
    }
    if (result?.kind === 'address' && targetBucketNames.includes(result.value)) {
      return true;
    }
  }

  return false;
}

/**
 * Find the approximate line number of a resource definition in raw HCL.
 */
export function findResourceLine(rawHcl: string, resourceType: string, resourceName: string): number | undefined {
  const pattern = new RegExp(
    `^\\s*resource\\s+"${escapeRegex(resourceType)}"\\s+"${escapeRegex(resourceName)}"`,
    'm'
  );
  const match = rawHcl.match(pattern);
  if (!match || match.index === undefined) return undefined;

  const lineNumber = rawHcl.substring(0, match.index).split('\n').length;
  return lineNumber;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
