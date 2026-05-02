import * as path from 'path';
import { ParsedFile, ResolutionResult, UnresolvableReason } from './types';
import { getNestedValue } from './utils/resource-helpers';

const INTERP = /^\$\{([^}]+)\}$/;
const AWS_RES_REF = /^(aws_[a-z0-9_]+)\.([a-z0-9_]+)\.([\w]+)$/;
const VAR_REF = /^var\.([a-z0-9_]+)$/i;
const LOCAL_REF = /^local\.([a-z0-9_]+)$/i;
const DATA_REF = /^data\.([a-z0-9_]+)\.([a-z0-9_]+)\.(\w+)$/i;
const MODULE_REF = /^module\.([a-z0-9_]+)\.(\w+)$/i;

/**
 * Resolve a Terraform expression into one of three outcomes:
 *   - literal:      a concrete string value we can compare against
 *   - address:      a resource address (used when the literal name uses interpolation)
 *   - unresolvable: needs runtime data (var with no default, SSM, module output, etc.)
 *
 * Returns undefined only when expr is not a string.
 */
export function resolveExpression(
  expr: unknown,
  files: ParsedFile[],
  sourceField = 'unknown',
  sourceFilePath?: string,
): ResolutionResult | undefined {
  if (typeof expr !== 'string') return undefined;

  // Pure literal - no interpolation, no bare ref syntax
  if (!expr.includes('${') && !looksLikeBareRef(expr)) {
    return { kind: 'literal', value: expr };
  }

  // Composite interpolation like "logs-${var.env}" or "${var.a}-${var.b}"
  const interpMatch = expr.match(INTERP);
  if (!interpMatch && expr.includes('${')) {
    return { kind: 'unresolvable', expression: expr, reason: 'complex-interpolation', sourceField };
  }

  const inner = interpMatch ? interpMatch[1] : expr;

  // aws_<type>.<name>.<attr>
  const awsMatch = inner.match(AWS_RES_REF);
  if (awsMatch) {
    const [, resourceType, resourceName, attribute] = awsMatch;
    return resolveAwsRef(resourceType, resourceName, attribute, files);
  }

  // var.X - resolve via variable default if present, scoped to the origin module directory
  const varMatch = inner.match(VAR_REF);
  if (varMatch) {
    const value = resolveVariableDefault(varMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return { kind: 'unresolvable', expression: expr, reason: 'var-no-default', sourceField };
  }

  // local.X - resolve via locals block if value is a literal, scoped to the origin module directory
  const localMatch = inner.match(LOCAL_REF);
  if (localMatch) {
    const value = resolveLocal(localMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return { kind: 'unresolvable', expression: expr, reason: 'local-not-literal', sourceField };
  }

  // data.<type>.<name>.<attr> - runtime-only
  const dataMatch = inner.match(DATA_REF);
  if (dataMatch) {
    const reason: UnresolvableReason =
      dataMatch[1] === 'aws_ssm_parameter' ? 'data-source-ssm' : 'data-source-other';
    return { kind: 'unresolvable', expression: expr, reason, sourceField };
  }

  // module.<name>.<output>
  if (MODULE_REF.test(inner)) {
    return { kind: 'unresolvable', expression: expr, reason: 'module-output', sourceField };
  }

  return { kind: 'unresolvable', expression: expr, reason: 'unknown-format', sourceField };
}

function looksLikeBareRef(s: string): boolean {
  return AWS_RES_REF.test(s) || /^(var|local|data|module)\./.test(s);
}

function resolveAwsRef(
  resourceType: string,
  resourceName: string,
  attribute: string,
  files: ParsedFile[],
): ResolutionResult {
  for (const file of files) {
    const typeBlock = file.json.resource?.[resourceType];
    if (!typeBlock) continue;
    const bodies = typeBlock[resourceName];
    if (!bodies) continue;
    const body = Array.isArray(bodies) ? bodies[0] : bodies;

    if (resourceType === 'aws_s3_bucket' && (attribute === 'id' || attribute === 'arn' || attribute === 'bucket')) {
      const bucketName = getNestedValue(body, 'bucket');
      if (typeof bucketName === 'string' && !bucketName.includes('${')) {
        return { kind: 'literal', value: bucketName };
      }
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }

    if (resourceType === 'aws_cloudwatch_log_group' && (attribute === 'name' || attribute === 'id' || attribute === 'arn')) {
      const name = getNestedValue(body, 'name');
      if (typeof name === 'string' && !name.includes('${')) {
        return { kind: 'literal', value: name };
      }
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }

    const value = getNestedValue(body, attribute);
    if (typeof value === 'string') {
      if (!value.includes('${')) return { kind: 'literal', value };
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }
  }

  // Resource not present in scanned files - still return its address so downstream
  // matching by address can succeed if the resource is defined elsewhere.
  return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
}

function resolveVariableDefault(
  name: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | undefined {
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const variables = file.json.variable;
    if (!variables) continue;
    const block = variables[name];
    if (!block) continue;
    const body = Array.isArray(block) ? block[0] : block;
    const def = (body as Record<string, unknown> | undefined)?.default;
    if (typeof def === 'string' && !def.includes('${')) return def;
  }
  return undefined;
}

function resolveLocal(
  name: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | undefined {
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const localsBlocks = file.json.locals;
    if (!Array.isArray(localsBlocks)) continue;
    for (const block of localsBlocks) {
      if (typeof block !== 'object' || block === null) continue;
      const value = (block as Record<string, unknown>)[name];
      if (typeof value === 'string' && !value.includes('${')) return value;
    }
  }
  return undefined;
}

/**
 * Human-readable explanation for an UnresolvableReason. Used in finding messages.
 */
export function explainReason(reason: UnresolvableReason): string {
  switch (reason) {
    case 'var-no-default':
      return 'Terraform variable has no static default - value is supplied at apply time.';
    case 'local-not-literal':
      return 'local value is not a static string literal.';
    case 'data-source-ssm':
      return 'value is fetched from AWS SSM Parameter Store at apply time.';
    case 'data-source-other':
      return 'value is fetched from a Terraform data source at apply time.';
    case 'module-output':
      return 'value comes from a module output and is not visible to source-level scanning.';
    case 'complex-interpolation':
      return 'expression combines multiple references - cannot determine final value statically.';
    case 'unknown-format':
      return 'expression is not in a recognized Terraform reference form.';
  }
}
