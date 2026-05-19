import * as fs from 'fs';
import { PlanOverlay, PlanResource, PlanDeletion } from './types';

/**
 * Parse a `terraform show -json plan.bin` JSON document into a PlanOverlay.
 *
 * Three plan blocks drive the overlay:
 *   - planned_values:  resolved attribute values keyed by normalised address
 *   - resource_changes: actions (delete/replace), after_unknown, after_sensitive
 *   - variables:        root-module variable values (resolves `var.X`)
 *
 * Throws on malformed JSON, missing format_version, unsupported major versions,
 * or plans marked `errored: true`. CLI converts these into exit-code-2 errors.
 */
export function parsePlanFile(filePath: string): PlanOverlay {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    throw new Error(
      `Plan file not found or unreadable: ${filePath}` +
        (err instanceof Error ? ` (${err.message})` : ''),
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `Plan file is not valid JSON: ${filePath}` +
        (err instanceof Error ? ` (${err.message})` : ''),
    );
  }

  return parsePlanObject(parsed);
}

/**
 * Parse a pre-loaded plan JSON object. Exposed for tests that do not want to
 * touch the filesystem.
 */
export function parsePlanObject(parsed: unknown): PlanOverlay {
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('Plan JSON top level is not an object.');
  }
  const plan = parsed as Record<string, unknown>;

  const formatVersion = plan.format_version;
  if (typeof formatVersion !== 'string') {
    throw new Error(
      'Plan JSON missing "format_version" - this does not look like `terraform show -json` output.',
    );
  }
  const major = formatVersion.split('.')[0];
  if (major !== '1') {
    throw new Error(
      `Unsupported plan format v${formatVersion}; expected 1.x. ` +
        `Regenerate with a Terraform version that emits format_version 1.x.`,
    );
  }

  if (plan.errored === true) {
    throw new Error(
      'Plan is in an errored state; regenerate via `terraform plan -out=tfplan.bin` and retry.',
    );
  }

  const terraformVersion =
    typeof plan.terraform_version === 'string' ? plan.terraform_version : 'unknown';

  const resources = new Map<string, PlanResource>();
  const instancesByNormalised = new Map<string, PlanResource[]>();
  const deletions = new Map<string, PlanDeletion>();
  const variables = new Map<string, string | number | boolean>();
  const outputs = new Map<string, { value: string | number | boolean; sensitive: boolean }>();

  // 1. variables (root) - flatten object/list values into dotted/indexed keys
  // so that `var.config.bucket_name` and `var.zones[0]` resolve. Without
  // flattening, the common "config object" pattern (one variable bundling many
  // settings) leaves every reference unresolvable → INCONCLUSIVE.
  const varsBlock = plan.variables;
  if (varsBlock && typeof varsBlock === 'object') {
    for (const [name, entry] of Object.entries(varsBlock as Record<string, unknown>)) {
      if (entry && typeof entry === 'object') {
        const value = (entry as Record<string, unknown>).value;
        flattenVariableValue(value, name, variables);
      }
    }
  }

  // 2. planned_values - walk root + child_modules recursively for resources.
  const plannedValues = plan.planned_values;
  if (plannedValues && typeof plannedValues === 'object') {
    const rootModule = (plannedValues as Record<string, unknown>).root_module;
    if (rootModule && typeof rootModule === 'object') {
      walkModule(
        rootModule as Record<string, unknown>,
        resources,
        instancesByNormalised,
        outputs,
      );
    }
  }

  // 3. resource_changes - layer on unknownPaths/sensitivePaths, populate deletions
  const resourceChanges = plan.resource_changes;
  if (Array.isArray(resourceChanges)) {
    for (const rc of resourceChanges) {
      if (!rc || typeof rc !== 'object') continue;
      const change = (rc as Record<string, unknown>).change;
      if (!change || typeof change !== 'object') continue;
      const actions = (change as Record<string, unknown>).actions;
      if (!Array.isArray(actions)) continue;

      const address = stringOr((rc as Record<string, unknown>).address, '');
      const type = stringOr((rc as Record<string, unknown>).type, '');
      const name = stringOr((rc as Record<string, unknown>).name, '');
      if (!address || !type || !name) continue;
      const key = normaliseAddress(address);

      const hasDelete = actions.includes('delete');
      const hasCreate = actions.includes('create');

      // Deletion (or replacement) -> populate deletions map from `before`
      if (hasDelete) {
        const before = (change as Record<string, unknown>).before;
        const beforeValues: Record<string, unknown> =
          before && typeof before === 'object' ? (before as Record<string, unknown>) : {};
        deletions.set(key, {
          address,
          type,
          name,
          before: beforeValues,
          replaceWithCreate: hasCreate,
        });
      }

      // Attach unknown/sensitive paths to the *exact* planned instance by
      // matching the full address. For count/for_each, instance [1]'s unknowns
      // must not bleed into instance [0]'s safety filters - that would falsely
      // mark [0] as known-after-apply when only [1] is.
      const afterUnknown = (change as Record<string, unknown>).after_unknown;
      const afterSensitive = (change as Record<string, unknown>).after_sensitive;
      const instances = instancesByNormalised.get(key) ?? [];
      const exact = instances.find((i) => i.address === address);
      if (exact) {
        flattenTruePaths(afterUnknown, '', exact.unknownPaths);
        flattenTruePaths(afterSensitive, '', exact.sensitivePaths);
      }
    }
  }

  // No-actionable-changes heuristic: no create/update/delete anywhere in
  // resource_changes. Covers both `-refresh-only` plans and plans where current
  // state already matches config. CLI surfaces a warning when set.
  let noActionableChanges = false;
  if (Array.isArray(resourceChanges) && resourceChanges.length > 0) {
    let anyActioned = false;
    for (const rc of resourceChanges) {
      const change = (rc as Record<string, unknown> | null)?.change;
      const actions = change && typeof change === 'object'
        ? (change as Record<string, unknown>).actions
        : undefined;
      if (Array.isArray(actions)) {
        for (const a of actions) {
          if (a === 'create' || a === 'update' || a === 'delete') {
            anyActioned = true;
            break;
          }
        }
      }
      if (anyActioned) break;
    }
    noActionableChanges = !anyActioned;
  }

  return {
    formatVersion,
    terraformVersion,
    resources,
    instancesByNormalised,
    deletions,
    flags: { noActionableChanges },
    variables,
    outputs,
  };
}

function walkModule(
  module: Record<string, unknown>,
  resources: Map<string, PlanResource>,
  instancesByNormalised: Map<string, PlanResource[]>,
  outputs: Map<string, { value: string | number | boolean; sensitive: boolean }>,
): void {
  const moduleResources = module.resources;
  if (Array.isArray(moduleResources)) {
    for (const r of moduleResources) {
      if (!r || typeof r !== 'object') continue;
      const rec = r as Record<string, unknown>;
      const address = stringOr(rec.address, '');
      const type = stringOr(rec.type, '');
      const name = stringOr(rec.name, '');
      if (!address || !type || !name) continue;
      const values =
        rec.values && typeof rec.values === 'object'
          ? (rec.values as Record<string, unknown>)
          : {};
      const key = normaliseAddress(address);
      const instance: PlanResource = {
        address,
        type,
        name,
        values,
        unknownPaths: new Set<string>(),
        sensitivePaths: new Set<string>(),
      };
      // instancesByNormalised: every instance, keyed by collapsed name.
      let bucket = instancesByNormalised.get(key);
      if (!bucket) {
        bucket = [];
        instancesByNormalised.set(key, bucket);
      }
      bucket.push(instance);
      // resources (legacy summary): first-write-wins per normalised name.
      if (!resources.has(key)) {
        resources.set(key, instance);
      }
    }
  }
  const childModules = module.child_modules;
  if (Array.isArray(childModules)) {
    for (const child of childModules) {
      if (!child || typeof child !== 'object') continue;
      const childRec = child as Record<string, unknown>;
      const modAddress = stringOr(childRec.address, '');
      const normalisedMod = modAddress.replace(/\[[^\]]*\]/g, '');
      const childOutputs = childRec.outputs;
      if (
        normalisedMod &&
        childOutputs &&
        typeof childOutputs === 'object' &&
        !Array.isArray(childOutputs)
      ) {
        for (const [name, entry] of Object.entries(
          childOutputs as Record<string, unknown>,
        )) {
          if (!entry || typeof entry !== 'object') continue;
          const v = (entry as Record<string, unknown>).value;
          const sensitive = (entry as Record<string, unknown>).sensitive === true;
          if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') {
            // First write wins: matches the `resources` convention so a module
            // with count/for_each picks the first instance's output value.
            const key = `${normalisedMod}.${name}`;
            if (!outputs.has(key)) {
              outputs.set(key, { value: v, sensitive });
            }
          }
        }
      }
      walkModule(childRec, resources, instancesByNormalised, outputs);
    }
  }
}

/**
 * Normalise a Terraform plan address by stripping `[...]` indexing segments.
 *   "aws_s3_bucket.logs[0]"             -> "aws_s3_bucket.logs"
 *   "aws_s3_bucket.logs[\"prod\"]"      -> "aws_s3_bucket.logs"
 *   "module.foo[0].aws_s3_bucket.logs"  -> "module.foo.aws_s3_bucket.logs"
 *
 * We also strip the leading `module.<name>.` prefix(es) so module-buried
 * resources are looked up by their plain `<type>.<name>` form when rules
 * scan by type. The full address survives on PlanResource.address for
 * citation in findings.
 */
export function normaliseAddress(address: string): string {
  // Strip all bracketed indices.
  const noIdx = address.replace(/\[[^\]]*\]/g, '');
  // Strip module prefixes: "module.foo.module.bar.aws_X.y" -> "aws_X.y"
  const parts = noIdx.split('.');
  while (parts.length >= 2 && parts[0] === 'module') {
    parts.splice(0, 2);
  }
  return parts.join('.');
}

function flattenTruePaths(value: unknown, prefix: string, out: Set<string>): void {
  if (value === true) {
    if (prefix) out.add(prefix);
    return;
  }
  if (value === false || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    // Per Terraform docs `after_unknown` / `after_sensitive` for a list is a
    // parallel-shaped array. We don't index per-element; mark the prefix.
    let anyTrue = false;
    for (const item of value) {
      if (item === true) {
        anyTrue = true;
      } else if (item && typeof item === 'object') {
        flattenTruePaths(item, prefix, out);
      }
    }
    if (anyTrue && prefix) out.add(prefix);
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const path = prefix ? `${prefix}.${k}` : k;
      flattenTruePaths(v, path, out);
    }
  }
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

/**
 * Recursively emit scalar leaves of a plan-variable value under dotted/indexed
 * keys matching Terraform expression syntax:
 *   "env"                        -> { value: "prod" }
 *   "config.bucket_name"         -> from { config: { value: { bucket_name: "x" } } }
 *   "zones[0]"                   -> from { zones: { value: ["a", "b"] } }
 *   "endpoints[0].url"           -> from a list-of-objects
 *
 * Non-scalar leaves (null, undefined, empty containers) emit nothing. Mixed
 * types are handled element-by-element. Caller passes the variable name as the
 * initial prefix.
 */
function flattenVariableValue(
  value: unknown,
  prefix: string,
  out: Map<string, string | number | boolean>,
): void {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    if (prefix) out.set(prefix, value);
    return;
  }
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, idx) => {
      flattenVariableValue(item, `${prefix}[${idx}]`, out);
    });
    return;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      flattenVariableValue(v, prefix ? `${prefix}.${k}` : k, out);
    }
  }
}
