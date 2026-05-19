import { ParsedFile, Finding, PlanOverlay, UnresolvableReason } from './types';
import { allRules } from './rules';
import { buildScanContext } from './context';
import { explainReason } from './resolver';

export interface RunOptions {
  strictAccountLogging?: boolean;
  plan?: PlanOverlay;
}

// INCONCLUSIVE reasons that represent a user-fixable situation: the value
// could have been resolved if the user had supplied a default, run a full
// plan, or restructured the expression. Under --plan + --strict-account-logging
// these become FAILs so audit-grade runs do not silently accept "we couldn't
// verify" verdicts.
const ESCALATABLE_REASONS: ReadonlySet<UnresolvableReason> = new Set([
  'var-no-default',
  'local-not-literal',
  'data-source-ssm',
  'data-source-other',
  'module-output',
  'complex-interpolation',
  'plan-deferred-data-source',
  // Divergent multi-instance refs are user-fixable: the author can index the
  // reference or restructure the resource. Treated as escalatable so audit
  // runs surface the configuration ambiguity as a hard FAIL.
  'plan-instances-divergent',
]);

// Reasons that stay INCONCLUSIVE even in strict + plan mode because Terraform
// itself cannot know the answer at plan time. Listed explicitly for the
// reader: plan-known-after-apply (AWS auto-generates the value post-create),
// plan-sensitive-redacted (user correctly handled a secret value),
// plan-remote-state-unreachable (backend reachability is a platform-team
// concern — the parser already rejects errored plans, so if this fires the
// remote state read unexpectedly failed, which the user cannot fix here).
// Anything not in ESCALATABLE_REASONS is treated as non-escalatable by default.

/**
 * Two-phase rule execution engine.
 *
 * Phase 1: Run phase1 rules (e.g., Bedrock logging detection) — these produce
 * the headline finding for a domain.
 * Phase 2: Run remaining rules that may cross-reference phase-1 domain context
 * (e.g., S3/CW rules escalating severity for buckets/groups used by Bedrock).
 *
 * Context is built once from the parsed files and shared by both phases.
 * buildScanContext derives its fields directly from `files` (and the overlay),
 * not from phase-1 rule outputs, so building it up front is safe — and it
 * means phase-1 rules see real derived fields instead of an empty stub.
 *
 * When `plan` is supplied, both phases see the overlay on context.planOverlay
 * so rules can opt-in to plan-resolved values without threading a new arg.
 */
export function runScan(files: ParsedFile[], options: RunOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const strictAccountLogging = options.strictAccountLogging ?? false;
  const overlay = options.plan;

  const context = buildScanContext(files, { strictAccountLogging, overlay });

  const phase1Rules = allRules.filter((r) => r.phase1);
  const phase2Rules = allRules.filter((r) => !r.phase1);

  for (const rule of phase1Rules) {
    findings.push(...rule.run(files, context));
  }
  for (const rule of phase2Rules) {
    findings.push(...rule.run(files, context));
  }

  // Strict + plan mode escalates user-fixable INCONCLUSIVE findings to FAIL.
  // Rationale: when the user has provided a plan AND asserted (via
  // --strict-account-logging) that the scanned tree is the entire estate,
  // a remaining INCONCLUSIVE either reflects a fixable user choice
  // (missing var default, -target=..., complex interpolation that could be
  // simplified) or a genuinely-unknowable case (plan-known-after-apply,
  // plan-sensitive-redacted). Only the former escalate. See README and
  // docs/plan-mode-design.md §8 for the full table.
  if (overlay && strictAccountLogging) {
    return findings.map((f) => escalateInconclusive(f));
  }

  return findings;
}

function escalateInconclusive(f: Finding): Finding {
  if (f.status !== 'INCONCLUSIVE' || !f.unresolvedReason) return f;
  if (!ESCALATABLE_REASONS.has(f.unresolvedReason)) return f;
  return {
    ...f,
    status: 'FAIL',
    // description is left unchanged on escalation. Note that remediation still
    // flows into SARIF message.text via the formatter's description+remediation
    // fold, so message.text is not fully stable across an INCONCLUSIVE<->FAIL
    // toggle - partialFingerprints is the load-bearing dedup mechanism for
    // GitHub Code Scanning. Holding description stable narrows the drift but
    // does not eliminate it; revisit if duplicate alerts become a real issue.
    remediation: [
      `Escalated to FAIL: unresolved reason "${f.unresolvedReason}" is user-fixable` +
        ` (${explainReason(f.unresolvedReason)}) and --plan + --strict-account-logging are both active.`,
      ...(f.remediation ? [f.remediation] : []),
    ].join(' '),
  };
}
