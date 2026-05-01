import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

// Same rationale as cw-retention.ts — kept inline rather than imported because
// the lifecycle and log-group thresholds are deliberately decoupled (one could
// be loosened without the other).
const RETENTION_RATIONALE =
  'Article 12 requires logs retained for an "appropriate period to the intended ' +
  'purpose" — no specific number is named, but bias drift, hallucinated decisions, ' +
  'and downstream-deployer audits routinely surface months after the event. ' +
  'Sub-180-day retention undermines post-market monitoring (Article 72) and ' +
  'incident investigation; 365 days is the typical floor for production AI.';

export const s3LifecycleRule: ScanRule = {
  id: 'S-12.1.2b',
  description: 'S3 log bucket must have lifecycle retention of at least 180 days',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12(1) — Logs retained for appropriate period',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. S3 lifecycle check skipped.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedBucketRefs) {
      findings.push(inconclusiveFromUnresolved(this.id, this.regulatoryReference, ref, 'bucket'));
    }

    if (context.logBucketNames.length === 0 && context.unresolvedBucketRefs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'Bedrock logging does not use S3. Skipping S3 lifecycle check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const lifecycleConfigs = findResources(files, 'aws_s3_bucket_lifecycle_configuration');

    for (const bucketName of context.logBucketNames) {
      const matching = lifecycleConfigs.find((lc) =>
        matchesBucket(lc.body, lc.name, [bucketName], files)
      );

      if (!matching) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `No aws_s3_bucket_lifecycle_configuration found for log bucket "${bucketName}". Without a lifecycle policy, retention is governed only by manual deletion — there is no enforced minimum.`,
          remediation:
            `Add an aws_s3_bucket_lifecycle_configuration for "${bucketName}" with ` +
            `an expiration rule of >= ${MIN_RETENTION_DAYS} days ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}). Why: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
        });
        continue;
      }

      const line = findResourceLine(matching.rawHcl, 'aws_s3_bucket_lifecycle_configuration', matching.name);

      // Check lifecycle rules for expiration days
      const rules = getNestedValue(matching.body, 'rule');
      const rulesArray = Array.isArray(rules) ? rules : rules ? [rules] : [];

      let maxDays = 0;
      for (const rule of rulesArray) {
        if (typeof rule !== 'object' || rule === null) continue;
        const days = getNestedValue(rule, 'expiration.days');
        if (typeof days === 'number' && days > maxDays) {
          maxDays = days;
        }
      }

      if (maxDays === 0) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Lifecycle configuration for bucket "${bucketName}" has no expiration.days set on any rule — objects will be retained indefinitely or transitioned without bound.`,
          remediation:
            `Set expiration.days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}) on at least one rule. ` +
            `Why: ${RETENTION_RATIONALE} An unbounded lifecycle leaves you exposed to ` +
            `storage cost surprises without giving compliance teams a documented retention floor.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else if (maxDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days, below the ${MIN_RETENTION_DAYS}-day floor complyscan applies for high-risk AI logging.`,
          remediation:
            `Increase expiration.days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}). Why: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
        });
      } else if (maxDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days. complyscan recommends >= ${RECOMMENDED_RETENTION_DAYS} days for production AI workloads.`,
          remediation:
            `Consider increasing expiration.days to ${RECOMMENDED_RETENTION_DAYS}. ` +
            `Why: 365 days covers most regulator-inquiry windows, calendar-quarter audit ` +
            `cycles, and the typical lag between an AI incident and its discovery downstream.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        });
      }
    }

    return findings;
  },
};
