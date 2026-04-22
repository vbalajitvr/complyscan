import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

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
          description: `No lifecycle configuration found for log bucket "${bucketName}".`,
          remediation: `Add an aws_s3_bucket_lifecycle_configuration for bucket "${bucketName}" with expiration days >= ${MIN_RETENTION_DAYS}.`,
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
          description: `Lifecycle configuration for bucket "${bucketName}" has no expiration days set.`,
          remediation: `Set expiration days to at least ${MIN_RETENTION_DAYS} in the lifecycle rule.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else if (maxDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days (minimum: ${MIN_RETENTION_DAYS}).`,
          remediation: `Increase expiration days to at least ${MIN_RETENTION_DAYS}.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else if (maxDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `Lifecycle retention for bucket "${bucketName}" is ${maxDays} days (recommended: ${RECOMMENDED_RETENTION_DAYS}).`,
          remediation: `Consider increasing expiration days to ${RECOMMENDED_RETENTION_DAYS}.`,
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
