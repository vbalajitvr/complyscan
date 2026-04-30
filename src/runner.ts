import { ParsedFile, Finding, ScanContext } from './types';
import { allRules } from './rules';
import { buildScanContext } from './context';

export interface RunOptions {
  strictAccountLogging?: boolean;
}

/**
 * Two-phase rule execution engine.
 *
 * Phase 1: Run phase1 rules (e.g., Bedrock logging detection) to build context.
 * Phase 2: Run remaining rules with the populated ScanContext.
 */
export function runScan(files: ParsedFile[], options: RunOptions = {}): Finding[] {
  const findings: Finding[] = [];
  const strictAccountLogging = options.strictAccountLogging ?? false;

  // Phase 1: Run phase1 rules to populate context
  const phase1Rules = allRules.filter((r) => r.phase1);
  const phase2Rules = allRules.filter((r) => !r.phase1);

  for (const rule of phase1Rules) {
    const emptyContext: ScanContext = {
      bedrockLoggingDetected: false,
      logBucketNames: [],
      logGroupNames: [],
      unresolvedBucketRefs: [],
      unresolvedGroupRefs: [],
      strictAccountLogging,
    };
    findings.push(...rule.run(files, emptyContext));
  }

  // Build context from the parsed files (extracts log bucket/group names)
  const context = buildScanContext(files, { strictAccountLogging });

  // Phase 2: Run remaining rules with context
  for (const rule of phase2Rules) {
    findings.push(...rule.run(files, context));
  }

  return findings;
}
