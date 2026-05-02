import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findBedrockRelatedModuleCalls } from '../utils/resource-helpers';

export const remoteModuleWallRule: ScanRule = {
  id: 'S-12.x.5',
  description: 'Remote Terraform modules cannot be scanned for compliance controls',
  severity: 'WARN',
  regulatoryReference: 'EU AI Act Article 12 - Scanner limitation: remote module contents not visible',
  nistReference: 'NIST AI RMF 1.0: GOVERN 6.1 (third-party AI risk policies); MANAGE 3.1 (third-party AI risk monitoring)',
  isoReference: 'ISO/IEC 42001:2023 Annex A: A.10.3 (Suppliers); A.4.2 (Resource documentation)',

  run(files: ParsedFile[], _context: ScanContext): Finding[] {
    // Only flag remote modules that are *plausibly* part of the Bedrock
    // logging / infra surface - modules whose local name or source URL
    // mentions a Bedrock token, or whose body passes a Bedrock-logging input.
    // Generic remote modules (iam, dynamodb, lambda, vpc, …) live elsewhere
    // in the Article 12 universe but are not within infrarails's scope, so
    // flagging them produces noise that drowns the real findings.
    const candidates = findBedrockRelatedModuleCalls(files).filter((m) => m.isRemote);
    if (candidates.length === 0) return [];

    return candidates.map(({ name, source, matchedTokens, matchedInputKeys, filePath }) => {
      const reasons: string[] = [];
      if (matchedTokens.length > 0) {
        reasons.push(`matches Bedrock token(s) ${matchedTokens.map((t) => `"${t}"`).join(', ')}`);
      }
      if (matchedInputKeys.length > 0) {
        reasons.push(`passes logging input(s) ${matchedInputKeys.map((k) => `"${k}"`).join(', ')}`);
      }
      const why = reasons.join('; ');

      return {
        ruleId: this.id,
        status: 'INCONCLUSIVE' as const,
        filePath,
        description: `Remote module "${name}" (source "${source}") looks Bedrock-related (${why}) but its contents cannot be scanned. Compliance of resources inside the module cannot be verified statically.`,
        remediation:
          'Run infrarails against `terraform show -json plan.json` for full apply-time resolution, or define Bedrock logging in the root module where it can be scanned.',
        regulatoryReference: this.regulatoryReference,
        nistReference: this.nistReference,
        isoReference: this.isoReference,
      };
    });
  },
};
