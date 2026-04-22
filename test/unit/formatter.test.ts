import { describe, it, expect } from 'vitest';
import { formatJson } from '../../src/formatter';
import { Finding } from '../../src/types';

describe('formatJson', () => {
  it('should output valid JSON with summary and findings', () => {
    const findings: Finding[] = [
      {
        ruleId: 'S-12.1.1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'Bedrock logging configured',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1)',
      },
      {
        ruleId: 'S-12.x.4',
        status: 'FAIL',
        filePath: 'test.tf',
        description: 'No CloudTrail',
        remediation: 'Add CloudTrail',
        regulatoryReference: 'EU AI Act Article 12',
      },
    ];

    const output = formatJson(findings);
    const parsed = JSON.parse(output);

    expect(parsed.summary).toEqual({
      total: 2,
      pass: 1,
      fail: 1,
      warn: 0,
      skip: 0,
      inconclusive: 0,
    });
    expect(parsed.findings).toHaveLength(2);
  });
});
