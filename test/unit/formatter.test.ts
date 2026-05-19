import { describe, it, expect } from 'vitest';
import { formatJson, formatSarif } from '../../src/formatter';
import { Finding } from '../../src/types';
import { allRules } from '../../src/rules';

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

  it('should emit structured frameworks array on each finding', () => {
    const findings: Finding[] = [
      {
        ruleId: 'S-12.1.1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'Bedrock logging configured',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1) - Automatic logging of events',
        nistReference:
          'NIST AI RMF 1.0: GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience)',
        isoReference:
          'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.findings[0].frameworks).toEqual([
      {
        framework: 'EU AI Act',
        items: [{ id: 'Article 12(1)', desc: 'Automatic logging of events' }],
      },
      {
        framework: 'NIST AI RMF',
        items: [
          { id: 'GOVERN 1.4', desc: 'transparent risk-management policies' },
          { id: 'MEASURE 2.7', desc: 'security and resilience' },
        ],
      },
      {
        framework: 'ISO/IEC 42001',
        items: [
          { id: 'A.6.2.8', desc: 'AI system event logs' },
          { id: 'A.6.2.6', desc: 'AI system operation and monitoring' },
        ],
      },
    ]);
    // Raw strings preserved for backwards compatibility.
    expect(parsed.findings[0].regulatoryReference).toContain('Article 12(1)');
    expect(parsed.findings[0].nistReference).toContain('GOVERN 1.4');
    expect(parsed.findings[0].isoReference).toContain('A.6.2.8');
  });

  it('should omit frameworks entries with no parsed items', () => {
    const findings: Finding[] = [
      {
        ruleId: 'X-1',
        status: 'PASS',
        filePath: 'test.tf',
        description: 'No refs',
        remediation: '',
        regulatoryReference: 'EU AI Act Article 12(1) - Logging',
      },
    ];

    const parsed = JSON.parse(formatJson(findings));
    expect(parsed.findings[0].frameworks).toHaveLength(1);
    expect(parsed.findings[0].frameworks[0].framework).toBe('EU AI Act');
  });
});

describe('formatSarif', () => {
  const sampleFindings: Finding[] = [
    {
      ruleId: 'S-12.1.1',
      status: 'FAIL',
      filePath: 'modules/bedrock/main.tf',
      line: 42,
      description: 'Bedrock invocation logging is not configured',
      remediation: 'Declare aws_bedrock_model_invocation_logging_configuration',
      regulatoryReference: 'EU AI Act Article 12(1) - Automatic logging of events',
      nistReference:
        'NIST AI RMF 1.0: GOVERN 1.4 (transparent risk-management policies); MEASURE 2.7 (security and resilience)',
      isoReference:
        'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs)',
    },
    {
      ruleId: 'S-12.1.2a',
      status: 'WARN',
      filePath: 'modules/bedrock/main.tf',
      line: 88,
      description: 'CloudWatch retention below 180 days',
      remediation: 'Set retention_in_days to >= 365',
      regulatoryReference: 'EU AI Act Article 12(2)',
    },
    {
      ruleId: 'S-12.x.4',
      status: 'PASS',
      filePath: 'cloudtrail.tf',
      description: 'CloudTrail enabled',
      remediation: '',
      regulatoryReference: 'EU AI Act Article 12',
    },
    {
      ruleId: 'S-12.x.1',
      status: 'INCONCLUSIVE',
      filePath: 'modules/logs/main.tf',
      description: 'Bucket name resolves through var without default',
      remediation: 'Add a default to var.log_bucket_name',
      regulatoryReference: 'EU AI Act Article 12',
      unresolvedReason: 'var-no-default',
    },
    {
      ruleId: 'S-9.x.1',
      status: 'SKIP',
      filePath: '',
      description: 'No Bedrock agents in scope',
      remediation: '',
      regulatoryReference: 'EU AI Act Article 9',
    },
  ];

  it('emits a SARIF 2.1.0 document with one run and the infrarails tool driver', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif-schema-2\.1\.0\.json$/);
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('infrarails');
    expect(sarif.runs[0].tool.driver.version).toBeDefined();
    expect(sarif.runs[0].tool.driver.informationUri).toMatch(/^https:\/\//);
  });

  it('includes the full rule catalogue, not just rules with findings', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    // Every registered rule should be advertised - giving consumers a stable
    // catalogue of what infrarails can find.
    for (const r of allRules) {
      expect(ruleIds).toContain(r.id);
    }
  });

  it('maps statuses to SARIF level + kind correctly', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const byRule = new Map<string, { level: string; kind: string }>(
      sarif.runs[0].results.map((r: { ruleId: string; level: string; kind: string }) => [
        r.ruleId,
        { level: r.level, kind: r.kind },
      ]),
    );

    expect(byRule.get('S-12.1.1')).toEqual({ level: 'error', kind: 'fail' });
    expect(byRule.get('S-12.1.2a')).toEqual({ level: 'warning', kind: 'fail' });
    expect(byRule.get('S-12.x.4')).toEqual({ level: 'none', kind: 'pass' });
    expect(byRule.get('S-12.x.1')).toEqual({ level: 'warning', kind: 'review' });
    expect(byRule.get('S-9.x.1')).toEqual({ level: 'none', kind: 'notApplicable' });
  });

  it('emits a result for every finding (including PASS / SKIP for the audit trail)', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    expect(sarif.runs[0].results).toHaveLength(sampleFindings.length);
  });

  it('attaches physical locations with line numbers when available', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.locations).toHaveLength(1);
    expect(fail.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'modules/bedrock/main.tf',
    );
    expect(fail.locations[0].physicalLocation.region.startLine).toBe(42);
  });

  it('omits the region when no line number is supplied', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const pass = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.x.4');
    expect(pass.locations[0].physicalLocation.artifactLocation.uri).toBe('cloudtrail.tf');
    expect(pass.locations[0].physicalLocation.region).toBeUndefined();
  });

  it('emits an empty locations array when filePath is empty (SKIP findings)', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const skip = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-9.x.1');
    expect(skip.locations).toEqual([]);
  });

  it('folds description + remediation into message.text', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.message.text).toContain('Bedrock invocation logging is not configured');
    expect(fail.message.text).toContain('Remediation:');
    expect(fail.message.text).toContain('aws_bedrock_model_invocation_logging_configuration');
  });

  it('omits the remediation suffix when remediation is empty', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const pass = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.x.4');
    expect(pass.message.text).toBe('CloudTrail enabled');
    expect(pass.message.text).not.toContain('Remediation');
  });

  it('exposes raw references, parsed frameworks, and unresolvedReason in properties', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.properties.status).toBe('FAIL');
    expect(fail.properties.regulatoryReference).toMatch(/Article 12\(1\)/);
    expect(fail.properties.nistReference).toMatch(/GOVERN 1\.4/);
    expect(fail.properties.isoReference).toMatch(/A\.6\.2\.8/);
    expect(fail.properties.frameworks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ framework: 'EU AI Act' }),
        expect.objectContaining({ framework: 'NIST AI RMF' }),
        expect.objectContaining({ framework: 'ISO/IEC 42001' }),
      ]),
    );
    expect(fail.properties.remediation).toBeDefined();

    const inconclusive = sarif.runs[0].results.find(
      (r: { ruleId: string }) => r.ruleId === 'S-12.x.1',
    );
    expect(inconclusive.properties.unresolvedReason).toBe('var-no-default');
  });

  it('includes partialFingerprints so GitHub Code Scanning can dedupe across runs', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const fail = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === 'S-12.1.1');
    expect(fail.partialFingerprints).toMatchObject({
      'ruleId/v1': 'S-12.1.1',
      'location/v1': 'modules/bedrock/main.tf:42',
    });
  });

  it('sets ruleIndex to point at the rule in the driver.rules catalogue', () => {
    const sarif = JSON.parse(formatSarif(sampleFindings));
    const rules: { id: string }[] = sarif.runs[0].tool.driver.rules;
    for (const result of sarif.runs[0].results as { ruleId: string; ruleIndex: number }[]) {
      expect(rules[result.ruleIndex].id).toBe(result.ruleId);
    }
  });

  it('produces an empty results array when there are no findings', () => {
    const sarif = JSON.parse(formatSarif([]));
    expect(sarif.runs[0].results).toEqual([]);
    // Catalogue is still emitted.
    expect(sarif.runs[0].tool.driver.rules.length).toBeGreaterThan(0);
  });
});
