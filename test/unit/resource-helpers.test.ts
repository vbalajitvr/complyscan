import { describe, it, expect } from 'vitest';
import {
  getNestedValue,
  findResourceLine,
  matchesBucket,
  BEDROCK_DIRECT_RESOURCE_TYPES,
  BEDROCK_DATA_SOURCE_TYPES,
  BEDROCK_IAM_ACTIONS,
  BEDROCK_VPC_ENDPOINT_SUFFIXES,
  BEDROCK_LOGGING_INPUT_KEYS,
  BEDROCK_MODULE_NAME_TOKENS,
  BASELINE_REMOTE_STATE_NAMES,
  findBedrockResources,
  findBedrockDataSources,
  findIamBedrockGrants,
  findBedrockVpcEndpoints,
  findBedrockRelatedModuleCalls,
  findBaselineRemoteState,
  findBedrockLoggingReferences,
} from '../../src/utils/resource-helpers';
import { ParsedFile } from '../../src/types';

function pf(json: ParsedFile['json'], filePath = 'main.tf'): ParsedFile {
  return { filePath, json, rawHcl: '' };
}

describe('getNestedValue', () => {
  it('should return a simple nested value', () => {
    const obj = { a: { b: { c: 'hello' } } };
    expect(getNestedValue(obj, 'a.b.c')).toBe('hello');
  });

  it('should auto-unwrap single-element arrays', () => {
    const obj = { a: [{ b: [{ c: 'hello' }] }] };
    expect(getNestedValue(obj, 'a.b.c')).toBe('hello');
  });

  it('should return undefined for missing paths', () => {
    const obj = { a: { b: 1 } };
    expect(getNestedValue(obj, 'a.c')).toBeUndefined();
  });

  it('should handle null/undefined gracefully', () => {
    expect(getNestedValue(null, 'a.b')).toBeUndefined();
    expect(getNestedValue(undefined, 'a.b')).toBeUndefined();
  });
});

describe('findResourceLine', () => {
  it('should find the line number of a resource', () => {
    const hcl = `resource "aws_s3_bucket" "other" {
  bucket = "other-bucket"
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-bucket"
}
`;
    expect(findResourceLine(hcl, 'aws_s3_bucket', 'logs')).toBe(4);
  });

  it('should return undefined when resource not found', () => {
    expect(findResourceLine('', 'aws_s3_bucket', 'logs')).toBeUndefined();
  });
});

describe('matchesBucket', () => {
  it('should match by bucket attribute', () => {
    const body = { bucket: 'my-bucket' };
    expect(matchesBucket(body, 'some-name', ['my-bucket'])).toBe(true);
  });

  it('should match by resource name', () => {
    const body = {};
    expect(matchesBucket(body, 'logs', ['logs'])).toBe(true);
  });

  it('should return false for no match', () => {
    const body = { bucket: 'other-bucket' };
    expect(matchesBucket(body, 'other-name', ['my-bucket'])).toBe(false);
  });

  it('should return false for empty targets', () => {
    expect(matchesBucket({}, 'logs', [])).toBe(false);
  });
});

describe('Bedrock finite lists', () => {
  it('BEDROCK_DIRECT_RESOURCE_TYPES has no duplicates and every entry starts with aws_bedrock', () => {
    expect(new Set(BEDROCK_DIRECT_RESOURCE_TYPES).size).toBe(BEDROCK_DIRECT_RESOURCE_TYPES.length);
    for (const t of BEDROCK_DIRECT_RESOURCE_TYPES) {
      expect(t.startsWith('aws_bedrock')).toBe(true);
    }
  });

  it('BEDROCK_DIRECT_RESOURCE_TYPES excludes the logging-config resource', () => {
    expect(BEDROCK_DIRECT_RESOURCE_TYPES).not.toContain(
      'aws_bedrock_model_invocation_logging_configuration',
    );
  });

  it('BEDROCK_IAM_ACTIONS covers Invoke, Converse, Retrieve verbs and bedrock:*', () => {
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:InvokeModel');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:Converse');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:RetrieveAndGenerate');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:*');
  });

  it('BEDROCK_VPC_ENDPOINT_SUFFIXES contains all four runtime/agent variants', () => {
    expect(BEDROCK_VPC_ENDPOINT_SUFFIXES).toEqual(
      expect.arrayContaining(['.bedrock', '.bedrock-runtime', '.bedrock-agent', '.bedrock-agent-runtime']),
    );
  });

  it('BEDROCK_LOGGING_INPUT_KEYS, BEDROCK_MODULE_NAME_TOKENS, BASELINE_REMOTE_STATE_NAMES are non-empty', () => {
    expect(BEDROCK_LOGGING_INPUT_KEYS.length).toBeGreaterThan(0);
    expect(BEDROCK_MODULE_NAME_TOKENS.length).toBeGreaterThan(0);
    expect(BASELINE_REMOTE_STATE_NAMES.length).toBeGreaterThan(0);
  });
});

describe('findBedrockResources', () => {
  it('finds direct Bedrock resources and skips the logging resource', () => {
    const files = [
      pf({
        resource: {
          aws_bedrockagent_agent: { a: [{ agent_name: 'a' }] },
          aws_bedrock_inference_profile: { p: [{ name: 'p' }] },
          aws_bedrock_model_invocation_logging_configuration: { main: [{}] },
          aws_s3_bucket: { logs: [{ bucket: 'x' }] },
        },
      }),
    ];
    const found = findBedrockResources(files);
    const types = found.map((r) => r.type);
    expect(types).toContain('aws_bedrockagent_agent');
    expect(types).toContain('aws_bedrock_inference_profile');
    expect(types).not.toContain('aws_bedrock_model_invocation_logging_configuration');
    expect(types).not.toContain('aws_s3_bucket');
  });
});

describe('findBedrockDataSources', () => {
  it('matches every entry in BEDROCK_DATA_SOURCE_TYPES', () => {
    for (const t of BEDROCK_DATA_SOURCE_TYPES) {
      const files = [pf({ data: { [t]: { x: [{}] } } })];
      const found = findBedrockDataSources(files);
      expect(found.map((r) => r.type)).toContain(t);
    }
  });

  it('ignores non-Bedrock data sources', () => {
    const files = [pf({ data: { aws_caller_identity: { current: [{}] } } })];
    expect(findBedrockDataSources(files)).toHaveLength(0);
  });
});

describe('findIamBedrockGrants', () => {
  it('matches actions array in aws_iam_policy_document data sources', () => {
    const files = [
      pf({
        data: {
          aws_iam_policy_document: {
            doc: [{ statement: [{ actions: ['bedrock:InvokeModel'], resources: ['*'] }] }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants).toHaveLength(1);
    expect(grants[0].actions).toEqual(['bedrock:InvokeModel']);
  });

  it('matches singular action field on a statement', () => {
    const files = [
      pf({
        data: {
          aws_iam_policy_document: {
            doc: [{ statement: { action: 'bedrock:Converse', resources: ['*'] } }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants[0].actions).toContain('bedrock:Converse');
  });

  it('matches inline JSON policy on aws_iam_role_policy', () => {
    const files = [
      pf({
        resource: {
          aws_iam_role_policy: {
            p: [
              {
                policy: JSON.stringify({
                  Statement: [{ Effect: 'Allow', Action: 'bedrock:Retrieve', Resource: '*' }],
                }),
              },
            ],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants).toHaveLength(1);
    expect(grants[0].actions).toContain('bedrock:Retrieve');
  });

  it('returns nothing for unparseable interpolated policy strings (no false signal)', () => {
    const files = [
      pf({
        resource: {
          aws_iam_role_policy: {
            p: [{ policy: '${data.template_file.policy.rendered}' }],
          },
        },
      }),
    ];
    expect(findIamBedrockGrants(files)).toHaveLength(0);
  });

  it('matches the bedrock:* wildcard literal', () => {
    const files = [
      pf({
        resource: {
          aws_iam_policy: {
            wide: [{ policy: JSON.stringify({ Statement: [{ Action: 'bedrock:*' }] }) }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants[0].actions).toContain('bedrock:*');
  });
});

describe('findBedrockVpcEndpoints', () => {
  it('matches bedrock-runtime literal', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: {
            br: [{ service_name: 'com.amazonaws.us-east-1.bedrock-runtime' }],
          },
        },
      }),
    ];
    const found = findBedrockVpcEndpoints(files);
    expect(found).toHaveLength(1);
    expect(found[0].serviceName).toBe('com.amazonaws.us-east-1.bedrock-runtime');
  });

  it('matches bedrock-agent-runtime', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: {
            br: [{ service_name: 'com.amazonaws.eu-west-1.bedrock-agent-runtime' }],
          },
        },
      }),
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(1);
  });

  it('returns nothing for non-Bedrock services', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: { s3: [{ service_name: 'com.amazonaws.us-east-1.s3' }] },
        },
      }),
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(0);
  });

  it('resolves var.X indirection for service_name', () => {
    const files: ParsedFile[] = [
      {
        filePath: '/repo/main.tf',
        rawHcl: '',
        json: {
          resource: {
            aws_vpc_endpoint: { br: [{ service_name: '${var.svc}' }] },
          },
          variable: {
            svc: [{ default: 'com.amazonaws.us-east-1.bedrock-runtime' }],
          },
        },
      },
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(1);
  });
});

describe('findBedrockRelatedModuleCalls', () => {
  it('matches a module by name token (bedrock)', () => {
    const files = [
      pf({
        module: {
          bedrock_logging: [{ source: 'registry.terraform.io/org/x/aws' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedTokens).toContain('bedrock');
  });

  it('matches a module by Bedrock-logging input key (log_bucket)', () => {
    const files = [
      pf({
        module: {
          generic: [{ source: './local', log_bucket: 'audit-logs' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedInputKeys).toContain('log_bucket');
  });

  it('ignores unrelated modules', () => {
    const files = [
      pf({
        module: {
          vpc: [{ source: './vpc', cidr_block: '10.0.0.0/16' }],
        },
      }),
    ];
    expect(findBedrockRelatedModuleCalls(files)).toHaveLength(0);
  });

  it('marks remote vs local correctly', () => {
    const files = [
      pf({
        module: {
          bedrock_a: [{ source: './local' }],
          bedrock_b: [{ source: 'registry.terraform.io/org/x/aws' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    const a = found.find((m) => m.name === 'bedrock_a');
    const b = found.find((m) => m.name === 'bedrock_b');
    expect(a?.isRemote).toBe(false);
    expect(b?.isRemote).toBe(true);
  });
});

describe('findBaselineRemoteState', () => {
  it('matches data terraform_remote_state with baseline name', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: {
            account_baseline: [{ backend: 's3' }],
          },
        },
      }),
    ];
    const found = findBaselineRemoteState(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedToken).toBe('account_baseline');
  });

  it('matches central_logging', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: { central_logging: [{ backend: 's3' }] },
        },
      }),
    ];
    expect(findBaselineRemoteState(files)).toHaveLength(1);
  });

  it('ignores unrelated remote-state references', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: { vpc: [{ backend: 's3' }] },
        },
      }),
    ];
    expect(findBaselineRemoteState(files)).toHaveLength(0);
  });
});

describe('findBedrockLoggingReferences', () => {
  it('detects data.terraform_remote_state.X.outputs.<bedrock-logging-key> in resource bodies', () => {
    const files = [
      pf({
        resource: {
          aws_s3_bucket_policy: {
            p: [
              {
                bucket: '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
                policy: '{}',
              },
            ],
          },
        },
      }),
    ];
    const found = findBedrockLoggingReferences(files);
    expect(found).toHaveLength(1);
    expect(found[0].remoteStateName).toBe('account_baseline');
    expect(found[0].outputKey).toBe('log_bucket');
  });

  it('does not match unrelated remote-state output keys', () => {
    const files = [
      pf({
        resource: {
          aws_s3_bucket_policy: {
            p: [{ bucket: '${data.terraform_remote_state.vpc.outputs.cidr_block}' }],
          },
        },
      }),
    ];
    expect(findBedrockLoggingReferences(files)).toHaveLength(0);
  });
});
