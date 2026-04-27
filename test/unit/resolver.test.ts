import { describe, it, expect } from 'vitest';
import { resolveExpression } from '../../src/resolver';
import { ParsedFile, HCL2JSONOutput } from '../../src/types';

function file(json: HCL2JSONOutput): ParsedFile {
  return { filePath: 'test.tf', json, rawHcl: '' };
}

describe('resolveExpression', () => {
  describe('literals', () => {
    it('returns literal for a plain string', () => {
      const result = resolveExpression('my-bucket-name', []);
      expect(result).toEqual({ kind: 'literal', value: 'my-bucket-name' });
    });

    it('returns undefined for non-string input', () => {
      expect(resolveExpression(123, [])).toBeUndefined();
      expect(resolveExpression(undefined, [])).toBeUndefined();
      expect(resolveExpression(null, [])).toBeUndefined();
    });
  });

  describe('aws_* resource references', () => {
    it('resolves aws_s3_bucket.<name>.id to the literal bucket name', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: 'real-bucket' }] } } }),
      ];
      const result = resolveExpression('${aws_s3_bucket.logs.id}', files);
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });

    it('returns address when aws_s3_bucket.bucket attribute uses interpolation', () => {
      const files = [
        file({
          resource: { aws_s3_bucket: { logs: [{ bucket: '${var.env}-logs' }] } },
        }),
      ];
      const result = resolveExpression('${aws_s3_bucket.logs.id}', files);
      expect(result).toEqual({
        kind: 'address',
        value: 'aws_s3_bucket.logs',
        resourceType: 'aws_s3_bucket',
        resourceName: 'logs',
      });
    });

    it('returns address when aws_s3_bucket resource is not in scanned files', () => {
      const result = resolveExpression('${aws_s3_bucket.external.id}', []);
      expect(result).toMatchObject({ kind: 'address', value: 'aws_s3_bucket.external' });
    });

    it('handles bare ref without interpolation braces', () => {
      const files = [
        file({ resource: { aws_s3_bucket: { logs: [{ bucket: 'real-bucket' }] } } }),
      ];
      const result = resolveExpression('aws_s3_bucket.logs.id', files);
      expect(result).toEqual({ kind: 'literal', value: 'real-bucket' });
    });
  });

  describe('Terraform variables', () => {
    it('resolves var.X to its literal default', () => {
      const files = [
        file({ variable: { log_bucket: [{ default: 'default-bucket' }] } }),
      ];
      const result = resolveExpression('${var.log_bucket}', files);
      expect(result).toEqual({ kind: 'literal', value: 'default-bucket' });
    });

    it('returns var-no-default when default is absent', () => {
      const files = [file({ variable: { log_bucket: [{ type: 'string' }] } })];
      const result = resolveExpression('${var.log_bucket}', files, 'logging_config.s3_config.bucket_name');
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'var-no-default',
        expression: '${var.log_bucket}',
        sourceField: 'logging_config.s3_config.bucket_name',
      });
    });

    it('returns var-no-default when variable is not declared in scanned files', () => {
      const result = resolveExpression('${var.unknown}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });

    it('does not resolve when default is itself an interpolation', () => {
      const files = [
        file({ variable: { log_bucket: [{ default: '${var.env}-logs' }] } }),
      ];
      const result = resolveExpression('${var.log_bucket}', files);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });
  });

  describe('Terraform locals', () => {
    it('resolves local.X to its literal value', () => {
      const files = [file({ locals: [{ log_bucket: 'local-bucket' }] })];
      const result = resolveExpression('${local.log_bucket}', files);
      expect(result).toEqual({ kind: 'literal', value: 'local-bucket' });
    });

    it('returns local-not-literal when local is not a literal string', () => {
      const files = [file({ locals: [{ log_bucket: '${var.env}-logs' }] })];
      const result = resolveExpression('${local.log_bucket}', files);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });

    it('returns local-not-literal when local is not declared', () => {
      const result = resolveExpression('${local.missing}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });
  });

  describe('data sources', () => {
    it('classifies data.aws_ssm_parameter.X.value as data-source-ssm', () => {
      const result = resolveExpression(
        '${data.aws_ssm_parameter.log_bucket.value}',
        [],
        'logging_config.s3_config.bucket_name',
      );
      expect(result).toMatchObject({
        kind: 'unresolvable',
        reason: 'data-source-ssm',
        expression: '${data.aws_ssm_parameter.log_bucket.value}',
      });
    });

    it('classifies other data sources as data-source-other', () => {
      const result = resolveExpression('${data.aws_caller_identity.current.account_id}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'data-source-other' });
    });
  });

  describe('module outputs', () => {
    it('classifies module.X.Y as module-output', () => {
      const result = resolveExpression('${module.logging.bucket_name}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'module-output' });
    });
  });

  describe('complex interpolations', () => {
    it('classifies prefix-${var.X} as complex-interpolation', () => {
      const result = resolveExpression('logs-${var.env}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'complex-interpolation' });
    });

    it('classifies ${var.a}-${var.b} as complex-interpolation', () => {
      const result = resolveExpression('${var.env}-${var.suffix}', []);
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'complex-interpolation' });
    });
  });

  describe('module-scoped variable resolution', () => {
    it('resolves var.X only from files in the same directory as sourceFilePath', () => {
      const parentFile: ParsedFile = {
        filePath: '/project/root.tf',
        json: { variable: { log_bucket: [{ default: 'parent-default' }] } },
        rawHcl: '',
      };
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { variable: { log_bucket: [{ type: 'string' }] } },
        rawHcl: '',
      };

      // Without sourceFilePath: leaks parent default into child context (old behaviour)
      const leaked = resolveExpression('${var.log_bucket}', [parentFile, childFile]);
      expect(leaked).toEqual({ kind: 'literal', value: 'parent-default' });

      // With sourceFilePath scoped to child dir: child has no default → INCONCLUSIVE
      const scoped = resolveExpression(
        '${var.log_bucket}',
        [parentFile, childFile],
        'logging_config.s3_config.bucket_name',
        '/project/modules/bedrock/main.tf',
      );
      expect(scoped).toMatchObject({ kind: 'unresolvable', reason: 'var-no-default' });
    });

    it('resolves var.X from correct module when same-dir file has a default', () => {
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { variable: { log_bucket: [{ default: 'child-bucket' }] } },
        rawHcl: '',
      };
      const result = resolveExpression(
        '${var.log_bucket}',
        [childFile],
        'field',
        '/project/modules/bedrock/main.tf',
      );
      expect(result).toEqual({ kind: 'literal', value: 'child-bucket' });
    });

    it('resolves local.X only from files in the same directory as sourceFilePath', () => {
      const parentFile: ParsedFile = {
        filePath: '/project/root.tf',
        json: { locals: [{ log_bucket: 'parent-local-bucket' }] },
        rawHcl: '',
      };
      const childFile: ParsedFile = {
        filePath: '/project/modules/bedrock/main.tf',
        json: { locals: [] },
        rawHcl: '',
      };

      // Scoped to child dir: child has no matching local → unresolvable
      const result = resolveExpression(
        '${local.log_bucket}',
        [parentFile, childFile],
        'field',
        '/project/modules/bedrock/main.tf',
      );
      expect(result).toMatchObject({ kind: 'unresolvable', reason: 'local-not-literal' });
    });
  });

  describe('source field tracking', () => {
    it('preserves sourceField in unresolvable results', () => {
      const result = resolveExpression(
        '${var.bucket}',
        [],
        'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      );
      expect(result).toMatchObject({
        sourceField: 'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      });
    });
  });
});
