import { describe, it, expect } from 'vitest';
import { getNestedValue, findResourceLine, matchesBucket } from '../../src/utils/resource-helpers';

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
