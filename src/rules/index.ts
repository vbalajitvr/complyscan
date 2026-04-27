import { ScanRule } from '../types';
import { bedrockLoggingRule } from './s-12-1-1-bedrock-logging';
import { cwRetentionRule } from './s-12-1-2a-cw-retention';
import { s3LifecycleRule } from './s-12-1-2b-s3-lifecycle';
import { s3VersioningRule } from './s-12-x-1-s3-versioning';
import { s3EncryptionRule } from './s-12-x-2a-s3-encryption';
import { cloudtrailRule } from './s-12-x-4-cloudtrail';
import { remoteModuleWallRule } from './s-12-x-5-module-wall';

export const allRules: ScanRule[] = [
  bedrockLoggingRule,
  cwRetentionRule,
  s3LifecycleRule,
  s3VersioningRule,
  s3EncryptionRule,
  cloudtrailRule,
  remoteModuleWallRule,
];
