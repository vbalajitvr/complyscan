import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import {
  findResources,
  findResourceLine,
  getNestedValue,
  findRemoteModules,
  findBedrockResources,
  findBedrockDataSources,
  findIamBedrockGrants,
  findBedrockVpcEndpoints,
  findBedrockRelatedModuleCalls,
  findBaselineRemoteState,
  findBedrockLoggingReferences,
} from '../utils/resource-helpers';

const MODALITY_TOGGLES = [
  'text_data_delivery_enabled',
  'image_data_delivery_enabled',
  'embedding_data_delivery_enabled',
  'video_data_delivery_enabled',
];

const REGULATORY_REFERENCE = 'EU AI Act Article 12(1) — Automatic logging of events';

const RUN_PLAN_HINT =
  'Run complyscan against "terraform show -json plan.json" for full apply-time resolution, or scan the stack/module that defines the missing pieces.';

interface DirectUsage {
  resourceAddress: string;
  type: string;
  filePath: string;
}

interface IndirectUsage {
  iam: ReturnType<typeof findIamBedrockGrants>;
  vpc: ReturnType<typeof findBedrockVpcEndpoints>;
  dataSources: ReturnType<typeof findBedrockDataSources>;
}

interface ExternalLoggingHint {
  modules: ReturnType<typeof findBedrockRelatedModuleCalls>;
  baselineState: ReturnType<typeof findBaselineRemoteState>;
  loggingRefs: ReturnType<typeof findBedrockLoggingReferences>;
}

export const bedrockLoggingRule: ScanRule = {
  id: 'S-12.1.1',
  description: 'Bedrock model invocation logging must be configured when Bedrock is in use',
  severity: 'FAIL',
  regulatoryReference: REGULATORY_REFERENCE,
  phase1: true,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    const configs = findResources(files, 'aws_bedrock_model_invocation_logging_configuration');

    // Case A — logging config present in scanned files. PASS / modality-FAIL.
    if (configs.length > 0) {
      return configs.map((config) => evaluateLoggingConfig(config));
    }

    const direct: DirectUsage[] = findBedrockResources(files).map((r) => ({
      resourceAddress: r.resourceAddress,
      type: r.type,
      filePath: r.filePath,
    }));
    const indirect: IndirectUsage = {
      iam: findIamBedrockGrants(files),
      vpc: findBedrockVpcEndpoints(files),
      dataSources: findBedrockDataSources(files),
    };
    const hint: ExternalLoggingHint = {
      modules: findBedrockRelatedModuleCalls(files),
      baselineState: findBaselineRemoteState(files),
      loggingRefs: findBedrockLoggingReferences(files),
    };

    const hasDirect = direct.length > 0;
    const hasIndirect = indirect.iam.length > 0 || indirect.vpc.length > 0 || indirect.dataSources.length > 0;
    const hasHint =
      hint.modules.length > 0 || hint.baselineState.length > 0 || hint.loggingRefs.length > 0;

    // Case B — no Bedrock signals at all.
    if (!hasDirect && !hasIndirect) {
      const remoteModules = findRemoteModules(files);
      if (remoteModules.length === 0) {
        return [
          {
            ruleId: this.id,
            status: 'SKIP',
            filePath: '',
            description: 'No Bedrock resources detected. Invocation logging check skipped.',
            remediation: '',
            regulatoryReference: REGULATORY_REFERENCE,
          },
        ];
      }
      return [buildRemoteModuleInconclusive(this.id, remoteModules, hint)];
    }

    // Case C — usage present (direct or indirect) and an external-logging hint
    // says logging may be wired up elsewhere. Always INCONCLUSIVE, regardless
    // of strict mode — we do not have enough evidence to FAIL.
    if (hasHint) {
      return [buildExternalHintInconclusive(this.id, direct, indirect, hint)];
    }

    // Case D — only indirect signals (IAM / VPC / data source) and no logging.
    // Indirect-only is never a confident FAIL — the deploying resource may be
    // in another stack. Always INCONCLUSIVE.
    if (!hasDirect) {
      return [buildIndirectOnlyInconclusive(this.id, indirect)];
    }

    // Case E — direct usage, no logging, no external hint.
    if (context.strictAccountLogging) {
      return [buildStrictModeFail(this.id, direct, indirect)];
    }
    return [buildPermissiveInconclusive(this.id, direct, indirect)];
  },
};

function evaluateLoggingConfig(config: {
  name: string;
  body: Record<string, unknown>;
  filePath: string;
  rawHcl: string;
}): Finding {
  const line = findResourceLine(
    config.rawHcl,
    'aws_bedrock_model_invocation_logging_configuration',
    config.name,
  );
  const loggingConfig = getNestedValue(config.body, 'logging_config');

  const explicitlyDisabled: string[] = [];
  const explicitlyEnabled: string[] = [];
  for (const toggle of MODALITY_TOGGLES) {
    const value = getNestedValue(loggingConfig, toggle);
    if (value === false) explicitlyDisabled.push(toggle);
    else if (value === true) explicitlyEnabled.push(toggle);
  }

  if (explicitlyEnabled.length === 0 && explicitlyDisabled.length === MODALITY_TOGGLES.length) {
    return {
      ruleId: 'S-12.1.1',
      status: 'FAIL',
      filePath: config.filePath,
      line,
      description: `Bedrock logging resource "${config.name}" exists but all data-delivery toggles are set to false — no invocations will be logged.`,
      remediation: `Enable at least one of ${MODALITY_TOGGLES.join(', ')} on logging_config.`,
      regulatoryReference: REGULATORY_REFERENCE,
    };
  }

  return {
    ruleId: 'S-12.1.1',
    status: 'PASS',
    filePath: config.filePath,
    line,
    description: `Bedrock invocation logging is configured (${config.name}).`,
    remediation: '',
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function buildRemoteModuleInconclusive(
  ruleId: string,
  remoteModules: ReturnType<typeof findRemoteModules>,
  hint: ExternalLoggingHint,
): Finding {
  const names = remoteModules.map((m) => `"${m.name}"`).join(', ');
  const bedrockRelated = hint.modules.filter((m) => m.isRemote);

  let extra = '';
  if (bedrockRelated.length > 0) {
    const detail = bedrockRelated
      .map((m) => describeModuleHint(m))
      .join('; ');
    extra = ` Module${bedrockRelated.length === 1 ? '' : 's'} ${detail} appear${bedrockRelated.length === 1 ? 's' : ''} Bedrock-logging-related.`;
  }

  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `No Bedrock resources found in scanned files, but remote module(s) ${names} could not be inspected. Bedrock usage and logging config may be defined inside those modules.${extra}`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function buildExternalHintInconclusive(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
  hint: ExternalLoggingHint,
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  const hintParts: string[] = [];

  if (hint.modules.length > 0) {
    hintParts.push(
      `module call(s) ${hint.modules.map(describeModuleHint).join('; ')}`,
    );
  }
  if (hint.loggingRefs.length > 0) {
    hintParts.push(
      `cross-stack reference(s) ${hint.loggingRefs
        .map((r) => `${r.resourceAddress} → data.terraform_remote_state.${r.remoteStateName}.outputs.${r.outputKey}`)
        .join('; ')}`,
    );
  }
  if (hint.baselineState.length > 0 && hint.loggingRefs.length === 0) {
    // Only mention baseline-state on its own when there is no concrete logging
    // reference (otherwise the loggingRefs message already names it).
    hintParts.push(
      `baseline remote-state data source(s) ${hint.baselineState.map((s) => s.dataAddress).join(', ')}`,
    );
  }

  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_model_invocation_logging_configuration in scanned files, but ${hintParts.join(' and ')} suggest logging is configured externally. Compliance cannot be verified from these files alone.`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function buildIndirectOnlyInconclusive(ruleId: string, indirect: IndirectUsage): Finding {
  const usageSummary = describeUsage([], indirect);
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_* resource and no logging config detected in scanned files. The deploying resource and logging may live in another stack.`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function buildStrictModeFail(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  return {
    ruleId,
    status: 'FAIL',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_model_invocation_logging_configuration is defined in scanned files. (Strict account-logging mode: missing logging treated as FAIL.)`,
    remediation:
      'Add an aws_bedrock_model_invocation_logging_configuration resource to log all model invocations.',
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function buildPermissiveInconclusive(
  ruleId: string,
  direct: DirectUsage[],
  indirect: IndirectUsage,
): Finding {
  const usageSummary = describeUsage(direct, indirect);
  return {
    ruleId,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `${usageSummary} No aws_bedrock_model_invocation_logging_configuration in scanned files. Logging may be configured in another stack (e.g. account-baseline). Pass --strict-account-logging if the entire infra estate is expected to be in scope.`,
    remediation: RUN_PLAN_HINT,
    regulatoryReference: REGULATORY_REFERENCE,
  };
}

function describeUsage(direct: DirectUsage[], indirect: IndirectUsage): string {
  const parts: string[] = [];
  if (direct.length > 0) {
    parts.push(
      `Bedrock direct usage detected (${direct.length} resource(s): ${direct.map((d) => d.resourceAddress).join(', ')}).`,
    );
  }
  if (indirect.iam.length > 0) {
    parts.push(
      `IAM grant(s) for Bedrock actions on ${indirect.iam
        .map((g) => `${g.resourceAddress} (${g.actions.join(', ')})`)
        .join('; ')}.`,
    );
  }
  if (indirect.vpc.length > 0) {
    parts.push(
      `VPC endpoint(s) to Bedrock service: ${indirect.vpc
        .map((v) => `${v.resourceAddress} (${v.serviceName})`)
        .join('; ')}.`,
    );
  }
  if (indirect.dataSources.length > 0) {
    parts.push(
      `Bedrock data source(s) referenced: ${indirect.dataSources.map((d) => d.dataAddress).join(', ')}.`,
    );
  }
  return parts.join(' ');
}

function describeModuleHint(m: {
  name: string;
  source: string | undefined;
  isRemote: boolean;
  matchedTokens: string[];
  matchedInputKeys: string[];
}): string {
  const sourceFragment = m.source ? ` (source: ${m.source})` : '';
  const reasons: string[] = [];
  if (m.matchedTokens.length > 0) reasons.push(`name token: ${m.matchedTokens.join(', ')}`);
  if (m.matchedInputKeys.length > 0) reasons.push(`inputs: ${m.matchedInputKeys.join(', ')}`);
  return `"${m.name}"${sourceFragment} [${reasons.join(' | ')}]`;
}
