resource "aws_bedrock_inference_profile" "claude_v3" {
  name        = "claude-v3"
  description = "Cross-region inference profile."
  model_source {
    copy_from = "anthropic.claude-3-sonnet-20240229-v1:0"
  }
}

resource "aws_bedrockagent_agent_action_group" "support_actions" {
  agent_id          = "AGENT123"
  agent_version     = "DRAFT"
  action_group_name = "support-actions"
}

resource "aws_bedrockagent_flow" "triage" {
  name               = "triage"
  execution_role_arn = "arn:aws:iam::123456789012:role/bedrock-flow"
}

resource "aws_bedrockagent_prompt" "system_prompt" {
  name = "system-prompt"
}

resource "aws_bedrock_guardrail_version" "pii_v1" {
  guardrail_arn = "arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123"
  description   = "v1"
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    text_data_delivery_enabled      = true
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = true
    video_data_delivery_enabled     = true

    s3_config {
      bucket_name = "expanded-logs"
    }
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "expanded-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = "expanded-logs"
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "expanded-logs"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "expanded-logs"
  rule {
    id     = "retain-logs"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "expanded-logs"
  enable_logging = true
}
