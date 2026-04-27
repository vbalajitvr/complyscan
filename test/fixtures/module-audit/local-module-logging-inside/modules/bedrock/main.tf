resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "Help."
}

resource "aws_s3_bucket" "logs" {
  bucket = "module-bedrock-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = "module-bedrock-logs"
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "module-bedrock-logs"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "module-bedrock-logs"
  rule {
    id     = "retain-logs"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config {
      bucket_name = "module-bedrock-logs"
    }
  }
}
