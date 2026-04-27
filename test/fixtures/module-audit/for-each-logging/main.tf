variable "regions" {
  type    = set(string)
  default = ["us-east-1", "eu-west-1"]
}

resource "aws_bedrockagent_agent" "multi_region" {
  for_each                = var.regions
  agent_name              = "agent-${each.key}"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "Help."
}

resource "aws_s3_bucket" "logs" {
  bucket = "multi-region-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "multi-region-logs"
  rule {
    id     = "retain"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config {
      bucket_name = "multi-region-logs"
    }
  }
}
