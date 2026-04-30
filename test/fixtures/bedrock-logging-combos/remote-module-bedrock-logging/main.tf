resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful support bot."
}

resource "aws_s3_bucket" "audit" {
  bucket = "audit-logs"
}

module "bedrock_logging" {
  source                   = "registry.terraform.io/org/bedrock-logging/aws"
  log_bucket               = aws_s3_bucket.audit.id
  cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:bedrock-cw"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "audit-logs"
  enable_logging = true
}
