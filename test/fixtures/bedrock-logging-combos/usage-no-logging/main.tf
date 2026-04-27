resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful support bot."
}

resource "aws_bedrock_guardrail" "pii_filter" {
  name                      = "pii-filter"
  blocked_input_messaging   = "Blocked."
  blocked_outputs_messaging = "Blocked."
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}
