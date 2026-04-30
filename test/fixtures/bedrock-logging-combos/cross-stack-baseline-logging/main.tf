resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful support bot."
}

data "terraform_remote_state" "account_baseline" {
  backend = "s3"
  config = {
    bucket = "tf-state"
    key    = "account-baseline/terraform.tfstate"
    region = "us-east-1"
  }
}

resource "aws_s3_bucket_policy" "bedrock_logs" {
  bucket = data.terraform_remote_state.account_baseline.outputs.log_bucket
  policy = "{}"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}
