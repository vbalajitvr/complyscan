resource "aws_bedrockagent_agent" "support_bot" {
  agent_name              = "support-bot"
  agent_resource_role_arn = "arn:aws:iam::123456789012:role/bedrock-agent"
  foundation_model        = "anthropic.claude-3-sonnet-20240229-v1:0"
  instruction             = "You are a helpful support bot."
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    text_data_delivery_enabled      = true
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = true
    video_data_delivery_enabled     = true

    s3_config {
      bucket_name = "local-bedrock-logs"
    }
  }
}
