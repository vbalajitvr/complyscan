data "aws_ssm_parameter" "bucket" {
  name = "/infra/bedrock/log-bucket"
}

resource "aws_bedrockagent_agent" "writer" {
  agent_name = "writer-agent"
  guardrail_configuration {
    guardrail_identifier = "g-1"
    guardrail_version    = "1"
  }
}

resource "aws_bedrock_guardrail" "safety" {
  name                      = "safety"
  blocked_input_messaging   = "blocked"
  blocked_outputs_messaging = "blocked"
}

resource "aws_bedrock_model_invocation_logging_configuration" "this" {
  logging_config {
    text_data_delivery_enabled = true
    s3_config {
      bucket_name = data.aws_ssm_parameter.bucket.value
    }
  }
}
