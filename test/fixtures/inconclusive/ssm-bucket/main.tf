data "aws_ssm_parameter" "log_bucket" {
  name = "/myapp/log-bucket-name"
}

data "aws_ssm_parameter" "log_group" {
  name = "/myapp/log-group-name"
}

resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "some-trail-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    text_data_delivery_enabled      = true

    s3_config {
      bucket_name = data.aws_ssm_parameter.log_bucket.value
    }

    cloudwatch_config {
      log_group_name = data.aws_ssm_parameter.log_group.value
      role_arn       = "arn:aws:iam::123456789012:role/bedrock-cw-role"
    }
  }
}
