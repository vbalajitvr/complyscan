variable "log_bucket_name" {
  type        = string
  description = "Name of the S3 bucket for AI audit logs (set via tfvars at apply time)."
}

variable "log_group_name" {
  type        = string
  description = "Name of the CloudWatch log group for Bedrock invocation logs."
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
      bucket_name = var.log_bucket_name
    }

    cloudwatch_config {
      log_group_name = var.log_group_name
      role_arn       = "arn:aws:iam::123456789012:role/bedrock-cw-role"
    }
  }
}
