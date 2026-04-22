variable "log_bucket_name" {
  type    = string
  default = "my-resolvable-log-bucket"
}

variable "log_group_name" {
  type    = string
  default = "/aws/bedrock/resolvable-logs"
}

resource "aws_s3_bucket" "logs" {
  bucket = var.log_bucket_name
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = var.log_bucket_name

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = var.log_bucket_name

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = var.log_bucket_name

  rule {
    id     = "retain-logs"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = var.log_group_name
  retention_in_days = 365
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

resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "my-resolvable-log-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
