resource "aws_s3_bucket" "logs" {
  bucket = "my-cw-s3-log-bucket"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = "my-cw-s3-log-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "my-cw-s3-log-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "my-cw-s3-log-bucket"

  rule {
    id     = "retain-logs"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/cw-s3-logs"
  retention_in_days = 365
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = "/aws/bedrock/cw-s3-logs"
      role_arn       = "arn:aws:iam::123456789012:role/bedrock-cw-role"
    }

    s3_config {
      bucket_name = "my-cw-s3-log-bucket"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "my-cw-s3-log-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
