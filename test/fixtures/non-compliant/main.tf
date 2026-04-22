resource "aws_s3_bucket" "logs" {
  bucket = "my-ai-log-bucket"
}

# No versioning configured
# No encryption configured
# No lifecycle configured

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "my-ai-log-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "my-ai-log-bucket"

  rule {
    id     = "short-retention"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/invocation-logs"
  retention_in_days = 7
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true

    s3_config {
      bucket_name = "my-ai-log-bucket"
    }

    cloudwatch_config {
      log_group_name = "/aws/bedrock/invocation-logs"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name           = "ai-audit-trail"
  s3_bucket_name = "my-ai-log-bucket"
  enable_logging = false
}
