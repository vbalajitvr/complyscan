variable "log_bucket_name" {
  type        = string
  description = "Set at apply time."
}

variable "log_group_name" {
  type        = string
  description = "Set at apply time."
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

resource "aws_s3_bucket" "logs" {
  bucket = "acme-prod-bedrock-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "retain"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock" {
  name              = "/aws/bedrock/invocation-logs"
  retention_in_days = 365
}
