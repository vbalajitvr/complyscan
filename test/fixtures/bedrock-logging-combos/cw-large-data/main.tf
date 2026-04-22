resource "aws_s3_bucket" "large_data" {
  bucket = "my-large-data-overflow-bucket"
}

resource "aws_s3_bucket_versioning" "large_data" {
  bucket = "my-large-data-overflow-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "large_data" {
  bucket = "my-large-data-overflow-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "large_data" {
  bucket = "my-large-data-overflow-bucket"

  rule {
    id     = "retain-large-data"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket" "trail" {
  bucket = "my-cw-large-data-trail-bucket"
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = "my-cw-large-data-trail-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = "my-cw-large-data-trail-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = "my-cw-large-data-trail-bucket"

  rule {
    id     = "retain-trail"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/cw-large-data-logs"
  retention_in_days = 365
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = "/aws/bedrock/cw-large-data-logs"
      role_arn       = "arn:aws:iam::123456789012:role/bedrock-cw-role"

      large_data_delivery_s3_config {
        bucket_name = "my-large-data-overflow-bucket"
        key_prefix  = "bedrock-large-data/"
      }
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "my-cw-large-data-trail-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
