resource "aws_s3_bucket" "logs" {
  bucket = "my-combo5-log-bucket"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = "my-combo5-log-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "my-combo5-log-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "my-combo5-log-bucket"

  rule {
    id     = "retain-logs"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket" "large_data" {
  bucket = "my-combo5-large-data-bucket"
}

resource "aws_s3_bucket_versioning" "large_data" {
  bucket = "my-combo5-large-data-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "large_data" {
  bucket = "my-combo5-large-data-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "large_data" {
  bucket = "my-combo5-large-data-bucket"

  rule {
    id     = "retain-large-data"
    status = "Enabled"

    expiration {
      days = 365
    }
  }
}

resource "aws_cloudwatch_log_group" "bedrock_logs" {
  name              = "/aws/bedrock/combo5-logs"
  retention_in_days = 365
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    text_data_delivery_enabled      = true

    cloudwatch_config {
      log_group_name = "/aws/bedrock/combo5-logs"
      role_arn       = "arn:aws:iam::123456789012:role/bedrock-cw-role"

      large_data_delivery_s3_config {
        bucket_name = "my-combo5-large-data-bucket"
        key_prefix  = "bedrock-large-data/"
      }
    }

    s3_config {
      bucket_name = "my-combo5-log-bucket"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "ai-audit-trail"
  s3_bucket_name                = "my-combo5-log-bucket"
  enable_logging                = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
