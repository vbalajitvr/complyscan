module "bedrock_logging" {
  source = "./modules/bedrock_logging"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "local-bedrock-logs"
  enable_logging = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "local-bedrock-logs"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = "local-bedrock-logs"
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = "local-bedrock-logs"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = "local-bedrock-logs"
  rule {
    id     = "retain-logs"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}
