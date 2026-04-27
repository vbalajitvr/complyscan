variable "log_bucket" {
  type = string
  # No default — real Terraform requires caller to pass a value.
  # complyscan should treat this as var-no-default (INCONCLUSIVE) because
  # there is no module-aware way to know what the parent passed in.
}

resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config {
      bucket_name = var.log_bucket
    }
  }
}
