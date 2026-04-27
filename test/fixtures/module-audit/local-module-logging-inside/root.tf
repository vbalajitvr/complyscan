module "bedrock" {
  source = "./modules/bedrock"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder"
  enable_logging = true
}
