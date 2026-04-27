module "bedrock" {
  source  = "terraform-aws-modules/bedrock/aws"
  version = "~> 1.0"

  agents = {
    support = {
      name = "support-bot"
    }
  }
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder"
  enable_logging = true
}
