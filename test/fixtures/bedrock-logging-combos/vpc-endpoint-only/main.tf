resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc_endpoint" "bedrock" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.us-east-1.bedrock-runtime"
  vpc_endpoint_type = "Interface"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "placeholder-bucket"
  enable_logging = true
}
