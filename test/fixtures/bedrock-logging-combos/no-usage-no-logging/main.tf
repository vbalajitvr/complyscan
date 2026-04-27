resource "aws_s3_bucket" "app_data" {
  bucket = "some-app-data-bucket"
}

resource "aws_cloudtrail" "main" {
  name           = "audit-trail"
  s3_bucket_name = "some-app-data-bucket"
  enable_logging = true
}
